//! znx-p2p — capa de red: swarm libp2p (TCP + Noise + Yamux) con dos
//! mecanismos complementarios entre nodos que comparten el mismo génesis:
//!
//! - `gossipsub` (broadcast): propaga transacciones y bloques nuevos a
//!   toda la red, tópicos `/znx/tx/1` y `/znx/blocks/1`.
//! - `request_response` (punto a punto): permite pedirle a un peer
//!   puntual "mandame el bloque de la altura H" — hace falta para que un
//!   nodo que se atrasó de una cadena más pesada pueda pedir los bloques
//!   que le faltan y ponerse al día (ver `znx-node`, pool de huérfanos).
//!
//! Sin Kademlia DHT — lista estática de bootnodes pasada por CLI.
//!
//! Endurecido contra peers maliciosos con dos behaviours oficiales de
//! `libp2p` (no lógica casera): `allow_block_list` (baneo — `znx-node`
//! decide CUÁNDO banear según mala conducta, acá solo se ejecuta) y
//! `connection_limits` (tope de conexiones totales y por-peer, mitiga un
//! flood simple de conexiones).
//!
//! Resistencia a eclipse attacks (mitigación parcial, ver
//! `netgroup_of`/`MAX_CONNECTIONS_PER_NETGROUP`): sin esto, el tope
//! por-peer-id no evita que un atacante con un único rango de IPs abra
//! muchas conexiones con `PeerId`s distintos (una keypair libp2p nueva es
//! gratis) y termine siendo la mayoría de los peers vistos por el nodo.
//! Se agrega un tope de conexiones por vecindario de red (agrupado por
//! /16 en IPv4, /32 en IPv6) y una rotación periódica de la conexión
//! saliente más vieja (`OUTBOUND_ROTATION_INTERVAL`) que vuelve a marcar
//! los bootnodes, para no depender para siempre de las primeras conexiones
//! salientes establecidas al arrancar. Es una mitigación parcial, no una
//! solución completa: sin descubrimiento de peers (no hay Kademlia DHT,
//! lista estática de bootnodes) el nodo sigue expuesto si TODOS sus
//! bootnodes configurados están comprometidos o son controlados por el
//! mismo atacante desde el día uno — eso queda fuera de alcance de lo que
//! resuelve diversidad/rotación de conexiones.
//!
//! Peer scoring nativo de gossipsub (además del ban list explícito de
//! arriba, que sigue siendo la respuesta a mala conducta objetivamente
//! comprobada): se activa con `with_peer_score` — reputación continua por
//! peer y por tópico (tiempo en el mesh, primeras entregas, colocación
//! por IP, mensajes inválidos) que gossipsub usa internamente para dejar
//! de propagarle/gossipearle a un peer de mala reputación aunque nunca
//! llegue a acumular los 5 strikes que dispara un baneo explícito. La
//! validación pasa a ser manual (`validate_messages`): `znx-node` decide
//! cuándo un mensaje es `Accept`/`Reject` vía
//! `NetworkHandle::report_message_validity` — un `Reject` aplica la
//! penalización P4 (mensajes inválidos) de gossipsub, además de lo que
//! `znx-node` ya hacía con `record_strike`. Ver `topic_score_params` por
//! qué P3 (entregas dentro del mesh) queda desactivado para nuestros dos
//! tópicos.
//!
//! Esto es SOLO propagación/transporte, no consenso: este crate no sabe
//! qué es un "bloque" más allá de bytes opacos, ni decide si una cadena
//! es válida o cuál gana un fork, ni QUÉ peer merece ser baneado — eso es
//! enteramente responsabilidad de `znx-node`/`znx-consensus` (ver
//! `docs/CONSENSUS.md`).

use std::collections::HashMap;
use std::io;
use std::time::{Duration, Instant};

use futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, StreamExt};
use libp2p::allow_block_list::{self, BlockedPeers};
use libp2p::connection_limits::{self, ConnectionLimits};
use libp2p::multiaddr::Protocol;
use libp2p::request_response::{self, ProtocolSupport, ResponseChannel};
use libp2p::swarm::{ConnectionId, NetworkBehaviour, SwarmEvent};
use libp2p::{gossipsub, noise, tcp, yamux, StreamProtocol, Swarm};
use thiserror::Error;
use tokio::sync::{mpsc, oneshot};

/// Tope de conexiones simultáneas — valores conservadores para un devnet,
/// mitigan un flood simple de conexiones (no un ataque distribuido real,
/// para eso hace falta bloqueo a nivel de red, fuera de alcance acá).
const MAX_CONNECTIONS_TOTAL: u32 = 100;
const MAX_CONNECTIONS_PER_PEER: u32 = 4;

/// Tope de conexiones establecidas simultáneas por "vecindario de red"
/// (ver `netgroup_of`). El tope por-peer-id de arriba no alcanza contra
/// eclipse por volumen: cada IP distinta que abre un atacante cuenta como
/// un `PeerId` distinto (una libp2p keypair nueva es gratis), así que un
/// atacante con un solo rango de direcciones (una máquina, un datacenter)
/// podría de otra forma ocupar la mayoría de las `MAX_CONNECTIONS_TOTAL`
/// conexiones del nodo con peers que en los hechos son todos el mismo
/// origen. Mismo criterio que usa Bitcoin Core para esto.
const MAX_CONNECTIONS_PER_NETGROUP: u32 = 8;

/// Cada cuánto se rota la conexión saliente más vieja: se cierra y se
/// vuelve a marcar (dial) la lista de bootnodes, para no depender para
/// siempre de las primeras conexiones salientes que se establecieron al
/// arrancar (que un atacante podría haber interceptado, ej. con un
/// secuestro de ruta temporal justo al inicio). Sin descubrimiento de
/// peers (no hay Kademlia DHT, ver el comentario del módulo) esto no
/// agrega diversidad nueva por sí solo, pero sí da una segunda oportunidad
/// periódica de conectar con los bootnodes reales si la primera conexión
/// fue con un impostor.
const OUTBOUND_ROTATION_INTERVAL: Duration = Duration::from_secs(600);

/// Cuánto esperar antes de reintentar un publish que falló por
/// `NoPeersSubscribedToTopic` — el mesh de gossipsub tarda un momento en
/// formarse después de conectar con un peer, así que la primera
/// publicación justo después de arrancar puede fallar aunque el peer ya
/// esté conectado. Sin esto, ese primer fallo se pierde para siempre y
/// los nodos quedan esperándose mutuamente (visto empíricamente al
/// probar 2 nodos: el bloque que no llegó nunca se reintentaba).
const PUBLISH_RETRY_DELAY: Duration = Duration::from_millis(500);

/// Tamaño máximo de un bloque aceptado por el protocolo de pedido de
/// bloques — cota generosa (16 MiB) contra un peer que declare un tamaño
/// absurdo para hacer que reservemos memoria de más.
const MAX_BLOCK_RESPONSE_BYTES: u32 = 16 * 1024 * 1024;

const BLOCK_SYNC_PROTOCOL: &str = "/znx/block-sync/1";

/// Agrupa una dirección por "vecindario de red" para el tope de
/// `MAX_CONNECTIONS_PER_NETGROUP`. IPv4 se agrupa por los primeros 2
/// octetos (equivalente a /16), IPv6 por los primeros 2 grupos
/// hexadecimales (equivalente a /32) — ninguno identifica una máquina
/// puntual, pero sí agrupa razonablemente direcciones que probablemente
/// comparten operador/proveedor. Direcciones dns4/dns6/dns (poco comunes
/// en la práctica, la mayoría de los peers se marcan por IP) se agrupan
/// por hostname completo — no hay aritmética de subred posible ahí.
fn netgroup_of(addr: &libp2p::Multiaddr) -> String {
    for protocol in addr.iter() {
        match protocol {
            Protocol::Ip4(ip) => {
                let [a, b, ..] = ip.octets();
                return format!("v4:{a}.{b}");
            }
            Protocol::Ip6(ip) => {
                let segments = ip.segments();
                return format!("v6:{:x}:{:x}", segments[0], segments[1]);
            }
            Protocol::Dns(name) | Protocol::Dns4(name) | Protocol::Dns6(name) => {
                return format!("dns:{name}");
            }
            _ => continue,
        }
    }
    // No debería pasar con el transporte TCP que usa este nodo (siempre
    // hay un Ip4/Ip6/Dns antes del /tcp), pero si pasara, cada dirección
    // así cuenta como su propio grupo — no aporta diversidad, pero
    // tampoco bloquea conexiones legítimas de por sí.
    format!("unknown:{addr}")
}

/// Parámetros de puntaje de gossipsub para uno de nuestros dos tópicos.
/// Se desactivan P3 (`mesh_message_deliveries`) y P3b (su penalización
/// asociada): están pensados para tópicos de altísima frecuencia (cientos
/// de mensajes por segundo, ej. attestations de un beacon chain) — con un
/// bloque nuevo cada 15s (devnet) a 120s (mainnet) y transacciones
/// esporádicas, el contador de entregas-en-la-ventana nunca alcanza el
/// umbral por defecto (`mesh_message_deliveries_threshold`, calibrado
/// para tráfico denso) y penalizaría por igual a TODOS los peers sin que
/// eso refleje ninguna mala conducta real. El resto de los parámetros (P1
/// tiempo en el mesh, P2 primeras entregas, P4 mensajes inválidos, P6
/// colocación por IP a nivel de `PeerScoreParams`) sí aplican con sus
/// valores por defecto — son razonables para cualquier frecuencia de
/// mensajes.
fn topic_score_params() -> gossipsub::TopicScoreParams {
    gossipsub::TopicScoreParams {
        mesh_message_deliveries_weight: 0.0,
        mesh_failure_penalty_weight: 0.0,
        ..Default::default()
    }
}

// Re-exportados para que znx-node no tenga que depender de `libp2p`
// directo solo para nombrar estos tipos en su CLI/lógica de huérfanos.
pub use gossipsub::MessageId;
pub use libp2p::{Multiaddr, PeerId};
pub use request_response::InboundRequestId;

/// Tópico de gossip para transacciones sueltas, todavía no incluidas en
/// ningún bloque — lo que hoy entra al mempool local vía RPC también se
/// publica acá para que el resto de la red lo vea.
pub const TX_TOPIC: &str = "/znx/tx/1";
/// Tópico de gossip para bloques nuevos (recién minados o aceptados).
pub const BLOCKS_TOPIC: &str = "/znx/blocks/1";

#[derive(Debug, Error)]
pub enum P2pError {
    #[error("no se pudo construir el swarm de libp2p: {0}")]
    Build(String),
    #[error("dirección de escucha inválida: {0}")]
    Listen(#[from] libp2p::TransportError<std::io::Error>),
    #[error("no se pudo publicar en gossipsub: {0}")]
    Publish(#[from] gossipsub::PublishError),
    #[error("no se pudo suscribir a un tópico de gossipsub: {0}")]
    Subscribe(#[from] gossipsub::SubscriptionError),
}

/// Mensaje entrante ya clasificado — lo único que le importa a
/// `znx-node`, sin exponerle los tipos internos de libp2p/gossipsub. Los
/// bytes de `Transaction`/`Block` son la codificación canónica de
/// znx-codec; decodificarlos es responsabilidad de quien consume esto.
#[derive(Debug)]
pub enum Inbound {
    /// `from` es el peer que nos mandó el mensaje directamente (siempre
    /// presente — es un dato del transporte, no de la firma de la
    /// aplicación), y `message_id` identifica el mensaje para poder
    /// reportar su validez con `NetworkHandle::report_message_validity`
    /// (con validación manual de gossipsub, esto es obligatorio: un
    /// mensaje que nunca se reporta no se vuelve a propagar).
    Transaction { bytes: Vec<u8>, message_id: MessageId, from: PeerId },
    Block { bytes: Vec<u8>, message_id: MessageId, from: PeerId },
    /// Un peer nos pide el bloque de `height` — znx-node decide qué
    /// responder (lee su propio storage) y llama a
    /// `NetworkHandle::respond_block` con el mismo `request_id`.
    BlockRequest { request_id: InboundRequestId, height: u64 },
    /// Se estableció una conexión nueva con `peer` — znx-node lo usa
    /// como disparador para intentar ponerse al día contra ese peer
    /// (sincronización completa/IBD, ver `znx-node::run_ibd_sync`).
    PeerConnected(PeerId),
}

enum Outbound {
    Transaction(Vec<u8>),
    Block(Vec<u8>),
    RequestBlock { peer: PeerId, height: u64, respond_to: oneshot::Sender<Option<Vec<u8>>> },
    RespondBlock { request_id: InboundRequestId, bytes: Option<Vec<u8>> },
    BanPeer(PeerId),
    ReportMessageValidity { message_id: MessageId, source: PeerId, accepted: bool },
}

/// Handle liviano y clonable para pedirle a la tarea que corre el swarm
/// que publique/pida/responda algo — el swarm en sí no se comparte entre
/// tareas (no es `Clone`), así que toda interacción es "mandar un mensaje
/// por canal", no una llamada directa a los behaviours.
#[derive(Clone)]
pub struct NetworkHandle {
    outbound: mpsc::UnboundedSender<Outbound>,
}

impl NetworkHandle {
    /// Si la tarea de red ya se apagó, esto no hace nada — no hay a quién
    /// reportarle el error, y para el caso de uso actual (znx-node
    /// terminando) no importa.
    pub fn publish_transaction(&self, bytes: Vec<u8>) {
        let _ = self.outbound.send(Outbound::Transaction(bytes));
    }

    pub fn publish_block(&self, bytes: Vec<u8>) {
        let _ = self.outbound.send(Outbound::Block(bytes));
    }

    /// Pide el bloque de `height` a `peer`, punto a punto. Devuelve `None`
    /// si el peer respondió que no lo tiene, si la petición falló (peer
    /// desconectado, timeout), o si la tarea de red ya se apagó antes de
    /// poder contestar.
    pub async fn request_block(&self, peer: PeerId, height: u64) -> Option<Vec<u8>> {
        let (respond_to, response) = oneshot::channel();
        if self.outbound.send(Outbound::RequestBlock { peer, height, respond_to }).is_err() {
            return None;
        }
        response.await.ok().flatten()
    }

    /// Contesta un `Inbound::BlockRequest` — `None` si no tenemos ese
    /// bloque. Si `request_id` ya no corresponde a un pedido pendiente
    /// (el peer se desconectó mientras tanto), no hace nada.
    pub fn respond_block(&self, request_id: InboundRequestId, bytes: Option<Vec<u8>>) {
        let _ = self.outbound.send(Outbound::RespondBlock { request_id, bytes });
    }

    /// Banea a `peer`: rechaza handshakes futuros (lista de bloqueo de
    /// libp2p) y desconecta cualquier conexión existente ahora mismo. La
    /// decisión de CUÁNDO banear (mala conducta repetida) es de
    /// `znx-node`, no de acá.
    pub fn ban_peer(&self, peer: PeerId) {
        let _ = self.outbound.send(Outbound::BanPeer(peer));
    }

    /// Reporta si un `Inbound::Transaction`/`Inbound::Block` era válido.
    /// Con validación manual de gossipsub esto es obligatorio para que el
    /// mensaje se termine de propagar al resto del mesh — no es opcional
    /// ni solo para scoring. `accepted: false` además aplica la
    /// penalización P4 de gossipsub sobre `source` (mensajes inválidos).
    /// Se llama una sola vez por mensaje, apenas se sabe la respuesta —
    /// si la validación real puede tardar (ej. un bloque que dispara
    /// backfill), se reporta `true` de entrada igual (ver comentario en
    /// `znx-node::handle_inbound_block`): la ventana del cache de
    /// gossipsub no alcanza para esperar varios round-trips de red, así
    /// que la decisión definitiva de mala conducta en esos casos sigue
    /// pasando por el baneo explícito (`ban_peer`), no por este reporte.
    pub fn report_message_validity(&self, message_id: MessageId, source: PeerId, accepted: bool) {
        let _ = self.outbound.send(Outbound::ReportMessageValidity { message_id, source, accepted });
    }
}

#[derive(Debug, Clone, Default)]
struct BlockSyncCodec;

#[derive(Debug, Clone)]
struct BlockRequestWire {
    height: u64,
}

#[derive(Debug, Clone)]
struct BlockResponseWire(Option<Vec<u8>>);

#[async_trait::async_trait]
impl request_response::Codec for BlockSyncCodec {
    type Protocol = StreamProtocol;
    type Request = BlockRequestWire;
    type Response = BlockResponseWire;

    async fn read_request<T>(&mut self, _protocol: &Self::Protocol, io: &mut T) -> io::Result<Self::Request>
    where
        T: AsyncRead + Unpin + Send,
    {
        let mut height_bytes = [0u8; 8];
        io.read_exact(&mut height_bytes).await?;
        Ok(BlockRequestWire { height: u64::from_be_bytes(height_bytes) })
    }

    async fn read_response<T>(&mut self, _protocol: &Self::Protocol, io: &mut T) -> io::Result<Self::Response>
    where
        T: AsyncRead + Unpin + Send,
    {
        let mut present = [0u8; 1];
        io.read_exact(&mut present).await?;
        if present[0] == 0 {
            return Ok(BlockResponseWire(None));
        }

        let mut len_bytes = [0u8; 4];
        io.read_exact(&mut len_bytes).await?;
        let len = u32::from_be_bytes(len_bytes);
        if len > MAX_BLOCK_RESPONSE_BYTES {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "respuesta de bloque excede el tamaño máximo permitido"));
        }

        let mut bytes = vec![0u8; len as usize];
        io.read_exact(&mut bytes).await?;
        Ok(BlockResponseWire(Some(bytes)))
    }

    async fn write_request<T>(&mut self, _protocol: &Self::Protocol, io: &mut T, request: Self::Request) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        io.write_all(&request.height.to_be_bytes()).await
    }

    async fn write_response<T>(&mut self, _protocol: &Self::Protocol, io: &mut T, response: Self::Response) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        match response.0 {
            None => io.write_all(&[0u8]).await,
            Some(bytes) => {
                io.write_all(&[1u8]).await?;
                io.write_all(&(bytes.len() as u32).to_be_bytes()).await?;
                io.write_all(&bytes).await
            }
        }
    }
}

#[derive(NetworkBehaviour)]
struct Behaviour {
    gossipsub: gossipsub::Behaviour,
    block_sync: request_response::Behaviour<BlockSyncCodec>,
    block_list: allow_block_list::Behaviour<BlockedPeers>,
    connection_limits: connection_limits::Behaviour,
}

pub struct Network {
    swarm: Swarm<Behaviour>,
    tx_topic: gossipsub::IdentTopic,
    blocks_topic: gossipsub::IdentTopic,
    outbound_rx: mpsc::UnboundedReceiver<Outbound>,
    retry_tx: mpsc::UnboundedSender<Outbound>,
    // Pedidos salientes todavía sin respuesta — cuando llega la respuesta
    // (o la petición falla), se resuelve y se saca de acá.
    pending_requests: HashMap<request_response::OutboundRequestId, oneshot::Sender<Option<Vec<u8>>>>,
    // Pedidos entrantes todavía sin contestar — znx-node decide qué
    // responder de forma asíncrona (lee su storage), así que hay que
    // guardar el canal de libp2p hasta que llame a `respond_block`.
    pending_responses: HashMap<InboundRequestId, ResponseChannel<BlockResponseWire>>,
    // Direcciones de bootnodes conocidas — se re-marcan (dial) en cada
    // rotación de salientes, no solo al arrancar.
    bootnodes: Vec<libp2p::Multiaddr>,
    // Cuántas conexiones establecidas hay ahora mismo por netgroup — para
    // rechazar una conexión nueva que llevaría a un grupo por encima de
    // `MAX_CONNECTIONS_PER_NETGROUP`.
    netgroup_counts: HashMap<String, u32>,
    // A qué netgroup pertenece cada conexión viva — para poder decrementar
    // `netgroup_counts` correctamente cuando se cierra (`ConnectionClosed`
    // no trae la dirección remota).
    connection_netgroups: HashMap<ConnectionId, String>,
    // Conexiones salientes vivas con cuándo se establecieron — para poder
    // elegir "la más vieja" en cada rotación periódica.
    outbound_established: HashMap<ConnectionId, (PeerId, Instant)>,
}

impl Network {
    /// Levanta el swarm, se suscribe a los tópicos de gossip conocidos,
    /// empieza a escuchar en `listen_addr` y marca (dial) a cada
    /// dirección de `bootnodes`. Un bootnode que no responde no es un
    /// error fatal acá (la red puede converger igual si otro peer nos
    /// marca a nosotros, o si el bootnode vuelve más tarde) — solo se
    /// loguea.
    pub fn new(listen_addr: &Multiaddr, bootnodes: &[Multiaddr]) -> Result<(Self, NetworkHandle), P2pError> {
        let mut swarm = libp2p::SwarmBuilder::with_new_identity()
            .with_tokio()
            .with_tcp(tcp::Config::default(), noise::Config::new, yamux::Config::default)
            .map_err(|e| P2pError::Build(e.to_string()))?
            .with_behaviour(|keypair| -> Result<Behaviour, Box<dyn std::error::Error + Send + Sync>> {
                // `validate_messages()`: la validación deja de ser
                // automática — cada mensaje entrante espera un
                // `report_message_validation_result` explícito (ver
                // `NetworkHandle::report_message_validity`) antes de
                // propagarse al resto del mesh o afectar el peer score.
                let gossipsub_config = gossipsub::ConfigBuilder::default()
                    .validate_messages()
                    .build()
                    .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { e.into() })?;
                let mut gossipsub = gossipsub::Behaviour::new(gossipsub::MessageAuthenticity::Signed(keypair.clone()), gossipsub_config)
                    .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { e.into() })?;
                let tx_topic = gossipsub::IdentTopic::new(TX_TOPIC);
                let blocks_topic = gossipsub::IdentTopic::new(BLOCKS_TOPIC);
                let mut peer_score_params = gossipsub::PeerScoreParams::default();
                peer_score_params.topics.insert(tx_topic.hash(), topic_score_params());
                peer_score_params.topics.insert(blocks_topic.hash(), topic_score_params());
                gossipsub
                    .with_peer_score(peer_score_params, gossipsub::PeerScoreThresholds::default())
                    .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { e.into() })?;
                let block_sync =
                    request_response::Behaviour::new([(StreamProtocol::new(BLOCK_SYNC_PROTOCOL), ProtocolSupport::Full)], request_response::Config::default());
                let block_list = allow_block_list::Behaviour::default();
                let limits = connection_limits::Behaviour::new(
                    ConnectionLimits::default()
                        .with_max_established_per_peer(Some(MAX_CONNECTIONS_PER_PEER))
                        .with_max_established(Some(MAX_CONNECTIONS_TOTAL)),
                );
                Ok(Behaviour { gossipsub, block_sync, block_list, connection_limits: limits })
            })
            .map_err(|e| P2pError::Build(e.to_string()))?
            .build();

        let tx_topic = gossipsub::IdentTopic::new(TX_TOPIC);
        let blocks_topic = gossipsub::IdentTopic::new(BLOCKS_TOPIC);
        swarm.behaviour_mut().gossipsub.subscribe(&tx_topic)?;
        swarm.behaviour_mut().gossipsub.subscribe(&blocks_topic)?;

        swarm.listen_on(listen_addr.clone())?;
        for addr in bootnodes {
            if let Err(e) = swarm.dial(addr.clone()) {
                eprintln!("znx-p2p: no se pudo marcar a {addr}: {e}");
            }
        }

        let (outbound_tx, outbound_rx) = mpsc::unbounded_channel();
        let network = Network {
            swarm,
            tx_topic,
            blocks_topic,
            outbound_rx,
            retry_tx: outbound_tx.clone(),
            pending_requests: HashMap::new(),
            pending_responses: HashMap::new(),
            bootnodes: bootnodes.to_vec(),
            netgroup_counts: HashMap::new(),
            connection_netgroups: HashMap::new(),
            outbound_established: HashMap::new(),
        };
        Ok((network, NetworkHandle { outbound: outbound_tx }))
    }

    /// Corre el swarm indefinidamente: reenvía por `inbound` cada mensaje
    /// de gossip y cada pedido de bloque entrante, resuelve las
    /// respuestas de los pedidos salientes, y publica/pide/responde lo
    /// que llegue por el canal interno de `NetworkHandle`. No vuelve — se
    /// usa con `tokio::spawn`, no se espera (`await`) directo en el flujo
    /// principal del nodo.
    pub async fn run(mut self, inbound: mpsc::UnboundedSender<Inbound>) {
        let tx_hash = self.tx_topic.hash();
        let blocks_hash = self.blocks_topic.hash();
        // El primer tick de `interval` es inmediato — se consume antes del
        // loop para que la primera rotación real sea después de
        // `OUTBOUND_ROTATION_INTERVAL`, no apenas arranca el nodo.
        let mut rotation_ticker = tokio::time::interval(OUTBOUND_ROTATION_INTERVAL);
        rotation_ticker.tick().await;

        loop {
            tokio::select! {
                event = self.swarm.select_next_some() => match event {
                    SwarmEvent::Behaviour(BehaviourEvent::Gossipsub(gossipsub::Event::Message { propagation_source, message_id, message })) => {
                        let inbound_msg = if message.topic == tx_hash {
                            Some(Inbound::Transaction { bytes: message.data, message_id: message_id.clone(), from: propagation_source })
                        } else if message.topic == blocks_hash {
                            Some(Inbound::Block { bytes: message.data, message_id: message_id.clone(), from: propagation_source })
                        } else {
                            None
                        };
                        match inbound_msg {
                            Some(msg) => {
                                // El receiver solo se dropea si znx-node
                                // ya se está apagando — no hay nada que
                                // hacer acá.
                                let _ = inbound.send(msg);
                            }
                            None => {
                                // Tópico desconocido (no debería pasar,
                                // solo estamos suscritos a 2) — igual hay
                                // que reportar para no dejarlo colgado en
                                // el cache de gossipsub para siempre.
                                self.swarm.behaviour_mut().gossipsub.report_message_validation_result(
                                    &message_id,
                                    &propagation_source,
                                    gossipsub::MessageAcceptance::Reject,
                                );
                            }
                        }
                    }
                    SwarmEvent::Behaviour(BehaviourEvent::BlockSync(request_response::Event::Message { message, .. })) => {
                        match message {
                            request_response::Message::Request { request_id, request, channel } => {
                                self.pending_responses.insert(request_id, channel);
                                let _ = inbound.send(Inbound::BlockRequest { request_id, height: request.height });
                            }
                            request_response::Message::Response { request_id, response } => {
                                if let Some(respond_to) = self.pending_requests.remove(&request_id) {
                                    let _ = respond_to.send(response.0);
                                }
                            }
                        }
                    }
                    SwarmEvent::Behaviour(BehaviourEvent::BlockSync(request_response::Event::OutboundFailure { request_id, .. })) => {
                        if let Some(respond_to) = self.pending_requests.remove(&request_id) {
                            let _ = respond_to.send(None);
                        }
                    }
                    SwarmEvent::Behaviour(BehaviourEvent::BlockSync(request_response::Event::InboundFailure { request_id, .. })) => {
                        self.pending_responses.remove(&request_id);
                    }
                    SwarmEvent::NewListenAddr { address, .. } => {
                        println!("znx-p2p: escuchando en {address}");
                    }
                    SwarmEvent::ConnectionEstablished { peer_id, connection_id, endpoint, .. } => {
                        let remote_addr = endpoint.get_remote_address().clone();
                        let group = netgroup_of(&remote_addr);
                        let over_limit = {
                            let count = self.netgroup_counts.entry(group.clone()).or_insert(0);
                            if *count >= MAX_CONNECTIONS_PER_NETGROUP {
                                true
                            } else {
                                *count += 1;
                                false
                            }
                        };
                        if over_limit {
                            println!(
                                "znx-p2p: rechazando a {peer_id} ({remote_addr}) — límite de conexiones por vecindario de red alcanzado ({group})"
                            );
                            self.swarm.close_connection(connection_id);
                        } else {
                            self.connection_netgroups.insert(connection_id, group);
                            if endpoint.is_dialer() {
                                self.outbound_established.insert(connection_id, (peer_id, Instant::now()));
                            }
                            println!("znx-p2p: conectado a {peer_id}");
                            let _ = inbound.send(Inbound::PeerConnected(peer_id));
                        }
                    }
                    SwarmEvent::ConnectionClosed { connection_id, .. } => {
                        self.outbound_established.remove(&connection_id);
                        if let Some(group) = self.connection_netgroups.remove(&connection_id) {
                            if let Some(count) = self.netgroup_counts.get_mut(&group) {
                                *count = count.saturating_sub(1);
                                if *count == 0 {
                                    self.netgroup_counts.remove(&group);
                                }
                            }
                        }
                    }
                    _ => {}
                },
                _ = rotation_ticker.tick() => {
                    self.rotate_oldest_outbound();
                },
                Some(cmd) = self.outbound_rx.recv() => match cmd {
                    Outbound::RequestBlock { peer, height, respond_to } => {
                        let request_id = self.swarm.behaviour_mut().block_sync.send_request(&peer, BlockRequestWire { height });
                        self.pending_requests.insert(request_id, respond_to);
                    }
                    Outbound::RespondBlock { request_id, bytes } => {
                        if let Some(channel) = self.pending_responses.remove(&request_id) {
                            let _ = self.swarm.behaviour_mut().block_sync.send_response(channel, BlockResponseWire(bytes));
                        }
                    }
                    Outbound::Transaction(bytes) => self.publish_or_retry(Outbound::Transaction(bytes.clone()), self.tx_topic.clone(), bytes),
                    Outbound::Block(bytes) => self.publish_or_retry(Outbound::Block(bytes.clone()), self.blocks_topic.clone(), bytes),
                    Outbound::BanPeer(peer) => {
                        self.swarm.behaviour_mut().block_list.block_peer(peer);
                        let _ = self.swarm.disconnect_peer_id(peer);
                        println!("znx-p2p: peer {peer} baneado");
                    }
                    Outbound::ReportMessageValidity { message_id, source, accepted } => {
                        let acceptance = if accepted { gossipsub::MessageAcceptance::Accept } else { gossipsub::MessageAcceptance::Reject };
                        self.swarm.behaviour_mut().gossipsub.report_message_validation_result(&message_id, &source, acceptance);
                    }
                }
            }
        }
    }

    /// Cierra la conexión saliente viva más vieja y vuelve a marcar
    /// (dial) todos los bootnodes conocidos — ver `OUTBOUND_ROTATION_INTERVAL`.
    /// Nunca rota si queda 1 sola conexión saliente o menos: preferible
    /// seguir viendo la red desde un solo lugar que quedarse sin salientes
    /// mientras se espera que el redial prospere.
    fn rotate_oldest_outbound(&mut self) {
        if self.outbound_established.len() <= 1 {
            return;
        }
        let oldest = self
            .outbound_established
            .iter()
            .min_by_key(|(_, (_, since))| *since)
            .map(|(id, (peer, _))| (*id, *peer));
        let Some((connection_id, peer_id)) = oldest else {
            return;
        };
        println!("znx-p2p: rotando conexión saliente más vieja con {peer_id} (diversidad de red)");
        // `ConnectionClosed` hace la limpieza de `outbound_established` /
        // `netgroup_counts` para esta conexión — no hace falta acá.
        self.swarm.close_connection(connection_id);
        for addr in self.bootnodes.clone() {
            if let Err(e) = self.swarm.dial(addr.clone()) {
                eprintln!("znx-p2p: no se pudo re-marcar a {addr} durante la rotación: {e}");
            }
        }
    }

    /// Publica en `topic`; si el mesh de gossipsub con el peer todavía no
    /// se formó (`NoPeersSubscribedToTopic`, normal recién arrancado
    /// aunque la conexión ya exista), reintenta el mismo comando después
    /// de `PUBLISH_RETRY_DELAY` en vez de perder el mensaje para siempre.
    fn publish_or_retry(&mut self, original: Outbound, topic: gossipsub::IdentTopic, bytes: Vec<u8>) {
        match self.swarm.behaviour_mut().gossipsub.publish(topic, bytes) {
            Ok(_) => {}
            Err(gossipsub::PublishError::NoPeersSubscribedToTopic) => {
                let retry_tx = self.retry_tx.clone();
                tokio::spawn(async move {
                    tokio::time::sleep(PUBLISH_RETRY_DELAY).await;
                    let _ = retry_tx.send(original);
                });
            }
            Err(e) => eprintln!("znx-p2p: no se pudo publicar: {e}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::netgroup_of;

    #[test]
    fn ipv4_addresses_share_netgroup_by_slash_16() {
        let a: libp2p::Multiaddr = "/ip4/203.0.113.10/tcp/30333".parse().unwrap();
        let b: libp2p::Multiaddr = "/ip4/203.0.113.200/tcp/40000".parse().unwrap();
        assert_eq!(netgroup_of(&a), netgroup_of(&b));
    }

    #[test]
    fn ipv4_addresses_in_different_slash_16_differ() {
        let a: libp2p::Multiaddr = "/ip4/203.0.113.10/tcp/30333".parse().unwrap();
        let b: libp2p::Multiaddr = "/ip4/198.51.100.10/tcp/30333".parse().unwrap();
        assert_ne!(netgroup_of(&a), netgroup_of(&b));
    }

    #[test]
    fn ipv6_addresses_share_netgroup_by_slash_32() {
        let a: libp2p::Multiaddr = "/ip6/2001:db8::1/tcp/30333".parse().unwrap();
        let b: libp2p::Multiaddr = "/ip6/2001:db8::dead:beef/tcp/30333".parse().unwrap();
        assert_eq!(netgroup_of(&a), netgroup_of(&b));
    }

    #[test]
    fn ipv6_addresses_in_different_slash_32_differ() {
        let a: libp2p::Multiaddr = "/ip6/2001:db8::1/tcp/30333".parse().unwrap();
        let b: libp2p::Multiaddr = "/ip6/2001:dead::1/tcp/30333".parse().unwrap();
        assert_ne!(netgroup_of(&a), netgroup_of(&b));
    }

    #[test]
    fn dns_addresses_group_by_full_hostname() {
        let a: libp2p::Multiaddr = "/dns4/node-a.example.com/tcp/30333".parse().unwrap();
        let b: libp2p::Multiaddr = "/dns4/node-b.example.com/tcp/30333".parse().unwrap();
        let c: libp2p::Multiaddr = "/dns4/node-a.example.com/tcp/40000".parse().unwrap();
        assert_ne!(netgroup_of(&a), netgroup_of(&b));
        assert_eq!(netgroup_of(&a), netgroup_of(&c));
    }
}
