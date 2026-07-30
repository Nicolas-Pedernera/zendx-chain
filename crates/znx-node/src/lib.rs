//! znx-node — nodo: minero PoW abierto (cualquiera puede minar, no hay
//! validator set permisionado) + servidor JSON-RPC mínimo para que
//! `znx-wallet-cli` pueda mandar transacciones y consultar UTXOs, + red
//! P2P (`znx-p2p`, gossipsub) para propagar transacciones y bloques entre
//! nodos que comparten el mismo génesis.
//!
//! Reemplaza el diseño anterior (PoA round-robin + gadget BFT, nunca
//! implementado): sin identidad de validador que rotar, la "autorización"
//! para producir un bloque es encontrar un nonce que cumpla la dificultad
//! vigente (ver `znx-consensus`). Sin finalidad BFT tampoco — hay reorg
//! (`try_reorg_to_chain`) para cadenas competidoras de hasta
//! `MAX_BACKFILL_DEPTH` bloques de profundidad: si un bloque entrante no
//! extiende la punta local, se le pide al peer que lo mandó (vía
//! `znx_p2p::NetworkHandle::request_block`, protocolo punto a punto, no
//! gossip) el padre, y el padre del padre, etc., hasta encontrar un
//! ancestro común con la cadena local o agotar la profundidad máxima. El
//! desempate cuando hay empate exacto de trabajo (el caso típico: un solo
//! bloque hermano a la misma altura, donde el target es idéntico porque
//! es una función determinística de la altura, no algo que cada minero
//! elige) es por **hash de header** (el menor gana), no por trabajo —
//! comparar trabajo ahí nunca desempataría nada. Forks de más de
//! `MAX_BACKFILL_DEPTH` bloques quedan fuera de alcance (equivalente a lo
//! que en cadenas reales resuelven los checkpoints).
//!
//! **Validación estricta, no solo logging**: a diferencia del diseño PoA
//! anterior (que aceptaba un bloque igual aunque su `state_root` no
//! coincidiera, solo alertando), acá un bloque que no valida se RECHAZA de
//! verdad — sin gadget de finalidad, la validación completa de cada
//! bloque es todo el modelo de seguridad.
//!
//! El servidor RPC lo provee el crate `znx-rpc` dedicado — `SharedNode`
//! solo implementa el trait `znx_rpc::RpcNode` (ver el `impl` más abajo),
//! delegando en el storage/mempool/génesis que ya tiene a mano.

pub mod genesis;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use thiserror::Error;
use tokio::sync::{mpsc, Mutex};

use znx_codec::{block_hash, decode, encode, tx_root};
use znx_consensus::ConsensusError;
use znx_crypto::{Address, CryptoError};
use znx_mempool::Mempool;
use znx_p2p::{Inbound, InboundRequestId, MessageId, Multiaddr, Network, NetworkHandle, P2pError, PeerId};
use znx_rpc::{MiningInfo, RpcError, RpcNode};
use znx_state::{apply_coinbase, apply_transaction, OverlayStore, StateError};
use znx_storage::{RocksStorage, StorageError};
use znx_types::{Block, BlockHeader, OutPoint, Transaction, TxOut};

pub use genesis::{Genesis, GenesisError};

/// Tope de transacciones incluidas por bloque — evita que un mempool muy
/// cargado produzca un bloque arbitrariamente grande. Sin significado
/// especial más allá de "un número razonable para un devnet", se revisa
/// si hace falta ajustarlo cuando haya carga real.
const MAX_TXS_PER_BLOCK: usize = 500;

/// Cuántos valores de `pow_nonce` probar por tanda antes de volver a
/// armar el candidato (releer la punta local, el mempool, refrescar el
/// timestamp). Con hashing blake3 de un header chico, esto se resuelve en
/// una fracción de segundo por tanda — mantiene la "obsolescencia" de un
/// candidato acotada sin necesitar un mecanismo de cancelación explícito.
const MINING_BATCH_ATTEMPTS: u64 = 500_000;

/// Cuántos bloques hacia atrás se está dispuesto a pedirle a un peer para
/// intentar reconstruir una cadena competidora antes de darse por vencido
/// — acota el costo (round-trips de red, bloques guardados en memoria
/// mientras se arma la cadena) de un fork profundo o de un peer que
/// mienta indefinidamente sobre tener un padre. Forks más profundos que
/// esto quedan fuera de alcance (ver doc de módulo).
const MAX_BACKFILL_DEPTH: u32 = 20;

/// Cota de seguridad para la sincronización completa (IBD, ver
/// `run_ibd_sync`) — no es una defensa contra un peer malicioso (cada
/// bloque descargado ya se valida completo antes de aplicarse), es solo
/// para que un bug propio no deje un `tokio::spawn` pidiendo bloques para
/// siempre. Generosa a propósito: el objetivo de IBD es cubrir cualquier
/// distancia, a diferencia del backfill reactivo (acotado a
/// `MAX_BACKFILL_DEPTH`, pensado para forks cortos).
const MAX_IBD_BLOCKS_PER_SYNC: u64 = 1_000_000;

/// Cuántas alturas pedir en paralelo por tanda durante IBD (ver
/// `run_ibd_sync`) en vez de esperar cada respuesta antes de pedir la
/// siguiente. Ni tan chico que no mejore nada sobre pedir de a uno (el
/// problema original: 1 round-trip por bloque, en serie), ni tan grande
/// que un peer lento se vuelva un cuello de botella enorme antes de
/// poder avanzar la punta local con lo que ya llegó.
const IBD_PIPELINE_WINDOW: usize = 16;

#[derive(Debug, Error)]
pub enum NodeError {
    #[error("error de storage: {0}")]
    Storage(#[from] StorageError),
    #[error("error de génesis: {0}")]
    Genesis(#[from] GenesisError),
    #[error("error de RPC: {0}")]
    Rpc(#[from] RpcError),
    #[error("error de red P2P: {0}")]
    P2p(#[from] P2pError),
    #[error("--miner-address inválida: {0}")]
    InvalidMinerAddress(CryptoError),
    #[error("premine de génesis inválido: {0}")]
    InvalidPremine(#[from] StateError),
}

pub struct NodeConfig {
    pub data_dir: PathBuf,
    pub genesis_path: PathBuf,
    pub bind_addr: SocketAddr,
    pub listen_addr: Multiaddr,
    pub peers: Vec<Multiaddr>,
    /// Dirección a la que paga la coinbase de los bloques que este
    /// proceso mine. `None` = no minar — el nodo igual valida/relee
    /// bloques y transacciones de la red y sirve RPC de solo consulta.
    pub miner_address: Option<String>,
}

/// Estado compartido entre el loop de minería, el handler de mensajes P2P
/// entrantes, y los handlers RPC — un solo `Mutex` por recurso (no uno
/// global) para que una consulta de solo lectura (`list_unspent`) no
/// tenga que esperar si lo único ocupado en ese momento es el mempool, y
/// viceversa.
pub struct SharedNode {
    pub storage: Mutex<RocksStorage>,
    pub mempool: Mutex<Mempool>,
    pub genesis: Genesis,
    pub network: NetworkHandle,
    /// Cuántas veces cada peer mandó (por gossip o como respuesta de
    /// backfill) un bloque que no valida. Deliberadamente simple —
    /// contador en memoria, sin persistencia ni expiración, no un
    /// sistema de reputación completo (ver doc de módulo) — alcanza para
    /// frenar a un peer activo dentro de la vida del proceso.
    strikes: Mutex<HashMap<PeerId, u32>>,
}

/// Strikes antes de banear a un peer (ver `SharedNode::strikes` y
/// `record_strike`).
const STRIKES_BEFORE_BAN: u32 = 5;

/// Suma un strike a `peer` por mandar un bloque inválido (gossip o
/// backfill) y lo banea si llega al umbral.
async fn record_strike(shared: &SharedNode, peer: PeerId, reason: &str) {
    let mut strikes = shared.strikes.lock().await;
    let count = strikes.entry(peer).or_insert(0);
    *count += 1;
    eprintln!("znx-node: strike #{count} contra {peer} ({reason})");
    if *count >= STRIKES_BEFORE_BAN {
        println!("znx-node: {peer} superó {STRIKES_BEFORE_BAN} strikes, baneado");
        shared.network.ban_peer(peer);
    }
}

impl RpcNode for SharedNode {
    async fn submit_transaction(&self, tx: Transaction) -> Result<[u8; 32], String> {
        let id = znx_codec::txid(&tx);
        // Mismo orden de locks que el resto del nodo (storage antes que
        // mempool) — evita un deadlock si algún día se paraleliza.
        let storage = self.storage.lock().await;
        self.mempool.lock().await.insert(&*storage, tx).map_err(|e| e.to_string())?;
        Ok(id)
    }

    async fn list_unspent(&self, address: Address) -> Result<Vec<(OutPoint, TxOut)>, String> {
        self.storage.lock().await.list_utxos_for(&address).map_err(|e| e.to_string())
    }

    async fn latest_height(&self) -> Result<Option<u64>, String> {
        self.storage.lock().await.latest_height().map_err(|e| e.to_string())
    }

    async fn get_block(&self, height: u64) -> Result<Option<Block>, String> {
        self.storage.lock().await.get_block(height).map_err(|e| e.to_string())
    }

    async fn get_block_by_hash(&self, hash: [u8; 32]) -> Result<Option<Block>, String> {
        self.storage.lock().await.get_block_by_hash(&hash).map_err(|e| e.to_string())
    }

    async fn get_transaction(&self, txid: [u8; 32]) -> Result<Option<(u64, [u8; 32], Transaction)>, String> {
        self.storage.lock().await.get_transaction(&txid).map_err(|e| e.to_string())
    }

    async fn mempool_len(&self) -> usize {
        self.mempool.lock().await.len()
    }

    async fn mining_info(&self) -> MiningInfo {
        let storage = self.storage.lock().await;
        let height = storage.latest_height().ok().flatten();
        let target = height
            .and_then(|h| storage.get_block(h).ok().flatten())
            .map(|block| block.header.target)
            .unwrap_or(self.genesis.initial_target);
        drop(storage);

        let next_height = height.map(|h| h + 1).unwrap_or(0);
        let next_subsidy = znx_consensus::subsidy_for_height(next_height, &self.genesis.subsidy_schedule, self.genesis.subsidy_period_blocks);
        MiningInfo { chain_id: self.genesis.chain_id.clone(), height, target, next_subsidy }
    }
}

/// Abre (o crea) el storage en `data_dir`, aplica el bloque génesis si
/// todavía no hay ninguno (primer arranque), levanta la red P2P y el
/// servidor RPC, arranca el loop de minería si se pasó `--miner-address`,
/// y corre el loop principal (aplicar mensajes entrantes) hasta Ctrl+C.
/// No vuelve hasta que el proceso se apaga.
pub async fn run(config: NodeConfig) -> Result<(), NodeError> {
    let mut storage = RocksStorage::open(&config.data_dir)?;
    let genesis = Genesis::load(&config.genesis_path)?;

    if storage.latest_height()?.is_none() {
        bootstrap_genesis(&mut storage, &genesis)?;
        println!(
            "génesis aplicado: chain_id={} subsidio_inicial={} período={} bloques tiempo_objetivo={}s premine_a={} direcciones",
            genesis.chain_id, genesis.subsidy_schedule[0], genesis.subsidy_period_blocks, genesis.target_block_time_secs, genesis.premine.len()
        );
    }

    let miner_address = config.miner_address.as_deref().map(Address::from_bech32).transpose().map_err(NodeError::InvalidMinerAddress)?;

    let (network, network_handle) = Network::new(&config.listen_addr, &config.peers)?;
    let (inbound_tx, inbound_rx) = mpsc::unbounded_channel();
    tokio::spawn(network.run(inbound_tx));

    let shared = Arc::new(SharedNode {
        storage: Mutex::new(storage),
        mempool: Mutex::new(Mempool::new(genesis.chain_id.clone())),
        genesis,
        network: network_handle,
        strikes: Mutex::new(HashMap::new()),
    });

    let server_handle = znx_rpc::start_server(config.bind_addr, shared.clone()).await?;
    println!("znx-node: RPC escuchando en {}", config.bind_addr);

    if let Some(miner) = miner_address {
        println!("znx-node: minando hacia {miner}");
        tokio::spawn(run_mining_loop(shared.clone(), miner));
    } else {
        println!("znx-node: corre sin minar (sin --miner-address) — valida y relee bloques/tx de la red");
    }

    run_main_loop(shared, inbound_rx).await;

    // `stop()` solo falla si el servidor ya se detuvo por su cuenta — no
    // hay nada que hacer ante eso en el shutdown, de ahí el `let _`.
    let _ = server_handle.stop();
    Ok(())
}

/// Aplica el bloque género. Si `genesis.premine` no está vacío, el
/// bloque 0 lleva una única transacción coinbase (altura 0) con un
/// output por entrada de premine — igual que una coinbase normal, pero
/// de una sola vez y fuera del calendario de emisión (`premine` no sale
/// de `subsidy_for_height`, es una asignación directa aparte). Se
/// construye igual en todos los nodos que arrancan del mismo archivo de
/// génesis (mismo orden de `premine` en el JSON → mismo `txid` → mismo
/// `tx_root` → mismo hash de génesis), así que no hace falta propagarla
/// por red.
///
/// `put_block` (a diferencia de `commit_block`) no toca el UTXO set —
/// hace falta `apply_coinbase` aparte para que las salidas de premine
/// existan de verdad. Se reusa esa función tal cual (en vez de escribir
/// los UTXOs a mano) para no duplicar la lógica de "de una transacción
/// coinbase-shaped, generar sus UTXOs" en dos lugares.
fn bootstrap_genesis(storage: &mut RocksStorage, genesis: &Genesis) -> Result<(), NodeError> {
    let transactions = if genesis.premine.is_empty() {
        vec![]
    } else {
        let outputs = genesis.premine.iter().map(|(address, amount)| TxOut { amount: *amount, pubkey_hash: *address }).collect();
        vec![Transaction::new_coinbase(genesis.chain_id.clone(), 0, 0, outputs)]
    };

    let genesis_block = Block {
        header: BlockHeader {
            height: 0,
            parent_hash: [0u8; 32],
            tx_root: tx_root(&transactions),
            timestamp: genesis.genesis_time_unix,
            target: genesis.initial_target,
            pow_nonce: 0,
        },
        transactions,
    };
    storage.put_block(&genesis_block)?;

    if let Some(premine_tx) = genesis_block.transactions.first() {
        let premine_total: u128 = premine_tx.outputs.iter().map(|out| out.amount).sum();
        apply_coinbase(storage, premine_tx, 0, premine_total)?;
    }
    Ok(())
}

/// Cada mensaje entrante se procesa en su propia tarea (`tokio::spawn`),
/// no `.await`-eado inline en este loop — un bloque huérfano de un peer
/// puede disparar `backfill_and_reorg` (hasta `MAX_BACKFILL_DEPTH`
/// round-trips de red, cada uno con su timeout), y antes de este cambio
/// eso bloqueaba TODO el procesamiento de mensajes de otros peers
/// mientras tanto — un peer malicioso mandando huérfanos falsos a
/// repetición podía dejar al nodo efectivamente colgado. Es seguro bajo
/// concurrencia sin cambios adicionales: toda mutación real pasa por
/// `shared.storage`/`shared.mempool` (`Mutex`), que sigue serializando
/// las escrituras — un intento que llega tarde (la punta ya avanzó por
/// otro mensaje procesado en paralelo) simplemente falla con
/// `UnexpectedHeight`/`ParentMismatch`, mismo patrón que ya maneja la
/// carrera contra el propio `submit_own_block`.
async fn run_main_loop(shared: Arc<SharedNode>, mut inbound_rx: mpsc::UnboundedReceiver<Inbound>) {
    loop {
        tokio::select! {
            Some(msg) = inbound_rx.recv() => {
                let shared = shared.clone();
                tokio::spawn(async move { handle_inbound(&shared, msg).await; });
            }
            _ = tokio::signal::ctrl_c() => {
                println!("znx-node: señal de apagado recibida, terminando...");
                break;
            }
        }
    }
}

/// Target de dificultad esperado en `height`: si no es un límite de
/// reajuste, el mismo del bloque anterior; si lo es, el resultado de
/// `znx_consensus::retarget` sobre cuánto tardó realmente el último
/// período versus cuánto debería haber tardado.
fn expected_target(storage: &RocksStorage, genesis: &Genesis, height: u64) -> Result<[u8; 32], StorageError> {
    if height == 0 {
        return Ok(genesis.initial_target);
    }
    let parent = storage.get_block(height - 1)?.expect("el bloque padre siempre existe antes de construir/validar uno nuevo");

    let interval = genesis.difficulty_adjustment_interval_blocks;
    if interval == 0 || !height.is_multiple_of(interval) || height < interval {
        return Ok(parent.header.target);
    }

    let boundary_block = storage.get_block(height - interval)?.expect("el bloque de referencia del período de reajuste siempre existe");
    let actual_timespan = parent.header.timestamp.saturating_sub(boundary_block.header.timestamp).max(1);
    let expected_timespan = genesis.target_block_time_secs.saturating_mul(interval);
    Ok(znx_consensus::retarget(&parent.header.target, actual_timespan, expected_timespan))
}

struct MiningCandidate {
    header: BlockHeader,
    transactions: Vec<Transaction>,
}

/// Arma un bloque candidato contra la punta local actual: valida cada tx
/// del mempool contra un `OverlayStore` (no toca el storage real todavía
/// — si perdemos la carrera de minería, no queremos haber mutado nada) y
/// arma la coinbase por `subsidio_del_halving + fees recolectados`.
async fn build_mining_candidate(shared: &SharedNode, miner: Address, extra_nonce: u64) -> Option<MiningCandidate> {
    let storage = shared.storage.lock().await;
    let local_height = storage.latest_height().ok()??;
    let parent = storage.get_block(local_height).ok()??;
    let parent_hash = block_hash(&parent);
    let height = local_height + 1;
    let target = expected_target(&storage, &shared.genesis, height).ok()?;

    let batch = shared.mempool.lock().await.next_batch(MAX_TXS_PER_BLOCK);

    let mut overlay = OverlayStore::new(&*storage);
    let mut included = Vec::with_capacity(batch.len());
    let mut total_fees: u128 = 0;
    for tx in batch {
        match apply_transaction(&mut overlay, &tx, &shared.genesis.chain_id) {
            Ok(applied) => {
                total_fees = total_fees.saturating_add(applied.fee);
                included.push(tx);
            }
            // El mempool solo hace admisión, no re-valida contra el
            // estado exacto en el momento de armar el candidato (ver doc
            // de znx-mempool) — una tx que ya no es válida acá se descarta.
            Err(e) => eprintln!("znx-node: tx descartada al armar el candidato: {e}"),
        }
    }
    drop(overlay);
    drop(storage);

    let subsidy = znx_consensus::subsidy_for_height(height, &shared.genesis.subsidy_schedule, shared.genesis.subsidy_period_blocks);
    let coinbase_amount = subsidy.saturating_add(total_fees);
    let coinbase = Transaction::new_coinbase(shared.genesis.chain_id.clone(), height, extra_nonce, vec![TxOut { amount: coinbase_amount, pubkey_hash: miner }]);

    let mut transactions = Vec::with_capacity(included.len() + 1);
    transactions.push(coinbase);
    transactions.extend(included);

    let header = BlockHeader { height, parent_hash, tx_root: tx_root(&transactions), timestamp: now_unix(), target, pow_nonce: 0 };
    Some(MiningCandidate { header, transactions })
}

/// Búsqueda de nonce pura (CPU-bound) — corre en un hilo bloqueante
/// (`tokio::task::spawn_blocking`), nunca directo en el runtime async.
fn mine_batch(mut header: BlockHeader, attempts: u64) -> Option<BlockHeader> {
    for nonce in 0..attempts {
        header.pow_nonce = nonce;
        let hash = znx_codec::pow_hash(&header);
        if znx_codec::meets_target(&hash, &header.target) {
            return Some(header);
        }
    }
    None
}

async fn run_mining_loop(shared: Arc<SharedNode>, miner: Address) {
    let mut extra_nonce: u64 = 0;
    loop {
        let Some(candidate) = build_mining_candidate(&shared, miner, extra_nonce).await else {
            tokio::time::sleep(Duration::from_millis(500)).await;
            continue;
        };
        extra_nonce = extra_nonce.wrapping_add(1);

        let header_template = candidate.header;
        let mined = tokio::task::spawn_blocking(move || mine_batch(header_template, MINING_BATCH_ATTEMPTS))
            .await
            .expect("la tarea de minería no debería panicear");

        let Some(mined_header) = mined else {
            // Agotamos la tanda sin encontrar un nonce válido para este
            // candidato — las tx que traía (todas menos la coinbase, que
            // se vuelve a armar sola en el próximo candidato) tienen que
            // volver al mempool. `next_batch` (dentro de
            // `build_mining_candidate`) ya las había sacado — sin este
            // paso se pierden en silencio para siempre: ni quedan en el
            // mempool ni terminan en ningún bloque, y quien las mandó
            // nunca se entera. Hallazgo real armando el flujo de
            // depósito/retiro (ver blockchain/docs/INTEGRATION.md): con
            // la dificultad ya ajustada varios escalones desde el
            // génesis, un candidato sin nonce válido pasa con frecuencia
            // real, no es un caso de borde teórico.
            requeue_failed_candidate(&shared, candidate.transactions).await;
            continue;
        };

        let block = Block { header: mined_header, transactions: candidate.transactions };
        submit_own_block(&shared, block).await;
    }
}

/// Núcleo sincrónico de `requeue_failed_candidate` — separado para poder
/// testearlo sin un `SharedNode` completo (que arrastra una
/// `NetworkHandle` real de libp2p). `transactions[0]` es siempre la
/// coinbase (la arma `build_mining_candidate` directo, nunca pasó por el
/// mempool) — se descarta acá sin reinsertarla, el próximo candidato
/// arma una nueva. Re-valida cada tx con `Mempool::insert` en vez de
/// reinsertarla a mano: mismo costo que cuando entró la primera vez,
/// pero reusa la única ruta de validación ya auditada en vez de abrir
/// una segunda sin validar.
fn requeue_transactions<S: znx_state::StateStore>(store: &S, mempool: &mut Mempool, transactions: Vec<Transaction>) {
    if transactions.len() <= 1 {
        return; // solo la coinbase, no había nada del mempool que perder
    }
    for tx in transactions.into_iter().skip(1) {
        if let Err(e) = mempool.insert(store, tx) {
            // No debería pasar (la tx ya era válida hace un instante y
            // nada cambió el estado entre medio, somos el único minero)
            // — si pasa igual, se loguea y se pierde esa tx puntual en
            // vez de tumbar el proceso.
            eprintln!("znx-node: no se pudo re-encolar una tx tras un candidato sin nonce válido: {e}");
        }
    }
}

/// Devuelve al mempool las tx de un candidato cuya búsqueda de nonce
/// falló — ver `requeue_transactions` para el detalle. Solo se ocupa de
/// tomar los locks en el orden correcto (storage antes que mempool,
/// mismo orden que el resto del nodo).
async fn requeue_failed_candidate(shared: &SharedNode, transactions: Vec<Transaction>) {
    let storage = shared.storage.lock().await;
    let mut mempool = shared.mempool.lock().await;
    requeue_transactions(&*storage, &mut mempool, transactions);
}

async fn submit_own_block(shared: &SharedNode, block: Block) {
    let height = block.header.height;
    let tx_count = block.transactions.len();
    let mut storage = shared.storage.lock().await;
    match commit_new_tip(&mut storage, &shared.genesis, &block) {
        Ok(()) => {
            drop(storage);
            println!("znx-node: minamos el bloque {height} ({tx_count} tx(s), coinbase incluida)");
            shared.network.publish_block(encode(&block));
        }
        Err(e) => {
            // Perdimos la carrera contra otro minero (alguien más ya
            // extendió la punta para esta altura) — normal en PoW
            // abierta, no es un bug.
            eprintln!("znx-node: bloque propio en altura {height} descartado ({e}) — alguien más ganó esta altura");
        }
    }
}

async fn handle_inbound(shared: &SharedNode, msg: Inbound) {
    match msg {
        Inbound::Transaction { bytes, message_id, from } => handle_inbound_transaction(shared, bytes, message_id, from).await,
        Inbound::Block { bytes, message_id, from } => handle_inbound_block(shared, bytes, message_id, from).await,
        Inbound::BlockRequest { request_id, height } => handle_block_request(shared, request_id, height).await,
        // Corre en la misma tarea aislada que ya le tocó a este mensaje
        // (ver doc de `run_main_loop`) — un IBD largo no bloquea el
        // procesamiento de otros mensajes, así que no hace falta un
        // `tokio::spawn` anidado acá.
        Inbound::PeerConnected(peer) => run_ibd_sync(shared, peer).await,
    }
}

async fn handle_inbound_transaction(shared: &SharedNode, bytes: Vec<u8>, message_id: MessageId, from: PeerId) {
    let tx: Transaction = match decode(&bytes) {
        Ok(tx) => tx,
        Err(e) => {
            eprintln!("znx-node: tx recibida por gossip no decodifica, se descarta: {e}");
            shared.network.report_message_validity(message_id, from, false);
            return;
        }
    };

    let storage = shared.storage.lock().await;
    if let Err(e) = shared.mempool.lock().await.insert(&*storage, tx) {
        // Normal si ya la teníamos, o si ya no es válida contra el estado
        // actual (alguien más ya la incluyó en un bloque) — no es un bug,
        // y no corresponde el castigo P4 de gossipsub por esto (a
        // diferencia de un decode que falla arriba, que sí es contenido
        // objetivamente malformado): puede ser un duplicado inofensivo o
        // quedó inválida por timing, no necesariamente culpa del peer que
        // nos la mandó.
        eprintln!("znx-node: tx recibida por gossip no admitida al mempool: {e}");
    }
    shared.network.report_message_validity(message_id, from, true);
}

/// Responde un pedido punto a punto de un bloque puntual (protocolo de
/// backfill, ver doc de módulo) — `None` si no lo tenemos.
async fn handle_block_request(shared: &SharedNode, request_id: InboundRequestId, height: u64) {
    let storage = shared.storage.lock().await;
    let response = match storage.get_block(height) {
        Ok(Some(block)) => Some(encode(&block)),
        Ok(None) => None,
        Err(e) => {
            eprintln!("znx-node: error leyendo el bloque {height} pedido por un peer: {e}");
            None
        }
    };
    drop(storage);
    shared.network.respond_block(request_id, response);
}

async fn handle_inbound_block(shared: &SharedNode, bytes: Vec<u8>, message_id: MessageId, from: PeerId) {
    let block: Block = match decode(&bytes) {
        Ok(block) => block,
        Err(e) => {
            eprintln!("znx-node: bloque recibido por gossip no decodifica, se descarta: {e}");
            shared.network.report_message_validity(message_id, from, false);
            return;
        }
    };
    let height = block.header.height;

    let mut storage = shared.storage.lock().await;
    match commit_new_tip(&mut storage, &shared.genesis, &block) {
        Ok(()) => {
            println!("znx-node: bloque {height} aceptado por gossip ({} tx(s))", block.transactions.len());
            shared.network.report_message_validity(message_id, from, true);
            return;
        }
        Err(BlockError::UnexpectedHeight { .. } | BlockError::ParentMismatch) => {
            // No extiende nuestra punta directo — puede ser un hermano a
            // la misma altura (caso más común y barato: no hace falta
            // pedirle nada a nadie), o el primer eslabón de una cadena
            // más profunda que hay que reconstruir pidiendo bloques. Se
            // reporta `Accept` ya mismo: la resolución real puede tardar
            // varios round-trips de backfill (segundos), más de lo que el
            // cache de gossipsub retiene el mensaje para un reporte
            // diferido — el castigo por mala conducta comprobada en estos
            // casos sigue pasando por `record_strike`/`ban_peer` más
            // abajo, no por el score de gossipsub.
            shared.network.report_message_validity(message_id, from, true);
        }
        Err(e) => {
            eprintln!("znx-node: bloque {height} recibido por gossip rechazado: {e}");
            shared.network.report_message_validity(message_id, from, false);
            drop(storage);
            record_strike(shared, from, "bloque gossipeado inválido").await;
            return;
        }
    }

    let local_height = match storage.latest_height() {
        Ok(Some(h)) => h,
        _ => return,
    };
    if block.header.height == local_height {
        match try_reorg_to_chain(&mut storage, &shared.genesis, local_height.saturating_sub(1), vec![block]) {
            Ok(true) => println!("znx-node: reorg en la altura {height} tras recibir un bloque hermano más pesado"),
            Ok(false) => {} // no aplica — esperable en PoW abierta, no se loguea como error
            Err(e) => {
                eprintln!("znx-node: bloque {height} recibido por gossip rechazado tras intentar reorg: {e}");
                drop(storage);
                record_strike(shared, from, "bloque hermano inválido").await;
            }
        }
        return;
    }
    drop(storage);

    // No es un hermano a la misma altura — intentar reconstruir la cadena
    // completa pidiéndole al peer que nos lo mandó el padre, el padre del
    // padre, etc., hasta encontrar un ancestro que ya tengamos localmente.
    backfill_and_reorg(shared, block, from).await;
}

/// Reconstruye hacia atrás la cadena de `block` pidiéndole a `peer` cada
/// padre que nos falte (protocolo punto a punto, no gossip), hasta
/// encontrar un bloque que ya tengamos localmente (el punto de fork) o
/// agotar `MAX_BACKFILL_DEPTH`. Si encuentra el punto de fork, delega en
/// `try_reorg_to_chain` la decisión de si la cadena reconstruida pesa más
/// que la local.
async fn backfill_and_reorg(shared: &SharedNode, block: Block, peer: PeerId) {
    let height = block.header.height;
    let mut chain = vec![block];

    for _ in 0..MAX_BACKFILL_DEPTH {
        let earliest = chain.first().expect("chain siempre tiene al menos el bloque recibido");
        let parent_hash = earliest.header.parent_hash;
        let earliest_height = earliest.header.height;

        let storage = shared.storage.lock().await;
        let local_ancestor = storage.get_block_by_hash(&parent_hash);
        drop(storage);

        let ancestor = match local_ancestor {
            Ok(ancestor) => ancestor,
            Err(e) => {
                eprintln!("znx-node: error de storage reconstruyendo la cadena del bloque {height}: {e}");
                return;
            }
        };

        if let Some(ancestor) = ancestor {
            let fork_height = ancestor.header.height;
            let mut storage = shared.storage.lock().await;
            match try_reorg_to_chain(&mut storage, &shared.genesis, fork_height, chain) {
                Ok(true) => println!("znx-node: reorg multi-bloque hasta la altura {fork_height} tras reconstruir una cadena más pesada"),
                Ok(false) => {} // la cadena reconstruida no pesaba más — esperable, no es un error
                Err(e) => {
                    eprintln!("znx-node: cadena candidata para el bloque {height} rechazada: {e}");
                    drop(storage);
                    record_strike(shared, peer, "cadena reconstruida por backfill inválida").await;
                }
            }
            return;
        }

        if earliest_height == 0 {
            // Llegamos al génesis sin encontrar un ancestro común — no
            // debería pasar (implicaría un génesis distinto), abandonar.
            eprintln!("znx-node: no se encontró ancestro común reconstruyendo la cadena del bloque {height}, se abandona");
            return;
        }

        let wanted_height = earliest_height - 1;
        match shared.network.request_block(peer, wanted_height).await {
            Some(parent_bytes) => match decode::<Block>(&parent_bytes) {
                Ok(parent_block) => chain.insert(0, parent_block),
                Err(e) => {
                    eprintln!("znx-node: el peer respondió el bloque {wanted_height} pero no decodifica, se abandona: {e}");
                    record_strike(shared, peer, "respuesta de backfill no decodifica").await;
                    return;
                }
            },
            None => {
                eprintln!("znx-node: el peer no tiene/no respondió el bloque {wanted_height}, se abandona el backfill del bloque {height}");
                return;
            }
        }
    }

    eprintln!("znx-node: backfill del bloque {height} superó la profundidad máxima ({MAX_BACKFILL_DEPTH} bloques), se abandona");
}

/// Sincronización completa (IBD): se dispara al conectarse un peer nuevo
/// (`Inbound::PeerConnected`), y pide `local_height+1`, `+2`, ... a ese
/// peer hasta que responda `None` (ya no tiene más — estamos al día con
/// él) o se llegue a `MAX_IBD_BLOCKS_PER_SYNC`. A diferencia de
/// `backfill_and_reorg` (reactivo, camina hacia atrás, acotado a
/// `MAX_BACKFILL_DEPTH`), esto es proactivo, camina hacia adelante desde
/// la punta local, y sin tope de profundidad — el objetivo es justamente
/// cubrir cualquier distancia con un peer recién conectado que tenga más
/// historia.
///
/// Pide de a `IBD_PIPELINE_WINDOW` alturas en paralelo por tanda (en vez
/// de esperar cada respuesta antes de pedir la siguiente) — en localhost
/// no se nota, pero en una red con latencia real evita multiplicar esa
/// latencia por la cantidad de bloques a sincronizar. `libp2p::request_response`
/// ya soporta varios pedidos en vuelo a la vez hacia el mismo peer (cada
/// uno con su propio `request_id`), así que esto no necesita ningún
/// cambio de protocolo en `znx-p2p` — `futures::future::join_all`
/// devuelve las respuestas en el mismo orden que los pedidos de entrada
/// (sin importar cuál llegó primero), así que aplicarlas en ese mismo
/// orden alcanza para respetar el orden estricto de altura que exige
/// `commit_new_tip`.
///
/// Sin fork-choice propio: aplica secuencialmente lo que este peer
/// ofrece (`commit_new_tip`, que ya valida cada bloque completo — PoW,
/// target, tx_root, coinbase, cada tx regular), sin comparar contra lo
/// que otros peers puedan tener. Tampoco deduplica sincronizaciones
/// concurrentes (mismo peer conectándose de nuevo, o corriendo a la vez
/// que un backfill) — inofensivo por el mismo motivo que ya hace segura
/// la concurrencia en el resto del nodo: un intento que llega tarde
/// simplemente falla con `UnexpectedHeight`/`ParentMismatch`.
async fn run_ibd_sync(shared: &SharedNode, peer: PeerId) {
    let mut synced = 0u64;
    loop {
        if synced >= MAX_IBD_BLOCKS_PER_SYNC {
            println!("znx-node: IBD contra {peer} superó {MAX_IBD_BLOCKS_PER_SYNC} bloques en una sola sincronización, se corta acá por esta vez");
            return;
        }

        let local_height = match shared.storage.lock().await.latest_height() {
            Ok(Some(h)) => h,
            _ => return,
        };

        let wanted: Vec<u64> = ((local_height + 1)..=(local_height + IBD_PIPELINE_WINDOW as u64)).collect();
        let responses = futures::future::join_all(wanted.iter().map(|&height| shared.network.request_block(peer, height))).await;

        for (height, response) in wanted.into_iter().zip(responses) {
            let Some(bytes) = response else {
                // El peer no tiene (o no respondió) esa altura — ya
                // estamos al día con él, o no tiene más para ofrecer. No
                // es un error. Las alturas más allá de esta en la misma
                // tanda se ignoran (si un peer bien comportado no tiene
                // `height`, tampoco va a tener nada más adelante).
                if synced > 0 {
                    println!("znx-node: IBD contra {peer} terminó, se sincronizaron {synced} bloque(s) hasta la altura {}", height - 1);
                }
                return;
            };

            let block: Block = match decode(&bytes) {
                Ok(block) => block,
                Err(e) => {
                    eprintln!("znx-node: IBD contra {peer}: el bloque {height} no decodifica, se corta: {e}");
                    record_strike(shared, peer, "respuesta de IBD no decodifica").await;
                    return;
                }
            };

            let mut storage = shared.storage.lock().await;
            match commit_new_tip(&mut storage, &shared.genesis, &block) {
                Ok(()) => {
                    drop(storage);
                    synced += 1;
                }
                Err(e) => {
                    drop(storage);
                    eprintln!("znx-node: IBD contra {peer}: el bloque {height} rechazado, se corta: {e}");
                    record_strike(shared, peer, "bloque de IBD inválido").await;
                    return;
                }
            }
        }
        // La tanda completa (IBD_PIPELINE_WINDOW bloques) se aplicó sin
        // cortar — arma la próxima tanda desde la nueva punta local.
    }
}

#[derive(Debug, Error)]
enum BlockError {
    #[error("altura inesperada: local está en {local}, el bloque trae {found} (se espera {local} + 1)")]
    UnexpectedHeight { local: u64, found: u64 },
    #[error("parent_hash no coincide con la punta local — posible fork")]
    ParentMismatch,
    #[error("prueba de trabajo insuficiente: {0}")]
    Pow(#[from] ConsensusError),
    #[error("target declarado no coincide con el esperado para esta altura")]
    UnexpectedTarget,
    #[error("tx_root del header no coincide con las transacciones incluidas")]
    BadTxRoot,
    #[error("el bloque no empieza con una transacción coinbase")]
    MissingCoinbase,
    #[error("una transacción regular tiene la forma de una coinbase")]
    UnexpectedCoinbase,
    #[error("transacción del bloque inválida: {0}")]
    Transaction(StateError),
    #[error("coinbase inválida: {0}")]
    Coinbase(StateError),
    #[error("desbordamiento aritmético validando el bloque")]
    Overflow,
    #[error("error de storage: {0}")]
    Storage(#[from] StorageError),
}

/// `(spent, created, undo)` — el diff de UTXOs de un bloque ya validado,
/// listo para comprometer, más los datos para deshacerlo más adelante.
type BlockDiff = (Vec<OutPoint>, Vec<(OutPoint, TxOut)>, Vec<(OutPoint, TxOut)>);

/// Valida un bloque candidato completo contra `base` (sin mutarlo — usa un
/// `OverlayStore`) y, si todo pasa, devuelve el diff de UTXOs (`spent`,
/// `created`) listo para comprometer, más los datos de deshacer (`undo`).
/// No asume nada sobre altura/parent_hash — eso lo chequea el caller
/// (`commit_new_tip`/`try_reorg_to_chain`) según el caso.
fn validate_full_block(base: &RocksStorage, genesis: &Genesis, block: &Block, expected_target: [u8; 32]) -> Result<BlockDiff, BlockError> {
    znx_consensus::verify_pow(&block.header)?;
    if block.header.target != expected_target {
        return Err(BlockError::UnexpectedTarget);
    }
    if tx_root(&block.transactions) != block.header.tx_root {
        return Err(BlockError::BadTxRoot);
    }

    let (coinbase, rest) = block.transactions.split_first().ok_or(BlockError::MissingCoinbase)?;
    if !coinbase.is_coinbase() {
        return Err(BlockError::MissingCoinbase);
    }
    if rest.iter().any(Transaction::is_coinbase) {
        return Err(BlockError::UnexpectedCoinbase);
    }

    let mut overlay = OverlayStore::new(base);
    let mut undo = Vec::new();
    let mut total_fees: u128 = 0;
    for tx in rest {
        let applied = apply_transaction(&mut overlay, tx, &genesis.chain_id).map_err(BlockError::Transaction)?;
        total_fees = total_fees.checked_add(applied.fee).ok_or(BlockError::Overflow)?;
        undo.extend(applied.consumed);
    }

    let subsidy = znx_consensus::subsidy_for_height(block.header.height, &genesis.subsidy_schedule, genesis.subsidy_period_blocks);
    let expected_total = subsidy.checked_add(total_fees).ok_or(BlockError::Overflow)?;
    apply_coinbase(&mut overlay, coinbase, block.header.height, expected_total).map_err(BlockError::Coinbase)?;

    let (spent, created) = overlay.into_diff();
    Ok((spent, created, undo))
}

/// Extiende la punta local con `block`, si `block` es exactamente el
/// siguiente esperado (altura `local+1`, `parent_hash` = hash de la punta
/// actual). No hace fork-choice — eso es `try_reorg_to_chain`.
fn commit_new_tip(storage: &mut RocksStorage, genesis: &Genesis, block: &Block) -> Result<(), BlockError> {
    let local_height = storage.latest_height()?.expect("el génesis siempre deja escrito al menos el bloque 0");
    if block.header.height != local_height + 1 {
        return Err(BlockError::UnexpectedHeight { local: local_height, found: block.header.height });
    }
    let local_tip = storage.get_block(local_height)?.expect("el bloque en `latest_height` siempre existe");
    if block.header.parent_hash != block_hash(&local_tip) {
        return Err(BlockError::ParentMismatch);
    }

    let target = expected_target(storage, genesis, block.header.height)?;
    let (spent, created, undo) = validate_full_block(storage, genesis, block, target)?;
    storage.commit_block(block, spent, created, undo)?;
    Ok(())
}

/// Intenta reemplazar la cadena local desde `fork_height` (la altura de
/// un ancestro común que ya tenemos guardado localmente) por
/// `candidate_chain` (los bloques `fork_height+1..=`, en orden — el
/// primero enlaza, por `parent_hash`, al bloque local en `fork_height`),
/// si el candidato pesa más. Con `candidate_chain` de un solo elemento y
/// `fork_height = local_height - 1` este es exactamente el caso de un
/// hermano compitiendo por la misma altura; con más elementos (armados
/// pidiéndole bloques a un peer, ver `backfill_and_reorg`) es un reorg de
/// varios bloques.
///
/// Desempate en caso de empate exacto de trabajo (el caso típico de un
/// solo hermano: el target de dificultad es una función determinística
/// de la altura — ver `expected_target` — no algo que cada minero elija,
/// así que dos cadenas sobre el mismo tramo casi siempre empatan en
/// trabajo si tienen la misma longitud) por **hash del último bloque de
/// cada cadena** — gana el numéricamente menor. No es "más trabajo" en
/// sentido estricto, pero es una regla determinística en la que todos
/// los nodos que vean ambas cadenas convergen al mismo ganador.
///
/// Devuelve `Ok(false)` si el candidato no pesa más (no es un error). Si
/// pesa más pero alguno de sus bloques no valida al aplicarlo de verdad,
/// se revierte a la cadena local original antes de devolver el error —
/// nunca deja el storage a mitad de camino entre las dos cadenas.
fn try_reorg_to_chain(storage: &mut RocksStorage, genesis: &Genesis, fork_height: u64, candidate_chain: Vec<Block>) -> Result<bool, BlockError> {
    let local_height = storage.latest_height()?.expect("el génesis siempre deja escrito al menos el bloque 0");

    let mut local_targets = Vec::with_capacity((local_height - fork_height) as usize);
    for height in (fork_height + 1)..=local_height {
        local_targets.push(storage.get_block(height)?.expect("bloque local entre el punto de fork y la punta siempre existe").header.target);
    }
    let candidate_targets: Vec<[u8; 32]> = candidate_chain.iter().map(|block| block.header.target).collect();

    let local_work = znx_consensus::cumulative_work(local_targets.iter());
    let candidate_work = znx_consensus::cumulative_work(candidate_targets.iter());

    let candidate_wins = match candidate_work.cmp(&local_work) {
        std::cmp::Ordering::Greater => true,
        std::cmp::Ordering::Less => false,
        std::cmp::Ordering::Equal => {
            let local_tip = storage.get_block(local_height)?.expect("el bloque en `latest_height` siempre existe");
            let candidate_tip = candidate_chain.last().expect("candidate_chain nunca está vacía");
            block_hash(candidate_tip) < block_hash(&local_tip)
        }
    };
    if !candidate_wins {
        return Ok(false);
    }

    let mut undone = Vec::with_capacity((local_height - fork_height) as usize);
    for _ in fork_height..local_height {
        undone.push(storage.undo_latest_block()?);
    }
    undone.reverse(); // de la más vieja (fork_height + 1) a la más nueva (local_height)

    for block in &candidate_chain {
        if let Err(e) = commit_new_tip(storage, genesis, block) {
            // La cadena candidata pesaba más pero resultó inválida a
            // mitad de camino (bug o mentira del peer) — deshacer lo que
            // sí llegó a aplicarse y restaurar la cadena local original.
            let partial_height = storage.latest_height()?.expect("todavía queda al menos el bloque del punto de fork");
            for _ in fork_height..partial_height {
                storage.undo_latest_block()?;
            }
            for original in &undone {
                commit_new_tip(storage, genesis, original).expect("cadena local ya validada antes, tiene que volver a aplicar");
            }
            return Err(e);
        }
    }
    Ok(true)
}

fn now_unix() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).expect("el reloj del sistema no está antes de 1970").as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use znx_codec::txid;
    use znx_crypto::Keypair;
    use znx_state::StateStore;

    fn test_genesis() -> Genesis {
        Genesis {
            chain_id: "znx-test-1".to_string(),
            genesis_time_unix: 0,
            subsidy_schedule: vec![50],
            subsidy_period_blocks: 1_000_000,
            target_block_time_secs: 120,
            difficulty_adjustment_interval_blocks: 2016,
            // Target máximo posible: cualquier hash lo cumple, así que
            // minar en estos tests es instantáneo (nonce=0 siempre sirve).
            initial_target: [0xffu8; 32],
            premine: vec![],
        }
    }

    fn open_temp() -> (tempfile::TempDir, RocksStorage) {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut storage = RocksStorage::open(dir.path()).expect("abre RocksDB");
        bootstrap_genesis(&mut storage, &test_genesis()).expect("bootstrap de génesis");
        (dir, storage)
    }

    #[test]
    fn bootstrap_genesis_without_premine_leaves_the_genesis_block_empty() {
        let (_dir, storage) = open_temp();
        // test_genesis() no declara premine — el bloque 0 no debería
        // llevar ninguna transacción (ni coinbase ni ninguna otra), igual
        // que el devnet real hoy.
        let genesis_block = storage.get_block(0).expect("lectura ok").expect("el génesis existe");
        assert!(genesis_block.transactions.is_empty());
    }

    #[test]
    fn bootstrap_genesis_with_premine_creates_one_utxo_per_recipient() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut storage = RocksStorage::open(dir.path()).expect("abre RocksDB");

        let founder = Keypair::generate().address();
        let investor = Keypair::generate().address();
        let mut genesis = test_genesis();
        genesis.premine = vec![(founder, 35_000_000), (investor, 25_000_000)];

        bootstrap_genesis(&mut storage, &genesis).expect("bootstrap con premine");

        let genesis_block = storage.get_block(0).expect("lectura ok").expect("el génesis existe");
        assert_eq!(genesis_block.transactions.len(), 1, "el premine viaja en una única transacción coinbase de altura 0");
        let premine_tx = &genesis_block.transactions[0];
        assert!(premine_tx.is_coinbase());

        let premine_txid = txid(premine_tx);
        assert_eq!(storage.get_utxo(&OutPoint { txid: premine_txid, vout: 0 }), Some(TxOut { amount: 35_000_000, pubkey_hash: founder }));
        assert_eq!(storage.get_utxo(&OutPoint { txid: premine_txid, vout: 1 }), Some(TxOut { amount: 25_000_000, pubkey_hash: investor }));

        // El premine no es "el subsidio del bloque 0" — es aparte del
        // calendario de emisión, así que reabrir el mismo storage no
        // debería duplicar nada ni interferir con la minería normal
        // desde la altura 1.
        assert_eq!(storage.latest_height().expect("lectura ok"), Some(0));
    }

    /// `genesis/mainnet.json` no se usa todavía (Fase 5 sigue meses
    /// adelante, ver `docs/CONSENSUS.md`) — pero que parsee con el mismo
    /// `Genesis::load` real que usa el nodo es una garantía barata de no
    /// romperlo en silencio con cambios futuros al formato. Valida forma
    /// y los 3 montos de premine, no bootstrapea nada (no hace falta
    /// storage real para esto).
    #[test]
    fn mainnet_genesis_file_parses_with_expected_premine() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../genesis/mainnet.json");
        let genesis = Genesis::load(&path).expect("genesis/mainnet.json tiene que parsear con el loader real");

        assert_eq!(genesis.chain_id, "znx-mainnet-1");
        assert_eq!(genesis.premine.len(), 3);
        let total_premine: u128 = genesis.premine.iter().map(|(_, amount)| amount).sum();
        assert_eq!(total_premine, 85_000_000_000_000_000_000_000_000, "85M ZNX a 18 decimales");
    }

    /// Arma y mina (trivialmente, target máximo) un bloque candidato a
    /// altura 1 con una única coinbase — alcanza para probar
    /// `commit_new_tip`/`try_reorg_to_sibling` sin depender de la red real
    /// ni del loop de minería completo (eso ya se probó a mano en un
    /// devnet de 2 nodos).
    fn mined_block_at_height_1(genesis: &Genesis, parent_hash: [u8; 32], miner: Address, extra_nonce: u64) -> Block {
        let coinbase =
            Transaction::new_coinbase(genesis.chain_id.clone(), 1, extra_nonce, vec![TxOut { amount: genesis.subsidy_schedule[0], pubkey_hash: miner }]);
        let header = BlockHeader {
            height: 1,
            parent_hash,
            tx_root: tx_root(std::slice::from_ref(&coinbase)),
            timestamp: 1_000,
            target: genesis.initial_target,
            pow_nonce: 0,
        };
        let mined = mine_batch(header, 10).expect("target máximo, cualquier nonce cumple en el primer intento");
        Block { header: mined, transactions: vec![coinbase] }
    }

    #[test]
    fn commit_new_tip_extends_and_then_rejects_the_same_height_again() {
        let (_dir, mut storage) = open_temp();
        let genesis = test_genesis();
        let genesis_hash = block_hash(&storage.get_block(0).unwrap().unwrap());
        let miner = Keypair::generate();

        let block1 = mined_block_at_height_1(&genesis, genesis_hash, miner.address(), 0);
        commit_new_tip(&mut storage, &genesis, &block1).expect("bloque válido debería aplicar");
        assert_eq!(storage.latest_height().unwrap(), Some(1));
        assert_eq!(storage.get_utxo(&OutPoint { txid: txid(&block1.transactions[0]), vout: 0 }), Some(TxOut { amount: 50, pubkey_hash: miner.address() }));

        // Reintentar "extender" con el mismo bloque ahora falla por altura
        // (ya estamos en 1, se esperaría 2).
        let err = commit_new_tip(&mut storage, &genesis, &block1).unwrap_err();
        assert!(matches!(err, BlockError::UnexpectedHeight { local: 1, found: 1 }));
    }

    #[test]
    fn commit_new_tip_rejects_a_block_with_the_wrong_parent() {
        let (_dir, mut storage) = open_temp();
        let genesis = test_genesis();
        let miner = Keypair::generate();

        let bogus_parent = [7u8; 32];
        let block = mined_block_at_height_1(&genesis, bogus_parent, miner.address(), 0);
        let err = commit_new_tip(&mut storage, &genesis, &block).unwrap_err();
        assert!(matches!(err, BlockError::ParentMismatch));
    }

    /// Encadena un segundo bloque (altura 2) sobre `parent`, con una
    /// coinbase propia — para armar cadenas candidatas de más de 1 bloque
    /// en los tests de reorg multi-bloque.
    fn mined_block_at_height_2(genesis: &Genesis, parent: &Block, miner: Address, extra_nonce: u64) -> Block {
        let coinbase =
            Transaction::new_coinbase(genesis.chain_id.clone(), 2, extra_nonce, vec![TxOut { amount: genesis.subsidy_schedule[0], pubkey_hash: miner }]);
        let header = BlockHeader {
            height: 2,
            parent_hash: block_hash(parent),
            tx_root: tx_root(std::slice::from_ref(&coinbase)),
            timestamp: 2_000,
            target: genesis.initial_target,
            pow_nonce: 0,
        };
        let mined = mine_batch(header, 10).expect("target máximo, cualquier nonce cumple en el primer intento");
        Block { header: mined, transactions: vec![coinbase] }
    }

    #[test]
    fn try_reorg_to_chain_swaps_a_single_sibling_by_the_smaller_header_hash() {
        let (_dir, mut storage) = open_temp();
        let genesis = test_genesis();
        let genesis_hash = block_hash(&storage.get_block(0).unwrap().unwrap());
        let miner_a = Keypair::generate();
        let miner_b = Keypair::generate();

        let block_a = mined_block_at_height_1(&genesis, genesis_hash, miner_a.address(), 0);
        let block_b = mined_block_at_height_1(&genesis, genesis_hash, miner_b.address(), 1);
        assert_ne!(block_hash(&block_a), block_hash(&block_b));

        let (winner, loser) = if block_hash(&block_a) < block_hash(&block_b) { (block_a, block_b) } else { (block_b, block_a) };

        // El que pierde el desempate llega primero y se aplica normal.
        commit_new_tip(&mut storage, &genesis, &loser).expect("aplica");
        assert_eq!(storage.get_block(1).unwrap().unwrap(), loser);

        // Después llega por gossip el que gana el desempate: tiene que
        // haber reorg (deshacer `loser`, aplicar `winner`). fork_height=0
        // (génesis) porque ambos son hermanos a la altura 1.
        let reorged = try_reorg_to_chain(&mut storage, &genesis, 0, vec![winner.clone()]).expect("no debería fallar");
        assert!(reorged);
        assert_eq!(storage.get_block(1).unwrap().unwrap(), winner);
        assert_eq!(storage.latest_height().unwrap(), Some(1));
        // El UTXO de la coinbase del que perdió ya no existe.
        assert_eq!(storage.get_utxo(&OutPoint { txid: txid(&loser.transactions[0]), vout: 0 }), None);

        // Al revés: si lo que llega por gossip pierde el desempate contra
        // lo que ya tenemos, no pasa nada.
        let not_reorged = try_reorg_to_chain(&mut storage, &genesis, 0, vec![loser]).expect("no debería fallar");
        assert!(!not_reorged);
        assert_eq!(storage.get_block(1).unwrap().unwrap(), winner);
    }

    #[test]
    fn try_reorg_to_chain_replaces_a_shorter_local_chain_with_a_longer_heavier_candidate() {
        let (_dir, mut storage) = open_temp();
        let genesis = test_genesis();
        let genesis_hash = block_hash(&storage.get_block(0).unwrap().unwrap());
        let miner = Keypair::generate();
        let other_miner = Keypair::generate();

        // Cadena local: 1 solo bloque.
        let local_1 = mined_block_at_height_1(&genesis, genesis_hash, miner.address(), 0);
        commit_new_tip(&mut storage, &genesis, &local_1).expect("aplica bloque 1 local");

        // Cadena candidata: 2 bloques. Mismo target por bloque que el
        // local (ambos antes del primer reajuste de dificultad, así que
        // `expected_target` da lo mismo en cualquier altura acá) — pesa
        // más simplemente por tener un bloque de más, el caso realista de
        // "nos quedamos atrás de una cadena más larga".
        let candidate_1 = mined_block_at_height_1(&genesis, genesis_hash, other_miner.address(), 1);
        let candidate_2 = mined_block_at_height_2(&genesis, &candidate_1, other_miner.address(), 1);

        let reorged = try_reorg_to_chain(&mut storage, &genesis, 0, vec![candidate_1.clone(), candidate_2.clone()]).expect("no debería fallar");
        assert!(reorged);
        assert_eq!(storage.latest_height().unwrap(), Some(2));
        assert_eq!(storage.get_block(1).unwrap().unwrap(), candidate_1);
        assert_eq!(storage.get_block(2).unwrap().unwrap(), candidate_2);
        // El UTXO de la coinbase de la cadena local vieja ya no existe.
        assert_eq!(storage.get_utxo(&OutPoint { txid: txid(&local_1.transactions[0]), vout: 0 }), None);
    }

    #[test]
    fn try_reorg_to_chain_keeps_a_longer_heavier_local_chain() {
        let (_dir, mut storage) = open_temp();
        let genesis = test_genesis();
        let genesis_hash = block_hash(&storage.get_block(0).unwrap().unwrap());
        let miner = Keypair::generate();
        let other_miner = Keypair::generate();

        // Cadena local: 2 bloques.
        let local_1 = mined_block_at_height_1(&genesis, genesis_hash, miner.address(), 0);
        commit_new_tip(&mut storage, &genesis, &local_1).expect("aplica bloque 1 local");
        let local_2 = mined_block_at_height_2(&genesis, &local_1, miner.address(), 0);
        commit_new_tip(&mut storage, &genesis, &local_2).expect("aplica bloque 2 local");

        // Candidato: 1 solo bloque -> menos trabajo total, no debería
        // desencadenar ningún reorg.
        let candidate_1 = mined_block_at_height_1(&genesis, genesis_hash, other_miner.address(), 1);
        let reorged = try_reorg_to_chain(&mut storage, &genesis, 0, vec![candidate_1]).expect("no debería fallar");
        assert!(!reorged);
        assert_eq!(storage.get_block(1).unwrap().unwrap(), local_1);
        assert_eq!(storage.get_block(2).unwrap().unwrap(), local_2);
    }

    /// Reproduce el bug real encontrado armando el flujo de depósito/
    /// retiro: una tx que `next_batch` sacó del mempool para un
    /// candidato cuya búsqueda de nonce falla tiene que poder volver al
    /// mempool — antes de `requeue_transactions`, se perdía en silencio
    /// para siempre.
    #[test]
    fn requeue_transactions_returns_a_dropped_candidate_tx_to_the_mempool() {
        use znx_codec::signing_bytes;

        let (_dir, mut storage) = open_temp();
        let genesis = test_genesis();
        let genesis_hash = block_hash(&storage.get_block(0).unwrap().unwrap());
        let miner = Keypair::generate();
        let spender = Keypair::generate();
        let receiver = Keypair::generate();

        // Financia a `spender` con un UTXO real minando un bloque hacia
        // su dirección — necesitamos una tx no-coinbase de verdad, no
        // alcanza con una coinbase sintética.
        let funding_block = mined_block_at_height_1(&genesis, genesis_hash, spender.address(), 0);
        commit_new_tip(&mut storage, &genesis, &funding_block).expect("financia a spender");
        let funding_outpoint = OutPoint { txid: txid(&funding_block.transactions[0]), vout: 0 };

        let mut spend_tx = Transaction {
            chain_id: genesis.chain_id.clone(),
            inputs: vec![znx_types::TxIn { prev_out: funding_outpoint, public_key: spender.public_key().to_bytes(), signature: [0u8; 64] }],
            outputs: vec![TxOut { amount: 30, pubkey_hash: receiver.address() }],
        };
        let signature = spender.sign(&signing_bytes(&spend_tx));
        spend_tx.inputs[0].signature = signature.to_bytes();

        let mut mempool = Mempool::new(genesis.chain_id.clone());
        mempool.insert(&storage, spend_tx.clone()).expect("la tx de spender es válida");
        assert_eq!(mempool.len(), 1);

        // Simula exactamente lo que hace `build_mining_candidate`: sacar
        // la tx del mempool para un candidato (acá, uno que "falla" —
        // nunca llega a minarse). `transactions[0]` es un lugar de
        // coinbase sintético, igual que arma el nodo real.
        let drained = mempool.next_batch(10);
        assert_eq!(drained.len(), 1, "next_batch sacó la tx del mempool");
        assert!(mempool.is_empty(), "el mempool queda vacío mientras el candidato está 'en vuelo'");

        let coinbase_placeholder = Transaction::new_coinbase(genesis.chain_id.clone(), 1, 0, vec![TxOut { amount: 50, pubkey_hash: miner.address() }]);
        let mut candidate_transactions = vec![coinbase_placeholder];
        candidate_transactions.extend(drained);

        requeue_transactions(&storage, &mut mempool, candidate_transactions);

        assert_eq!(mempool.len(), 1, "la tx del spender tiene que volver al mempool");
        let requeued = mempool.next_batch(10);
        assert_eq!(requeued, vec![spend_tx], "la misma tx, no una copia distinta");
    }

    #[test]
    fn requeue_transactions_with_only_coinbase_is_a_noop() {
        let (_dir, storage) = open_temp();
        let genesis = test_genesis();
        let miner = Keypair::generate();
        let mut mempool = Mempool::new(genesis.chain_id.clone());

        let coinbase_only = vec![Transaction::new_coinbase(genesis.chain_id, 1, 0, vec![TxOut { amount: 50, pubkey_hash: miner.address() }])];
        requeue_transactions(&storage, &mut mempool, coinbase_only);

        assert!(mempool.is_empty(), "no había ninguna tx de mempool que perder");
    }
}
