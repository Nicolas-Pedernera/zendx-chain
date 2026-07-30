//! znx-node — binario principal: parsea argumentos y delega en
//! `znx_node::run` (ver `lib.rs` para el wiring real).

use std::net::SocketAddr;
use std::path::PathBuf;

use clap::Parser;
use znx_p2p::Multiaddr;

#[derive(Debug, Parser)]
#[command(about = "Nodo de Zend X Chain — PoW abierta + UTXO, con propagación P2P (gossipsub)")]
struct Cli {
    /// Directorio donde vive la base RocksDB. Se crea si no existe; si ya
    /// existe con datos, el génesis NO se reaplica (se asume ya aplicado).
    #[arg(long, value_name = "PATH")]
    data_dir: PathBuf,

    /// Archivo de génesis (solo se lee si `data_dir` está vacío).
    #[arg(long, value_name = "PATH", default_value = "genesis/devnet.json")]
    genesis: PathBuf,

    /// Interfaz donde escucha el servidor JSON-RPC.
    #[arg(long, default_value = "0.0.0.0")]
    bind_host: String,

    /// Puerto donde escucha el servidor JSON-RPC. También se puede setear
    /// por `PORT` — la convención que usa Render para decirle a un
    /// servicio en qué puerto tiene que escuchar (ver blockchain/render.yaml
    /// y el "Service Address" que Render le asigna al servicio).
    #[arg(long, env = "PORT", default_value_t = 26657)]
    bind_port: u16,

    /// Dirección de escucha libp2p (multiaddr).
    #[arg(long, value_name = "MULTIADDR", default_value = "/ip4/0.0.0.0/tcp/0")]
    listen_addr: Multiaddr,

    /// Peer al que marcar (dial) al arrancar. Repetible.
    #[arg(long = "peer", value_name = "MULTIADDR")]
    peers: Vec<Multiaddr>,

    /// Dirección bech32 a la que pagar la coinbase de los bloques que
    /// este proceso mine. Si se omite, el nodo no mina — solo valida y
    /// relee bloques/transacciones de la red y sirve RPC de consulta.
    #[arg(long, value_name = "znx1...")]
    miner_address: Option<String>,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    let bind_addr: SocketAddr =
        format!("{}:{}", cli.bind_host, cli.bind_port).parse().unwrap_or_else(|e| panic!("--bind-host inválido: {e}"));
    let config = znx_node::NodeConfig {
        data_dir: cli.data_dir,
        genesis_path: cli.genesis,
        bind_addr,
        listen_addr: cli.listen_addr,
        peers: cli.peers,
        miner_address: cli.miner_address,
    };

    if let Err(e) = znx_node::run(config).await {
        eprintln!("znx-node: error fatal: {e}");
        std::process::exit(1);
    }
}
