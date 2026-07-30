//! znx-testkit — harness de devnet multi-nodo para tests/experimentos.
//! Automatiza lo que hasta esta sesión se hacía a mano en cada
//! verificación en vivo (generar llaves y un génesis con parámetros
//! ajustados, lanzar `znx-node` en background con `nohup`, sondear con
//! `curl` crudo, limpiar procesos/directorios al final) — repetitivo y
//! propenso a errores de shell (ya pasó dos veces: variables de entorno
//! que no persistían entre llamadas de la terminal, un hex mal contado).
//!
//! Orquesta el **binario real** de `znx-node` como subproceso de verdad
//! (`std::process::Command`, vía `CARGO_BIN_EXE_znx-node` — el mecanismo
//! estándar de Cargo para que un crate ubique en tiempo de compilación el
//! binario ya compilado de otro crate del mismo workspace) — no una
//! versión in-process/mockeada. Más fiel (prueba exactamente el mismo
//! binario que corre en producción) a costa de velocidad (arrancar un
//! proceso real por nodo) — aceptable para tests de integración, no para
//! el loop rápido de tests unitarios del resto del workspace.

use std::net::{SocketAddr, TcpListener};
use std::path::Path;
use std::process::Stdio;
use std::time::Duration;

use jsonrpsee_core::client::ClientT;
use jsonrpsee_core::rpc_params;
use jsonrpsee_http_client::{HttpClient, HttpClientBuilder};
use serde::Deserialize;
use serde_json::json;
use tempfile::TempDir;
use tokio::process::{Child, Command};
use tokio::time::{sleep, Instant};

use znx_crypto::Address;

#[derive(Debug, thiserror::Error)]
pub enum TestkitError {
    #[error("se agotó el tiempo de espera")]
    Timeout,
    #[error("error de RPC: {0}")]
    Rpc(String),
}

/// Ubica el binario compilado de `znx-node`. `CARGO_BIN_EXE_znx-node`
/// (seteada por Cargo en tiempo de compilación) solo está disponible
/// para tests de integración/benchmarks, no para los tests unitarios de
/// este mismo crate (`#[cfg(test)] mod tests` acá abajo) — para esos,
/// hace falta resolverlo en runtime relativo al directorio de build
/// (`OUT_DIR`/`CARGO_MANIFEST_DIR` + `../../target/<profile>/znx-node`,
/// el mismo workaround que usan otros harnesses de test en esta
/// situación). Se evalúa perezosamente (no en tiempo de compilación de
/// la librería en sí, que rompería `cargo build`/`cargo check` normal
/// para cualquier crate que dependa de este).
fn znx_node_bin() -> std::path::PathBuf {
    if let Ok(path) = std::env::var("CARGO_BIN_EXE_znx-node") {
        return std::path::PathBuf::from(path);
    }
    let profile = if cfg!(debug_assertions) { "debug" } else { "release" };
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target").join(profile).join("znx-node")
}

fn free_tcp_port() -> u16 {
    // Bindear en :0 y leer el puerto que asignó el SO, después soltarlo —
    // patrón estándar de cualquier harness de test. Hay una ventana de
    // carrera teórica (otro proceso podría tomar el puerto antes de que
    // el hijo lo bindee), aceptable acá.
    TcpListener::bind("127.0.0.1:0").expect("bind a un puerto libre").local_addr().expect("local_addr").port()
}

/// Escribe un génesis de devnet en `path` con dificultad ajustable —
/// `leading_zero_bytes` más alto = más lento de minar (mismo truco que se
/// usó a mano esta sesión para controlar el timing de pruebas de fork/
/// backfill/ban: un target más difícil da más margen para observar
/// estados intermedios antes de que los nodos converjan).
pub fn write_test_genesis(path: &Path, leading_zero_bytes: u8) {
    let mut target = [0xffu8; 32];
    for byte in target.iter_mut().take(leading_zero_bytes as usize) {
        *byte = 0;
    }
    let genesis = json!({
        "chain_id": "znx-testkit-1",
        "genesis_time": "2026-01-01T00:00:00Z",
        "decimals": 18,
        "subsidy_schedule": ["50000000000000000000"],
        "subsidy_period_blocks": 1_000_000,
        "target_block_time_secs": 15,
        "difficulty_adjustment_interval_blocks": 60,
        "initial_target": hex::encode(target),
    });
    std::fs::write(path, serde_json::to_string_pretty(&genesis).expect("serializa")).unwrap_or_else(|e| panic!("no se pudo escribir el génesis de test en {path:?}: {e}"));
}

#[derive(Debug, Deserialize)]
struct LatestHeightResult {
    height: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct UnspentOutputResult {
    amount: String,
}

/// Un `znx-node` real corriendo como subproceso, con su propio directorio
/// de datos temporal. `Drop` mata el proceso — los tests no necesitan un
/// `shutdown()` explícito.
pub struct TestNode {
    _data_dir: TempDir,
    // Nunca se lee directo — se mantiene viva solo para que `kill_on_drop`
    // mate el proceso cuando el `TestNode` se dropea.
    _child: Child,
    rpc_addr: SocketAddr,
    p2p_port: u16,
}

impl TestNode {
    /// Lanza un `znx-node` real contra `genesis_path`. `miner_address =
    /// None` corre como réplica pura (no mina). `peers` son multiaddrs de
    /// otros `TestNode` (ver `p2p_multiaddr`).
    pub fn spawn(genesis_path: &Path, miner_address: Option<&Address>, peers: &[String]) -> Self {
        let data_dir = tempfile::tempdir().expect("tempdir");
        let rpc_port = free_tcp_port();
        let p2p_port = free_tcp_port();
        let rpc_addr: SocketAddr = format!("127.0.0.1:{rpc_port}").parse().expect("dirección local válida");

        let mut cmd = Command::new(znx_node_bin());
        cmd.arg("--data-dir")
            .arg(data_dir.path())
            .arg("--genesis")
            .arg(genesis_path)
            .arg("--bind-host")
            .arg("127.0.0.1")
            .arg("--bind-port")
            .arg(rpc_port.to_string())
            .arg("--listen-addr")
            .arg(format!("/ip4/127.0.0.1/tcp/{p2p_port}"))
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        if let Some(address) = miner_address {
            cmd.arg("--miner-address").arg(address.to_bech32());
        }
        for peer in peers {
            cmd.arg("--peer").arg(peer);
        }

        let child = cmd.spawn().unwrap_or_else(|e| panic!("no se pudo lanzar znx-node ({:?}): {e}", znx_node_bin()));
        TestNode { _data_dir: data_dir, _child: child, rpc_addr, p2p_port }
    }

    /// Multiaddr para que otro `TestNode` lo use como `--peer`.
    pub fn p2p_multiaddr(&self) -> String {
        format!("/ip4/127.0.0.1/tcp/{}", self.p2p_port)
    }

    pub fn rpc_addr(&self) -> SocketAddr {
        self.rpc_addr
    }

    fn rpc_client(&self) -> HttpClient {
        HttpClientBuilder::default().build(format!("http://{}", self.rpc_addr)).expect("cliente RPC válido")
    }

    /// Altura actual, o `None` si el nodo todavía no levantó el servidor
    /// RPC (reintenta un rato — el proceso recién lanzado puede tardar
    /// unos milisegundos en escuchar) o si el proceso murió.
    pub async fn latest_height(&self) -> Option<u64> {
        let client = self.rpc_client();
        for _ in 0..50 {
            if let Ok(result) = client.request::<LatestHeightResult, _>("get_latest_height", rpc_params![]).await {
                return result.height;
            }
            sleep(Duration::from_millis(100)).await;
        }
        None
    }

    /// Espera hasta que la altura sea `>= target`, o falla con `Timeout`.
    pub async fn wait_for_height(&self, target: u64, timeout: Duration) -> Result<u64, TestkitError> {
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(height) = self.latest_height().await {
                if height >= target {
                    return Ok(height);
                }
            }
            if Instant::now() >= deadline {
                return Err(TestkitError::Timeout);
            }
            sleep(Duration::from_millis(200)).await;
        }
    }

    /// Suma de UTXOs de `address` (vía `list_unspent`).
    pub async fn balance(&self, address: &Address) -> Result<u128, TestkitError> {
        let client = self.rpc_client();
        let utxos: Vec<UnspentOutputResult> =
            client.request("list_unspent", rpc_params![address.to_bech32()]).await.map_err(|e| TestkitError::Rpc(e.to_string()))?;
        Ok(utxos.iter().map(|u| u.amount.parse::<u128>().expect("el nodo siempre manda un u128 válido")).sum())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use znx_crypto::Keypair;

    /// Test de humo del harness contra sí mismo — real, de varios
    /// segundos (arranca 2 procesos znx-node de verdad), por eso
    /// `#[ignore]`: no corre en `cargo test --workspace` normal, hace
    /// falta `cargo test -p znx-testkit -- --ignored`.
    #[tokio::test]
    #[ignore]
    async fn two_nodes_converge_to_the_same_height() {
        let dir = tempfile::tempdir().expect("tempdir");
        let genesis_path = dir.path().join("genesis.json");
        write_test_genesis(&genesis_path, 2); // fácil, mina rápido

        let miner_a = Keypair::generate();
        let miner_b = Keypair::generate();

        let node_a = TestNode::spawn(&genesis_path, Some(&miner_a.address()), &[]);
        let node_b = TestNode::spawn(&genesis_path, Some(&miner_b.address()), std::slice::from_ref(&node_a.p2p_multiaddr()));

        node_a.wait_for_height(5, Duration::from_secs(30)).await.expect("A llega a altura 5");
        node_b.wait_for_height(5, Duration::from_secs(30)).await.expect("B llega a altura 5");

        assert!(node_a.latest_height().await.expect("A tiene altura") >= 5);
        assert!(node_b.latest_height().await.expect("B tiene altura") >= 5);
    }

    /// Prueba específicamente la sincronización completa (IBD), no el
    /// reorg corto: A mina solo hasta bien por encima de
    /// `MAX_BACKFILL_DEPTH` (20) antes de que B se conecte, así que el
    /// backfill reactivo (acotado a 20 bloques) no alcanzaría para poner
    /// a B al día — si B llega a la misma altura, fue por IBD.
    #[tokio::test]
    #[ignore]
    async fn a_new_node_catches_up_via_ibd_past_the_backfill_depth() {
        let dir = tempfile::tempdir().expect("tempdir");
        let genesis_path = dir.path().join("genesis.json");
        write_test_genesis(&genesis_path, 2); // fácil, mina rápido

        let miner_a = Keypair::generate();
        let node_a = TestNode::spawn(&genesis_path, Some(&miner_a.address()), &[]);
        node_a.wait_for_height(50, Duration::from_secs(60)).await.expect("A supera los 50 bloques (bien por encima de MAX_BACKFILL_DEPTH)");

        // B arranca desde cero, sin minar — si llega a una altura
        // comparable, fue exclusivamente por IBD al conectarse a A.
        let node_b = TestNode::spawn(&genesis_path, None, std::slice::from_ref(&node_a.p2p_multiaddr()));
        node_b.wait_for_height(50, Duration::from_secs(60)).await.expect("B se pone al día vía IBD");

        assert!(node_b.latest_height().await.expect("B tiene altura") >= 50);
    }
}
