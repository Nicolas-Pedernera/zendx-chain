//! Test de humo real (`#[ignore]`, no corre en `cargo test --workspace`
//! normal — arranca 2 procesos reales, `znx-node` y `znx-custody`, hace
//! falta `cargo test -p znx-custody -- --ignored`): un nodo real mina
//! hacia la dirección de una wallet de custodia, `znx-custody` (el
//! binario real, no una versión in-process) firma y manda un retiro real
//! desde esa wallet, y se confirma que el balance de destino sube tras
//! el próximo bloque. Cubre de punta a punta lo que `INTEGRATION.md`
//! describe: el backend nunca ve la llave privada, solo llama
//! `sign_withdrawal` por RPC.

use std::net::TcpListener;
use std::time::Duration;

use jsonrpsee_core::client::ClientT;
use jsonrpsee_core::params::ObjectParams;
use jsonrpsee_core::rpc_params;
use jsonrpsee_http_client::{HttpClient, HttpClientBuilder};
use serde::Deserialize;
use tokio::process::{Child, Command};
use tokio::time::sleep;

use znx_crypto::Keypair;
use znx_testkit::{write_test_genesis, TestNode};

const CHAIN_ID: &str = "znx-testkit-1";

fn free_tcp_port() -> u16 {
    TcpListener::bind("127.0.0.1:0").expect("bind a un puerto libre").local_addr().expect("local_addr").port()
}

fn custody_bin() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_BIN_EXE_znx-custody"))
}

struct CustodyProcess {
    _child: Child,
    client: HttpClient,
}

impl CustodyProcess {
    async fn spawn(keystore_path: &std::path::Path, journal_path: &std::path::Path, node_addr: std::net::SocketAddr, password: &str, token: &str) -> Self {
        let listen_port = free_tcp_port();
        let listen_addr = format!("127.0.0.1:{listen_port}");

        let child = Command::new(custody_bin())
            .arg("--keystore")
            .arg(keystore_path)
            .arg("--journal")
            .arg(journal_path)
            .arg("--node")
            .arg(format!("http://{node_addr}"))
            .arg("--listen-host")
            .arg("127.0.0.1")
            .arg("--listen-port")
            .arg(listen_port.to_string())
            .arg("--chain-id")
            .arg(CHAIN_ID)
            .env("ZNX_CUSTODY_PASSWORD", password)
            .env("ZNX_CUSTODY_TOKEN", token)
            .kill_on_drop(true)
            .spawn()
            .unwrap_or_else(|e| panic!("no se pudo lanzar znx-custody: {e}"));

        let client = HttpClientBuilder::default().build(format!("http://{listen_addr}")).expect("cliente RPC válido");

        // Reintenta hasta que el servidor levante (arranca async, puede
        // tardar unos milisegundos en escuchar).
        for _ in 0..50 {
            if client.request::<CustodyAddressResult, _>("custody_address", rpc_params![]).await.is_ok() {
                return CustodyProcess { _child: child, client };
            }
            sleep(Duration::from_millis(100)).await;
        }
        panic!("znx-custody no levantó el RPC a tiempo");
    }
}

#[derive(Debug, Deserialize)]
struct CustodyAddressResult {
    #[allow(dead_code)]
    address: String,
}

#[derive(Debug, Deserialize)]
struct SignWithdrawalResult {
    txid: String,
}

#[tokio::test]
#[ignore]
async fn sign_withdrawal_moves_real_funds_end_to_end() {
    let dir = tempfile::tempdir().expect("tempdir");
    let genesis_path = dir.path().join("genesis.json");
    write_test_genesis(&genesis_path, 2); // fácil, mina rápido

    // La wallet de custodia es la que mina — así arranca con fondos
    // reales sin necesidad de una transferencia previa.
    let custody_keypair = Keypair::generate();
    let keystore = znx_wallet::Keystore::create(&custody_keypair, "contraseña-de-test").expect("cifra sin error");
    let keystore_path = dir.path().join("custody-keystore.json");
    keystore.save(&keystore_path).expect("guarda sin error");

    let node = TestNode::spawn(&genesis_path, Some(&custody_keypair.address()), &[]);
    node.wait_for_height(3, Duration::from_secs(30)).await.expect("el nodo mina algunos bloques");

    let journal_path = dir.path().join("journal.jsonl");
    let custody = CustodyProcess::spawn(&keystore_path, &journal_path, node.rpc_addr(), "contraseña-de-test", "el-token-secreto").await;

    // Un auth_token incorrecto tiene que rechazarse, no solo "funcionar
    // igual" — si esto no fallara, la autenticación no estaría haciendo
    // nada.
    let destination = Keypair::generate().address();

    let mut wrong_token_params = ObjectParams::new();
    wrong_token_params.insert("request_id", "req-auth-check").expect("String serializa");
    wrong_token_params.insert("to", destination.to_bech32()).expect("String serializa");
    wrong_token_params.insert("amount", "1000000000000000000").expect("String serializa");
    wrong_token_params.insert("auth_token", "un-token-equivocado").expect("String serializa");
    let rejected: Result<SignWithdrawalResult, _> = custody.client.request("sign_withdrawal", wrong_token_params).await;
    assert!(rejected.is_err(), "un auth_token inválido tiene que ser rechazado");

    let balance_before = node.balance(&destination).await.expect("lectura de balance ok");
    assert_eq!(balance_before, 0);

    let withdraw_amount: u128 = 1_000_000_000_000_000_000; // 1 ZNX (18 decimales)
    let request_id = "req-retiro-1";
    let mut params = ObjectParams::new();
    params.insert("request_id", request_id).expect("String serializa");
    params.insert("to", destination.to_bech32()).expect("String serializa");
    params.insert("amount", withdraw_amount.to_string()).expect("String serializa");
    params.insert("auth_token", "el-token-secreto").expect("String serializa");
    let result: SignWithdrawalResult =
        custody.client.request("sign_withdrawal", params).await.unwrap_or_else(|e| panic!("sign_withdrawal falló: {e}"));
    assert_eq!(result.txid.len(), 64, "el txid tiene que ser 32 bytes en hex");

    // Repetir el mismo request_id con los mismos parámetros (simula una
    // Edge Function reintentando tras haberse caído antes de guardar el
    // txid) tiene que devolver el mismo txid, sin firmar/mandar una
    // segunda tx — es exactamente el mecanismo de "reconciliación" que
    // reemplaza escanear la cadena.
    let mut replay_params = ObjectParams::new();
    replay_params.insert("request_id", request_id).expect("String serializa");
    replay_params.insert("to", destination.to_bech32()).expect("String serializa");
    replay_params.insert("amount", withdraw_amount.to_string()).expect("String serializa");
    replay_params.insert("auth_token", "el-token-secreto").expect("String serializa");
    let replayed: SignWithdrawalResult =
        custody.client.request("sign_withdrawal", replay_params).await.unwrap_or_else(|e| panic!("el replay del mismo request_id falló: {e}"));
    assert_eq!(replayed.txid, result.txid, "el mismo request_id tiene que devolver el mismo txid, no firmar de nuevo");

    // El mismo request_id con OTROS parámetros (un bug del llamador, no
    // un reintento legítimo) tiene que rechazarse, no devolver el txid
    // viejo silenciosamente ni firmar un retiro distinto bajo ese id.
    let mut conflicting_params = ObjectParams::new();
    conflicting_params.insert("request_id", request_id).expect("String serializa");
    conflicting_params.insert("to", destination.to_bech32()).expect("String serializa");
    conflicting_params.insert("amount", (withdraw_amount + 1).to_string()).expect("String serializa");
    conflicting_params.insert("auth_token", "el-token-secreto").expect("String serializa");
    let conflicting: Result<SignWithdrawalResult, _> = custody.client.request("sign_withdrawal", conflicting_params).await;
    assert!(conflicting.is_err(), "reusar un request_id con otros parámetros tiene que rechazarse");

    // La tx queda en el mempool del nodo hasta que este mismo nodo (el
    // único minero acá) la incluya en su próximo bloque minado.
    let height_before = node.latest_height().await.expect("altura antes del retiro");
    node.wait_for_height(height_before + 1, Duration::from_secs(30)).await.expect("el nodo mina el bloque con el retiro");

    // Si el replay hubiera mandado una segunda tx, acá el balance
    // duplicaría el monto — confirma que el journal realmente evitó el
    // segundo envío, no solo que devolvió el mismo txid en la respuesta.
    let balance_after = node.balance(&destination).await.expect("lectura de balance ok");
    assert_eq!(balance_after, withdraw_amount);
}
