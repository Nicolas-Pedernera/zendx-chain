//! Cliente RPC + selección de UTXOs + armado/firma/envío de una
//! transferencia — antes vivía duplicado a mano dentro de
//! `znx-wallet-cli::main`. Separado de `keystore.rs`: acá no hay nada
//! sobre cifrado, solo la mecánica de gastar UTXOs ya desbloqueados (un
//! `Keypair` en memoria).
//!
//! Devuelve `Result` en los bordes reales (una llamada RPC a un proceso
//! externo puede fallar en cualquier momento) — a diferencia de
//! `znx-wallet-cli` original, que podía darse el lujo de `panic!` porque
//! era un proceso de un solo uso por invocación. `znx-custody` es un
//! servicio de larga vida: una falla transitoria del nodo no puede
//! tumbar el proceso entero.

use jsonrpsee_core::client::ClientT;
use jsonrpsee_core::params::ObjectParams;
use jsonrpsee_core::rpc_params;
use jsonrpsee_http_client::{HttpClient, HttpClientBuilder};
use serde::Deserialize;
use serde_json::json;
use thiserror::Error;

use znx_codec::signing_bytes;
use znx_crypto::{Address, Keypair};
use znx_types::{OutPoint, Transaction, TxIn, TxOut};

#[derive(Debug, Error)]
pub enum WalletError {
    #[error("`list_unspent` falló: {0}")]
    FetchUnspent(String),
    #[error("`submit_transaction` falló: {0}")]
    Submit(String),
    #[error("`get_latest_height` falló: {0}")]
    LatestHeight(String),
    #[error("`get_transaction` falló: {0}")]
    GetTransaction(String),
    #[error("amount + fee desborda u128")]
    AmountOverflow,
    #[error("fondos insuficientes: se necesitan {target}, hay {available} disponibles")]
    InsufficientFunds { target: u128, available: u128 },
}

/// Cliente HTTP JSON-RPC contra un `znx-node`. Panic-on-error a
/// propósito (no en un boundary de red, es un error de configuración —
/// una URL sintácticamente inválida — que no tiene sentido reintentar ni
/// propagar como `Result`; falla rápido al arrancar en vez de arrastrar
/// un cliente inservible).
///
/// Acepta `host:puerto` sin esquema además de una URL completa —
/// conveniencia para cuando `node` viene de una variable de entorno que
/// solo da eso (ej. `fromService`/`property: hostport` de Render, ver
/// `blockchain/render.yaml`), sin que quien llame tenga que concatenar
/// `http://` a mano.
pub fn http_client(node: &str) -> HttpClient {
    let node = if node.contains("://") { node.to_string() } else { format!("http://{node}") };
    HttpClientBuilder::default().build(&node).unwrap_or_else(|e| panic!("no se pudo construir el cliente RPC para {node}: {e}"))
}

#[derive(Debug, Deserialize)]
struct UnspentOutputResponse {
    txid: String,
    vout: u32,
    amount: String,
}

#[derive(Debug, Deserialize)]
struct SubmitTransactionResponse {
    txid: String,
}

/// UTXOs propios de `address`, ya decodificados a `(OutPoint, monto)`.
pub async fn fetch_unspent(client: &HttpClient, address: &Address) -> Result<Vec<(OutPoint, u128)>, WalletError> {
    let utxos: Vec<UnspentOutputResponse> =
        client.request("list_unspent", rpc_params![address.to_bech32()]).await.map_err(|e| WalletError::FetchUnspent(e.to_string()))?;
    Ok(utxos
        .into_iter()
        .map(|u| {
            let txid_bytes = hex::decode(&u.txid).expect("el nodo siempre manda txid hex válido");
            let txid: [u8; 32] = txid_bytes.try_into().expect("el nodo siempre manda un txid de 32 bytes");
            (OutPoint { txid, vout: u.vout }, u.amount.parse::<u128>().expect("el nodo siempre manda un u128 válido"))
        })
        .collect())
}

#[derive(Debug, Deserialize)]
struct LatestHeightResponse {
    height: Option<u64>,
}

/// Altura del último bloque minado (`None` si la chain no tiene ningún
/// bloque más allá del génesis) — usado para calcular confirmaciones de
/// una tx (ver `znx-custody`, escaneo de depósitos).
pub async fn latest_height(client: &HttpClient) -> Result<Option<u64>, WalletError> {
    let result: LatestHeightResponse =
        client.request("get_latest_height", rpc_params![]).await.map_err(|e| WalletError::LatestHeight(e.to_string()))?;
    Ok(result.height)
}

#[derive(Debug, Deserialize)]
struct TransactionHeightResponse {
    height: u64,
}

/// Altura del bloque que confirmó `txid`, o `None` si todavía no está en
/// ningún bloque (en mempool, o el txid no existe). Solo lee `height` de
/// la respuesta de `get_transaction` — no hace falta la tx completa acá.
pub async fn transaction_height(client: &HttpClient, txid: [u8; 32]) -> Result<Option<u64>, WalletError> {
    let result: Option<TransactionHeightResponse> =
        client.request("get_transaction", rpc_params![hex::encode(txid)]).await.map_err(|e| WalletError::GetTransaction(e.to_string()))?;
    Ok(result.map(|r| r.height))
}

/// Elige UTXOs (de mayor a menor monto) hasta cubrir `target` — greedy,
/// simple de razonar, no intenta minimizar la cantidad de inputs ni
/// mezclar montos para privacidad (fuera de alcance por ahora).
pub fn select_utxos(mut utxos: Vec<(OutPoint, u128)>, target: u128) -> Option<(Vec<OutPoint>, u128)> {
    utxos.sort_by_key(|(_, amount)| std::cmp::Reverse(*amount));

    let mut selected = Vec::new();
    let mut total: u128 = 0;
    for (outpoint, amount) in utxos {
        if total >= target {
            break;
        }
        total = total.checked_add(amount)?;
        selected.push(outpoint);
    }

    if total < target {
        None
    } else {
        Some((selected, total))
    }
}

/// Arma y firma una transferencia de `from` hacia `to`, sobre UTXOs ya
/// consultados aparte (vía `fetch_unspent`) — separado de la consulta al
/// nodo para poder testear la selección/armado sin un nodo real.
pub fn build_transfer(chain_id: String, from: &Keypair, to: Address, amount: u128, fee: u128, utxos: Vec<(OutPoint, u128)>) -> Result<Transaction, WalletError> {
    let target = amount.checked_add(fee).ok_or(WalletError::AmountOverflow)?;
    let available: u128 = utxos.iter().map(|(_, a)| a).sum();
    let Some((spend, total_selected)) = select_utxos(utxos, target) else {
        return Err(WalletError::InsufficientFunds { target, available });
    };

    let mut outputs = vec![TxOut { amount, pubkey_hash: to }];
    let change = total_selected - target;
    if change > 0 {
        outputs.push(TxOut { amount: change, pubkey_hash: from.address() });
    }

    let inputs = spend.into_iter().map(|prev_out| TxIn { prev_out, public_key: from.public_key().to_bytes(), signature: [0u8; 64] }).collect();

    let mut tx = Transaction { chain_id, inputs, outputs };
    let message = signing_bytes(&tx);
    let signature = from.sign(&message);
    for input in &mut tx.inputs {
        input.signature = signature.to_bytes();
    }
    Ok(tx)
}

/// Manda una transacción ya firmada al nodo. Devuelve el txid.
pub async fn submit_transaction(client: &HttpClient, tx: &Transaction) -> Result<[u8; 32], WalletError> {
    let inputs_json: Vec<_> = tx
        .inputs
        .iter()
        .map(|i| {
            json!({
                "prev_txid": hex::encode(i.prev_out.txid),
                "prev_vout": i.prev_out.vout,
                "public_key": hex::encode(i.public_key),
                "signature": hex::encode(i.signature),
            })
        })
        .collect();
    let outputs_json: Vec<_> = tx.outputs.iter().map(|o| json!({ "amount": o.amount.to_string(), "pubkey_hash": o.pubkey_hash.to_bech32() })).collect();

    let mut params = ObjectParams::new();
    params.insert("chain_id", &tx.chain_id).expect("String serializa");
    params.insert("inputs", inputs_json).expect("Vec<Value> serializa");
    params.insert("outputs", outputs_json).expect("Vec<Value> serializa");

    let result: SubmitTransactionResponse = client.request("submit_transaction", params).await.map_err(|e| WalletError::Submit(e.to_string()))?;
    let txid_bytes = hex::decode(&result.txid).expect("el nodo siempre manda txid hex válido");
    Ok(txid_bytes.try_into().expect("el nodo siempre manda un txid de 32 bytes"))
}

/// Combina consulta+armado+firma+envío — lo que tanto `znx-wallet-cli
/// send` como `znx-custody` (firma de retiros) necesitan hacer en un
/// solo paso.
pub async fn send(client: &HttpClient, chain_id: String, from: &Keypair, to: Address, amount: u128, fee: u128) -> Result<[u8; 32], WalletError> {
    let utxos = fetch_unspent(client, &from.address()).await?;
    let tx = build_transfer(chain_id, from, to, amount, fee, utxos)?;
    submit_transaction(client, &tx).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn http_client_adds_scheme_when_missing() {
        // No hay forma de inspeccionar la URL final desde `HttpClient`
        // (no expone getters) — alcanza con que no paniquee: si no le
        // hubiéramos agregado el esquema, `HttpClientBuilder::build`
        // rechazaría "host:puerto" por no ser una URL válida.
        let _ = http_client("znx-devnet-node:26657");
    }

    #[test]
    fn http_client_keeps_an_explicit_scheme() {
        let _ = http_client("http://127.0.0.1:26657");
    }

    fn outpoint(byte: u8) -> OutPoint {
        OutPoint { txid: [byte; 32], vout: 0 }
    }

    #[test]
    fn select_utxos_picks_largest_first_and_stops_once_covered() {
        let utxos = vec![(outpoint(1), 10), (outpoint(2), 50), (outpoint(3), 5)];
        let (selected, total) = select_utxos(utxos, 40).expect("cubre con el más grande solo");
        assert_eq!(selected, vec![outpoint(2)]);
        assert_eq!(total, 50);
    }

    #[test]
    fn select_utxos_combines_several_when_needed() {
        let utxos = vec![(outpoint(1), 10), (outpoint(2), 20), (outpoint(3), 5)];
        let (selected, total) = select_utxos(utxos, 25).expect("combina 20 + 10");
        assert_eq!(selected.len(), 2);
        assert!(selected.contains(&outpoint(1)));
        assert!(selected.contains(&outpoint(2)));
        assert_eq!(total, 30);
    }

    #[test]
    fn select_utxos_none_when_funds_insufficient() {
        let utxos = vec![(outpoint(1), 10), (outpoint(2), 5)];
        assert_eq!(select_utxos(utxos, 100), None);
    }

    #[test]
    fn build_transfer_adds_change_output_to_sender() {
        let from = Keypair::generate();
        let to = Keypair::generate().address();
        let utxos = vec![(outpoint(1), 100)];

        let tx = build_transfer("znx-test-1".to_string(), &from, to, 30, 5, utxos).expect("fondos suficientes");

        assert_eq!(tx.outputs.len(), 2);
        assert_eq!(tx.outputs[0], TxOut { amount: 30, pubkey_hash: to });
        assert_eq!(tx.outputs[1], TxOut { amount: 65, pubkey_hash: from.address() });
        assert_eq!(tx.inputs.len(), 1);
        assert_eq!(tx.inputs[0].prev_out, outpoint(1));
    }

    #[test]
    fn build_transfer_omits_change_output_when_exact() {
        let from = Keypair::generate();
        let to = Keypair::generate().address();
        let utxos = vec![(outpoint(1), 35)];

        let tx = build_transfer("znx-test-1".to_string(), &from, to, 30, 5, utxos).expect("fondos exactos");

        assert_eq!(tx.outputs.len(), 1);
        assert_eq!(tx.outputs[0], TxOut { amount: 30, pubkey_hash: to });
    }

    #[test]
    fn build_transfer_fails_with_insufficient_funds() {
        let from = Keypair::generate();
        let to = Keypair::generate().address();
        let utxos = vec![(outpoint(1), 10)];

        let err = build_transfer("znx-test-1".to_string(), &from, to, 30, 5, utxos).unwrap_err();
        assert!(matches!(err, WalletError::InsufficientFunds { target: 35, available: 10 }));
    }

    #[test]
    fn build_transfer_signature_is_valid_against_the_signing_bytes() {
        let from = Keypair::generate();
        let to = Keypair::generate().address();
        let utxos = vec![(outpoint(1), 100)];

        let tx = build_transfer("znx-test-1".to_string(), &from, to, 30, 0, utxos).expect("fondos suficientes");
        let message = signing_bytes(&tx);
        znx_crypto::verify_raw(&tx.inputs[0].public_key, &message, &tx.inputs[0].signature).expect("firma válida");
    }
}
