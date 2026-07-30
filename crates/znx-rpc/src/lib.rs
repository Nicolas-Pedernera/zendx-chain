//! znx-rpc — servidor JSON-RPC (`jsonrpsee`, sin el macro `#[rpc]`) de la
//! API completa de Zend X Chain. Reemplaza el stopgap que vivía embebido
//! en `znx-node` (Fase 1/2): acá el crate no sabe nada de cómo vive el
//! storage/mempool por dentro — solo conoce el trait `RpcNode`, que quien
//! corre un nodo real implementa (`znx-node::SharedNode`). Evita un ciclo
//! de dependencias (znx-node depende de znx-rpc para levantar el
//! servidor, no al revés) sin necesidad de mover `RocksStorage`/
//! `Mempool`/el tipo de génesis fuera de znx-node.
//!
//! Convención de los parámetros/resultados: direcciones en bech32,
//! montos (`u128`) como string decimal, hashes/txid/pubkey/firma en hex —
//! nunca un `number` de JSON que pueda truncar un `u128`.
//!
//! Los métodos del trait son `async fn` nativos (estables desde Rust
//! 1.75, sin macro) — no hace falta `async-trait` acá como en `znx-p2p`
//! (ahí lo exige `libp2p::request_response::Codec`, una API externa; acá
//! no necesitamos dyn-dispatch, `start_server` es genérico sobre `C:
//! RpcNode`).

use std::net::SocketAddr;
use std::sync::Arc;

use jsonrpsee::server::{Server, ServerHandle};
use jsonrpsee::types::{ErrorCode, ErrorObjectOwned};
use jsonrpsee::RpcModule;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use znx_crypto::Address;
use znx_types::{Block, OutPoint, Transaction, TxIn, TxOut};

#[derive(Debug, Error)]
pub enum RpcError {
    #[error("no se pudo levantar el servidor RPC en {addr}: {source}")]
    Bind { addr: SocketAddr, #[source] source: std::io::Error },
    #[error("no se pudo registrar un método RPC: {0}")]
    Register(#[from] jsonrpsee::core::RegisterMethodError),
}

/// Info resumida de minería/emisión para `get_mining_info`. Quien
/// implementa `RpcNode` la arma completa (tiene a mano el génesis
/// entero: subsidio inicial, intervalo de halving) — acá solo se
/// serializa para JSON-RPC.
#[derive(Debug, Clone)]
pub struct MiningInfo {
    pub chain_id: String,
    pub height: Option<u64>,
    pub target: [u8; 32],
    pub next_subsidy: u128,
}

/// Lo único que un handler JSON-RPC necesita de un nodo real. Cada
/// método delega en lo que quien lo implemente ya tiene a mano (storage,
/// mempool, génesis) — este trait no asume nada sobre cómo está
/// organizado eso por dentro.
/// Firmas escritas como `-> impl Future<Output = ...> + Send` (en vez de
/// `async fn`, que en la sintaxis nativa de Rust no anota el `Send` del
/// future) porque `jsonrpsee::RpcModule::register_async_method` exige
/// justamente eso — el servidor puede correr los handlers en cualquier
/// hilo del pool de tokio. Las implementaciones (ver `znx-node`) pueden
/// seguir escribiéndose con `async fn` normal.
pub trait RpcNode: Send + Sync {
    /// Admite `tx` al mempool. Devuelve su txid, o el motivo de rechazo
    /// como texto (mismo criterio que hoy: error de mempool convertido a
    /// string, no un tipo estructurado — total termina siendo texto de
    /// error JSON-RPC de cualquier forma).
    fn submit_transaction(&self, tx: Transaction) -> impl std::future::Future<Output = Result<[u8; 32], String>> + Send;
    fn list_unspent(&self, address: Address) -> impl std::future::Future<Output = Result<Vec<(OutPoint, TxOut)>, String>> + Send;
    fn latest_height(&self) -> impl std::future::Future<Output = Result<Option<u64>, String>> + Send;
    fn get_block(&self, height: u64) -> impl std::future::Future<Output = Result<Option<Block>, String>> + Send;
    fn get_block_by_hash(&self, hash: [u8; 32]) -> impl std::future::Future<Output = Result<Option<Block>, String>> + Send;
    /// Transacción confirmada por txid, junto con la altura y el hash del
    /// bloque que la confirmó. `None` si nunca se confirmó.
    fn get_transaction(&self, txid: [u8; 32]) -> impl std::future::Future<Output = Result<Option<(u64, [u8; 32], Transaction)>, String>> + Send;
    fn mempool_len(&self) -> impl std::future::Future<Output = usize> + Send;
    fn mining_info(&self) -> impl std::future::Future<Output = MiningInfo> + Send;
}

#[derive(Debug, Deserialize)]
struct TxInParams {
    prev_txid: String,
    prev_vout: u32,
    public_key: String,
    signature: String,
}

#[derive(Debug, Deserialize)]
struct TxOutParams {
    amount: String,
    pubkey_hash: String,
}

#[derive(Debug, Deserialize)]
struct SubmitTransactionParams {
    chain_id: String,
    inputs: Vec<TxInParams>,
    outputs: Vec<TxOutParams>,
}

#[derive(Debug, Clone, Serialize)]
struct SubmitTransactionResult {
    txid: String,
}

#[derive(Debug, Clone, Serialize)]
struct UnspentOutput {
    txid: String,
    vout: u32,
    amount: String,
}

#[derive(Debug, Clone, Serialize)]
struct LatestHeightResult {
    height: Option<u64>,
}

#[derive(Debug, Clone, Serialize)]
struct TxInResult {
    prev_txid: String,
    prev_vout: u32,
    public_key: String,
    signature: String,
}

#[derive(Debug, Clone, Serialize)]
struct TxOutResult {
    amount: String,
    pubkey_hash: String,
}

#[derive(Debug, Clone, Serialize)]
struct TransactionResult {
    txid: String,
    chain_id: String,
    is_coinbase: bool,
    inputs: Vec<TxInResult>,
    outputs: Vec<TxOutResult>,
}

#[derive(Debug, Clone, Serialize)]
struct BlockResult {
    height: u64,
    hash: String,
    parent_hash: String,
    tx_root: String,
    timestamp: u64,
    target: String,
    pow_nonce: u64,
    transactions: Vec<TransactionResult>,
}

#[derive(Debug, Clone, Serialize)]
struct GetTransactionResult {
    height: u64,
    block_hash: String,
    #[serde(flatten)]
    transaction: TransactionResult,
}

#[derive(Debug, Clone, Serialize)]
struct MempoolInfoResult {
    pending_count: usize,
}

#[derive(Debug, Clone, Serialize)]
struct MiningInfoResult {
    chain_id: String,
    height: Option<u64>,
    target: String,
    next_subsidy: String,
}

fn invalid_params(message: impl std::fmt::Display) -> ErrorObjectOwned {
    ErrorObjectOwned::owned(ErrorCode::InvalidParams.code(), message.to_string(), None::<()>)
}

fn internal_error(message: impl std::fmt::Display) -> ErrorObjectOwned {
    ErrorObjectOwned::owned(ErrorCode::InternalError.code(), message.to_string(), None::<()>)
}

fn decode_hex_array<const N: usize>(field: &str, hex_str: &str) -> Result<[u8; N], ErrorObjectOwned> {
    let bytes = hex::decode(hex_str).map_err(|_| invalid_params(format!("`{field}` no es hex válido")))?;
    bytes.try_into().map_err(|_| invalid_params(format!("`{field}` tiene que ser de {N} bytes")))
}

fn parse_transaction(params: SubmitTransactionParams) -> Result<Transaction, ErrorObjectOwned> {
    let inputs = params
        .inputs
        .into_iter()
        .map(|i| {
            let prev_txid = decode_hex_array::<32>("prev_txid", &i.prev_txid)?;
            let public_key = decode_hex_array::<32>("public_key", &i.public_key)?;
            let signature = decode_hex_array::<64>("signature", &i.signature)?;
            Ok(TxIn { prev_out: OutPoint { txid: prev_txid, vout: i.prev_vout }, public_key, signature })
        })
        .collect::<Result<Vec<_>, ErrorObjectOwned>>()?;

    let outputs = params
        .outputs
        .into_iter()
        .map(|o| {
            let amount = o.amount.parse::<u128>().map_err(|_| invalid_params("`amount` no es un u128 válido"))?;
            let pubkey_hash = Address::from_bech32(&o.pubkey_hash).map_err(invalid_params)?;
            Ok(TxOut { amount, pubkey_hash })
        })
        .collect::<Result<Vec<_>, ErrorObjectOwned>>()?;

    Ok(Transaction { chain_id: params.chain_id, inputs, outputs })
}

fn transaction_to_result(tx: &Transaction) -> TransactionResult {
    TransactionResult {
        txid: hex::encode(znx_codec::txid(tx)),
        chain_id: tx.chain_id.clone(),
        is_coinbase: tx.is_coinbase(),
        inputs: tx
            .inputs
            .iter()
            .map(|i| TxInResult {
                prev_txid: hex::encode(i.prev_out.txid),
                prev_vout: i.prev_out.vout,
                public_key: hex::encode(i.public_key),
                signature: hex::encode(i.signature),
            })
            .collect(),
        outputs: tx.outputs.iter().map(|o| TxOutResult { amount: o.amount.to_string(), pubkey_hash: o.pubkey_hash.to_bech32() }).collect(),
    }
}

fn block_to_result(block: &Block) -> BlockResult {
    BlockResult {
        height: block.header.height,
        hash: hex::encode(znx_codec::block_hash(block)),
        parent_hash: hex::encode(block.header.parent_hash),
        tx_root: hex::encode(block.header.tx_root),
        timestamp: block.header.timestamp,
        target: hex::encode(block.header.target),
        pow_nonce: block.header.pow_nonce,
        transactions: block.transactions.iter().map(transaction_to_result).collect(),
    }
}

/// Levanta el servidor y lo pone a escuchar en `addr`. Devuelve enseguida
/// (no bloquea) — el servidor sigue corriendo en el runtime de tokio
/// hasta que se llama `.stop()` sobre el handle devuelto.
pub async fn start_server<C>(addr: SocketAddr, ctx: Arc<C>) -> Result<ServerHandle, RpcError>
where
    C: RpcNode + Send + Sync + 'static,
{
    let server = Server::builder().build(addr).await.map_err(|source| RpcError::Bind { addr, source })?;
    let mut module = RpcModule::new(ctx);

    module.register_async_method("submit_transaction", |params, ctx, _extensions| async move {
        let raw: SubmitTransactionParams = params.parse()?;
        let tx = parse_transaction(raw)?;
        let txid = ctx.submit_transaction(tx).await.map_err(invalid_params)?;
        Ok::<_, ErrorObjectOwned>(SubmitTransactionResult { txid: hex::encode(txid) })
    })?;

    module.register_async_method("list_unspent", |params, ctx, _extensions| async move {
        let address_str: String = params.one()?;
        let address = Address::from_bech32(&address_str).map_err(invalid_params)?;
        let utxos = ctx.list_unspent(address).await.map_err(internal_error)?;
        let result = utxos
            .into_iter()
            .map(|(outpoint, output)| UnspentOutput { txid: hex::encode(outpoint.txid), vout: outpoint.vout, amount: output.amount.to_string() })
            .collect::<Vec<_>>();
        Ok::<_, ErrorObjectOwned>(result)
    })?;

    module.register_async_method("get_latest_height", |_params, ctx, _extensions| async move {
        let height = ctx.latest_height().await.map_err(internal_error)?;
        Ok::<_, ErrorObjectOwned>(LatestHeightResult { height })
    })?;

    module.register_async_method("get_block", |params, ctx, _extensions| async move {
        let height: u64 = params.one()?;
        let block = ctx.get_block(height).await.map_err(internal_error)?;
        Ok::<_, ErrorObjectOwned>(block.as_ref().map(block_to_result))
    })?;

    module.register_async_method("get_block_by_hash", |params, ctx, _extensions| async move {
        let hash_str: String = params.one()?;
        let hash = decode_hex_array::<32>("hash", &hash_str)?;
        let block = ctx.get_block_by_hash(hash).await.map_err(internal_error)?;
        Ok::<_, ErrorObjectOwned>(block.as_ref().map(block_to_result))
    })?;

    module.register_async_method("get_transaction", |params, ctx, _extensions| async move {
        let txid_str: String = params.one()?;
        let txid = decode_hex_array::<32>("txid", &txid_str)?;
        let result = ctx.get_transaction(txid).await.map_err(internal_error)?;
        Ok::<_, ErrorObjectOwned>(result.map(|(height, block_hash, tx)| GetTransactionResult {
            height,
            block_hash: hex::encode(block_hash),
            transaction: transaction_to_result(&tx),
        }))
    })?;

    module.register_async_method("get_mempool_info", |_params, ctx, _extensions| async move {
        let pending_count = ctx.mempool_len().await;
        Ok::<_, ErrorObjectOwned>(MempoolInfoResult { pending_count })
    })?;

    module.register_async_method("get_mining_info", |_params, ctx, _extensions| async move {
        let info = ctx.mining_info().await;
        Ok::<_, ErrorObjectOwned>(MiningInfoResult {
            chain_id: info.chain_id,
            height: info.height,
            target: hex::encode(info.target),
            next_subsidy: info.next_subsidy.to_string(),
        })
    })?;

    Ok(server.start(module))
}
