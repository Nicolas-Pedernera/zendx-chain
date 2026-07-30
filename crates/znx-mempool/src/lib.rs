//! znx-mempool — pool de transacciones pendientes, previo a su inclusión
//! en un bloque por el minero (`znx-node`). Valida cada transacción
//! entrante contra el UTXO set *actual* (vía `znx_state::StateStore`, de
//! solo lectura) al momento de admitirla: firma, `chain_id`, que cada
//! outpoint que gasta exista, y que ningún otro tx ya pendiente esté
//! gastando ese mismo outpoint (el equivalente UTXO de "rechazar doble
//! gasto dentro del propio mempool" — acá no hay nonces que secuenciar).
//!
//! La validación acá es *admisión*, no la autoridad final: el UTXO set
//! puede moverse entre que una tx entra al mempool y que el minero
//! efectivamente la aplica (vía `znx_state::apply_transaction`). Si para
//! entonces ya no es válida, el minero simplemente la descarta — no hay
//! una segunda pasada de re-validación acá adentro.
//!
//! Las transacciones coinbase nunca pasan por acá: las arma el minero
//! directo al construir el bloque candidato, no llegan por gossip/RPC
//! como una tx suelta.

use std::collections::{HashMap, HashSet, VecDeque};

use thiserror::Error;
use znx_codec::{signing_bytes, txid};
use znx_crypto::{address_from_public_key_bytes, verify_raw};
use znx_state::StateStore;
use znx_types::{OutPoint, Transaction};

#[derive(Debug, Error, PartialEq, Eq)]
pub enum MempoolError {
    #[error("llave pública inválida en un input de la transacción")]
    InvalidPublicKey,
    #[error("la dirección derivada de la llave pública de un input no coincide con el dueño del UTXO referenciado")]
    AddressMismatch,
    #[error("firma inválida en un input de la transacción")]
    InvalidSignature,
    #[error("chain_id incorrecto: se esperaba '{expected}', la tx trae '{found}'")]
    WrongChainId { expected: String, found: String },
    #[error("la transacción no tiene ningún input")]
    NoInputs,
    #[error("las transacciones coinbase no se admiten por esta vía, las arma el minero directamente")]
    CoinbaseNotAllowed,
    #[error("un mismo outpoint aparece más de una vez como input de la misma transacción")]
    DuplicateInput,
    #[error("el outpoint referenciado no existe en el UTXO set (ya gastado en cadena, o nunca existió)")]
    UnknownOutpoint,
    #[error("el outpoint referenciado ya está siendo gastado por otra transacción pendiente en el mempool")]
    OutpointAlreadyClaimed,
    #[error("esta transacción (mismo txid) ya está en el mempool")]
    AlreadyInMempool,
    #[error("los inputs no alcanzan para cubrir los outputs: disponible {available}, se necesitan {required}")]
    InsufficientInputs { available: u128, required: u128 },
    #[error("desbordamiento aritmético validando la transacción")]
    Overflow,
    #[error("el mempool está lleno — probá de nuevo más tarde")]
    Full,
}

/// Tope de transacciones pendientes simultáneas — sin esto, un flood de
/// transacciones válidas pero triviales (ej. encadenando el vuelto de a
/// poco entre outputs propios) puede crecer el mempool sin límite. Se
/// rechaza directo en vez de desalojar la más vieja: sin priorización
/// por fee-rate todavía (ver doc de módulo), desalojar abriría una vía
/// de "sacar la tx de otro metiendo la propia" sin ningún costo real de
/// por medio.
const MAX_MEMPOOL_SIZE: usize = 10_000;

/// Pool en memoria — se reconstruye desde cero al reiniciar el nodo (a
/// diferencia del estado, que persiste en `znx-storage`). Perder
/// transacciones pendientes en un restart es aceptable en esta fase: el
/// emisor puede reenviarlas.
#[derive(Debug)]
pub struct Mempool {
    chain_id: String,
    txs: HashMap<[u8; 32], Transaction>,
    // outpoint gastado -> txid de la tx pendiente que lo gasta. Sirve tanto
    // para rechazar un segundo intento de gastar el mismo outpoint (doble
    // gasto dentro del mempool) como para liberar las claims cuando esa tx
    // sale del pool (`next_batch`).
    claimed_by: HashMap<OutPoint, [u8; 32]>,
    order: VecDeque<[u8; 32]>,
    max_size: usize,
}

impl Mempool {
    pub fn new(chain_id: impl Into<String>) -> Self {
        Self::with_max_size(chain_id, MAX_MEMPOOL_SIZE)
    }

    /// Mismo que `new`, con un tope de tamaño distinto al default — pensado
    /// para tests (probar el rechazo por `Full` sin tener que insertar
    /// `MAX_MEMPOOL_SIZE` transacciones reales de verdad).
    pub fn with_max_size(chain_id: impl Into<String>, max_size: usize) -> Self {
        Self { chain_id: chain_id.into(), txs: HashMap::new(), claimed_by: HashMap::new(), order: VecDeque::new(), max_size }
    }

    pub fn len(&self) -> usize {
        self.order.len()
    }

    pub fn is_empty(&self) -> bool {
        self.order.is_empty()
    }

    /// Valida y admite una transacción. Falla rápido, en el mismo orden
    /// que `znx_state::apply_transaction` (forma/chain_id antes que
    /// firma antes que disponibilidad de outpoints), para que los
    /// mensajes de error sean consistentes entre ambos puntos de
    /// validación de la red.
    pub fn insert<S: StateStore>(&mut self, store: &S, tx: Transaction) -> Result<(), MempoolError> {
        if self.order.len() >= self.max_size {
            return Err(MempoolError::Full);
        }
        if tx.is_coinbase() {
            return Err(MempoolError::CoinbaseNotAllowed);
        }
        if tx.inputs.is_empty() {
            return Err(MempoolError::NoInputs);
        }
        if tx.chain_id != self.chain_id {
            return Err(MempoolError::WrongChainId { expected: self.chain_id.clone(), found: tx.chain_id.clone() });
        }

        let id = txid(&tx);
        if self.txs.contains_key(&id) {
            return Err(MempoolError::AlreadyInMempool);
        }

        let mut seen_outpoints = HashSet::with_capacity(tx.inputs.len());
        for input in &tx.inputs {
            if !seen_outpoints.insert(input.prev_out) {
                return Err(MempoolError::DuplicateInput);
            }
        }

        let message = signing_bytes(&tx);
        let mut total_in: u128 = 0;
        for input in &tx.inputs {
            if self.claimed_by.contains_key(&input.prev_out) {
                return Err(MempoolError::OutpointAlreadyClaimed);
            }
            let utxo = store.get_utxo(&input.prev_out).ok_or(MempoolError::UnknownOutpoint)?;

            let derived_owner = address_from_public_key_bytes(&input.public_key).map_err(|_| MempoolError::InvalidPublicKey)?;
            if derived_owner != utxo.pubkey_hash {
                return Err(MempoolError::AddressMismatch);
            }
            verify_raw(&input.public_key, &message, &input.signature).map_err(|_| MempoolError::InvalidSignature)?;

            total_in = total_in.checked_add(utxo.amount).ok_or(MempoolError::Overflow)?;
        }

        let total_out = tx.outputs.iter().try_fold(0u128, |acc, out| acc.checked_add(out.amount)).ok_or(MempoolError::Overflow)?;
        if total_out > total_in {
            return Err(MempoolError::InsufficientInputs { available: total_in, required: total_out });
        }

        for input in &tx.inputs {
            self.claimed_by.insert(input.prev_out, id);
        }
        self.txs.insert(id, tx);
        self.order.push_back(id);
        Ok(())
    }

    /// Saca hasta `max` transacciones para que el minero las incluya en un
    /// bloque candidato, en el orden en que se admitieron (FIFO). Quedan
    /// removidas del mempool (y sus outpoints liberados) sin importar si
    /// el bloque termina de minarse o no — si el nodo necesita reintentar
    /// un template, vuelve a llamar a `next_batch` con lo que quede.
    pub fn next_batch(&mut self, max: usize) -> Vec<Transaction> {
        let mut batch = Vec::with_capacity(max.min(self.order.len()));
        for _ in 0..max {
            let Some(id) = self.order.pop_front() else {
                break;
            };
            let Some(tx) = self.txs.remove(&id) else {
                continue;
            };
            for input in &tx.inputs {
                self.claimed_by.remove(&input.prev_out);
            }
            batch.push(tx);
        }
        batch
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use znx_crypto::{Address, Keypair};
    use znx_state::MemoryStateStore;
    use znx_types::{OutPoint, TxIn, TxOut};

    const CHAIN_ID: &str = "znx-devnet-1";

    fn store_with(owner: Address, amount: u128) -> (MemoryStateStore, OutPoint) {
        let mut store = MemoryStateStore::new();
        let op = OutPoint { txid: znx_crypto::hash(&owner.0), vout: 0 };
        store.seed_utxo(op, TxOut { amount, pubkey_hash: owner });
        (store, op)
    }

    fn signed_spend(sender: &Keypair, spend: OutPoint, outputs: Vec<TxOut>) -> Transaction {
        let mut tx = Transaction {
            chain_id: CHAIN_ID.to_string(),
            inputs: vec![TxIn { prev_out: spend, public_key: sender.public_key().to_bytes(), signature: [0u8; 64] }],
            outputs,
        };
        let signature = sender.sign(&signing_bytes(&tx));
        tx.inputs[0].signature = signature.to_bytes();
        tx
    }

    #[test]
    fn accepts_a_valid_transaction() {
        let sender = Keypair::generate();
        let receiver = Keypair::generate();
        let (store, spend) = store_with(sender.address(), 1_000);
        let mut mempool = Mempool::new(CHAIN_ID);

        mempool
            .insert(&store, signed_spend(&sender, spend, vec![TxOut { amount: 900, pubkey_hash: receiver.address() }]))
            .expect("tx válida");
        assert_eq!(mempool.len(), 1);
    }

    #[test]
    fn rejects_tampered_signature() {
        let sender = Keypair::generate();
        let receiver = Keypair::generate();
        let (store, spend) = store_with(sender.address(), 1_000);
        let mut mempool = Mempool::new(CHAIN_ID);

        let mut tx = signed_spend(&sender, spend, vec![TxOut { amount: 900, pubkey_hash: receiver.address() }]);
        tx.outputs[0].amount = 999;

        assert_eq!(mempool.insert(&store, tx), Err(MempoolError::InvalidSignature));
    }

    #[test]
    fn rejects_wrong_chain_id() {
        let sender = Keypair::generate();
        let receiver = Keypair::generate();
        let (store, spend) = store_with(sender.address(), 1_000);
        let mut mempool = Mempool::new(CHAIN_ID);

        let mut tx = signed_spend(&sender, spend, vec![TxOut { amount: 900, pubkey_hash: receiver.address() }]);
        tx.chain_id = "znx-mainnet-1".to_string();

        assert_eq!(
            mempool.insert(&store, tx),
            Err(MempoolError::WrongChainId { expected: CHAIN_ID.to_string(), found: "znx-mainnet-1".to_string() })
        );
    }

    #[test]
    fn rejects_spending_unknown_outpoint() {
        let sender = Keypair::generate();
        let receiver = Keypair::generate();
        let store = MemoryStateStore::new();
        let mut mempool = Mempool::new(CHAIN_ID);
        let bogus = OutPoint { txid: [9u8; 32], vout: 0 };

        let err = mempool
            .insert(&store, signed_spend(&sender, bogus, vec![TxOut { amount: 100, pubkey_hash: receiver.address() }]))
            .unwrap_err();
        assert_eq!(err, MempoolError::UnknownOutpoint);
    }

    #[test]
    fn rejects_insufficient_inputs() {
        let sender = Keypair::generate();
        let receiver = Keypair::generate();
        let (store, spend) = store_with(sender.address(), 50);
        let mut mempool = Mempool::new(CHAIN_ID);

        let err = mempool
            .insert(&store, signed_spend(&sender, spend, vec![TxOut { amount: 100, pubkey_hash: receiver.address() }]))
            .unwrap_err();
        assert_eq!(err, MempoolError::InsufficientInputs { available: 50, required: 100 });
    }

    #[test]
    fn rejects_a_second_transaction_spending_the_same_pending_outpoint() {
        let sender = Keypair::generate();
        let receiver = Keypair::generate();
        let (store, spend) = store_with(sender.address(), 1_000);
        let mut mempool = Mempool::new(CHAIN_ID);

        mempool
            .insert(&store, signed_spend(&sender, spend, vec![TxOut { amount: 900, pubkey_hash: receiver.address() }]))
            .expect("primera tx entra");

        let err = mempool
            .insert(&store, signed_spend(&sender, spend, vec![TxOut { amount: 800, pubkey_hash: receiver.address() }]))
            .unwrap_err();
        assert_eq!(err, MempoolError::OutpointAlreadyClaimed);
    }

    #[test]
    fn rejects_inserting_the_exact_same_transaction_twice() {
        let sender = Keypair::generate();
        let receiver = Keypair::generate();
        let (store, spend) = store_with(sender.address(), 1_000);
        let mut mempool = Mempool::new(CHAIN_ID);

        let tx = signed_spend(&sender, spend, vec![TxOut { amount: 900, pubkey_hash: receiver.address() }]);
        mempool.insert(&store, tx.clone()).expect("primera vez entra");
        assert_eq!(mempool.insert(&store, tx), Err(MempoolError::AlreadyInMempool));
    }

    #[test]
    fn rejects_coinbase_shaped_transactions() {
        let miner = Keypair::generate();
        let store = MemoryStateStore::new();
        let mut mempool = Mempool::new(CHAIN_ID);

        let tx = Transaction::new_coinbase(CHAIN_ID.to_string(), 1, 0, vec![TxOut { amount: 50, pubkey_hash: miner.address() }]);
        assert_eq!(mempool.insert(&store, tx), Err(MempoolError::CoinbaseNotAllowed));
    }

    #[test]
    fn next_batch_drains_in_fifo_order_and_frees_claimed_outpoints() {
        let sender_a = Keypair::generate();
        let sender_b = Keypair::generate();
        let receiver = Keypair::generate();
        let (mut store, spend_a) = store_with(sender_a.address(), 1_000);
        let op_b = OutPoint { txid: znx_crypto::hash(&sender_b.address().0), vout: 0 };
        store.seed_utxo(op_b, TxOut { amount: 1_000, pubkey_hash: sender_b.address() });
        let mut mempool = Mempool::new(CHAIN_ID);

        let tx_a = signed_spend(&sender_a, spend_a, vec![TxOut { amount: 10, pubkey_hash: receiver.address() }]);
        let tx_b = signed_spend(&sender_b, op_b, vec![TxOut { amount: 10, pubkey_hash: receiver.address() }]);
        mempool.insert(&store, tx_a.clone()).unwrap();
        mempool.insert(&store, tx_b.clone()).unwrap();

        let batch = mempool.next_batch(10);
        assert_eq!(batch.len(), 2);
        assert_eq!(batch[0], tx_a);
        assert_eq!(batch[1], tx_b);
        assert!(mempool.is_empty());
        assert!(mempool.claimed_by.is_empty());
    }

    #[test]
    fn next_batch_respects_max_and_leaves_the_rest_pending() {
        let sender = Keypair::generate();
        let receiver = Keypair::generate();
        let (mut store, spend) = store_with(sender.address(), 1_000);
        let mut mempool = Mempool::new(CHAIN_ID);

        let tx1 = signed_spend(&sender, spend, vec![TxOut { amount: 10, pubkey_hash: receiver.address() }]);
        let id1 = txid(&tx1);
        let change = OutPoint { txid: id1, vout: 0 };
        store.seed_utxo(change, TxOut { amount: 10, pubkey_hash: receiver.address() });
        mempool.insert(&store, tx1).unwrap();

        let tx2 = signed_spend(&receiver, change, vec![TxOut { amount: 5, pubkey_hash: sender.address() }]);
        mempool.insert(&store, tx2).unwrap();

        let batch = mempool.next_batch(1);
        assert_eq!(batch.len(), 1);
        assert_eq!(mempool.len(), 1);
    }

    #[test]
    fn rejects_new_transactions_once_the_pool_is_full() {
        let sender = Keypair::generate();
        let receiver = Keypair::generate();
        let (mut store, spend_ok) = store_with(sender.address(), 1_000);
        // Tope chico a propósito (no `MAX_MEMPOOL_SIZE` real, sería lento
        // insertar 10.000 tx de verdad solo para este test) — el
        // comportamiento que importa (rechazar al llegar al tope) es el
        // mismo sea cual sea el número.
        let mut mempool = Mempool::with_max_size(CHAIN_ID, 1);

        mempool.insert(&store, signed_spend(&sender, spend_ok, vec![TxOut { amount: 900, pubkey_hash: receiver.address() }])).expect("entra, hay lugar");

        let spend_extra = OutPoint { txid: znx_crypto::hash(&receiver.address().0), vout: 0 };
        store.seed_utxo(spend_extra, TxOut { amount: 500, pubkey_hash: receiver.address() });
        let err = mempool.insert(&store, signed_spend(&receiver, spend_extra, vec![TxOut { amount: 100, pubkey_hash: sender.address() }])).unwrap_err();
        assert_eq!(err, MempoolError::Full);
    }
}
