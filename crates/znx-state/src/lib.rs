//! znx-state — state transition function (STF): valida y aplica
//! transacciones contra un conjunto de salidas no gastadas (UTXO set).
//! Opera contra el trait `StateStore`, agnóstico de dónde vive el estado —
//! `MemoryStateStore` (acá adentro) sirve para tests y para znx-testkit; un
//! backend real sobre RocksDB lo provee znx-storage, implementando el
//! mismo trait sin que este crate tenga que cambiar.
//!
//! Este crate solo sabe "dado un bloque ya aceptado, cómo cambia el UTXO
//! set" — decidir SI un bloque es válido para extender la cadena (prueba
//! de trabajo, dificultad esperada, fork-choice) es responsabilidad de
//! znx-consensus, no de acá. Por eso `apply_coinbase` recibe
//! `expected_total` como parámetro en vez de calcular el subsidio de
//! halving él mismo — ese cálculo vive en znx-consensus.
//!
//! No hay cuenta de tesoro ni fee "enviado a algún lado": en el modelo
//! UTXO el fee es implícito (`sum(inputs) - sum(outputs)` de las tx
//! regulares del bloque) y queda disponible para que el minero lo
//! reclame en su propia transacción coinbase, junto con el subsidio.

use std::collections::{HashMap, HashSet};
use std::convert::Infallible;

use thiserror::Error;
use znx_codec::{signing_bytes, txid};
use znx_crypto::{address_from_public_key_bytes, verify_raw, CryptoError};
use znx_types::{OutPoint, Transaction, TxOut};

#[derive(Debug, Error, PartialEq, Eq)]
pub enum StateError {
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
    #[error("un mismo outpoint aparece más de una vez como input de la misma transacción")]
    DuplicateInput,
    #[error("el outpoint referenciado no existe (ya gastado o nunca existió)")]
    UnknownOutpoint,
    #[error("los inputs no alcanzan para cubrir los outputs: disponible {available}, se necesitan {required}")]
    InsufficientInputs { available: u128, required: u128 },
    #[error("se esperaba una transacción coinbase y no lo es")]
    NotCoinbase,
    #[error("una transacción regular no puede tener la forma de una coinbase")]
    UnexpectedCoinbase,
    #[error("altura codificada en el input de coinbase no coincide: se esperaba {expected}, se encontró {found}")]
    WrongCoinbaseHeight { expected: u64, found: u64 },
    #[error("la coinbase reclama más de lo permitido: reclama {claimed}, el máximo permitido es {allowed}")]
    CoinbaseOverclaims { claimed: u128, allowed: u128 },
    #[error("desbordamiento aritmético aplicando la transacción")]
    Overflow,
    #[error("error del store subyacente al confirmar los cambios: {0}")]
    Store(String),
}

impl From<CryptoError> for StateError {
    fn from(_: CryptoError) -> Self {
        // Cualquier error de znx-crypto en esta ruta (bytes de pubkey con
        // largo inválido, etc.) es indistinguible en la práctica de "esta
        // transacción viene mal formada" — no hace falta distinguir el
        // motivo puntual acá, con InvalidPublicKey alcanza.
        StateError::InvalidPublicKey
    }
}

/// Abstracción sobre "dónde vive el UTXO set" — implementada acá con un
/// `HashMap` en memoria, y más adelante también por znx-storage (RocksDB).
/// Un error de LECTURA inesperado (I/O real, corrupción de disco) no es
/// algo de lo que este trait pretenda recuperarse — panic, no `Result`.
///
/// `apply_changes` sí es falible (I/O real de escritura) y **atómica**:
/// todos los cambios entran o ninguno — `apply_transaction`/
/// `apply_coinbase` arman el lote completo en memoria antes de llamar acá,
/// así un fallo de escritura a mitad de una transacción nunca deja el
/// estado corrupto a medio aplicar (outpoint borrado sin el nuevo output
/// correspondiente, por ejemplo).
pub trait StateStore {
    type Error: std::fmt::Display;

    fn get_utxo(&self, outpoint: &OutPoint) -> Option<TxOut>;
    fn apply_changes(&mut self, spent: Vec<OutPoint>, created: Vec<(OutPoint, TxOut)>) -> Result<(), Self::Error>;
}

#[derive(Debug, Default)]
pub struct MemoryStateStore {
    utxos: HashMap<OutPoint, TxOut>,
}

impl MemoryStateStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Setea un UTXO directo, sin pasar por `apply_changes` — atajo de
    /// conveniencia para armar estado inicial en tests (de este crate y de
    /// cualquier otro que dependa de `MemoryStateStore`, ej. znx-mempool,
    /// znx-testkit). No es parte del trait `StateStore` a propósito: la
    /// vía "real" de mutar estado siempre es `apply_changes` (atómica).
    pub fn seed_utxo(&mut self, outpoint: OutPoint, output: TxOut) {
        self.utxos.insert(outpoint, output);
    }
}

impl StateStore for MemoryStateStore {
    type Error = Infallible;

    fn get_utxo(&self, outpoint: &OutPoint) -> Option<TxOut> {
        self.utxos.get(outpoint).copied()
    }

    fn apply_changes(&mut self, spent: Vec<OutPoint>, created: Vec<(OutPoint, TxOut)>) -> Result<(), Self::Error> {
        // Un HashMap en memoria dentro de un solo proceso no tiene forma
        // real de fallar a mitad de camino (no hay I/O) — la atomicidad acá
        // es gratis, el punto de esta API es el contrato para backends
        // reales (RocksDB con WriteBatch).
        for outpoint in spent {
            self.utxos.remove(&outpoint);
        }
        for (outpoint, output) in created {
            self.utxos.insert(outpoint, output);
        }
        Ok(())
    }
}

/// Resultado de aplicar una transacción regular al UTXO set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppliedTransaction {
    /// `sum(inputs) - sum(outputs)`.
    pub fee: u128,
    /// Los `(outpoint, output)` que esta transacción gastó, con su valor
    /// ORIGINAL (antes de borrarlos del UTXO set). Znx-node los acumula
    /// como "datos para deshacer" (undo data): si más adelante hace falta
    /// un reorg que descarte el bloque donde se incluyó esta tx, son
    /// exactamente los outputs que hay que recrear para volver al estado
    /// de antes — sin guardarlos acá, "deshacer" un gasto no sabría qué
    /// UTXO reconstruir (ya se borró).
    pub consumed: Vec<(OutPoint, TxOut)>,
}

/// Aplica una transacción regular (no coinbase) al UTXO set. Verifica, en
/// este orden (fail-fast, cada paso asume que el anterior pasó):
/// 1. no tiene la forma de una coinbase, y tiene al menos un input,
/// 2. el `chain_id` coincide con el de esta red (replay protection entre
///    devnet/testnet/mainnet),
/// 3. ningún outpoint se repite entre los inputs de la misma tx (evita
///    "gastar el mismo UTXO dos veces dentro de una sola transacción"),
/// 4. cada outpoint referenciado existe en el UTXO set (si no, ya fue
///    gastado por otra tx, o nunca existió — ambos casos son el
///    equivalente UTXO de un doble gasto),
/// 5. la llave pública de cada input deriva la dirección dueña del UTXO
///    que ese input referencia, y la firma verifica contra el preimage
///    compartido de la tx (ver znx-codec::signing_bytes),
/// 6. la suma de los inputs alcanza para cubrir la suma de los outputs
///    (la diferencia es el fee).
///
/// Efectos (en un único `apply_changes` atómico): se borran los outpoints
/// gastados y se crean los nuevos, uno por output, en `(txid(tx), vout)`.
pub fn apply_transaction<S: StateStore>(store: &mut S, tx: &Transaction, expected_chain_id: &str) -> Result<AppliedTransaction, StateError> {
    if tx.is_coinbase() {
        return Err(StateError::UnexpectedCoinbase);
    }
    if tx.inputs.is_empty() {
        return Err(StateError::NoInputs);
    }
    if tx.chain_id != expected_chain_id {
        return Err(StateError::WrongChainId { expected: expected_chain_id.to_string(), found: tx.chain_id.clone() });
    }

    let mut seen_outpoints = HashSet::with_capacity(tx.inputs.len());
    for input in &tx.inputs {
        if !seen_outpoints.insert(input.prev_out) {
            return Err(StateError::DuplicateInput);
        }
    }

    let message = signing_bytes(tx);
    let mut total_in: u128 = 0;
    let mut spent = Vec::with_capacity(tx.inputs.len());
    let mut consumed = Vec::with_capacity(tx.inputs.len());
    for input in &tx.inputs {
        let utxo = store.get_utxo(&input.prev_out).ok_or(StateError::UnknownOutpoint)?;

        let derived_owner = address_from_public_key_bytes(&input.public_key)?;
        if derived_owner != utxo.pubkey_hash {
            return Err(StateError::AddressMismatch);
        }
        verify_raw(&input.public_key, &message, &input.signature).map_err(|_| StateError::InvalidSignature)?;

        total_in = total_in.checked_add(utxo.amount).ok_or(StateError::Overflow)?;
        spent.push(input.prev_out);
        consumed.push((input.prev_out, utxo));
    }

    let total_out = sum_outputs(&tx.outputs)?;
    if total_out > total_in {
        return Err(StateError::InsufficientInputs { available: total_in, required: total_out });
    }
    let fee = total_in - total_out;

    let created = new_outputs(tx);
    store
        .apply_changes(spent, created)
        .map_err(|e| StateError::Store(e.to_string()))?;

    Ok(AppliedTransaction { fee, consumed })
}

/// Aplica la transacción coinbase de un bloque — la única forma legítima
/// de crear UTXOs nuevos sin gastar ninguno existente. `height` es la
/// altura del bloque que se está construyendo/validando (znx-consensus la
/// conoce, se la pasa acá); se chequea contra la altura codificada en el
/// input sintético de la tx (ver `TxIn::coinbase`) para que un minero no
/// pueda reusar/rebobinar la altura y así, indirectamente, el subsidio.
/// `expected_total` es `subsidio_del_halving_en(height) + fees_recolectados
/// de las demás tx del bloque` — calculado por el caller (znx-consensus),
/// no acá: este crate no conoce el calendario de halving.
pub fn apply_coinbase<S: StateStore>(store: &mut S, tx: &Transaction, height: u64, expected_total: u128) -> Result<(), StateError> {
    if !tx.is_coinbase() {
        return Err(StateError::NotCoinbase);
    }

    let claimed_height = u64::from_le_bytes(
        tx.inputs[0].signature[0..8]
            .try_into()
            .expect("el slice tiene exactamente 8 bytes"),
    );
    if claimed_height != height {
        return Err(StateError::WrongCoinbaseHeight { expected: height, found: claimed_height });
    }

    let total_out = sum_outputs(&tx.outputs)?;
    if total_out > expected_total {
        return Err(StateError::CoinbaseOverclaims { claimed: total_out, allowed: expected_total });
    }

    let created = new_outputs(tx);
    store
        .apply_changes(vec![], created)
        .map_err(|e| StateError::Store(e.to_string()))
}

fn sum_outputs(outputs: &[TxOut]) -> Result<u128, StateError> {
    outputs
        .iter()
        .try_fold(0u128, |acc, out| acc.checked_add(out.amount))
        .ok_or(StateError::Overflow)
}

fn new_outputs(tx: &Transaction) -> Vec<(OutPoint, TxOut)> {
    let id = txid(tx);
    tx.outputs
        .iter()
        .enumerate()
        .map(|(vout, out)| (OutPoint { txid: id, vout: vout as u32 }, *out))
        .collect()
}

/// `StateStore` de staging sobre una base de solo lectura: acumula un
/// diff (`spent`/`created`) en memoria sin tocar la base hasta que el
/// caller decide extraerlo con `into_diff`. Sirve para validar un bloque
/// candidato completo (todas sus tx, coinbase incluida) contra un `snapshot`
/// consistente ANTES de comprometer nada al storage real — si alguna tx a
/// mitad del bloque resulta inválida, no queda ningún cambio a medio
/// aplicar (a diferencia de aplicar tx por tx directo contra el storage
/// real, donde un rechazo a mitad de camino dejaría el UTXO set con las
/// primeras tx del bloque ya aplicadas y el resto no).
pub struct OverlayStore<'a, S: StateStore> {
    base: &'a S,
    spent: HashSet<OutPoint>,
    created: HashMap<OutPoint, TxOut>,
}

impl<'a, S: StateStore> OverlayStore<'a, S> {
    pub fn new(base: &'a S) -> Self {
        OverlayStore { base, spent: HashSet::new(), created: HashMap::new() }
    }

    /// Extrae el diff acumulado — para comprometerlo de verdad contra el
    /// storage real en un único `apply_changes`/`commit_block` atómico una
    /// vez que todo el bloque validó.
    pub fn into_diff(self) -> (Vec<OutPoint>, Vec<(OutPoint, TxOut)>) {
        (self.spent.into_iter().collect(), self.created.into_iter().collect())
    }
}

impl<'a, S: StateStore> StateStore for OverlayStore<'a, S> {
    type Error = S::Error;

    fn get_utxo(&self, outpoint: &OutPoint) -> Option<TxOut> {
        if self.spent.contains(outpoint) {
            return None;
        }
        if let Some(output) = self.created.get(outpoint) {
            return Some(*output);
        }
        self.base.get_utxo(outpoint)
    }

    fn apply_changes(&mut self, spent: Vec<OutPoint>, created: Vec<(OutPoint, TxOut)>) -> Result<(), Self::Error> {
        for outpoint in spent {
            self.spent.insert(outpoint);
            self.created.remove(&outpoint);
        }
        for (outpoint, output) in created {
            self.created.insert(outpoint, output);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use znx_crypto::{Address, Keypair};
    use znx_types::TxIn;

    const CHAIN_ID: &str = "znx-devnet-1";

    fn seed_spendable(store: &mut MemoryStateStore, owner: Address, amount: u128) -> OutPoint {
        let outpoint = OutPoint { txid: znx_crypto::hash(&owner.0), vout: 0 };
        store.seed_utxo(outpoint, TxOut { amount, pubkey_hash: owner });
        outpoint
    }

    fn signed_transfer(store: &MemoryStateStore, sender: &Keypair, spend: OutPoint, outputs: Vec<TxOut>) -> Transaction {
        let mut tx = Transaction {
            chain_id: CHAIN_ID.to_string(),
            inputs: vec![TxIn { prev_out: spend, public_key: sender.public_key().to_bytes(), signature: [0u8; 64] }],
            outputs,
        };
        let _ = store; // el store solo hace falta para inspeccionar en otros tests; acá no.
        let message = signing_bytes(&tx);
        let signature = sender.sign(&message);
        tx.inputs[0].signature = signature.to_bytes();
        tx
    }

    #[test]
    fn transfer_spends_input_and_creates_outputs() {
        let mut store = MemoryStateStore::new();
        let sender = Keypair::generate();
        let receiver = Keypair::generate();
        let spend = seed_spendable(&mut store, sender.address(), 1_000);

        let tx = signed_transfer(
            &store,
            &sender,
            spend,
            vec![TxOut { amount: 700, pubkey_hash: receiver.address() }, TxOut { amount: 290, pubkey_hash: sender.address() }],
        );
        let applied = apply_transaction(&mut store, &tx, CHAIN_ID).expect("transferencia válida");

        assert_eq!(applied.fee, 10);
        assert_eq!(applied.consumed, vec![(spend, TxOut { amount: 1_000, pubkey_hash: sender.address() })]);
        assert_eq!(store.get_utxo(&spend), None);
        let id = txid(&tx);
        assert_eq!(store.get_utxo(&OutPoint { txid: id, vout: 0 }), Some(TxOut { amount: 700, pubkey_hash: receiver.address() }));
        assert_eq!(store.get_utxo(&OutPoint { txid: id, vout: 1 }), Some(TxOut { amount: 290, pubkey_hash: sender.address() }));
    }

    #[test]
    fn rejects_spending_unknown_outpoint() {
        let mut store = MemoryStateStore::new();
        let sender = Keypair::generate();
        let receiver = Keypair::generate();
        let bogus = OutPoint { txid: [3u8; 32], vout: 0 };

        let tx = signed_transfer(&store, &sender, bogus, vec![TxOut { amount: 100, pubkey_hash: receiver.address() }]);
        let err = apply_transaction(&mut store, &tx, CHAIN_ID).unwrap_err();
        assert_eq!(err, StateError::UnknownOutpoint);
    }

    #[test]
    fn rejects_insufficient_inputs() {
        let mut store = MemoryStateStore::new();
        let sender = Keypair::generate();
        let receiver = Keypair::generate();
        let spend = seed_spendable(&mut store, sender.address(), 50);

        let tx = signed_transfer(&store, &sender, spend, vec![TxOut { amount: 100, pubkey_hash: receiver.address() }]);
        let err = apply_transaction(&mut store, &tx, CHAIN_ID).unwrap_err();
        assert_eq!(err, StateError::InsufficientInputs { available: 50, required: 100 });
    }

    #[test]
    fn rejects_wrong_chain_id() {
        let mut store = MemoryStateStore::new();
        let sender = Keypair::generate();
        let receiver = Keypair::generate();
        let spend = seed_spendable(&mut store, sender.address(), 1_000);

        let mut tx = signed_transfer(&store, &sender, spend, vec![TxOut { amount: 100, pubkey_hash: receiver.address() }]);
        tx.chain_id = "znx-mainnet-1".to_string();

        let err = apply_transaction(&mut store, &tx, CHAIN_ID).unwrap_err();
        assert_eq!(err, StateError::WrongChainId { expected: CHAIN_ID.to_string(), found: "znx-mainnet-1".to_string() });
    }

    #[test]
    fn rejects_tampered_output_after_signing() {
        let mut store = MemoryStateStore::new();
        let sender = Keypair::generate();
        let receiver = Keypair::generate();
        let spend = seed_spendable(&mut store, sender.address(), 1_000);

        let mut tx = signed_transfer(&store, &sender, spend, vec![TxOut { amount: 100, pubkey_hash: receiver.address() }]);
        tx.outputs[0].amount = 999; // firma sigue siendo la del monto original

        let err = apply_transaction(&mut store, &tx, CHAIN_ID).unwrap_err();
        assert_eq!(err, StateError::InvalidSignature);
    }

    #[test]
    fn rejects_signature_from_a_key_that_does_not_own_the_utxo() {
        let mut store = MemoryStateStore::new();
        let real_owner = Keypair::generate();
        let attacker = Keypair::generate();
        let receiver = Keypair::generate();
        let spend = seed_spendable(&mut store, real_owner.address(), 1_000);

        // El atacante firma con su propia llave un input que gasta un UTXO
        // que en realidad pertenece a `real_owner`.
        let mut tx = Transaction {
            chain_id: CHAIN_ID.to_string(),
            inputs: vec![TxIn { prev_out: spend, public_key: attacker.public_key().to_bytes(), signature: [0u8; 64] }],
            outputs: vec![TxOut { amount: 100, pubkey_hash: receiver.address() }],
        };
        let signature = attacker.sign(&signing_bytes(&tx));
        tx.inputs[0].signature = signature.to_bytes();

        let err = apply_transaction(&mut store, &tx, CHAIN_ID).unwrap_err();
        assert_eq!(err, StateError::AddressMismatch);
    }

    #[test]
    fn rejects_duplicate_input_within_same_transaction() {
        let mut store = MemoryStateStore::new();
        let sender = Keypair::generate();
        let receiver = Keypair::generate();
        let spend = seed_spendable(&mut store, sender.address(), 1_000);

        let mut tx = Transaction {
            chain_id: CHAIN_ID.to_string(),
            inputs: vec![
                TxIn { prev_out: spend, public_key: sender.public_key().to_bytes(), signature: [0u8; 64] },
                TxIn { prev_out: spend, public_key: sender.public_key().to_bytes(), signature: [0u8; 64] },
            ],
            outputs: vec![TxOut { amount: 100, pubkey_hash: receiver.address() }],
        };
        let signature = sender.sign(&signing_bytes(&tx));
        tx.inputs[0].signature = signature.to_bytes();
        tx.inputs[1].signature = signature.to_bytes();

        let err = apply_transaction(&mut store, &tx, CHAIN_ID).unwrap_err();
        assert_eq!(err, StateError::DuplicateInput);
    }

    #[test]
    fn coinbase_creates_outputs_up_to_the_allowed_total() {
        let mut store = MemoryStateStore::new();
        let miner = Keypair::generate();

        let tx = Transaction::new_coinbase(CHAIN_ID.to_string(), 1, 0, vec![TxOut { amount: 50, pubkey_hash: miner.address() }]);
        apply_coinbase(&mut store, &tx, 1, 50).expect("coinbase dentro del límite");

        let id = txid(&tx);
        assert_eq!(store.get_utxo(&OutPoint { txid: id, vout: 0 }), Some(TxOut { amount: 50, pubkey_hash: miner.address() }));
    }

    #[test]
    fn coinbase_rejects_claiming_more_than_allowed() {
        let mut store = MemoryStateStore::new();
        let miner = Keypair::generate();

        let tx = Transaction::new_coinbase(CHAIN_ID.to_string(), 1, 0, vec![TxOut { amount: 51, pubkey_hash: miner.address() }]);
        let err = apply_coinbase(&mut store, &tx, 1, 50).unwrap_err();
        assert_eq!(err, StateError::CoinbaseOverclaims { claimed: 51, allowed: 50 });
    }

    #[test]
    fn coinbase_rejects_mismatched_height() {
        let mut store = MemoryStateStore::new();
        let miner = Keypair::generate();

        let tx = Transaction::new_coinbase(CHAIN_ID.to_string(), 1, 0, vec![TxOut { amount: 50, pubkey_hash: miner.address() }]);
        let err = apply_coinbase(&mut store, &tx, 2, 50).unwrap_err();
        assert_eq!(err, StateError::WrongCoinbaseHeight { expected: 2, found: 1 });
    }

    #[test]
    fn apply_transaction_rejects_a_transaction_shaped_like_a_coinbase() {
        let mut store = MemoryStateStore::new();
        let miner = Keypair::generate();
        let tx = Transaction::new_coinbase(CHAIN_ID.to_string(), 1, 0, vec![TxOut { amount: 50, pubkey_hash: miner.address() }]);

        let err = apply_transaction(&mut store, &tx, CHAIN_ID).unwrap_err();
        assert_eq!(err, StateError::UnexpectedCoinbase);
    }

    #[test]
    fn apply_coinbase_rejects_a_regular_transaction() {
        let mut store = MemoryStateStore::new();
        let sender = Keypair::generate();
        let receiver = Keypair::generate();
        let spend = seed_spendable(&mut store, sender.address(), 1_000);
        let tx = signed_transfer(&store, &sender, spend, vec![TxOut { amount: 100, pubkey_hash: receiver.address() }]);

        let err = apply_coinbase(&mut store, &tx, 1, 100).unwrap_err();
        assert_eq!(err, StateError::NotCoinbase);
    }

    #[test]
    fn overlay_store_does_not_mutate_the_base_until_diff_is_extracted() {
        let mut base = MemoryStateStore::new();
        let sender = Keypair::generate();
        let receiver = Keypair::generate();
        let spend = seed_spendable(&mut base, sender.address(), 1_000);

        let mut overlay = OverlayStore::new(&base);
        let tx = signed_transfer(&base, &sender, spend, vec![TxOut { amount: 900, pubkey_hash: receiver.address() }]);
        apply_transaction(&mut overlay, &tx, CHAIN_ID).expect("válida contra el overlay");

        // La base no cambió — el overlay ve el UTXO gastado y el nuevo
        // creado, pero `base` sigue intacta hasta que alguien extraiga el
        // diff y lo aplique de verdad.
        assert_eq!(overlay.get_utxo(&spend), None);
        assert_eq!(base.get_utxo(&spend), Some(TxOut { amount: 1_000, pubkey_hash: sender.address() }));

        let (spent, created) = overlay.into_diff();
        base.apply_changes(spent, created).expect("aplica sin error en MemoryStateStore");
        assert_eq!(base.get_utxo(&spend), None);
    }
}
