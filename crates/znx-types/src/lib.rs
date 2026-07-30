//! znx-types — tipos de datos centrales del protocolo: UTXOs, transacciones
//! y bloques. Solo shapes de datos (más helpers triviales de construcción);
//! la (de)serialización canónica y el hashing determinístico viven en
//! znx-codec, y la validación de firmas/gasto vive en znx-state.
//!
//! Modelo UTXO (no de cuentas): una transacción no tiene `from`/`to`/`nonce`,
//! gasta salidas previas (`inputs`, referenciadas por `OutPoint`) y crea
//! salidas nuevas (`outputs`). PoW abierta en vez de PoA: `BlockHeader` no
//! tiene `proposer` (no hay identidad de validador) ni `state_root` (no se
//! commitea el UTXO set en el header — la seguridad es "replay completo
//! desde génesis", igual que Bitcoin), pero sí `target`/`pow_nonce` para la
//! prueba de trabajo.

use borsh::{BorshDeserialize, BorshSerialize};
pub use znx_crypto::Address;

/// Referencia a una salida previa: el índice `vout`-ésimo output de la
/// transacción `txid`. Es la "clave primaria" de un UTXO.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, BorshSerialize, BorshDeserialize)]
pub struct OutPoint {
    pub txid: [u8; 32],
    pub vout: u32,
}

/// `txid`/`vout` reservados para marcar el único input de una transacción
/// coinbase — no referencia ningún output real, así que no puede colisionar
/// con un `OutPoint` legítimo (un vout real nunca es `u32::MAX`... en la
/// práctica, pero además ningún txid real puede ser todo-ceros porque
/// `txid` es un hash blake3, y la probabilidad de que un hash real dé
/// exactamente `[0; 32]` es despreciable).
pub const COINBASE_PREV_TXID: [u8; 32] = [0u8; 32];
pub const COINBASE_PREV_VOUT: u32 = u32::MAX;

/// Salida no gastada: monto + a qué dirección paga. Sin lenguaje de script
/// (a diferencia de Bitcoin real) — la única condición de gasto es
/// "pay-to-pubkey-hash": quien gasta debe probar que conoce la llave
/// privada cuyo hash es `pubkey_hash`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct TxOut {
    pub amount: u128,
    pub pubkey_hash: Address,
}

/// Entrada de una transacción: qué salida previa gasta, y la prueba de que
/// quien construye la tx puede gastarla (pubkey + firma). Para el input de
/// una transacción coinbase (`prev_out` con los valores de
/// `COINBASE_PREV_TXID`/`COINBASE_PREV_VOUT`) los campos `public_key`/
/// `signature` NO son una firma real — se reutilizan como bytes libres
/// para codificar `height`+`extra_nonce` (igual que el scriptSig de
/// coinbase de Bitcoin, BIP34): eso evita que dos coinbases del mismo
/// minero en bloques distintos generen el mismo `txid`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct TxIn {
    pub prev_out: OutPoint,
    pub public_key: [u8; 32],
    pub signature: [u8; 64],
}

impl TxIn {
    /// Construye el input sintético de una transacción coinbase, con
    /// `height`+`extra_nonce` codificados en el campo `signature` (16 de
    /// sus 64 bytes; el resto queda en cero) para garantizar unicidad de
    /// `txid` entre bloques.
    pub fn coinbase(height: u64, extra_nonce: u64) -> Self {
        let mut signature = [0u8; 64];
        signature[0..8].copy_from_slice(&height.to_le_bytes());
        signature[8..16].copy_from_slice(&extra_nonce.to_le_bytes());
        TxIn {
            prev_out: OutPoint { txid: COINBASE_PREV_TXID, vout: COINBASE_PREV_VOUT },
            public_key: [0u8; 32],
            signature,
        }
    }

    pub fn is_coinbase_marker(&self) -> bool {
        self.prev_out.txid == COINBASE_PREV_TXID && self.prev_out.vout == COINBASE_PREV_VOUT
    }
}

/// Transacción: gasta `inputs` (salidas previas) y crea `outputs` nuevos.
/// `chain_id` es replay protection entre redes, igual que antes. La firma
/// ya no es "sobre el body completo" de un único remitente: todos los
/// inputs de una tx comparten un mismo preimage que cubre
/// `(chain_id, [(prev_out, public_key) por input], outputs)` sin las
/// firmas mismas (ver znx-codec::signing_bytes) — una simplificación
/// deliberada respecto al sighash-por-input de Bitcoin real, para no tener
/// que evaluar un lenguaje de script.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct Transaction {
    pub chain_id: String,
    pub inputs: Vec<TxIn>,
    pub outputs: Vec<TxOut>,
}

impl Transaction {
    /// Una transacción coinbase es la única forma legítima de crear monedas
    /// nuevas (recompensa de bloque + fees) — se reconoce estructuralmente:
    /// exactamente un input, y ese input es el marcador sintético de
    /// coinbase (no referencia ningún UTXO real).
    pub fn is_coinbase(&self) -> bool {
        matches!(self.inputs.as_slice(), [only] if only.is_coinbase_marker())
    }

    pub fn new_coinbase(chain_id: String, height: u64, extra_nonce: u64, outputs: Vec<TxOut>) -> Self {
        Transaction { chain_id, inputs: vec![TxIn::coinbase(height, extra_nonce)], outputs }
    }
}

/// Encabezado de bloque. Sin `proposer` (no hay identidad de validador en
/// PoW abierta) ni `state_root` (no se commitea el UTXO set acá — igual que
/// Bitcoin, la seguridad es "cada nodo repite la validación completa desde
/// génesis", no una raíz de estado en el header). `target` guarda el
/// umbral de dificultad completo de 32 bytes (no el `nBits` compacto de
/// Bitcoin — mismo efecto, mucho más simple de implementar bien). Un hash
/// de este header es válido para extender la cadena cuando, interpretado
/// como entero de 256 bits, es <= `target` (ver znx-codec::meets_target).
#[derive(Debug, Clone, Copy, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct BlockHeader {
    pub height: u64,
    pub parent_hash: [u8; 32],
    /// Root de Merkle (ver znx-codec::tx_root) de las transacciones del
    /// bloque, incluida la coinbase.
    pub tx_root: [u8; 32],
    /// Segundos desde epoch UNIX. La validación de que sea razonable
    /// respecto al bloque anterior vive en znx-consensus, no acá — este
    /// tipo solo describe la forma del dato.
    pub timestamp: u64,
    pub target: [u8; 32],
    pub pow_nonce: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct Block {
    pub header: BlockHeader,
    pub transactions: Vec<Transaction>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn coinbase_input_round_trips_height_and_extra_nonce() {
        let input = TxIn::coinbase(42, 7);
        assert!(input.is_coinbase_marker());
        assert_eq!(&input.signature[0..8], &42u64.to_le_bytes());
        assert_eq!(&input.signature[8..16], &7u64.to_le_bytes());
    }

    #[test]
    fn transaction_is_coinbase_only_for_the_synthetic_input() {
        let coinbase = Transaction::new_coinbase("znx-devnet-1".to_string(), 1, 0, vec![]);
        assert!(coinbase.is_coinbase());

        let regular = Transaction {
            chain_id: "znx-devnet-1".to_string(),
            inputs: vec![TxIn {
                prev_out: OutPoint { txid: [9u8; 32], vout: 0 },
                public_key: [0u8; 32],
                signature: [0u8; 64],
            }],
            outputs: vec![],
        };
        assert!(!regular.is_coinbase());
    }
}
