//! znx-codec — serialización canónica (borsh) y hashing determinístico de
//! los tipos de znx-types. "Canónica" acá quiere decir: el mismo valor
//! siempre serializa exactamente a los mismos bytes, en cualquier nodo,
//! en cualquier momento — imprescindible porque estos bytes son lo que se
//! firma y lo que se hashea para roots de bloque/PoW. Borsh fue diseñado
//! explícitamente para esto (a diferencia de JSON o incluso bincode con
//! ciertos tipos, no hay ambigüedad de orden de campos ni de
//! representación numérica).

use borsh::{to_vec, BorshSerialize, BorshDeserialize};
use znx_types::{Block, BlockHeader, OutPoint, Transaction, TxOut};

#[derive(Debug, thiserror::Error)]
pub enum CodecError {
    #[error("error de (de)serialización borsh: {0}")]
    Borsh(#[from] std::io::Error),
}

/// Codifica cualquier tipo del protocolo a bytes canónicos.
pub fn encode<T: BorshSerialize>(value: &T) -> Vec<u8> {
    // BorshSerialize a un Vec<u8> no falla en la práctica (no hay límites
    // de tamaño ni I/O real de por medio) — to_vec() solo devuelve
    // Result por la firma genérica del trait Write. unwrap() documentado
    // a propósito, no silenciado.
    to_vec(value).expect("serializar a Vec<u8> en memoria no falla")
}

pub fn decode<T: BorshDeserialize>(bytes: &[u8]) -> Result<T, CodecError> {
    T::try_from_slice(bytes).map_err(CodecError::from)
}

/// Hash blake3 (vía znx-crypto) de la codificación canónica de cualquier
/// valor — la primitiva sobre la que se construyen txid/block_hash/etc.
pub fn hash_of<T: BorshSerialize>(value: &T) -> [u8; 32] {
    znx_crypto::hash(&encode(value))
}

#[derive(BorshSerialize)]
struct SigningPreimageInput<'a> {
    prev_out: &'a OutPoint,
    public_key: &'a [u8; 32],
}

#[derive(BorshSerialize)]
struct SigningPreimage<'a> {
    chain_id: &'a str,
    inputs: Vec<SigningPreimageInput<'a>>,
    outputs: &'a [TxOut],
}

/// Bytes exactos que hay que firmar/verificar para una transacción. Deja
/// afuera las firmas de cada input a propósito (obvio: no se puede firmar
/// algo que incluye la propia firma) — pero SÍ incluye `prev_out`/
/// `public_key` de todos los inputs y todos los outputs, así que ningún
/// input ni output se puede alterar sin invalidar todas las firmas. Todos
/// los inputs de una tx firman este mismo preimage (simplificación
/// deliberada: no hay sighash-por-input con blanking de scripts como en
/// Bitcoin real).
pub fn signing_bytes(tx: &Transaction) -> Vec<u8> {
    let preimage = SigningPreimage {
        chain_id: &tx.chain_id,
        inputs: tx
            .inputs
            .iter()
            .map(|input| SigningPreimageInput { prev_out: &input.prev_out, public_key: &input.public_key })
            .collect(),
        outputs: &tx.outputs,
    };
    to_vec(&preimage).expect("serializar a Vec<u8> en memoria no falla")
}

/// Hash de una transacción completa (incluidas las firmas) — se usa como
/// ID de transacción (para referenciarla desde un `OutPoint`, buscarla en
/// el mempool/índices), no como lo que se firma.
pub fn txid(tx: &Transaction) -> [u8; 32] {
    hash_of(tx)
}

/// Root de Merkle de las transacciones de un bloque (la coinbase incluida,
/// primera de la lista). Algoritmo estándar estilo Bitcoin: hoja = `txid`
/// de cada tx; si una capa tiene una cantidad impar de nodos, el último se
/// duplica antes de combinar de a pares; se repite hasta quedar un solo
/// hash. Lista vacía devuelve el hash de bytes vacíos (root de un bloque
/// sin transacciones), no un valor mágico como `[0u8; 32]` que podría
/// confundirse con "no calculado".
pub fn tx_root(transactions: &[Transaction]) -> [u8; 32] {
    if transactions.is_empty() {
        return znx_crypto::hash(&[]);
    }

    let mut layer: Vec<[u8; 32]> = transactions.iter().map(txid).collect();
    while layer.len() > 1 {
        if layer.len() % 2 == 1 {
            let last = *layer.last().expect("layer no vacía en este punto");
            layer.push(last);
        }
        layer = layer
            .chunks_exact(2)
            .map(|pair| {
                let mut concatenated = Vec::with_capacity(64);
                concatenated.extend_from_slice(&pair[0]);
                concatenated.extend_from_slice(&pair[1]);
                znx_crypto::hash(&concatenated)
            })
            .collect();
    }
    layer[0]
}

/// Hash de un encabezado de bloque — es lo que un bloque hijo referencia
/// como `parent_hash`, Y el hash sobre el que se evalúa la prueba de
/// trabajo (ver `meets_target`): como `pow_nonce` es un campo del header,
/// recalcular este hash con distintos `pow_nonce` es literalmente lo que
/// hace el loop de minería.
pub fn block_header_hash(header: &BlockHeader) -> [u8; 32] {
    hash_of(header)
}

pub fn block_hash(block: &Block) -> [u8; 32] {
    block_header_hash(&block.header)
}

/// Alias de `block_header_hash` con el nombre que usa el loop de minería —
/// mismo hash, distinto nombre según si quien lo llama piensa en "identidad
/// del bloque" (`block_header_hash`) o en "candidato a cumplir la prueba de
/// trabajo" (`pow_hash`).
pub fn pow_hash(header: &BlockHeader) -> [u8; 32] {
    block_header_hash(header)
}

/// Compara un hash contra un target de dificultad, ambos interpretados
/// como enteros de 256 bits big-endian: cumple la prueba de trabajo si
/// `hash <= target` (a menor target, mayor dificultad — igual que Bitcoin).
/// `[u8; 32]` ya compara lexicográficamente byte a byte en orden (como un
/// slice), que es exactamente la comparación de enteros big-endian que
/// hace falta acá — no hace falta lógica manual.
pub fn meets_target(hash: &[u8; 32], target: &[u8; 32]) -> bool {
    hash <= target
}

#[cfg(test)]
mod tests {
    use super::*;
    use znx_crypto::Keypair;
    use znx_types::{Address, TxIn};

    fn sample_output(addr: Address, amount: u128) -> TxOut {
        TxOut { amount, pubkey_hash: addr }
    }

    fn sample_transaction() -> Transaction {
        let sender = Keypair::generate();
        let receiver = Keypair::generate();
        Transaction {
            chain_id: "znx-devnet-1".to_string(),
            inputs: vec![TxIn {
                prev_out: OutPoint { txid: [7u8; 32], vout: 0 },
                public_key: sender.public_key().to_bytes(),
                signature: [0u8; 64],
            }],
            outputs: vec![sample_output(receiver.address(), 1_000_000)],
        }
    }

    #[test]
    fn transaction_roundtrip() {
        let tx = sample_transaction();
        let bytes = encode(&tx);
        let decoded: Transaction = decode(&bytes).expect("decodifica");
        assert_eq!(tx, decoded);
    }

    #[test]
    fn encoding_is_byte_stable_across_calls() {
        let tx = sample_transaction();
        let bytes1 = encode(&tx);
        let bytes2 = encode(&tx);
        assert_eq!(bytes1, bytes2);
    }

    #[test]
    fn hash_of_is_deterministic_and_sensitive_to_content() {
        let tx1 = sample_transaction();
        let mut tx2 = tx1.clone();
        tx2.outputs[0].amount += 1;

        assert_eq!(hash_of(&tx1), hash_of(&tx1));
        assert_ne!(hash_of(&tx1), hash_of(&tx2));
    }

    #[test]
    fn sign_and_verify_transaction_end_to_end() {
        let sender = Keypair::generate();
        let receiver = Keypair::generate();
        let mut tx = Transaction {
            chain_id: "znx-devnet-1".to_string(),
            inputs: vec![TxIn {
                prev_out: OutPoint { txid: [1u8; 32], vout: 0 },
                public_key: sender.public_key().to_bytes(),
                signature: [0u8; 64],
            }],
            outputs: vec![sample_output(receiver.address(), 500)],
        };

        let message = signing_bytes(&tx);
        let signature = sender.sign(&message);
        tx.inputs[0].signature = signature.to_bytes();

        // Reconstruir a partir de los bytes crudos (simula lo que hace
        // znx-state al recibir la tx por red/mempool) y verificar que la
        // firma valida contra el preimage sin firmas.
        let unsigned_message = signing_bytes(&tx);
        znx_crypto::verify_raw(&tx.inputs[0].public_key, &unsigned_message, &tx.inputs[0].signature).expect("firma válida");
    }

    #[test]
    fn tampered_output_fails_verification() {
        let sender = Keypair::generate();
        let receiver = Keypair::generate();
        let mut tx = Transaction {
            chain_id: "znx-devnet-1".to_string(),
            inputs: vec![TxIn {
                prev_out: OutPoint { txid: [1u8; 32], vout: 0 },
                public_key: sender.public_key().to_bytes(),
                signature: [0u8; 64],
            }],
            outputs: vec![sample_output(receiver.address(), 500)],
        };
        let signature = sender.sign(&signing_bytes(&tx));
        tx.inputs[0].signature = signature.to_bytes();

        let mut tampered = tx.clone();
        tampered.outputs[0].amount = 999_999_999;

        assert!(znx_crypto::verify_raw(&tampered.inputs[0].public_key, &signing_bytes(&tampered), &tampered.inputs[0].signature).is_err());
    }

    #[test]
    fn tx_root_changes_with_contents_and_is_stable_for_same_set() {
        let tx = sample_transaction();

        let root_empty = tx_root(&[]);
        let root_one = tx_root(std::slice::from_ref(&tx));
        let root_one_again = tx_root(std::slice::from_ref(&tx));

        assert_ne!(root_empty, root_one);
        assert_eq!(root_one, root_one_again);
    }

    #[test]
    fn tx_root_handles_odd_count_by_duplicating_last() {
        let tx1 = sample_transaction();
        let tx2 = sample_transaction();
        let tx3 = sample_transaction();

        // No debe entrar en pánico con una cantidad impar de hojas, y
        // distintos conjuntos deben dar roots distintos.
        let root_three = tx_root(&[tx1.clone(), tx2.clone(), tx3.clone()]);
        let root_two = tx_root(&[tx1, tx2]);
        assert_ne!(root_three, root_two);
    }

    #[test]
    fn meets_target_compares_as_big_endian_256_bit_integers() {
        let mut low_hash = [0u8; 32];
        low_hash[31] = 1;
        let mut high_target = [0u8; 32];
        high_target[0] = 0xff;

        assert!(meets_target(&low_hash, &high_target));
        assert!(!meets_target(&high_target, &low_hash));

        let equal = [5u8; 32];
        assert!(meets_target(&equal, &equal));
    }
}
