//! znx-storage — persistencia real sobre RocksDB. Implementa
//! `znx_state::StateStore` (así `apply_transaction`/`apply_coinbase` de
//! znx-state funcionan sin cambios contra un backend en disco, no solo
//! contra `MemoryStateStore`), más storage de bloques y los datos de
//! "deshacer" (undo data) que hacen falta para un reorg de 1 bloque (ver
//! `commit_block`/`undo_latest_block`, usados por znx-node).
//!
//! Sin `state_root` en el header del bloque (ver znx-types): la seguridad
//! del modelo UTXO+PoW es "cada nodo repite la validación completa desde
//! génesis", no una raíz commiteada. `state_root()` sigue existiendo acá
//! como diagnóstico interno (detectar divergencia entre nodos durante
//! desarrollo/testkit), pero ya no es una regla de consenso.

use std::path::Path;

use rocksdb::{IteratorMode, Options, WriteBatch, DB};
use thiserror::Error;
use znx_codec::{decode, encode};
use znx_state::StateStore;
use znx_types::{Address, Block, OutPoint, Transaction, TxOut};

const CF_UTXOS: &str = "utxos";
const CF_META: &str = "meta";
const CF_BLOCKS: &str = "blocks";
const CF_BLOCK_HASH_INDEX: &str = "block_hash_index";
const CF_UNDO: &str = "undo";
/// Índice `txid -> altura del bloque que la confirmó`. Solo se llena
/// desde `commit_block`/`undo_latest_block` (bloques reales, ya
/// commiteados) — `put_block` (usado solo para el génesis, que no tiene
/// transacciones) no lo toca. Habilita `get_transaction(txid)` sin tener
/// que recorrer todos los bloques.
const CF_TX_INDEX: &str = "tx_index";

const META_KEY_LATEST_HEIGHT: &[u8] = b"latest_height";

#[derive(Debug, Error)]
pub enum StorageError {
    #[error("error de RocksDB: {0}")]
    RocksDb(#[from] rocksdb::Error),
    #[error("error de (de)serialización: {0}")]
    Codec(#[from] znx_codec::CodecError),
}

pub struct RocksStorage {
    db: DB,
}

/// Clave de RocksDB para un `OutPoint`: `txid` (32 bytes) seguido de
/// `vout` en big-endian (4 bytes) — concatenación directa en vez de pasar
/// por borsh, para que la clave sea simple de razonar y quede ordenada de
/// forma útil (todos los outputs de un mismo txid quedan contiguos).
fn utxo_key(outpoint: &OutPoint) -> [u8; 36] {
    let mut key = [0u8; 36];
    key[0..32].copy_from_slice(&outpoint.txid);
    key[32..36].copy_from_slice(&outpoint.vout.to_be_bytes());
    key
}

impl RocksStorage {
    /// Abre (o crea) la base en `path`, con las 4 column families del
    /// protocolo. Volver a abrir el mismo `path` después de un restart del
    /// proceso recupera exactamente el mismo estado — no hay migración ni
    /// reconstrucción, RocksDB persiste en disco de forma durable (WAL +
    /// fsync en cada `write`, comportamiento por defecto que no se
    /// desactiva acá).
    pub fn open(path: &Path) -> Result<Self, StorageError> {
        let mut db_opts = Options::default();
        db_opts.create_if_missing(true);
        db_opts.create_missing_column_families(true);
        // Sin codec de compresión: el crate `rocksdb` trae snappy/lz4/zstd/
        // zlib/bzip2 bundleados por defecto y cada uno se compila desde
        // fuente en C++ (build muy pesado de CPU). No usamos ninguno acá
        // (Cargo.toml los deshabilitó), así que hay que fijarlo explícito
        // para no depender del default de RocksDB. Revisar si en producción
        // el volumen de datos justifica pagar el costo de build por lz4.
        db_opts.set_compression_type(rocksdb::DBCompressionType::None);

        let cfs = [CF_UTXOS, CF_META, CF_BLOCKS, CF_BLOCK_HASH_INDEX, CF_UNDO, CF_TX_INDEX];
        let db = DB::open_cf(&db_opts, path, cfs)?;
        Ok(RocksStorage { db })
    }

    fn cf(&self, name: &str) -> &rocksdb::ColumnFamily {
        // Los nombres son fijos y se crean en `open` — si faltara alguno
        // acá es un bug de este mismo archivo, no una condición
        // recuperable en runtime (de ahí el `expect`, no un `Result`).
        self.db
            .cf_handle(name)
            .unwrap_or_else(|| panic!("column family '{name}' no existe — bug de inicialización en RocksStorage::open"))
    }

    pub fn put_block(&mut self, block: &Block) -> Result<(), StorageError> {
        let height_key = block.header.height.to_be_bytes();
        let block_hash = znx_codec::block_hash(block);

        let mut batch = WriteBatch::default();
        batch.put_cf(self.cf(CF_BLOCKS), height_key, encode(block));
        batch.put_cf(self.cf(CF_BLOCK_HASH_INDEX), block_hash, height_key);
        batch.put_cf(self.cf(CF_META), META_KEY_LATEST_HEIGHT, height_key);
        self.db.write(batch)?;
        Ok(())
    }

    pub fn get_block(&self, height: u64) -> Result<Option<Block>, StorageError> {
        match self.db.get_cf(self.cf(CF_BLOCKS), height.to_be_bytes())? {
            Some(bytes) => Ok(Some(decode(&bytes)?)),
            None => Ok(None),
        }
    }

    pub fn get_block_by_hash(&self, hash: &[u8; 32]) -> Result<Option<Block>, StorageError> {
        match self.db.get_cf(self.cf(CF_BLOCK_HASH_INDEX), hash)? {
            Some(height_bytes) => {
                let height = u64::from_be_bytes(height_bytes.as_slice().try_into().expect("siempre 8 bytes, los escribimos acá mismo"));
                self.get_block(height)
            }
            None => Ok(None),
        }
    }

    pub fn latest_height(&self) -> Result<Option<u64>, StorageError> {
        match self.db.get_cf(self.cf(CF_META), META_KEY_LATEST_HEIGHT)? {
            Some(bytes) => Ok(Some(u64::from_be_bytes(bytes.as_slice().try_into().expect("siempre 8 bytes, los escribimos acá mismo")))),
            None => Ok(None),
        }
    }

    /// Hash determinístico sobre todo el UTXO set, en el orden en que
    /// RocksDB itera las keys. Diagnóstico interno (detectar divergencia
    /// de estado entre nodos durante desarrollo/testkit) — ya no es parte
    /// del header del bloque ni de ninguna regla de consenso.
    pub fn state_root(&self) -> Result<[u8; 32], StorageError> {
        let mut concatenated = Vec::new();
        let iter = self.db.iterator_cf(self.cf(CF_UTXOS), IteratorMode::Start);
        for item in iter {
            let (key, value) = item?;
            concatenated.extend_from_slice(&key);
            concatenated.extend_from_slice(&value);
        }
        Ok(znx_crypto::hash(&concatenated))
    }

    /// Todos los UTXOs cuyo `pubkey_hash` es `owner` — recorre el CF
    /// entero y filtra (no hay un índice por dirección). Aceptable a
    /// escala de devnet/testnet; Bitcoin Core tampoco lo tiene sin
    /// `-txindex`/wallet propio — si el volumen lo justifica más adelante,
    /// esto es lo primero que habría que indexar.
    pub fn list_utxos_for(&self, owner: &Address) -> Result<Vec<(OutPoint, TxOut)>, StorageError> {
        let mut results = Vec::new();
        let iter = self.db.iterator_cf(self.cf(CF_UTXOS), IteratorMode::Start);
        for item in iter {
            let (key, value) = item?;
            let output: TxOut = decode(&value)?;
            if &output.pubkey_hash == owner {
                let txid: [u8; 32] = key[0..32].try_into().expect("clave de UTXO siempre de 36 bytes");
                let vout = u32::from_be_bytes(key[32..36].try_into().expect("clave de UTXO siempre de 36 bytes"));
                results.push((OutPoint { txid, vout }, output));
            }
        }
        Ok(results)
    }

    /// Busca una transacción confirmada por su `txid`, vía `CF_TX_INDEX`.
    /// `None` si nunca se confirmó (nunca existió, sigue en mempool sin
    /// minar, o el bloque que la tenía se deshizo por un reorg y no volvió
    /// a incluirse en la cadena que ganó). Devuelve también la altura y el
    /// hash del bloque que la confirmó, para que quien llame no tenga que
    /// pedir el bloque aparte solo para tener el hash.
    pub fn get_transaction(&self, txid: &[u8; 32]) -> Result<Option<(u64, [u8; 32], Transaction)>, StorageError> {
        let Some(height_bytes) = self.db.get_cf(self.cf(CF_TX_INDEX), txid)? else {
            return Ok(None);
        };
        let height = u64::from_be_bytes(height_bytes.as_slice().try_into().expect("siempre 8 bytes, los escribimos acá mismo"));
        let block = self.get_block(height)?.expect("el índice de tx siempre apunta a un bloque que existe");
        let hash = znx_codec::block_hash(&block);
        let tx = block
            .transactions
            .into_iter()
            .find(|tx| &znx_codec::txid(tx) == txid)
            .expect("el índice de tx siempre apunta a un bloque que contiene ese txid");
        Ok(Some((height, hash, tx)))
    }

    fn get_undo(&self, height: u64) -> Result<Vec<(OutPoint, TxOut)>, StorageError> {
        match self.db.get_cf(self.cf(CF_UNDO), height.to_be_bytes())? {
            Some(bytes) => Ok(decode(&bytes)?),
            None => Ok(Vec::new()),
        }
    }

    /// Escribe en un único `WriteBatch` atómico todo lo que produce un
    /// bloque nuevo: el diff de UTXOs que dejó (`spent`/`created` — ya
    /// validado contra un `znx_state::OverlayStore` antes de llegar acá,
    /// ver znx-node), el bloque en sí, el índice por hash, la altura más
    /// reciente, y los datos de deshacer (`undo`: los outputs que este
    /// bloque gastó, con su valor original, para poder recrearlos si más
    /// adelante hace falta un reorg que descarte este bloque). Que todo
    /// esto sea un solo batch (a diferencia del `apply_changes` +
    /// `put_block` separados de antes) además cierra una ventana de
    /// inconsistencia ante un crash a mitad de escritura.
    pub fn commit_block(
        &mut self,
        block: &Block,
        spent: Vec<OutPoint>,
        created: Vec<(OutPoint, TxOut)>,
        undo: Vec<(OutPoint, TxOut)>,
    ) -> Result<(), StorageError> {
        let height_key = block.header.height.to_be_bytes();
        let hash = znx_codec::block_hash(block);

        let mut batch = WriteBatch::default();
        let utxos_cf = self.cf(CF_UTXOS);
        for outpoint in &spent {
            batch.delete_cf(utxos_cf, utxo_key(outpoint));
        }
        for (outpoint, output) in &created {
            batch.put_cf(utxos_cf, utxo_key(outpoint), encode(output));
        }
        batch.put_cf(self.cf(CF_BLOCKS), height_key, encode(block));
        batch.put_cf(self.cf(CF_BLOCK_HASH_INDEX), hash, height_key);
        batch.put_cf(self.cf(CF_META), META_KEY_LATEST_HEIGHT, height_key);
        batch.put_cf(self.cf(CF_UNDO), height_key, encode(&undo));
        let tx_index_cf = self.cf(CF_TX_INDEX);
        for tx in &block.transactions {
            batch.put_cf(tx_index_cf, znx_codec::txid(tx), height_key);
        }
        self.db.write(batch)?;
        Ok(())
    }

    /// Deshace el último bloque: recrea los UTXOs que gastó (con los
    /// valores guardados por `commit_block`) y borra los que creó, en un
    /// único `WriteBatch` atómico, y retrocede `latest_height`. Usado por
    /// el fork-choice de znx-node cuando llega una cadena competidora con
    /// más trabajo acumulado que la punta local — deshace solo UN bloque;
    /// un reorg de más profundidad llama a esto repetidamente.
    pub fn undo_latest_block(&mut self) -> Result<Block, StorageError> {
        let height = self.latest_height()?.expect("no se puede deshacer sin al menos un bloque (ni el génesis)");
        let block = self.get_block(height)?.expect("bloque en latest_height siempre existe");
        let undo = self.get_undo(height)?;

        let mut batch = WriteBatch::default();
        let utxos_cf = self.cf(CF_UTXOS);
        let tx_index_cf = self.cf(CF_TX_INDEX);
        for tx in &block.transactions {
            let id = znx_codec::txid(tx);
            for vout in 0..tx.outputs.len() as u32 {
                batch.delete_cf(utxos_cf, utxo_key(&OutPoint { txid: id, vout }));
            }
            batch.delete_cf(tx_index_cf, id);
        }
        for (outpoint, output) in &undo {
            batch.put_cf(utxos_cf, utxo_key(outpoint), encode(output));
        }

        let meta_cf = self.cf(CF_META);
        if height == 0 {
            batch.delete_cf(meta_cf, META_KEY_LATEST_HEIGHT);
        } else {
            batch.put_cf(meta_cf, META_KEY_LATEST_HEIGHT, (height - 1).to_be_bytes());
        }
        batch.delete_cf(self.cf(CF_BLOCKS), height.to_be_bytes());
        batch.delete_cf(self.cf(CF_BLOCK_HASH_INDEX), znx_codec::block_hash(&block));
        batch.delete_cf(self.cf(CF_UNDO), height.to_be_bytes());

        self.db.write(batch)?;
        Ok(block)
    }
}

impl StateStore for RocksStorage {
    type Error = StorageError;

    fn get_utxo(&self, outpoint: &OutPoint) -> Option<TxOut> {
        match self.db.get_cf(self.cf(CF_UTXOS), utxo_key(outpoint)) {
            Ok(Some(bytes)) => Some(decode(&bytes).unwrap_or_else(|e| panic!("UTXO {outpoint:?} corrupto en disco (no decodifica): {e}"))),
            Ok(None) => None,
            Err(e) => panic!("error de I/O leyendo el UTXO {outpoint:?}: {e}"),
        }
    }

    fn apply_changes(&mut self, spent: Vec<OutPoint>, created: Vec<(OutPoint, TxOut)>) -> Result<(), Self::Error> {
        let mut batch = WriteBatch::default();
        let utxos_cf = self.cf(CF_UTXOS);
        for outpoint in &spent {
            batch.delete_cf(utxos_cf, utxo_key(outpoint));
        }
        for (outpoint, output) in &created {
            batch.put_cf(utxos_cf, utxo_key(outpoint), encode(output));
        }
        // Un solo `db.write(batch)` — RocksDB garantiza que un WriteBatch
        // se aplica atómicamente (todo o nada), incluso ante un crash del
        // proceso a mitad de la escritura.
        self.db.write(batch)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use znx_codec::block_hash;
    use znx_crypto::Keypair;
    use znx_state::{apply_coinbase, apply_transaction};
    use znx_types::{BlockHeader, Transaction, TxIn};

    const CHAIN_ID: &str = "znx-devnet-1";

    fn open_temp() -> (tempfile::TempDir, RocksStorage) {
        let dir = tempfile::tempdir().expect("tempdir");
        let storage = RocksStorage::open(dir.path()).expect("abre RocksDB");
        (dir, storage)
    }

    fn outpoint(byte: u8, vout: u32) -> OutPoint {
        OutPoint { txid: [byte; 32], vout }
    }

    #[test]
    fn unknown_utxo_is_none() {
        let (_dir, storage) = open_temp();
        assert_eq!(storage.get_utxo(&outpoint(1, 0)), None);
    }

    #[test]
    fn apply_changes_persists_and_removes_utxos() {
        let (_dir, mut storage) = open_temp();
        let addr = Keypair::generate().address();
        let op = outpoint(9, 0);

        storage
            .apply_changes(vec![], vec![(op, TxOut { amount: 42, pubkey_hash: addr })])
            .expect("escritura válida");
        assert_eq!(storage.get_utxo(&op), Some(TxOut { amount: 42, pubkey_hash: addr }));

        storage.apply_changes(vec![op], vec![]).expect("borrado válido");
        assert_eq!(storage.get_utxo(&op), None);
    }

    #[test]
    fn state_survives_reopening_the_same_path() {
        let dir = tempfile::tempdir().expect("tempdir");
        let addr = Keypair::generate().address();
        let op = outpoint(7, 0);

        {
            let mut storage = RocksStorage::open(dir.path()).expect("abre RocksDB");
            storage
                .apply_changes(vec![], vec![(op, TxOut { amount: 777, pubkey_hash: addr })])
                .expect("escritura válida");
            // `storage` se dropea acá — simula el proceso del nodo cerrando.
        }

        // "Restart": abrimos de nuevo el mismo path desde cero.
        let storage = RocksStorage::open(dir.path()).expect("reabre RocksDB");
        assert_eq!(storage.get_utxo(&op), Some(TxOut { amount: 777, pubkey_hash: addr }));
    }

    #[test]
    fn coinbase_and_transaction_end_to_end_against_rocksdb() {
        let (_dir, mut storage) = open_temp();
        let miner = Keypair::generate();
        let receiver = Keypair::generate();

        let coinbase = Transaction::new_coinbase(CHAIN_ID.to_string(), 1, 0, vec![TxOut { amount: 50, pubkey_hash: miner.address() }]);
        apply_coinbase(&mut storage, &coinbase, 1, 50).expect("coinbase válida");

        let coinbase_id = znx_codec::txid(&coinbase);
        let spend = OutPoint { txid: coinbase_id, vout: 0 };

        let mut tx = Transaction {
            chain_id: CHAIN_ID.to_string(),
            inputs: vec![TxIn { prev_out: spend, public_key: miner.public_key().to_bytes(), signature: [0u8; 64] }],
            outputs: vec![TxOut { amount: 40, pubkey_hash: receiver.address() }, TxOut { amount: 8, pubkey_hash: miner.address() }],
        };
        let signature = miner.sign(&znx_codec::signing_bytes(&tx));
        tx.inputs[0].signature = signature.to_bytes();

        let applied = apply_transaction(&mut storage, &tx, CHAIN_ID).expect("transferencia válida");
        assert_eq!(applied.fee, 2);

        assert_eq!(storage.get_utxo(&spend), None);
        let tx_id = znx_codec::txid(&tx);
        assert_eq!(storage.get_utxo(&OutPoint { txid: tx_id, vout: 0 }), Some(TxOut { amount: 40, pubkey_hash: receiver.address() }));
        assert_eq!(storage.get_utxo(&OutPoint { txid: tx_id, vout: 1 }), Some(TxOut { amount: 8, pubkey_hash: miner.address() }));
    }

    #[test]
    fn commit_block_then_undo_restores_the_previous_utxo_set() {
        let (_dir, mut storage) = open_temp();
        let miner = Keypair::generate();
        let receiver = Keypair::generate();

        let genesis_block = sample_block(0, [0u8; 32]);
        storage.put_block(&genesis_block).expect("guarda bloque 0");
        let genesis_hash = block_hash(&genesis_block);

        // Sembramos un UTXO gastable directo (simula que vino de un
        // bloque anterior ya confirmado) para poder armar una tx regular
        // además de la coinbase en el bloque que vamos a commitear.
        let seed_op = OutPoint { txid: [42u8; 32], vout: 0 };
        storage.apply_changes(vec![], vec![(seed_op, TxOut { amount: 100, pubkey_hash: miner.address() })]).expect("siembra");

        let coinbase = Transaction::new_coinbase(CHAIN_ID.to_string(), 1, 0, vec![TxOut { amount: 50, pubkey_hash: miner.address() }]);
        let mut spend_tx = Transaction {
            chain_id: CHAIN_ID.to_string(),
            inputs: vec![TxIn { prev_out: seed_op, public_key: miner.public_key().to_bytes(), signature: [0u8; 64] }],
            outputs: vec![TxOut { amount: 90, pubkey_hash: receiver.address() }],
        };
        let signature = miner.sign(&znx_codec::signing_bytes(&spend_tx));
        spend_tx.inputs[0].signature = signature.to_bytes();

        let block = Block {
            header: BlockHeader {
                height: 1,
                parent_hash: genesis_hash,
                tx_root: znx_codec::tx_root(&[coinbase.clone(), spend_tx.clone()]),
                timestamp: 1_753_000_001,
                target: [0xffu8; 32],
                pow_nonce: 0,
            },
            transactions: vec![coinbase.clone(), spend_tx.clone()],
        };

        let spent = vec![seed_op];
        let coinbase_id = znx_codec::txid(&coinbase);
        let spend_tx_id = znx_codec::txid(&spend_tx);
        let created = vec![
            (OutPoint { txid: coinbase_id, vout: 0 }, TxOut { amount: 50, pubkey_hash: miner.address() }),
            (OutPoint { txid: spend_tx_id, vout: 0 }, TxOut { amount: 90, pubkey_hash: receiver.address() }),
        ];
        let undo = vec![(seed_op, TxOut { amount: 100, pubkey_hash: miner.address() })];

        storage.commit_block(&block, spent, created, undo).expect("commit válido");

        assert_eq!(storage.latest_height().expect("lectura ok"), Some(1));
        assert_eq!(storage.get_utxo(&seed_op), None);
        assert_eq!(storage.get_utxo(&OutPoint { txid: coinbase_id, vout: 0 }), Some(TxOut { amount: 50, pubkey_hash: miner.address() }));
        assert_eq!(storage.get_utxo(&OutPoint { txid: spend_tx_id, vout: 0 }), Some(TxOut { amount: 90, pubkey_hash: receiver.address() }));

        let undone = storage.undo_latest_block().expect("deshace sin error");
        assert_eq!(undone, block);
        assert_eq!(storage.latest_height().expect("lectura ok"), Some(0));
        assert_eq!(storage.get_utxo(&seed_op), Some(TxOut { amount: 100, pubkey_hash: miner.address() }));
        assert_eq!(storage.get_utxo(&OutPoint { txid: coinbase_id, vout: 0 }), None);
        assert_eq!(storage.get_utxo(&OutPoint { txid: spend_tx_id, vout: 0 }), None);
    }

    #[test]
    fn get_transaction_is_indexed_on_commit_and_removed_on_undo() {
        let (_dir, mut storage) = open_temp();
        let miner = Keypair::generate();

        let genesis_block = sample_block(0, [0u8; 32]);
        storage.put_block(&genesis_block).expect("guarda bloque 0");
        let genesis_hash = block_hash(&genesis_block);

        let coinbase = Transaction::new_coinbase(CHAIN_ID.to_string(), 1, 0, vec![TxOut { amount: 50, pubkey_hash: miner.address() }]);
        let coinbase_id = znx_codec::txid(&coinbase);

        assert_eq!(storage.get_transaction(&coinbase_id).expect("lectura ok"), None);

        let block = Block {
            header: BlockHeader {
                height: 1,
                parent_hash: genesis_hash,
                tx_root: znx_codec::tx_root(std::slice::from_ref(&coinbase)),
                timestamp: 1_753_000_001,
                target: [0xffu8; 32],
                pow_nonce: 0,
            },
            transactions: vec![coinbase.clone()],
        };
        let created = vec![(OutPoint { txid: coinbase_id, vout: 0 }, TxOut { amount: 50, pubkey_hash: miner.address() })];
        storage.commit_block(&block, vec![], created, vec![]).expect("commit válido");
        let block_hash_value = block_hash(&block);

        let (height, hash, tx) = storage.get_transaction(&coinbase_id).expect("lectura ok").expect("indexada tras el commit");
        assert_eq!(height, 1);
        assert_eq!(hash, block_hash_value);
        assert_eq!(tx, coinbase);

        storage.undo_latest_block().expect("deshace sin error");
        assert_eq!(storage.get_transaction(&coinbase_id).expect("lectura ok"), None);
    }

    #[test]
    fn list_utxos_for_returns_only_the_matching_owner() {
        let (_dir, mut storage) = open_temp();
        let owner = Keypair::generate();
        let other = Keypair::generate();

        storage
            .apply_changes(
                vec![],
                vec![
                    (OutPoint { txid: [1u8; 32], vout: 0 }, TxOut { amount: 10, pubkey_hash: owner.address() }),
                    (OutPoint { txid: [2u8; 32], vout: 0 }, TxOut { amount: 20, pubkey_hash: owner.address() }),
                    (OutPoint { txid: [3u8; 32], vout: 0 }, TxOut { amount: 30, pubkey_hash: other.address() }),
                ],
            )
            .expect("siembra");

        let mut owned = storage.list_utxos_for(&owner.address()).expect("lectura ok");
        owned.sort_by_key(|(_, out)| out.amount);
        assert_eq!(owned.len(), 2);
        assert_eq!(owned[0].1.amount, 10);
        assert_eq!(owned[1].1.amount, 20);
    }

    fn sample_block(height: u64, parent_hash: [u8; 32]) -> Block {
        Block {
            header: BlockHeader {
                height,
                parent_hash,
                tx_root: [0u8; 32],
                timestamp: 1_753_000_000 + height,
                target: [0xffu8; 32],
                pow_nonce: 0,
            },
            transactions: vec![],
        }
    }

    #[test]
    fn block_roundtrip_by_height_and_hash_updates_latest_height() {
        let (_dir, mut storage) = open_temp();
        assert_eq!(storage.latest_height().expect("lectura ok"), None);

        let genesis_block = sample_block(0, [0u8; 32]);
        let genesis_hash = block_hash(&genesis_block);
        storage.put_block(&genesis_block).expect("guarda bloque 0");

        let block_one = sample_block(1, genesis_hash);
        storage.put_block(&block_one).expect("guarda bloque 1");

        assert_eq!(storage.latest_height().expect("lectura ok"), Some(1));
        assert_eq!(storage.get_block(0).expect("lectura ok"), Some(genesis_block.clone()));
        assert_eq!(storage.get_block(1).expect("lectura ok"), Some(block_one.clone()));
        assert_eq!(storage.get_block_by_hash(&genesis_hash).expect("lectura ok"), Some(genesis_block));
        assert_eq!(storage.get_block(99).expect("lectura ok"), None);
    }

    #[test]
    fn state_root_is_deterministic_and_sensitive_to_content() {
        let (_dir, mut storage) = open_temp();
        let addr = Keypair::generate().address();
        let op = outpoint(3, 0);

        let root_empty = storage.state_root().expect("state root vacío");

        storage
            .apply_changes(vec![], vec![(op, TxOut { amount: 1, pubkey_hash: addr })])
            .expect("escritura válida");
        let root_with_one_utxo = storage.state_root().expect("state root con datos");
        let root_with_one_utxo_again = storage.state_root().expect("state root de nuevo");

        assert_ne!(root_empty, root_with_one_utxo);
        assert_eq!(root_with_one_utxo, root_with_one_utxo_again);
    }
}
