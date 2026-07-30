//! Keystore cifrado: reemplaza los 32 bytes crudos sin cifrar que
//! `znx-wallet-cli` guardaba antes (aceptable solo para devnet). Cambio
//! de formato incompatible a propósito, sin migración — las llaves de
//! devnet existentes no protegen fondos reales, no vale la pena la
//! complejidad de soportar ambos formatos.
//!
//! `address`/`public_key` viajan en texto plano en el archivo (no son
//! secretos, derivan de la pubkey) — así `address`/`balance --key` no
//! necesitan pedir contraseña para una operación de solo lectura. Solo
//! la llave privada de 32 bytes va cifrada.
//!
//! KDF: Argon2id (resistente a ASICs/GPU, a diferencia de PBKDF2/scrypt
//! viejos), parámetros por default = mínimo interactivo recomendado por
//! OWASP (no se puede tardar segundos enteros cada vez que se firma una
//! transacción). Cifrado: XChaCha20-Poly1305 (AEAD, nonce de 24 bytes —
//! suficientemente grande para generarlo con el RNG del sistema sin
//! preocuparse por colisiones, a diferencia del nonce de 12 bytes de
//! ChaCha20-Poly1305 "clásico"). La dirección se usa como dato asociado
//! (AAD): liga el ciphertext a esa dirección puntual, para que no se
//! pueda mover silenciosamente entre archivos de keystore distintos sin
//! que falle la autenticación.

use std::fs;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use rand_core::{Rng, UnwrapErr};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use znx_crypto::{Address, CryptoError, Keypair};

const KDF_M_COST_KIB: u32 = 19_456;
const KDF_T_COST: u32 = 2;
const KDF_P_COST: u32 = 1;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24;
const KEY_LEN: usize = 32;

#[derive(Debug, Error)]
pub enum KeystoreError {
    #[error("no se pudo leer/escribir el keystore: {0}")]
    Io(#[from] io::Error),
    #[error("JSON de keystore inválido (¿un archivo de un formato viejo sin cifrar?): {0}")]
    Json(#[from] serde_json::Error),
    #[error("dirección inválida en el keystore: {0}")]
    Address(#[from] CryptoError),
    #[error("campo hex inválido en el keystore: {0}")]
    InvalidHex(String),
    #[error("no se pudo derivar la clave de la contraseña: {0}")]
    Kdf(String),
    #[error("contraseña incorrecta (o keystore corrupto)")]
    WrongPassword,
}

#[derive(Debug, Serialize, Deserialize)]
struct RawKeystore {
    version: u8,
    address: String,
    public_key: String,
    kdf: String,
    kdf_salt: String,
    kdf_m_cost_kib: u32,
    kdf_t_cost: u32,
    kdf_p_cost: u32,
    cipher: String,
    nonce: String,
    ciphertext: String,
}

pub struct Keystore {
    pub address: Address,
    public_key: [u8; 32],
    salt: [u8; SALT_LEN],
    m_cost_kib: u32,
    t_cost: u32,
    p_cost: u32,
    nonce: [u8; NONCE_LEN],
    ciphertext: Vec<u8>,
}

fn random_bytes<const N: usize>() -> [u8; N] {
    // Mismo patrón que znx-crypto (`Keypair::generate`): `SysRng` es
    // falible (`TryRngCore`, el syscall de entropía en teoría puede
    // fallar) — `UnwrapErr` lo vuelve infalible entrando en pánico si eso
    // pasara, la respuesta correcta acá (sin entropía real no hay forma
    // segura de generar sal/nonce).
    let mut rng = UnwrapErr(getrandom::SysRng);
    let mut bytes = [0u8; N];
    rng.fill_bytes(&mut bytes);
    bytes
}

fn decode_hex_array<const N: usize>(field: &str, hex_str: &str) -> Result<[u8; N], KeystoreError> {
    let bytes = hex::decode(hex_str).map_err(|_| KeystoreError::InvalidHex(field.to_string()))?;
    bytes.try_into().map_err(|_| KeystoreError::InvalidHex(format!("{field} tiene que ser de {N} bytes")))
}

fn derive_key(password: &str, salt: &[u8], m_cost_kib: u32, t_cost: u32, p_cost: u32) -> Result<[u8; KEY_LEN], KeystoreError> {
    let params = Params::new(m_cost_kib, t_cost, p_cost, Some(KEY_LEN)).map_err(|e| KeystoreError::Kdf(e.to_string()))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0u8; KEY_LEN];
    argon2.hash_password_into(password.as_bytes(), salt, &mut key).map_err(|e| KeystoreError::Kdf(e.to_string()))?;
    Ok(key)
}

impl Keystore {
    /// Cifra la llave privada de `keypair` con `password` (parámetros de
    /// KDF por default — ver doc de módulo). No escribe nada a disco
    /// todavía, eso es `save`.
    pub fn create(keypair: &Keypair, password: &str) -> Result<Self, KeystoreError> {
        let address = keypair.address();
        let salt = random_bytes::<SALT_LEN>();
        let key = derive_key(password, &salt, KDF_M_COST_KIB, KDF_T_COST, KDF_P_COST)?;

        let nonce_bytes = random_bytes::<NONCE_LEN>();
        let cipher = XChaCha20Poly1305::new(Key::from_slice(&key));
        let nonce = XNonce::from_slice(&nonce_bytes);
        let secret = keypair.secret_bytes();
        let ciphertext = cipher
            .encrypt(nonce, Payload { msg: &secret, aad: &address.0 })
            .map_err(|_| KeystoreError::Kdf("no se pudo cifrar la llave privada".to_string()))?;

        Ok(Keystore {
            address,
            public_key: keypair.public_key().to_bytes(),
            salt,
            m_cost_kib: KDF_M_COST_KIB,
            t_cost: KDF_T_COST,
            p_cost: KDF_P_COST,
            nonce: nonce_bytes,
            ciphertext,
        })
    }

    fn to_raw(&self) -> RawKeystore {
        RawKeystore {
            version: 1,
            address: self.address.to_bech32(),
            public_key: hex::encode(self.public_key),
            kdf: "argon2id".to_string(),
            kdf_salt: hex::encode(self.salt),
            kdf_m_cost_kib: self.m_cost_kib,
            kdf_t_cost: self.t_cost,
            kdf_p_cost: self.p_cost,
            cipher: "xchacha20poly1305".to_string(),
            nonce: hex::encode(self.nonce),
            ciphertext: hex::encode(&self.ciphertext),
        }
    }

    fn from_raw(raw: RawKeystore) -> Result<Self, KeystoreError> {
        Ok(Keystore {
            address: Address::from_bech32(&raw.address)?,
            public_key: decode_hex_array("public_key", &raw.public_key)?,
            salt: decode_hex_array("kdf_salt", &raw.kdf_salt)?,
            m_cost_kib: raw.kdf_m_cost_kib,
            t_cost: raw.kdf_t_cost,
            p_cost: raw.kdf_p_cost,
            nonce: decode_hex_array("nonce", &raw.nonce)?,
            ciphertext: hex::decode(&raw.ciphertext).map_err(|_| KeystoreError::InvalidHex("ciphertext".to_string()))?,
        })
    }

    /// Escribe el keystore a `path` como JSON, con permisos restringidos
    /// a solo-dueño (el ciphertext está protegido por contraseña, pero
    /// igual no hace falta dejarlo world-readable).
    pub fn save(&self, path: &Path) -> Result<(), KeystoreError> {
        let json = serde_json::to_string_pretty(&self.to_raw()).expect("RawKeystore siempre serializa");
        fs::write(path, json)?;

        let mut perms = fs::metadata(path)?.permissions();
        perms.set_mode(0o600);
        fs::set_permissions(path, perms)?;
        Ok(())
    }

    /// Lee y parsea el keystore — NO descifra la llave privada (para eso
    /// está `decrypt`, que pide la contraseña). Alcanza para `address`/
    /// `balance --key`, que no necesitan la llave privada.
    pub fn load(path: &Path) -> Result<Self, KeystoreError> {
        let contents = fs::read_to_string(path)?;
        let raw: RawKeystore = serde_json::from_str(&contents)?;
        Self::from_raw(raw)
    }

    /// Mismo formato que `save`/`load`, pero a un `String` en vez de un
    /// archivo — para guardar el keystore en una columna de Postgres
    /// (ver `znx-custody`, direcciones de depósito por usuario) sin pasar
    /// por el filesystem.
    pub fn to_json(&self) -> String {
        serde_json::to_string(&self.to_raw()).expect("RawKeystore siempre serializa")
    }

    /// Contraparte de `to_json`.
    pub fn from_json(s: &str) -> Result<Self, KeystoreError> {
        let raw: RawKeystore = serde_json::from_str(s)?;
        Self::from_raw(raw)
    }

    /// Deriva la clave de `password` y descifra+autentica la llave
    /// privada. Una contraseña equivocada falla acá (autenticación AEAD
    /// — nunca hay un "descifrado silencioso corrupto" que produzca una
    /// llave inválida sin avisar).
    pub fn decrypt(&self, password: &str) -> Result<Keypair, KeystoreError> {
        let key = derive_key(password, &self.salt, self.m_cost_kib, self.t_cost, self.p_cost)?;
        let cipher = XChaCha20Poly1305::new(Key::from_slice(&key));
        let nonce = XNonce::from_slice(&self.nonce);

        let plaintext = cipher.decrypt(nonce, Payload { msg: &self.ciphertext, aad: &self.address.0 }).map_err(|_| KeystoreError::WrongPassword)?;
        let secret: [u8; 32] = plaintext.try_into().map_err(|_| KeystoreError::WrongPassword)?;

        let keypair = Keypair::from_secret_bytes(secret);
        if keypair.public_key().to_bytes() != self.public_key {
            // No debería pasar nunca (la autenticación AEAD ya lo
            // garantiza), pero verificarlo también acá es barato y deja
            // el invariante explícito en vez de confiar ciegamente.
            return Err(KeystoreError::WrongPassword);
        }
        Ok(keypair)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_save_load_decrypt_roundtrip() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("keystore.json");
        let keypair = Keypair::generate();

        let keystore = Keystore::create(&keypair, "correcto horse battery staple").expect("cifra sin error");
        keystore.save(&path).expect("guarda sin error");

        let loaded = Keystore::load(&path).expect("carga sin error");
        assert_eq!(loaded.address, keypair.address());

        let decrypted = loaded.decrypt("correcto horse battery staple").expect("descifra con la contraseña correcta");
        assert_eq!(decrypted.address(), keypair.address());
        assert_eq!(decrypted.public_key(), keypair.public_key());
    }

    #[test]
    fn to_json_then_from_json_roundtrip_decrypts() {
        let keypair = Keypair::generate();
        let keystore = Keystore::create(&keypair, "contraseña-de-test").expect("cifra sin error");

        let json = keystore.to_json();
        let parsed = Keystore::from_json(&json).expect("parsea sin error");
        assert_eq!(parsed.address, keypair.address());

        let decrypted = parsed.decrypt("contraseña-de-test").expect("descifra con la contraseña correcta");
        assert_eq!(decrypted.address(), keypair.address());
    }

    #[test]
    fn wrong_password_fails_to_decrypt() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("keystore.json");
        let keypair = Keypair::generate();

        Keystore::create(&keypair, "la-correcta").expect("cifra sin error").save(&path).expect("guarda sin error");

        let loaded = Keystore::load(&path).expect("carga sin error");
        // `Keypair` no deriva `Debug` a propósito (evita que un logueo
        // accidental exponga material sensible) — por eso `matches!`
        // sobre el `Result` en vez de `.unwrap_err()`, que exige `Debug`.
        assert!(matches!(loaded.decrypt("otra-distinta"), Err(KeystoreError::WrongPassword)));
    }

    #[test]
    fn ciphertext_does_not_decrypt_under_a_different_address_aad() {
        // Simula mezclar el ciphertext de un keystore con la dirección de
        // otro (a mano, no debería pasar en uso normal) — la
        // autenticación AEAD sobre `address` como AAD tiene que rechazarlo.
        let keypair_a = Keypair::generate();
        let keypair_b = Keypair::generate();

        let mut keystore = Keystore::create(&keypair_a, "una-contraseña").expect("cifra sin error");
        keystore.address = keypair_b.address();

        assert!(matches!(keystore.decrypt("una-contraseña"), Err(KeystoreError::WrongPassword)));
    }
}
