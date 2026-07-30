//! znx-crypto — primitivas criptográficas del protocolo: llaves ed25519,
//! firmas, hashing (blake3) y derivación de direcciones (bech32, prefijo
//! `znx`). Ningún otro crate del workspace debe implementar cripto propia;
//! todo pasa por acá para que la superficie auditable quede en un solo lugar.

use bech32::{Bech32, Hrp};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use getrandom::SysRng;
use rand_core::UnwrapErr;
use thiserror::Error;
use zeroize::Zeroize;

/// Prefijo humano (HRP) de las direcciones de la chain, ej. `znx1...`.
pub const ADDRESS_HRP: &str = "znx";

/// Direcciones son blake3(pubkey) truncado a 20 bytes — mismo largo que
/// Ethereum, suficiente espacio para evitar colisiones prácticas mientras
/// se mantiene la representación de texto corta.
pub const ADDRESS_LEN: usize = 20;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("firma inválida")]
    InvalidSignature,
    #[error("bytes de llave pública con largo inválido")]
    InvalidPublicKeyLength,
    #[error("no se pudo decodificar la dirección: {0}")]
    AddressDecode(String),
    #[error("prefijo de dirección inesperado: se esperaba '{expected}', se encontró '{found}'")]
    UnexpectedHrp { expected: String, found: String },
}

/// Dirección de cuenta: 20 bytes derivados de la llave pública. `Copy` y
/// `Ord` a propósito — se usa como clave de mapas de estado y en índices
/// de storage, donde comparar/clonar tiene que ser barato. `BorshSerialize`/
/// `BorshDeserialize` para que znx-types pueda embeberla directo en
/// `Transaction`/`Account` sin una capa de conversión intermedia.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, borsh::BorshSerialize, borsh::BorshDeserialize)]
pub struct Address(pub [u8; ADDRESS_LEN]);

impl Address {
    /// Deriva la dirección de una llave pública: blake3(pubkey)[..20].
    /// Determinístico — la misma pubkey siempre da la misma dirección, en
    /// cualquier nodo, sin estado compartido.
    pub fn from_public_key(pk: &VerifyingKey) -> Self {
        let digest = blake3::hash(pk.as_bytes());
        let mut bytes = [0u8; ADDRESS_LEN];
        bytes.copy_from_slice(&digest.as_bytes()[..ADDRESS_LEN]);
        Address(bytes)
    }

    pub fn to_bech32(&self) -> String {
        let hrp = Hrp::parse(ADDRESS_HRP).expect("HRP estático válido");
        bech32::encode::<Bech32>(hrp, &self.0).expect("20 bytes siempre codifican")
    }

    pub fn from_bech32(s: &str) -> Result<Self, CryptoError> {
        let (hrp, data) = bech32::decode(s).map_err(|e| CryptoError::AddressDecode(e.to_string()))?;
        if hrp.as_str() != ADDRESS_HRP {
            return Err(CryptoError::UnexpectedHrp {
                expected: ADDRESS_HRP.to_string(),
                found: hrp.as_str().to_string(),
            });
        }
        let bytes: [u8; ADDRESS_LEN] = data
            .try_into()
            .map_err(|_| CryptoError::InvalidPublicKeyLength)?;
        Ok(Address(bytes))
    }
}

impl std::fmt::Display for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_bech32())
    }
}

/// Par de llaves de un validador o cuenta. La llave privada nunca se
/// serializa como parte de este tipo (no deriva `Serialize`) — solo vive
/// en memoria y se pisa con ceros al soltarse (`Drop` vía `zeroize`).
pub struct Keypair {
    signing_key: SigningKey,
}

impl Keypair {
    /// Genera un par de llaves nuevo con el RNG del sistema operativo
    /// (`SysRng`, vía `getrandom`) — nunca usar un RNG determinístico/con
    /// seed fija fuera de tests, filtraría la llave privada. `SysRng` es
    /// falible (`TryCryptoRng`, el syscall de entropía en teoría puede
    /// fallar) — `UnwrapErr` lo vuelve infalible entrando en pánico si
    /// eso pasara, que es la respuesta correcta: sin entropía real no hay
    /// forma segura de generar una llave.
    pub fn generate() -> Self {
        let mut rng = UnwrapErr(SysRng);
        let signing_key = SigningKey::generate(&mut rng);
        Keypair { signing_key }
    }

    /// Reconstruye un keypair a partir de 32 bytes de llave privada cruda
    /// (ej. leídos de un keystore cifrado en disco). El caller es
    /// responsable de haber protegido esos bytes hasta acá.
    pub fn from_secret_bytes(bytes: [u8; 32]) -> Self {
        let signing_key = SigningKey::from_bytes(&bytes);
        Keypair { signing_key }
    }

    pub fn public_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }

    pub fn address(&self) -> Address {
        Address::from_public_key(&self.public_key())
    }

    pub fn sign(&self, message: &[u8]) -> Signature {
        self.signing_key.sign(message)
    }

    /// Bytes crudos de la llave privada — solo para persistir en un
    /// keystore cifrado. Quien reciba este valor es responsable de
    /// `zeroize`-arlo cuando termine de usarlo.
    pub fn secret_bytes(&self) -> [u8; 32] {
        self.signing_key.to_bytes()
    }
}

impl Drop for Keypair {
    fn drop(&mut self) {
        let mut bytes = self.signing_key.to_bytes();
        bytes.zeroize();
    }
}

/// Verifica una firma contra una llave pública y un mensaje. No hay forma
/// de verificar "en general" sin la pubkey — evita el error clásico de
/// aceptar la pubkey embebida en el propio mensaje sin validarla contra
/// la dirección remitente (eso lo hace la capa de znx-state, no acá).
pub fn verify(public_key: &VerifyingKey, message: &[u8], signature: &Signature) -> Result<(), CryptoError> {
    public_key
        .verify(message, signature)
        .map_err(|_| CryptoError::InvalidSignature)
}

pub fn public_key_from_bytes(bytes: &[u8]) -> Result<VerifyingKey, CryptoError> {
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| CryptoError::InvalidPublicKeyLength)?;
    VerifyingKey::from_bytes(&arr).map_err(|_| CryptoError::InvalidPublicKeyLength)
}

/// Deriva la dirección directo desde bytes crudos de llave pública — atajo
/// para consumidores (ej. znx-state validando una transacción) que reciben
/// la pubkey por red/storage como `[u8; 32]` y no quieren pasar por el tipo
/// `VerifyingKey` de ed25519-dalek explícitamente.
pub fn address_from_public_key_bytes(bytes: &[u8; 32]) -> Result<Address, CryptoError> {
    let pk = public_key_from_bytes(bytes)?;
    Ok(Address::from_public_key(&pk))
}

/// Verifica una firma a partir de bytes crudos (pubkey de 32 bytes, firma
/// de 64 bytes) — evita que cada crate consumidor tenga que importar
/// `ed25519-dalek` directo solo para reconstruir `VerifyingKey`/`Signature`
/// antes de llamar a `verify`.
pub fn verify_raw(public_key_bytes: &[u8; 32], message: &[u8], signature_bytes: &[u8; 64]) -> Result<(), CryptoError> {
    let public_key = public_key_from_bytes(public_key_bytes)?;
    let signature = Signature::from_bytes(signature_bytes);
    verify(&public_key, message, &signature)
}

/// Hash blake3 genérico de 32 bytes — usado tanto para direcciones como
/// para roots de bloque/estado en znx-storage/znx-types.
pub fn hash(data: &[u8]) -> [u8; 32] {
    *blake3::hash(data).as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_and_verify_roundtrip() {
        let kp = Keypair::generate();
        let msg = b"transferencia de prueba";
        let sig = kp.sign(msg);
        assert!(verify(&kp.public_key(), msg, &sig).is_ok());
    }

    #[test]
    fn verify_rejects_tampered_message() {
        let kp = Keypair::generate();
        let sig = kp.sign(b"monto: 100");
        assert!(verify(&kp.public_key(), b"monto: 100000", &sig).is_err());
    }

    #[test]
    fn verify_rejects_wrong_key() {
        let kp1 = Keypair::generate();
        let kp2 = Keypair::generate();
        let sig = kp1.sign(b"hola");
        assert!(verify(&kp2.public_key(), b"hola", &sig).is_err());
    }

    #[test]
    fn address_is_deterministic() {
        let kp = Keypair::generate();
        let a1 = kp.address();
        let a2 = Address::from_public_key(&kp.public_key());
        assert_eq!(a1, a2);
    }

    #[test]
    fn address_bech32_roundtrip() {
        let kp = Keypair::generate();
        let addr = kp.address();
        let encoded = addr.to_bech32();
        assert!(encoded.starts_with("znx1"));
        let decoded = Address::from_bech32(&encoded).expect("decodifica");
        assert_eq!(addr, decoded);
    }

    #[test]
    fn address_from_bech32_rejects_wrong_hrp() {
        // bech32 arbitrario con otro HRP (bc1... estilo Bitcoin) — tiene
        // que rechazarse por prefijo, no aceptarse silenciosamente.
        let hrp = Hrp::parse("bc").unwrap();
        let bogus = bech32::encode::<Bech32>(hrp, &[0u8; ADDRESS_LEN]).unwrap();
        assert!(matches!(
            Address::from_bech32(&bogus),
            Err(CryptoError::UnexpectedHrp { .. })
        ));
    }

    #[test]
    fn secret_bytes_roundtrip_produces_same_keypair() {
        let kp1 = Keypair::generate();
        let secret = kp1.secret_bytes();
        let kp2 = Keypair::from_secret_bytes(secret);
        assert_eq!(kp1.public_key(), kp2.public_key());
        assert_eq!(kp1.address(), kp2.address());
    }

    #[test]
    fn verify_raw_roundtrip() {
        let kp = Keypair::generate();
        let msg = b"transferencia de prueba";
        let sig = kp.sign(msg);
        assert!(verify_raw(&kp.public_key().to_bytes(), msg, &sig.to_bytes()).is_ok());
    }

    #[test]
    fn verify_raw_rejects_tampered_message() {
        let kp = Keypair::generate();
        let sig = kp.sign(b"monto: 100");
        assert!(verify_raw(&kp.public_key().to_bytes(), b"monto: 100000", &sig.to_bytes()).is_err());
    }

    #[test]
    fn address_from_public_key_bytes_matches_typed_derivation() {
        let kp = Keypair::generate();
        let via_bytes = address_from_public_key_bytes(&kp.public_key().to_bytes()).expect("pubkey válida");
        assert_eq!(via_bytes, kp.address());
    }

    #[test]
    fn hash_is_deterministic_and_avalanches() {
        let h1 = hash(b"zendx");
        let h2 = hash(b"zendx");
        let h3 = hash(b"zendY");
        assert_eq!(h1, h2);
        assert_ne!(h1, h3);
    }
}
