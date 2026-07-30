//! znx-wallet — lógica de wallet compartida entre `znx-wallet-cli` (CLI
//! interactiva de devnet) y `znx-custody` (servicio de firma sin
//! interacción humana, ver `blockchain/docs/INTEGRATION.md`). Antes vivía
//! duplicada dentro del binario de `znx-wallet-cli` — se extrae acá para
//! que un segundo proceso pueda reusar exactamente la misma mecánica de
//! cifrado de llave y de armado/firma/envío de transferencias, en vez de
//! reimplementarla (y arriesgar una divergencia sutil en algo que firma
//! dinero).

mod client;
mod keystore;

pub use client::{build_transfer, fetch_unspent, http_client, latest_height, select_utxos, send, submit_transaction, transaction_height, WalletError};
pub use keystore::{Keystore, KeystoreError};
