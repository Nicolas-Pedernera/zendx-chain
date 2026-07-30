//! Carga y parseo de `genesis/devnet.json` — ver `docs/ARCHITECTURE.md`.
//!
//! `subsidy_schedule` declara los escalones "irregulares" del calendario
//! de emisión (`subsidy_schedule[k]` rige el período `k`-ésimo de
//! `subsidy_period_blocks` bloques); pasado el último escalón, el
//! subsidio sigue dividiéndose a la mitad cada período (ver
//! `znx_consensus::subsidy_for_height`). Un solo elemento reproduce el
//! halving puro de siempre — es lo que usa el devnet.
//!
//! `premine` es opcional (default: lista vacía) — asigna ZNX directo a
//! direcciones concretas en el bloque género, como una coinbase de altura
//! 0 (ver `bootstrap_genesis` en `lib.rs`). El devnet no declara premine:
//! sigue arrancando de cero, cualquiera mina desde el primer bloque.
//!
//! Los montos (`subsidy_schedule`, `premine[].amount`) viajan como string
//! en el JSON (un u128 puede exceder el rango seguro de un `number` de
//! JSON/JS), así que se parsean a mano acá en vez de con
//! `#[serde(deserialize_with = ...)]` genérico — el archivo es chico y a
//! mano es más simple de auditar.

use std::path::Path;

use serde::Deserialize;
use thiserror::Error;
use znx_crypto::{Address, CryptoError};

#[derive(Debug, Error)]
pub enum GenesisError {
    #[error("no se pudo leer el archivo de génesis: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON de génesis inválido: {0}")]
    Json(#[from] serde_json::Error),
    #[error("`subsidy_schedule` no puede estar vacío")]
    EmptySubsidySchedule,
    #[error("`subsidy_schedule[{index}]` inválido en el génesis: '{value}' no es un u128 válido")]
    InvalidSubsidy { index: usize, value: String },
    #[error("`initial_target` inválido en el génesis: {0}")]
    InvalidTarget(String),
    #[error("`genesis_time` inválido (se espera RFC3339): {0}")]
    InvalidTimestamp(String),
    #[error("dirección de premine inválida ('{0}'): {1}")]
    InvalidPremineAddress(String, CryptoError),
    #[error("monto de premine inválido para '{address}': '{value}' no es un u128 válido")]
    InvalidPremineAmount { address: String, value: String },
}

#[derive(Debug, Deserialize)]
struct RawPremineEntry {
    address: String,
    amount: String,
}

#[derive(Debug, Deserialize)]
struct RawGenesis {
    chain_id: String,
    genesis_time: String,
    subsidy_schedule: Vec<String>,
    subsidy_period_blocks: u64,
    target_block_time_secs: u64,
    difficulty_adjustment_interval_blocks: u64,
    initial_target: String,
    #[serde(default)]
    premine: Vec<RawPremineEntry>,
}

/// Génesis ya parseado y validado — subsidios de `String` a `u128`, target
/// de hex a `[u8; 32]`, timestamp de RFC3339 a segundos Unix, direcciones
/// de premine de bech32 a `Address`.
#[derive(Debug, Clone)]
pub struct Genesis {
    pub chain_id: String,
    pub genesis_time_unix: u64,
    pub subsidy_schedule: Vec<u128>,
    pub subsidy_period_blocks: u64,
    pub target_block_time_secs: u64,
    pub difficulty_adjustment_interval_blocks: u64,
    pub initial_target: [u8; 32],
    pub premine: Vec<(Address, u128)>,
}

impl Genesis {
    pub fn load(path: &Path) -> Result<Self, GenesisError> {
        let contents = std::fs::read_to_string(path)?;
        let raw: RawGenesis = serde_json::from_str(&contents)?;

        let genesis_time_unix = chrono::DateTime::parse_from_rfc3339(&raw.genesis_time)
            .map_err(|e| GenesisError::InvalidTimestamp(e.to_string()))?
            .timestamp()
            .try_into()
            .map_err(|_| GenesisError::InvalidTimestamp(raw.genesis_time.clone()))?;

        if raw.subsidy_schedule.is_empty() {
            return Err(GenesisError::EmptySubsidySchedule);
        }
        let subsidy_schedule = raw
            .subsidy_schedule
            .iter()
            .enumerate()
            .map(|(index, value)| value.parse::<u128>().map_err(|_| GenesisError::InvalidSubsidy { index, value: value.clone() }))
            .collect::<Result<Vec<_>, _>>()?;

        let target_bytes = hex::decode(&raw.initial_target).map_err(|e| GenesisError::InvalidTarget(e.to_string()))?;
        let initial_target: [u8; 32] = target_bytes
            .try_into()
            .map_err(|_| GenesisError::InvalidTarget("tiene que ser de 32 bytes (64 caracteres hex)".to_string()))?;

        let premine = raw
            .premine
            .into_iter()
            .map(|entry| {
                let address = Address::from_bech32(&entry.address).map_err(|e| GenesisError::InvalidPremineAddress(entry.address.clone(), e))?;
                let amount = entry
                    .amount
                    .parse::<u128>()
                    .map_err(|_| GenesisError::InvalidPremineAmount { address: entry.address.clone(), value: entry.amount.clone() })?;
                Ok((address, amount))
            })
            .collect::<Result<Vec<_>, GenesisError>>()?;

        Ok(Genesis {
            chain_id: raw.chain_id,
            genesis_time_unix,
            subsidy_schedule,
            subsidy_period_blocks: raw.subsidy_period_blocks,
            target_block_time_secs: raw.target_block_time_secs,
            difficulty_adjustment_interval_blocks: raw.difficulty_adjustment_interval_blocks,
            initial_target,
            premine,
        })
    }
}
