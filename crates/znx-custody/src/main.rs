//! znx-custody — servicio de firma de retiros para el backend de
//! `zendx` (diseño en `blockchain/docs/INTEGRATION.md`). Mantiene
//! descifrada en memoria la llave privada de la wallet caliente de la
//! plataforma (nunca en disco, nunca logueada) y expone un único método
//! JSON-RPC de escritura (`sign_withdrawal`) para que el backend pida una
//! transferencia sin manejar la llave privada directamente — reusa la
//! misma mecánica de keystore cifrado y de armado/firma/envío que
//! `znx-wallet-cli` (crate `znx-wallet`), apuntando a un `znx-node` real.
//!
//! **No pensado para exponerse a internet**: el bind por default es
//! localhost. En Render vive como Private Service, sin URL pública.
//!
//! **Polling saliente contra Supabase** (opcional, activado si
//! `--supabase-url`/env `SUPABASE_URL` y la env `CUSTODY_POLL_SECRET`
//! están seteados): en vez de que la Edge Function de `zendx` le pegue a
//! este proceso (que exigiría exponerlo a internet), este proceso
//! consulta periódicamente `listarRetirosZNX` buscando filas
//! `wallet_movements` pendientes, las firma localmente reusando la misma
//! lógica que `sign_withdrawal`, y reporta el resultado a
//! `confirmarRetiroZNX` — todo saliente, nunca expone un puerto. Ver
//! "Flujo de retiro" en `INTEGRATION.md`.

use std::collections::HashMap;
use std::io::Write;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use clap::Parser;
use jsonrpsee::server::Server;
use jsonrpsee::types::{ErrorCode, ErrorObjectOwned};
use jsonrpsee::RpcModule;
use jsonrpsee_http_client::HttpClient;
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex as AsyncMutex;

use znx_crypto::{Address, Keypair};
use znx_wallet::Keystore;

#[derive(Parser)]
#[command(about = "Servicio de firma de retiros de Zend X Chain (custodia de la wallet caliente de la plataforma)")]
struct Cli {
    /// Keystore cifrado de la wallet caliente de la plataforma (mismo
    /// formato que genera `znx-wallet-cli keygen`).
    #[arg(long, value_name = "PATH")]
    keystore: PathBuf,

    /// `znx-rpc` del nodo contra el que arma/manda transferencias. También
    /// se puede setear por `ZNX_NODE_URL` (así, en un despliegue en
    /// Render, el servicio de custodia puede recibir la URL interna del
    /// nodo vía `fromService` en `render.yaml` sin hardcodearla).
    #[arg(long, env = "ZNX_NODE_URL", default_value = "http://127.0.0.1:26657")]
    node: String,

    /// Interfaz donde escucha este servicio. Por default solo
    /// localhost — ver el aviso de módulo sobre no exponerlo a internet.
    #[arg(long, default_value = "127.0.0.1")]
    listen_host: String,

    /// Puerto donde escucha. También se puede setear por `PORT` — la
    /// convención que usa Render para decirle a un servicio web en qué
    /// puerto tiene que escuchar (ver blockchain/render.yaml).
    #[arg(long, env = "PORT", default_value_t = 26658)]
    listen_port: u16,

    /// `chain_id` a usar al armar transferencias — tiene que coincidir
    /// con el del nodo, si no toda tx se rechaza al mandarla.
    #[arg(long)]
    chain_id: String,

    /// Archivo de journal (JSON-lines, uno por retiro ya procesado) que
    /// hace idempotente a `sign_withdrawal` — ver doc de módulo de
    /// `Journal`. Se crea si no existe.
    #[arg(long, value_name = "PATH", default_value = "znx-custody-journal.jsonl")]
    journal: PathBuf,

    /// URL base del proyecto de Supabase contra el que hacer polling de
    /// retiros pendientes (ver doc de módulo). Si no se setea (ni por
    /// flag ni por env `SUPABASE_URL`), el polling queda deshabilitado —
    /// el resto del binario funciona igual (RPC `sign_withdrawal` normal).
    #[arg(long, env = "SUPABASE_URL")]
    supabase_url: Option<String>,

    /// Cada cuántos segundos consultar `listarRetirosZNX`/direcciones de
    /// depósito (mismo tick para ambos, no dos timers separados).
    #[arg(long, default_value_t = 20)]
    poll_interval_secs: u64,

    /// Confirmaciones necesarias antes de acreditar (y barrer) un
    /// depósito ZNX. `INTEGRATION.md` deja este número formalmente sin
    /// decidir — este default es revisable sin tocar el resto del diseño.
    #[arg(long, default_value_t = 6)]
    deposit_confirmations: u64,
}

/// Contraseña que desbloquea el keystore de custodia al arrancar. Mismo
/// atajo que `znx-wallet-cli` (`ZNX_WALLET_PASSWORD`), pero con su propia
/// variable — en un despliegue real esto lo provee un secret manager
/// (Supabase Vault u otro), no una terminal interactiva.
fn read_keystore_password() -> String {
    if let Ok(password) = std::env::var("ZNX_CUSTODY_PASSWORD") {
        return password;
    }
    rpassword::prompt_password("Contraseña del keystore de custodia: ").unwrap_or_else(|e| panic!("no se pudo leer la contraseña: {e}"))
}

/// Comparación en tiempo constante — evita que la duración de la
/// comparación filtre por timing cuántos bytes iniciales del token
/// coinciden (un `==` de `&str`/`Vec<u8>` normal corta en el primer byte
/// distinto). El shared secret es la única barrera de autenticación de
/// este servicio hoy, vale la pena no regalar ni ese margen.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b.iter()).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Decimales de la chain — ver `decimals: 18` en `genesis/devnet.json`.
const ZNX_DECIMALS: u32 = 18;

/// Convierte un monto decimal en ZNX enteros (lo que guarda
/// `wallet_movements.monto`, ej. `"12.5"`) a unidades base on-chain
/// (`u128`, lo que espera `znx_wallet::send`). Aritmética puramente de
/// enteros/strings — nunca pasa por `f64`: un `f64` no representa exacto
/// la mayoría de los decimales, y a esta escala (10^18) el error de
/// redondeo es plata real perdida o de más, no un detalle cosmético.
fn parse_znx_decimal_to_base_units(raw: &str) -> Result<u128, String> {
    let s = raw.trim();
    if s.is_empty() {
        return Err("monto vacío".to_string());
    }
    if s.starts_with('-') {
        return Err("monto negativo".to_string());
    }

    let mut parts = s.splitn(2, '.');
    let int_part = parts.next().unwrap_or("");
    let frac_part = parts.next().unwrap_or("");

    let int_part = if int_part.is_empty() { "0" } else { int_part };
    if !int_part.chars().all(|c| c.is_ascii_digit()) {
        return Err(format!("`{raw}` no es un monto decimal válido"));
    }
    if !frac_part.chars().all(|c| c.is_ascii_digit()) {
        return Err(format!("`{raw}` no es un monto decimal válido"));
    }
    if frac_part.len() > ZNX_DECIMALS as usize {
        return Err(format!("`{raw}` tiene más de {ZNX_DECIMALS} decimales"));
    }

    let scale = 10u128.checked_pow(ZNX_DECIMALS).expect("10^18 cabe en u128");
    let int_units: u128 = int_part.parse().map_err(|_| format!("`{raw}` desborda u128"))?;
    let int_base = int_units.checked_mul(scale).ok_or_else(|| format!("`{raw}` desborda u128"))?;

    let padded_frac = format!("{frac_part:0<width$}", width = ZNX_DECIMALS as usize);
    let frac_units: u128 = if padded_frac.is_empty() { 0 } else { padded_frac.parse().map_err(|_| format!("`{raw}` no es un monto decimal válido"))? };

    let total = int_base.checked_add(frac_units).ok_or_else(|| format!("`{raw}` desborda u128"))?;
    if total == 0 {
        return Err("el monto tiene que ser mayor a cero".to_string());
    }
    Ok(total)
}

/// Inversa de `parse_znx_decimal_to_base_units` — usada al reportar un
/// depósito detectado on-chain (unidades base) como el `monto` decimal
/// que espera Postgres. Misma disciplina de enteros, nunca floats.
fn format_base_units_as_znx_decimal(units: u128) -> String {
    let scale = 10u128.checked_pow(ZNX_DECIMALS).expect("10^18 cabe en u128");
    let int_part = units / scale;
    let frac_part = units % scale;
    if frac_part == 0 {
        return int_part.to_string();
    }
    let frac_str = format!("{frac_part:0width$}", width = ZNX_DECIMALS as usize);
    let trimmed = frac_str.trim_end_matches('0');
    format!("{int_part}.{trimmed}")
}

#[derive(Debug, Deserialize)]
struct SignWithdrawalParams {
    /// Identificador elegido por quien llama (en la práctica, el id de la
    /// fila `withdrawal_requests` del lado de `zendx`) — la clave que hace
    /// idempotente este método. Ver `Journal`.
    request_id: String,
    to: String,
    amount: String,
    #[serde(default)]
    fee: Option<String>,
    auth_token: String,
}

#[derive(Debug, Clone, Serialize)]
struct SignWithdrawalResult {
    txid: String,
}

#[derive(Debug, Clone, Serialize)]
struct CustodyAddressResult {
    address: String,
}

fn invalid_params(message: impl std::fmt::Display) -> ErrorObjectOwned {
    ErrorObjectOwned::owned(ErrorCode::InvalidParams.code(), message.to_string(), None::<()>)
}

fn internal_error(message: impl std::fmt::Display) -> ErrorObjectOwned {
    ErrorObjectOwned::owned(ErrorCode::InternalError.code(), message.to_string(), None::<()>)
}

/// Falla cerrado (rechaza todo pedido) si `ZNX_CUSTODY_TOKEN` no está
/// configurado — nunca "sin token configurado, dejo pasar cualquiera".
fn check_auth(token: &str) -> Result<(), ErrorObjectOwned> {
    let expected = std::env::var("ZNX_CUSTODY_TOKEN")
        .map_err(|_| internal_error("ZNX_CUSTODY_TOKEN no está configurado en el proceso — rechazo por defecto (fail-closed)"))?;
    if !constant_time_eq(token.as_bytes(), expected.as_bytes()) {
        return Err(invalid_params("auth_token inválido"));
    }
    Ok(())
}

/// Registro de un retiro ya procesado — lo que hace falta para poder
/// devolver la misma respuesta ante un pedido repetido, y para detectar
/// si un `request_id` se reusó con parámetros distintos (un bug del
/// llamador, no un reintento legítimo).
#[derive(Debug, Clone, Serialize, Deserialize)]
struct JournalEntry {
    request_id: String,
    to: String,
    amount: String,
    fee: String,
    txid: String,
}

/// Journal en disco (JSON-lines, un `JournalEntry` por línea) de los
/// retiros ya procesados. Existe para que `sign_withdrawal` sea
/// idempotente: si la Edge Function que llama se cae después de que la
/// tx salió on-chain pero antes de guardar el `txid` en Postgres, alcanza
/// con reintentar `sign_withdrawal` con el mismo `request_id` — nunca
/// hace falta escanear la cadena para "reconciliar" (`znx-rpc` ni
/// siquiera tiene forma de listar transacciones *enviadas* desde una
/// dirección, solo UTXOs no gastados). Se relee entero al arrancar
/// (simple: el volumen de retiros de un devnet no justifica un índice más
/// sofisticado) y sobrevive un restart del proceso al vivir en disco, no
/// solo en memoria.
struct Journal {
    path: PathBuf,
    entries: HashMap<String, JournalEntry>,
}

impl Journal {
    fn load(path: PathBuf) -> Self {
        let mut entries = HashMap::new();
        if let Ok(contents) = std::fs::read_to_string(&path) {
            for line in contents.lines().filter(|l| !l.trim().is_empty()) {
                let entry: JournalEntry = serde_json::from_str(line).unwrap_or_else(|e| panic!("línea corrupta en el journal {path:?}: {e}"));
                entries.insert(entry.request_id.clone(), entry);
            }
        }
        Journal { path, entries }
    }

    fn get(&self, request_id: &str) -> Option<&JournalEntry> {
        self.entries.get(request_id)
    }

    /// Agrega una entrada nueva — asume que el llamador ya chequeó que
    /// `request_id` no existía (`sign_withdrawal` lo hace bajo el mismo
    /// lock que protege esta escritura, ver el handler).
    fn append(&mut self, entry: JournalEntry) {
        let line = serde_json::to_string(&entry).expect("JournalEntry siempre serializa");
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .unwrap_or_else(|e| panic!("no se pudo abrir el journal {:?}: {e}", self.path));
        writeln!(file, "{line}").unwrap_or_else(|e| panic!("no se pudo escribir en el journal {:?}: {e}", self.path));
        self.entries.insert(entry.request_id.clone(), entry);
    }
}

struct CustodyContext {
    keypair: Keypair,
    client: HttpClient,
    chain_id: String,
    journal: AsyncMutex<Journal>,
}

/// Arma+firma+manda un retiro y lo registra en el journal — el corazón
/// de `sign_withdrawal`, sacado a función propia para que lo reuse tanto
/// el handler RPC (llamado directo) como el loop de polling contra
/// Supabase (ver doc de módulo). Idempotente por `request_id`: si ya
/// existe en el journal con los mismos parámetros, devuelve el mismo
/// txid sin volver a firmar/mandar; con parámetros distintos, rechaza.
///
/// El lock del journal se mantiene durante todo el armado/firma/envío
/// (no solo la consulta/escritura): además de la idempotencia, serializa
/// los retiros entre sí, evitando que dos pedidos concurrentes elijan
/// UTXOs superpuestos y uno de los dos falle por doble gasto.
async fn process_withdrawal(ctx: &CustodyContext, request_id: String, to_raw: String, to: Address, amount: u128, fee: u128) -> Result<String, String> {
    let amount_str = amount.to_string();
    let fee_str = fee.to_string();

    let mut journal = ctx.journal.lock().await;
    if let Some(existing) = journal.get(&request_id) {
        if existing.to != to_raw || existing.amount != amount_str || existing.fee != fee_str {
            return Err(format!("request_id {request_id} ya se usó antes con otros parámetros"));
        }
        return Ok(existing.txid.clone());
    }

    let txid = znx_wallet::send(&ctx.client, ctx.chain_id.clone(), &ctx.keypair, to, amount, fee).await.map_err(|e| e.to_string())?;
    let txid_hex = hex::encode(txid);
    journal.append(JournalEntry { request_id, to: to_raw, amount: amount_str, fee: fee_str, txid: txid_hex.clone() });
    Ok(txid_hex)
}

#[derive(Debug, Deserialize)]
struct PendingWithdrawal {
    id: String,
    monto: String,
    destino: String,
}

#[derive(Debug, Serialize)]
struct ConfirmarRetiroBody<'a> {
    movement_id: &'a str,
    resultado: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    txid: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    motivo: Option<&'a str>,
}

/// Le avisa a `confirmarRetiroZNX` el resultado de un retiro — solo loguea
/// si falla el POST en sí (red, Supabase caído): no hay a quién más
/// devolverle el error acá, y no vale la pena reintentar el reporte
/// mismo, el próximo ciclo de polling ya va a volver a ver la fila si
/// hizo falta.
async fn reportar_resultado_retiro(http: &reqwest::Client, supabase_url: &str, poll_secret: &str, movement_id: &str, resultado: &str, txid: Option<&str>, motivo: Option<&str>) {
    let url = format!("{supabase_url}/functions/v1/confirmarRetiroZNX");
    let body = ConfirmarRetiroBody { movement_id, resultado, txid, motivo };
    if let Err(e) = http.post(&url).header("x-custody-secret", poll_secret).json(&body).send().await {
        eprintln!("znx-custody: no se pudo reportar el resultado del retiro {movement_id} a Supabase: {e}");
    }
}

/// Procesa un único retiro pendiente que devolvió `listarRetirosZNX`.
/// Dos clases de error, tratadas distinto:
/// - **Permanente** (dirección o monto inválido): no tiene sentido
///   reintentar, se reporta `fallido` ya mismo (dispara el crédito de
///   vuelta del lado de Supabase).
/// - **Transitorio** (nodo caído, red, etc.): no se reporta nada, la fila
///   queda `procesando` y este mismo loop la vuelve a ver en el próximo
///   tick — es el mecanismo de reconciliación por idempotencia que ya
///   describe `INTEGRATION.md`, no hace falta un job aparte.
async fn procesar_retiro_pendiente(ctx: &CustodyContext, http: &reqwest::Client, supabase_url: &str, poll_secret: &str, item: PendingWithdrawal) {
    let to = match Address::from_bech32(&item.destino) {
        Ok(addr) => addr,
        Err(e) => {
            eprintln!("znx-custody: retiro {} tiene un destino inválido ({e}), lo marco fallido", item.id);
            reportar_resultado_retiro(http, supabase_url, poll_secret, &item.id, "fallido", None, Some("dirección de destino inválida")).await;
            return;
        }
    };

    let amount = match parse_znx_decimal_to_base_units(&item.monto) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("znx-custody: retiro {} tiene un monto inválido ({e}), lo marco fallido", item.id);
            reportar_resultado_retiro(http, supabase_url, poll_secret, &item.id, "fallido", None, Some("monto inválido")).await;
            return;
        }
    };

    match process_withdrawal(ctx, item.id.clone(), item.destino.clone(), to, amount, 0).await {
        Ok(txid) => reportar_resultado_retiro(http, supabase_url, poll_secret, &item.id, "completado", Some(&txid), None).await,
        Err(e) => eprintln!("znx-custody: retiro {} no se pudo procesar todavía, reintento en el próximo ciclo: {e}", item.id),
    }
}

/// POST genérico con `x-custody-secret` + body JSON, deserializando la
/// respuesta — el mismo patrón se repite para las 4 llamadas de
/// solicitud/scan de depósitos, factorizado acá para no repetirlo.
async fn poll_get<T: serde::de::DeserializeOwned>(http: &reqwest::Client, supabase_url: &str, poll_secret: &str, function_name: &str) -> Result<T, String> {
    let url = format!("{supabase_url}/functions/v1/{function_name}");
    let resp = http.post(&url).header("x-custody-secret", poll_secret).send().await.map_err(|e| e.to_string())?;
    if !resp.status().is_success() {
        return Err(format!("{function_name} devolvió {}", resp.status()));
    }
    resp.json::<T>().await.map_err(|e| e.to_string())
}

#[derive(Debug, Deserialize)]
struct PendingDepositAddressRequest {
    id: String,
}

#[derive(Debug, Serialize)]
struct ConfirmarDireccionDepositoBody<'a> {
    solicitud_id: &'a str,
    address: &'a str,
    encrypted_keystore: &'a str,
}

/// Cumple solicitudes de dirección de depósito pendientes: por cada una,
/// genera un `Keypair` independiente nuevo (ver doc de módulo — sin
/// derivación jerárquica, cada dirección de depósito es una llave propia
/// sin relación con las demás ni con la de custodia), lo cifra con
/// `ZNX_DEPOSIT_KEYS_PASSWORD` (distinta de la del keystore de custodia
/// — un secreto de menor blast radius) y reporta la dirección + el
/// keystore cifrado. El ciphertext viaja tal cual por HTTP y se guarda
/// en Postgres — inofensivo sin la contraseña, mismo principio que
/// `deploy/devnet-custody-keystore.json`.
async fn cumplir_solicitudes_deposito(http: &reqwest::Client, supabase_url: &str, poll_secret: &str, deposit_password: &str) {
    let solicitudes: Vec<PendingDepositAddressRequest> = match poll_get(http, supabase_url, poll_secret, "listarSolicitudesDepositoZNX").await {
        Ok(s) => s,
        Err(e) => {
            eprintln!("znx-custody: no se pudo consultar listarSolicitudesDepositoZNX: {e}");
            return;
        }
    };

    for solicitud in solicitudes {
        let keypair = Keypair::generate();
        let address = keypair.address().to_bech32();
        let encrypted_keystore = match Keystore::create(&keypair, deposit_password) {
            Ok(ks) => ks.to_json(),
            Err(e) => {
                eprintln!("znx-custody: no se pudo cifrar la nueva dirección de depósito para la solicitud {}: {e}", solicitud.id);
                continue;
            }
        };

        let url = format!("{supabase_url}/functions/v1/confirmarDireccionDepositoZNX");
        let body = ConfirmarDireccionDepositoBody { solicitud_id: &solicitud.id, address: &address, encrypted_keystore: &encrypted_keystore };
        if let Err(e) = http.post(&url).header("x-custody-secret", poll_secret).json(&body).send().await {
            eprintln!("znx-custody: no se pudo confirmar la dirección de depósito de la solicitud {}: {e}", solicitud.id);
        }
    }
}

#[derive(Debug, Deserialize)]
struct DepositAddress {
    id: String,
    address: String,
    encrypted_keystore: String,
}

#[derive(Debug, Serialize)]
struct ConfirmarDepositoBody<'a> {
    address_id: &'a str,
    tx_hash: &'a str,
    vout: u32,
    amount: &'a str,
}

/// Escanea una dirección de depósito activa: por cada UTXO con
/// confirmaciones suficientes, reporta el depósito (idempotente del lado
/// de Supabase por `unique(tx_hash, vout)` — un mismo UTXO reportado dos
/// veces, ej. porque el barrido de un ciclo anterior falló después de
/// reportar, no vuelve a acreditar) y después barre ESOS MISMOS UTXOs
/// (nunca los inmaduros, aunque el nodo ya los muestre como no
/// gastados) hacia la wallet de custodia en una sola transacción.
async fn escanear_direccion_deposito(ctx: &CustodyContext, http: &reqwest::Client, supabase_url: &str, poll_secret: &str, deposit_password: &str, confirmations_needed: u64, item: DepositAddress) {
    let address = match Address::from_bech32(&item.address) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("znx-custody: la dirección de depósito {} ({}) no parsea: {e}", item.id, item.address);
            return;
        }
    };

    let utxos = match znx_wallet::fetch_unspent(&ctx.client, &address).await {
        Ok(u) => u,
        Err(e) => {
            eprintln!("znx-custody: no se pudo consultar UTXOs de la dirección de depósito {}: {e}", item.id);
            return;
        }
    };
    if utxos.is_empty() {
        return;
    }

    let latest_height = match znx_wallet::latest_height(&ctx.client).await {
        Ok(Some(h)) => h,
        Ok(None) => return, // chain sin bloques todavía, no hay nada confirmado
        Err(e) => {
            eprintln!("znx-custody: no se pudo consultar la altura actual: {e}");
            return;
        }
    };

    let mut confirmed_utxos = Vec::new();
    for (outpoint, amount) in utxos {
        let height = match znx_wallet::transaction_height(&ctx.client, outpoint.txid).await {
            Ok(Some(h)) => h,
            Ok(None) => continue, // todavía en mempool, sin confirmar
            Err(e) => {
                eprintln!("znx-custody: no se pudo consultar la altura de {}: {e}", hex::encode(outpoint.txid));
                continue;
            }
        };
        let confirmations = latest_height.saturating_sub(height) + 1;
        if confirmations < confirmations_needed {
            continue;
        }

        let body = ConfirmarDepositoBody { address_id: &item.id, tx_hash: &hex::encode(outpoint.txid), vout: outpoint.vout, amount: &format_base_units_as_znx_decimal(amount) };
        let url = format!("{supabase_url}/functions/v1/confirmarDepositoZNX");
        if let Err(e) = http.post(&url).header("x-custody-secret", poll_secret).json(&body).send().await {
            eprintln!("znx-custody: no se pudo reportar el depósito {}:{} de la dirección {}: {e}", hex::encode(outpoint.txid), outpoint.vout, item.id);
            continue; // no lo barremos si ni siquiera se pudo reportar
        }
        confirmed_utxos.push((outpoint, amount));
    }

    if confirmed_utxos.is_empty() {
        return;
    }

    let keystore = match Keystore::from_json(&item.encrypted_keystore) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("znx-custody: el keystore de la dirección de depósito {} no parsea: {e}", item.id);
            return;
        }
    };
    let deposit_keypair = match keystore.decrypt(deposit_password) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("znx-custody: no se pudo descifrar el keystore de la dirección de depósito {}: {e}", item.id);
            return;
        }
    };

    let total: u128 = confirmed_utxos.iter().map(|(_, a)| a).sum();
    let tx = match znx_wallet::build_transfer(ctx.chain_id.clone(), &deposit_keypair, ctx.keypair.address(), total, 0, confirmed_utxos) {
        Ok(tx) => tx,
        Err(e) => {
            eprintln!("znx-custody: no se pudo armar el barrido de la dirección de depósito {}: {e}", item.id);
            return;
        }
    };
    if let Err(e) = znx_wallet::submit_transaction(&ctx.client, &tx).await {
        eprintln!("znx-custody: no se pudo mandar el barrido de la dirección de depósito {} (reintenta el próximo ciclo): {e}", item.id);
    }
}

/// Escanea todas las direcciones de depósito activas — ver
/// `escanear_direccion_deposito` para el detalle por dirección.
async fn escanear_depositos(ctx: &CustodyContext, http: &reqwest::Client, supabase_url: &str, poll_secret: &str, deposit_password: &str, confirmations_needed: u64) {
    let direcciones: Vec<DepositAddress> = match poll_get(http, supabase_url, poll_secret, "listarDireccionesDepositoZNX").await {
        Ok(d) => d,
        Err(e) => {
            eprintln!("znx-custody: no se pudo consultar listarDireccionesDepositoZNX: {e}");
            return;
        }
    };
    for item in direcciones {
        escanear_direccion_deposito(ctx, http, supabase_url, poll_secret, deposit_password, confirmations_needed, item).await;
    }
}

/// Loop de polling: cada `interval` procesa retiros ZNX pendientes
/// (`listarRetirosZNX`) y, si `ZNX_DEPOSIT_KEYS_PASSWORD` está seteada,
/// también cumple solicitudes de dirección de depósito y escanea las ya
/// activas. Un fallo de cualquier paso solo se loguea — el próximo tick
/// reintenta solo, nunca tumba el proceso.
async fn run_poll_loop(ctx: Arc<CustodyContext>, supabase_url: String, poll_secret: String, interval: Duration, deposit_confirmations: u64) {
    // `reqwest::Client::new()` no trae ningún timeout por default (ni
    // `timeout` ni `read_timeout` — confirmado en el source de reqwest,
    // el único de socket es un `tcp_user_timeout` de 30s que no cubre
    // "el servidor responde lento pero la conexión sigue viva"). Sin
    // esto, un cuelgue de Supabase respondiendo bloquearía este tick
    // para siempre — y como el loop es secuencial, todos los ticks
    // futuros con él. Con el timeout, un cuelgue falla solo y el
    // próximo tick sigue andando sin intervención externa.
    let http = reqwest::Client::builder().timeout(Duration::from_secs(30)).build().expect("el cliente HTTP siempre se puede construir con esta config");
    let mut ticker = tokio::time::interval(interval);
    let mut warned_missing_deposit_password = false;
    loop {
        ticker.tick().await;

        let pendientes: Result<Vec<PendingWithdrawal>, String> = poll_get(&http, &supabase_url, &poll_secret, "listarRetirosZNX").await;
        match pendientes {
            Ok(pendientes) => {
                for item in pendientes {
                    procesar_retiro_pendiente(&ctx, &http, &supabase_url, &poll_secret, item).await;
                }
            }
            Err(e) => eprintln!("znx-custody: no se pudo consultar listarRetirosZNX: {e}"),
        }

        match std::env::var("ZNX_DEPOSIT_KEYS_PASSWORD") {
            Ok(deposit_password) => {
                cumplir_solicitudes_deposito(&http, &supabase_url, &poll_secret, &deposit_password).await;
                escanear_depositos(&ctx, &http, &supabase_url, &poll_secret, &deposit_password, deposit_confirmations).await;
            }
            Err(_) => {
                if !warned_missing_deposit_password {
                    eprintln!("znx-custody: ADVERTENCIA — falta ZNX_DEPOSIT_KEYS_PASSWORD, el flujo de depósito queda deshabilitado");
                    warned_missing_deposit_password = true;
                }
            }
        }
    }
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    let keystore = Keystore::load(&cli.keystore).unwrap_or_else(|e| panic!("no se pudo leer el keystore en {:?}: {e}", cli.keystore));
    let password = read_keystore_password();
    let keypair = keystore.decrypt(&password).unwrap_or_else(|e| panic!("no se pudo descifrar el keystore de custodia: {e}"));
    let address = keypair.address();

    if std::env::var("ZNX_CUSTODY_TOKEN").is_err() {
        eprintln!("znx-custody: ADVERTENCIA — ZNX_CUSTODY_TOKEN no está seteado, sign_withdrawal va a rechazar todos los pedidos");
    }

    let client = znx_wallet::http_client(&cli.node);
    let journal = AsyncMutex::new(Journal::load(cli.journal));
    let ctx = Arc::new(CustodyContext { keypair, client, chain_id: cli.chain_id, journal });

    match (&cli.supabase_url, std::env::var("CUSTODY_POLL_SECRET")) {
        (Some(supabase_url), Ok(poll_secret)) => {
            println!("znx-custody: polling de retiros ZNX habilitado contra {supabase_url} cada {}s", cli.poll_interval_secs);
            tokio::spawn(run_poll_loop(ctx.clone(), supabase_url.clone(), poll_secret, Duration::from_secs(cli.poll_interval_secs), cli.deposit_confirmations));
        }
        (Some(_), Err(_)) => {
            eprintln!("znx-custody: ADVERTENCIA — se seteó --supabase-url pero falta CUSTODY_POLL_SECRET, el polling queda deshabilitado");
        }
        (None, _) => {}
    }

    let listen_addr: SocketAddr =
        format!("{}:{}", cli.listen_host, cli.listen_port).parse().unwrap_or_else(|e| panic!("--listen-host inválido: {e}"));
    let server = Server::builder().build(listen_addr).await.unwrap_or_else(|e| panic!("no se pudo levantar el servidor en {listen_addr}: {e}"));
    let mut module = RpcModule::new(ctx);

    module
        .register_async_method("sign_withdrawal", |params, ctx, _extensions| async move {
            let raw: SignWithdrawalParams = params.parse()?;
            check_auth(&raw.auth_token)?;

            let fee_str = raw.fee.clone().unwrap_or_else(|| "0".to_string());
            // Valida antes de tocar el journal — no vale la pena cachear
            // un pedido que ni siquiera es sintácticamente válido bajo su
            // request_id.
            let to = Address::from_bech32(&raw.to).map_err(invalid_params)?;
            let amount = raw.amount.parse::<u128>().map_err(|_| invalid_params("`amount` no es un u128 válido"))?;
            let fee = fee_str.parse::<u128>().map_err(|_| invalid_params("`fee` no es un u128 válido"))?;

            let txid = process_withdrawal(&ctx, raw.request_id, raw.to, to, amount, fee).await.map_err(internal_error)?;
            Ok::<_, ErrorObjectOwned>(SignWithdrawalResult { txid })
        })
        .expect("registra sign_withdrawal");

    module
        .register_async_method("custody_address", |_params, ctx, _extensions| async move {
            Ok::<_, ErrorObjectOwned>(CustodyAddressResult { address: ctx.keypair.address().to_bech32() })
        })
        .expect("registra custody_address");

    let handle = server.start(module);
    println!("znx-custody: wallet de custodia {address}, escuchando en {listen_addr}");

    tokio::select! {
        _ = handle.clone().stopped() => {}
        _ = tokio::signal::ctrl_c() => {
            println!("znx-custody: señal de apagado recibida, terminando...");
            let _ = handle.stop();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(request_id: &str, txid: &str) -> JournalEntry {
        JournalEntry { request_id: request_id.to_string(), to: "znx1destino".to_string(), amount: "10".to_string(), fee: "1".to_string(), txid: txid.to_string() }
    }

    #[test]
    fn journal_append_then_reload_from_disk_preserves_entries() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("journal.jsonl");

        let mut journal = Journal::load(path.clone());
        assert!(journal.get("req-1").is_none());
        journal.append(entry("req-1", "aa"));
        journal.append(entry("req-2", "bb"));
        assert_eq!(journal.get("req-1").expect("existe").txid, "aa");

        // Simula un restart del proceso: releer desde cero tiene que ver
        // lo que ya se había escrito.
        let reloaded = Journal::load(path);
        assert_eq!(reloaded.get("req-1").expect("existe tras reload").txid, "aa");
        assert_eq!(reloaded.get("req-2").expect("existe tras reload").txid, "bb");
        assert!(reloaded.get("req-3").is_none());
    }

    #[test]
    fn journal_load_of_missing_file_starts_empty() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("no-existe-todavia.jsonl");
        let journal = Journal::load(path);
        assert!(journal.get("cualquiera").is_none());
    }

    #[test]
    fn parse_znx_decimal_whole_number() {
        assert_eq!(parse_znx_decimal_to_base_units("10").unwrap(), 10_000_000_000_000_000_000);
    }

    #[test]
    fn parse_znx_decimal_with_fraction() {
        assert_eq!(parse_znx_decimal_to_base_units("12.5").unwrap(), 12_500_000_000_000_000_000);
    }

    #[test]
    fn parse_znx_decimal_smallest_unit() {
        assert_eq!(parse_znx_decimal_to_base_units("0.000000000000000001").unwrap(), 1);
    }

    #[test]
    fn parse_znx_decimal_leading_dot() {
        assert_eq!(parse_znx_decimal_to_base_units(".5").unwrap(), 500_000_000_000_000_000);
    }

    #[test]
    fn parse_znx_decimal_too_many_decimals_rejected() {
        assert!(parse_znx_decimal_to_base_units("1.2345678901234567890").is_err());
    }

    #[test]
    fn parse_znx_decimal_zero_rejected() {
        assert!(parse_znx_decimal_to_base_units("0").is_err());
        assert!(parse_znx_decimal_to_base_units("0.0").is_err());
    }

    #[test]
    fn parse_znx_decimal_negative_rejected() {
        assert!(parse_znx_decimal_to_base_units("-5").is_err());
    }

    #[test]
    fn parse_znx_decimal_garbage_rejected() {
        assert!(parse_znx_decimal_to_base_units("no-es-un-numero").is_err());
        assert!(parse_znx_decimal_to_base_units("1.2.3").is_err());
        assert!(parse_znx_decimal_to_base_units("").is_err());
        assert!(parse_znx_decimal_to_base_units("   ").is_err());
    }

    #[test]
    fn parse_znx_decimal_overflow_rejected() {
        // 100.000.000 ZNX (supply total) * 10^18 todavía entra en u128,
        // pero un monto absurdamente más grande tiene que desbordar
        // controladamente, nunca hacer wraparound silencioso.
        assert!(parse_znx_decimal_to_base_units("999999999999999999999999999999999999999999").is_err());
    }

    #[test]
    fn format_base_units_whole_number() {
        assert_eq!(format_base_units_as_znx_decimal(10_000_000_000_000_000_000), "10");
    }

    #[test]
    fn format_base_units_with_fraction_trims_trailing_zeros() {
        assert_eq!(format_base_units_as_znx_decimal(12_500_000_000_000_000_000), "12.5");
    }

    #[test]
    fn format_base_units_smallest_unit() {
        assert_eq!(format_base_units_as_znx_decimal(1), "0.000000000000000001");
    }

    #[test]
    fn format_base_units_zero() {
        assert_eq!(format_base_units_as_znx_decimal(0), "0");
    }

    #[test]
    fn parse_then_format_roundtrips() {
        for raw in ["10", "12.5", "0.000000000000000001", "1234567.891"] {
            let units = parse_znx_decimal_to_base_units(raw).unwrap();
            let formatted = format_base_units_as_znx_decimal(units);
            assert_eq!(parse_znx_decimal_to_base_units(&formatted).unwrap(), units, "roundtrip de {raw}");
        }
    }
}
