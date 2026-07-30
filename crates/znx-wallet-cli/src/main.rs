//! znx-wallet-cli — CLI de devnet: generar llaves, consultar balance
//! (suma de UTXOs) y firmar/mandar transferencias contra un `znx-node`
//! corriendo. La mecánica de keystore cifrado y de selección de UTXOs +
//! armado/firma/envío de una transferencia vive en `znx-wallet`
//! (compartida con `znx-custody`, el servicio de firma sin interacción
//! humana) — este binario es solo la capa de CLI encima de eso.

use std::path::PathBuf;

use clap::{Parser, Subcommand};

use znx_crypto::Address;
use znx_wallet::Keystore;

#[derive(Parser)]
#[command(about = "CLI de wallet de Zend X Chain (devnet, PoW abierta + UTXO)")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Genera un par de llaves nuevo y lo guarda en `--out`.
    Keygen {
        #[arg(long, value_name = "PATH")]
        out: PathBuf,
    },
    /// Imprime la dirección bech32 derivada de una llave.
    Address {
        #[arg(long, value_name = "PATH")]
        key: PathBuf,
    },
    /// Consulta el balance (suma de UTXOs) de una dirección contra un nodo.
    Balance {
        #[arg(long, default_value = "http://127.0.0.1:26657")]
        node: String,
        #[arg(long, value_name = "PATH", conflicts_with = "address")]
        key: Option<PathBuf>,
        #[arg(long, value_name = "znx1...", conflicts_with = "key")]
        address: Option<String>,
    },
    /// Arma, firma y manda una transferencia (selecciona UTXOs propios
    /// automáticamente).
    Send {
        #[arg(long, default_value = "http://127.0.0.1:26657")]
        node: String,
        #[arg(long, value_name = "PATH")]
        key: PathBuf,
        #[arg(long, value_name = "znx1...")]
        to: String,
        #[arg(long)]
        amount: u128,
        #[arg(long, default_value_t = 0)]
        fee: u128,
        #[arg(long)]
        chain_id: String,
    },
}

/// Contraseña para un keystore nuevo (con confirmación). Atajo para
/// scripts/pruebas: si está seteada `ZNX_WALLET_PASSWORD`, se usa
/// directo sin preguntar nada por terminal — cómodo para automatizar,
/// pero ojo: una variable de entorno queda visible para otros procesos
/// del mismo usuario en el sistema (`/proc/<pid>/environ`), así que no es
/// el camino recomendado para uso interactivo normal.
fn read_new_password() -> String {
    if let Ok(password) = std::env::var("ZNX_WALLET_PASSWORD") {
        return password;
    }
    loop {
        let p1 = rpassword::prompt_password("Contraseña para cifrar la llave: ").unwrap_or_else(|e| panic!("no se pudo leer la contraseña: {e}"));
        let p2 = rpassword::prompt_password("Confirmar contraseña: ").unwrap_or_else(|e| panic!("no se pudo leer la contraseña: {e}"));
        if p1 == p2 {
            return p1;
        }
        eprintln!("las contraseñas no coinciden, probá de nuevo");
    }
}

/// Contraseña para descifrar un keystore existente — mismo atajo de
/// `ZNX_WALLET_PASSWORD` que `read_new_password`.
fn read_password() -> String {
    if let Ok(password) = std::env::var("ZNX_WALLET_PASSWORD") {
        return password;
    }
    rpassword::prompt_password("Contraseña: ").unwrap_or_else(|e| panic!("no se pudo leer la contraseña: {e}"))
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    match cli.command {
        Command::Keygen { out } => {
            let keypair = znx_crypto::Keypair::generate();
            let password = read_new_password();
            let keystore = Keystore::create(&keypair, &password).unwrap_or_else(|e| panic!("no se pudo cifrar la llave: {e}"));
            keystore.save(&out).unwrap_or_else(|e| panic!("no se pudo guardar el keystore en {out:?}: {e}"));
            println!("keystore cifrado guardado en {out:?}");
            println!("address: {}", keypair.address());
            println!("public_key: {}", hex::encode(keypair.public_key().to_bytes()));
        }
        Command::Address { key } => {
            let keystore = Keystore::load(&key).unwrap_or_else(|e| panic!("no se pudo leer el keystore en {key:?}: {e}"));
            println!("{}", keystore.address);
        }
        Command::Balance { node, key, address } => {
            let address = match (key, address) {
                (Some(key_path), None) => Keystore::load(&key_path).unwrap_or_else(|e| panic!("no se pudo leer el keystore en {key_path:?}: {e}")).address,
                (None, Some(addr)) => Address::from_bech32(&addr).unwrap_or_else(|e| panic!("dirección inválida: {e}")),
                _ => panic!("pasá exactamente uno de --key o --address"),
            };
            let client = znx_wallet::http_client(&node);
            let utxos = znx_wallet::fetch_unspent(&client, &address).await.unwrap_or_else(|e| panic!("no se pudo consultar el nodo: {e}"));
            let total: u128 = utxos.iter().map(|(_, amount)| amount).sum();
            println!("balance: {total}");
            println!("utxos: {}", utxos.len());
        }
        Command::Send { node, key, to, amount, fee, chain_id } => {
            let keystore = Keystore::load(&key).unwrap_or_else(|e| panic!("no se pudo leer el keystore en {key:?}: {e}"));
            let password = read_password();
            let keypair = keystore.decrypt(&password).unwrap_or_else(|e| panic!("no se pudo descifrar la llave: {e}"));
            let to_address = Address::from_bech32(&to).unwrap_or_else(|e| panic!("dirección de destino inválida: {e}"));
            let client = znx_wallet::http_client(&node);

            let txid = znx_wallet::send(&client, chain_id, &keypair, to_address, amount, fee).await.unwrap_or_else(|e| panic!("no se pudo mandar la transferencia: {e}"));
            println!("tx enviada, txid: {}", hex::encode(txid));
        }
    }
}
