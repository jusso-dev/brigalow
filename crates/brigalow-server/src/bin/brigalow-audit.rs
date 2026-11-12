//! Operator-only audit checkpoint signing; dedicated HSM key, never a policy key.
use brigalow_core::Purpose;
use brigalow_crypto::{Algorithm, Key};
use brigalow_server::{
    audit_checkpoint::{self, Error},
    config::{Backend, Config},
    publish::Published,
};
use brigalow_store::Store;
use clap::{Parser, Subcommand};
use std::{
    io::{Read, Write},
    path::{Path, PathBuf},
};
use uuid::Uuid;
#[derive(Parser)]
struct Args {
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
enum Command {
    Init {
        #[arg(long)]
        output: PathBuf,
    },
    /// Sign, persist and atomically publish the current tenant head (uses the HSM).
    Checkpoint {
        #[arg(long)]
        org: Uuid,
        #[arg(long)]
        key: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    /// Read-only re-export of an already persisted checkpoint; never uses the HSM or signs.
    Recover {
        #[arg(long)]
        org: Uuid,
        #[arg(long)]
        seq: u64,
        /// Independently pinned audit public key (DER), never one taken from the bundle.
        #[arg(long)]
        public_key: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
}
fn write(path: &Path, bytes: &[u8]) -> Result<(), Error> {
    let mut file = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(path)
        .map_err(|_| Error::Failed)?;
    file.write_all(bytes)
        .and_then(|_| file.sync_all())
        .map_err(|_| Error::Failed)
}
fn read_bounded(path: &Path) -> Result<Vec<u8>, Error> {
    let mut bytes = vec![];
    std::fs::File::open(path)
        .map_err(|_| Error::Failed)?
        .take(4097)
        .read_to_end(&mut bytes)
        .map_err(|_| Error::Failed)?;
    if bytes.len() > 4096 {
        return Err(Error::Failed);
    }
    Ok(bytes)
}
/// Signing commands only: the PKCS#11 backend is required, with no fallback.
fn signing_backend(
    config: &Config,
) -> Result<std::sync::Arc<dyn brigalow_crypto::KeyBackend>, Error> {
    if config.backend != Backend::Pkcs11 {
        return Err(Error::Failed);
    }
    config
        .key_backend()
        .map_err(|_| Error::Failed)?
        .ok_or(Error::Failed)
}
async fn execute(args: Args) -> Result<String, Error> {
    let config = Config::load().map_err(|_| Error::Failed)?;
    match args.command {
        Command::Init { output } => {
            let backend = signing_backend(&config)?;
            std::fs::create_dir(&output).map_err(|_| Error::Failed)?;
            let key = backend
                .generate(Algorithm::P256, Purpose::Release)
                .map_err(|_| Error::Failed)?;
            write(
                &output.join("audit-key.json"),
                &serde_json::to_vec(&key).map_err(|_| Error::Failed)?,
            )?;
            write(
                &output.join("audit-public.der"),
                &backend.public_key(&key).map_err(|_| Error::Failed)?,
            )?;
            Ok("Audit key initialised. Pin audit-public.der through an independent trusted channel.".into())
        }
        Command::Checkpoint { org, key, output } => {
            let backend = signing_backend(&config)?;
            let key: Key =
                serde_json::from_slice(&read_bounded(&key)?).map_err(|_| Error::Failed)?;
            let store = Store::connect(config.database_options())
                .await
                .map_err(|_| Error::Failed)?;
            let result = audit_checkpoint::create(
                &store.tenant(org),
                backend.as_ref(),
                &key,
                &output,
                &mut |_| Ok(()),
            )
            .await;
            store.close().await;
            let seq = result?;
            Ok(format!("Checkpoint {seq} signed, persisted and published. Retain it independently and record the expected head outside this host."))
        }
        Command::Recover {
            org,
            seq,
            public_key,
            output,
        } => {
            // No key backend is loaded: recovery must work with the HSM absent or disabled.
            let pinned = read_bounded(&public_key)?;
            let store = Store::connect(config.database_options())
                .await
                .map_err(|_| Error::Failed)?;
            let result =
                audit_checkpoint::recover(&store.tenant(org), org, seq, &pinned, &output).await;
            store.close().await;
            Ok(match result? {
                Published::Created => format!("Persisted checkpoint {seq} verified with the pinned key and recovered without signing."),
                Published::Identical => format!("Existing output for checkpoint {seq} is identical to the verified persisted checkpoint."),
            })
        }
    }
}
#[tokio::main]
async fn main() {
    match execute(Args::parse()).await {
        Ok(message) => {
            eprintln!("{message}");
        }
        Err(error) => {
            eprintln!("Audit operation failed: {error}");
            std::process::exit(1);
        }
    }
}
