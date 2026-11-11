//! Operator-only audit checkpoint signing; dedicated HSM key, never a policy key.
use brigalow_core::{audit::Verifier, Purpose};
use brigalow_crypto::{Algorithm, Key};
use brigalow_server::config::{Backend, Config};
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
    Checkpoint {
        #[arg(long)]
        org: Uuid,
        #[arg(long)]
        key: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
}
fn write(path: &Path, bytes: &[u8]) -> Result<(), ()> {
    let mut file = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(path)
        .map_err(|_| ())?;
    file.write_all(bytes)
        .and_then(|_| file.sync_all())
        .map_err(|_| ())
}
async fn execute(args: Args) -> Result<(), ()> {
    let config = Config::load().map_err(|_| ())?;
    if config.backend != Backend::Pkcs11 {
        return Err(());
    }
    let backend = config.key_backend().map_err(|_| ())?.ok_or(())?;
    match args.command {
        Command::Init { output } => {
            std::fs::create_dir(&output).map_err(|_| ())?;
            let key = backend
                .generate(Algorithm::P256, Purpose::Release)
                .map_err(|_| ())?;
            write(
                &output.join("audit-key.json"),
                &serde_json::to_vec(&key).map_err(|_| ())?,
            )?;
            write(
                &output.join("audit-public.der"),
                &backend.public_key(&key).map_err(|_| ())?,
            )?;
        }
        Command::Checkpoint { org, key, output } => {
            // Create output directory first, but no signature is published until persistence succeeds.
            std::fs::create_dir(&output).map_err(|_| ())?;
            let mut bytes = vec![];
            std::fs::File::open(key)
                .map_err(|_| ())?
                .take(4097)
                .read_to_end(&mut bytes)
                .map_err(|_| ())?;
            if bytes.len() > 4096 {
                return Err(());
            }
            let key: Key = serde_json::from_slice(&bytes).map_err(|_| ())?;
            let store = Store::connect(config.database_options())
                .await
                .map_err(|_| ())?;
            let tenant = store.tenant(org);
            let checkpoint = tenant.checkpoint_head(&key).await.map_err(|_| ())?;
            let mut verifier = Verifier::default();
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(output.join("audit.jsonl"))
                .map_err(|_| ())?;
            while verifier.count() < checkpoint.seq {
                let entries = tenant
                    .audit_page(verifier.count() as i64, 1000)
                    .await
                    .map_err(|_| ())?;
                if entries.is_empty() {
                    return Err(());
                }
                for entry in entries
                    .into_iter()
                    .take((checkpoint.seq - verifier.count()) as usize)
                {
                    verifier.push(&entry).map_err(|_| ())?;
                    serde_json::to_writer(&mut file, &entry).map_err(|_| ())?;
                    file.write_all(b"\n").map_err(|_| ())?;
                }
            }
            if !verifier.matches_checkpoint(&checkpoint) {
                return Err(());
            }
            file.sync_all().map_err(|_| ())?;
            let signed =
                brigalow_crypto::audit::sign(backend.as_ref(), &key, checkpoint).map_err(|_| ())?;
            tenant.save_checkpoint(&signed).await.map_err(|_| ())?;
            write(
                &output.join("checkpoint.json"),
                &serde_json::to_vec(&signed).map_err(|_| ())?,
            )?;
            write(
                &output.join("checkpoint.bytes"),
                &signed.checkpoint.message().map_err(|_| ())?,
            )?;
            write(&output.join("checkpoint.sig"), &signed.signature)?;
            store.close().await;
        }
    }
    eprintln!("Audit operation complete. Retain checkpoint independently; pin the audit public key out of band.");
    Ok(())
}
#[tokio::main]
async fn main() {
    if execute(Args::parse()).await.is_err() {
        eprintln!("Audit operation failed; reconcile persisted checkpoints before retrying.");
        std::process::exit(1);
    }
}
