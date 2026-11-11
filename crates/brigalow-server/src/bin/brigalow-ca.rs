//! Optional operator-only private CA. No HTTP listener, root key, or software fallback.
use brigalow_core::Purpose;
use brigalow_crypto::{
    certificates,
    private_ca::{self, Issuer, Profile},
    Algorithm, Key,
};
use brigalow_server::config::{Backend, Config};
use brigalow_store::private_ca::CaStore;
use clap::{Parser, Subcommand};
use der::{Decode, DecodePem, Encode, EncodePem};
use serde::Deserialize;
use std::{
    io::{Read, Write},
    path::{Path, PathBuf},
};
use uuid::Uuid;

#[derive(Parser)]
#[command(about = "Operator-only private CA; HSM issuer custody required")]
struct Args {
    /// Non-secret issuer/profile JSON. Runtime DB/HSM configuration uses BRIGALOW_CONFIG.
    #[arg(long)]
    ca: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
enum Command {
    /// Generate a non-exportable intermediate key and CSR. Sign CSR with your offline root.
    Init {
        #[arg(long)]
        subject: String,
        #[arg(long)]
        output: PathBuf,
    },
    /// Issue today's 72-hour leaf after verifying CSR proof of possession.
    Issue {
        #[arg(long)]
        profile: Uuid,
        #[arg(long)]
        csr: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    /// Recover committed public outputs without signing again; day is days since Unix epoch (UTC).
    Export {
        #[arg(long)]
        profile: Uuid,
        #[arg(long)]
        day: i64,
        #[arg(long)]
        output: PathBuf,
    },
    Revoke {
        #[arg(long)]
        profile: Uuid,
        #[arg(long)]
        day: i64,
    },
    /// Write a signed DER CRL for operator publication; validity is 24 hours.
    Crl {
        #[arg(long)]
        output: PathBuf,
    },
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CaConfig {
    org: Uuid,
    issuer_key_file: PathBuf,
    chain: Vec<PathBuf>,
    anchors: Vec<PathBuf>,
    profiles: Vec<Profile>,
}
fn read(path: &Path) -> Result<Vec<u8>, ()> {
    let mut bytes = vec![];
    std::fs::File::open(path)
        .map_err(|_| ())?
        .take(1_048_577)
        .read_to_end(&mut bytes)
        .map_err(|_| ())?;
    if bytes.len() > 1_048_576 {
        return Err(());
    }
    Ok(bytes)
}
fn write(path: &Path, bytes: &[u8]) -> Result<(), ()> {
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|_| ())?;
    file.write_all(bytes)
        .and_then(|_| file.sync_all())
        .map_err(|_| ())
}
fn export(path: &Path, chain: &[Vec<u8>]) -> Result<(), ()> {
    std::fs::create_dir(path).map_err(|_| ())?;
    let mut pem = String::new();
    for cert in chain {
        pem.push_str(
            &x509_cert::Certificate::from_der(cert)
                .map_err(|_| ())?
                .to_pem(der::pem::LineEnding::LF)
                .map_err(|_| ())?,
        );
    }
    write(&path.join("chain.pem"), pem.as_bytes())?;
    write(
        &path.join("chain.json"),
        &serde_json::to_vec(&serde_json::json!({"chain":chain})).map_err(|_| ())?,
    )?;
    write(&path.join("leaf.der"), chain.first().ok_or(())?)
}
async fn execute(args: Args) -> Result<(), ()> {
    let config = Config::load().map_err(|_| ())?;
    if config.backend != Backend::Pkcs11 {
        return Err(());
    }
    let backend = config.key_backend().map_err(|_| ())?.ok_or(())?;
    if let Command::Init { subject, output } = &args.command {
        if subject.len() > 1024 || subject.is_empty() {
            return Err(());
        }
        std::fs::create_dir(output).map_err(|_| ())?;
        let key = backend
            .generate(Algorithm::P256, Purpose::Release)
            .map_err(|_| ())?;
        write(
            &output.join("issuer-key.json"),
            &serde_json::to_vec(&key).map_err(|_| ())?,
        )?;
        write(
            &output.join("issuer.csr"),
            certificates::csr(backend.as_ref(), &key, subject)
                .map_err(|_| ())?
                .as_bytes(),
        )?;
        eprintln!("Private intermediate key reference and CSR written; no private key exported.");
        return Ok(());
    }
    let ca: CaConfig =
        serde_json::from_slice(&read(args.ca.as_deref().ok_or(())?)?).map_err(|_| ())?;
    if ca.org.is_nil() || ca.profiles.len() > 1000 {
        return Err(());
    }
    let mut ids = std::collections::BTreeSet::new();
    for profile in &ca.profiles {
        profile.validate().map_err(|_| ())?;
        if !ids.insert(profile.id) {
            return Err(());
        }
    }
    let key: Key = serde_json::from_slice(&read(&ca.issuer_key_file)?).map_err(|_| ())?;
    let chain = ca
        .chain
        .iter()
        .map(|p| read(p))
        .collect::<Result<Vec<_>, _>>()?;
    let anchors = ca
        .anchors
        .iter()
        .map(|p| read(p))
        .collect::<Result<Vec<_>, _>>()?;
    let issuer = Issuer::new(backend.as_ref(), &key, chain, anchors).map_err(|_| ())?;
    let store = CaStore::connect(config.database_options(), ca.org)
        .await
        .map_err(|_| ())?;
    match args.command {
        Command::Issue {
            profile,
            csr,
            output,
        } => {
            if output.exists() {
                return Err(());
            }
            let profile = ca.profiles.iter().find(|p| p.id == profile).ok_or(())?;
            let csr = x509_cert::request::CertReq::from_pem(read(&csr)?)
                .map_err(|_| ())?
                .to_der()
                .map_err(|_| ())?;
            let public = private_ca::csr_public_key(&csr).map_err(|_| ())?;
            let leaf = store
                .reserve(
                    key.id,
                    profile.id,
                    serde_json::to_value(profile).map_err(|_| ())?,
                    public,
                )
                .await
                .map_err(|_| ())?;
            let chain = issuer
                .issue(
                    &leaf.public_key,
                    &leaf.serial,
                    profile,
                    leaf.issued_at as u64,
                )
                .map_err(|_| ())?;
            store.finish(&leaf, chain.clone()).await.map_err(|_| ())?;
            export(&output, &chain)?;
            eprintln!(
                "Private leaf committed: profile={} UTC day={}; validity 72h.",
                profile.id, leaf.day
            );
        }
        Command::Export {
            profile,
            day,
            output,
        } => {
            let leaf = store.leaf(profile, day).await.map_err(|_| ())?.ok_or(())?;
            export(&output, &leaf.chain.ok_or(())?)?;
            eprintln!(
                "Historical public certificate exported; revoked={}",
                leaf.revoked_at.is_some()
            );
        }
        Command::Revoke { profile, day } => {
            store.revoke(profile, day).await.map_err(|_| ())?;
            eprintln!("Day revoked in ledger. Generate and publish a new CRL for the issuing key.");
        }
        Command::Crl { output } => {
            if output.exists() {
                return Err(());
            }
            let intent = store.reserve_crl(key.id).await.map_err(|_| ())?;
            let der = issuer
                .crl(intent.number as u64, &intent.revoked, intent.at as u64)
                .map_err(|_| ())?;
            store
                .finish_crl(key.id, &intent, der.clone())
                .await
                .map_err(|_| ())?;
            write(&output, &der)?;
            eprintln!(
                "Private CA CRL committed: number={}; publish DER output before nextUpdate.",
                intent.number
            );
        }
        Command::Init { .. } => unreachable!(),
    }
    store.close().await;
    Ok(())
}
#[tokio::main]
async fn main() {
    if execute(Args::parse()).await.is_err() {
        eprintln!(
            "Private CA operation failed; inspect ledger before retrying. No fallback permitted."
        );
        std::process::exit(1);
    }
}
