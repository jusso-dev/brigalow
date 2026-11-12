//! Operator audit checkpoint creation and read-only recovery, sharing one atomic bundle format.
//!
//! `create` signs a new head with the dedicated audit key. `recover` never touches a key
//! backend: it re-exports an already persisted record after verifying it against an
//! operator-supplied, independently pinned public key and the exact audit prefix.
use crate::publish::{self, Existing, Published, Stage};
use brigalow_core::audit::{Checkpoint, SignedCheckpoint, Verifier};
use brigalow_crypto::{Key, KeyBackend};
use brigalow_store::Tenant;
use std::{io::Write, path::Path};

pub const AUDIT: &str = "audit.jsonl";
pub const CHECKPOINT: &str = "checkpoint.json";
pub const BYTES: &str = "checkpoint.bytes";
pub const SIGNATURE: &str = "checkpoint.sig";
/// Written and fsynced last; binds the bundle to one checkpoint and the digest of every file.
pub const MARKER: &str = "COMPLETE.json";
const MARKER_FORMAT: &str = "brigalow.audit.checkpoint-bundle.v1";
const PAGE: i64 = 1000;

/// Operator-facing outcomes. Messages are fixed text: no driver, path or key details.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Error {
    #[error("audit checkpoint operation failed")]
    Failed,
    #[error("atomic no-replace publication is unsupported on this platform; nothing was signed")]
    Unsupported,
    #[error("output already exists; choose a new output directory")]
    OutputExists,
    #[error("checkpoint {0} is already persisted; use `brigalow-audit recover` instead of signing again")]
    AlreadyPersisted(u64),
    #[error("checkpoint {0} was signed but persistence is unconfirmed; run `brigalow-audit recover` for this sequence and do not re-sign")]
    PersistenceUnconfirmed(u64),
    #[error("checkpoint {0} is persisted but its output was not published; run `brigalow-audit recover` for this sequence")]
    NotPublished(u64),
    #[error("no persisted checkpoint is visible for this organisation and sequence; this does not show that the HSM did not sign")]
    Absent,
    #[error("persisted checkpoint failed verification (record, pinned key, organisation or audit prefix)")]
    Verification,
    #[error("existing output differs from the persisted checkpoint")]
    Mismatch,
}

/// Fault-injection points for crash-safety tests; production callers pass `|_| Ok(())`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    Persisted,
    Staged(&'static str),
}

fn staging(output: &Path) -> Result<Stage, Error> {
    let stage = Stage::create(output).map_err(|error| match error {
        publish::Error::Unsupported => Error::Unsupported,
        _ => Error::Failed,
    })?;
    match stage.ensure_absent() {
        Ok(()) => Ok(stage),
        Err(publish::Error::Exists) => Err(Error::OutputExists),
        Err(_) => Err(Error::Failed),
    }
}

/// Stream and verify exactly `checkpoint.seq` entries with bounded pages.
async fn stage_prefix(
    tenant: &Tenant,
    checkpoint: &Checkpoint,
    stage: &mut Stage,
) -> Result<bool, Error> {
    let mut file = stage.file(AUDIT).map_err(|_| Error::Failed)?;
    let mut verifier = Verifier::default();
    while verifier.count() < checkpoint.seq {
        let after = i64::try_from(verifier.count()).map_err(|_| Error::Failed)?;
        let entries = tenant
            .audit_page(after, PAGE)
            .await
            .map_err(|_| Error::Failed)?;
        if entries.is_empty() {
            return Ok(false);
        }
        let wanted = checkpoint.seq - verifier.count();
        for entry in entries.into_iter().take(wanted as usize) {
            if verifier.push(&entry).is_err() {
                return Ok(false);
            }
            serde_json::to_writer(&mut file, &entry).map_err(|_| Error::Failed)?;
            file.write_all(b"\n").map_err(|_| Error::Failed)?;
        }
    }
    let matches = verifier.matches_checkpoint(checkpoint);
    stage.finish(file).map_err(|_| Error::Failed)?;
    Ok(matches)
}

fn marker(signed: &SignedCheckpoint, stage: &Stage) -> Result<Vec<u8>, Error> {
    let c = &signed.checkpoint;
    serde_json::to_vec(&serde_json::json!({
        "format": MARKER_FORMAT,
        "version": c.version,
        "org_id": c.org_id,
        "seq": c.seq,
        "entry_hash": c.entry_hash,
        "sha256": stage.digests(),
    }))
    .map_err(|_| Error::Failed)
}

fn stage_signed(
    signed: &SignedCheckpoint,
    stage: &mut Stage,
    hook: &mut dyn FnMut(Phase) -> Result<(), ()>,
) -> Result<Vec<u8>, ()> {
    let json = serde_json::to_vec(signed).map_err(|_| ())?;
    let bytes = signed.checkpoint.message().map_err(|_| ())?;
    for (name, data) in [
        (CHECKPOINT, json.as_slice()),
        (BYTES, bytes.as_slice()),
        (SIGNATURE, signed.signature.as_slice()),
    ] {
        stage.write(name, data).map_err(|_| ())?;
        hook(Phase::Staged(name))?;
    }
    marker(signed, stage).map_err(|_| ())
}

/// Sign and persist the current tenant head, then atomically publish the bundle.
/// Returns the persisted sequence.
pub async fn create(
    tenant: &Tenant,
    backend: &dyn KeyBackend,
    key: &Key,
    output: &Path,
    hook: &mut dyn FnMut(Phase) -> Result<(), ()>,
) -> Result<u64, Error> {
    // Refuse unsupported platforms and existing outputs before any signature exists.
    let mut stage = staging(output)?;
    let checkpoint = tenant
        .checkpoint_head(key)
        .await
        .map_err(|_| Error::Failed)?;
    let seq = checkpoint.seq;
    // Duplicate scheduling: do not ask the HSM to sign an already retained head.
    // `save_checkpoint` remains the authoritative uniqueness check for races.
    match tenant.checkpoint_record(seq).await {
        Ok(None) => {}
        Ok(Some(_)) | Err(brigalow_store::Error::Invalid) => {
            return Err(Error::AlreadyPersisted(seq))
        }
        Err(_) => return Err(Error::Failed),
    }
    if !stage_prefix(tenant, &checkpoint, &mut stage).await? {
        return Err(Error::Failed);
    }
    let signed =
        brigalow_crypto::audit::sign(backend, key, checkpoint).map_err(|_| Error::Failed)?;
    match tenant.save_checkpoint(&signed).await {
        Ok(()) => {}
        // Uniqueness or head conflicts commit nothing; the signature is discarded unpublished.
        Err(brigalow_store::Error::Conflict) => return Err(Error::AlreadyPersisted(seq)),
        Err(_) => return Err(Error::PersistenceUnconfirmed(seq)),
    }
    hook(Phase::Persisted).map_err(|_| Error::NotPublished(seq))?;
    let marker = stage_signed(&signed, &mut stage, hook).map_err(|_| Error::NotPublished(seq))?;
    match stage.publish(MARKER, &marker, Existing::Refuse) {
        Ok(_) => Ok(seq),
        Err(_) => Err(Error::NotPublished(seq)),
    }
}

/// Read-only recovery of a persisted checkpoint. Never signs and never creates a record.
pub async fn recover(
    tenant: &Tenant,
    org: uuid::Uuid,
    seq: u64,
    pinned_public_key: &[u8],
    output: &Path,
) -> Result<Published, Error> {
    let mut stage = Stage::create(output).map_err(|error| match error {
        publish::Error::Unsupported => Error::Unsupported,
        _ => Error::Failed,
    })?;
    let signed = match tenant.checkpoint_record(seq).await {
        Ok(Some(signed)) => signed,
        Ok(None) => return Err(Error::Absent),
        Err(brigalow_store::Error::Invalid) => return Err(Error::Verification),
        Err(_) => return Err(Error::Failed),
    };
    if signed.checkpoint.org_id != org || signed.checkpoint.seq != seq {
        return Err(Error::Verification);
    }
    brigalow_crypto::audit::verify(&signed, pinned_public_key).map_err(|_| Error::Verification)?;
    if !stage_prefix(tenant, &signed.checkpoint, &mut stage).await? {
        return Err(Error::Verification);
    }
    let marker = stage_signed(&signed, &mut stage, &mut |_| Ok(())).map_err(|_| Error::Failed)?;
    stage
        .publish(MARKER, &marker, Existing::RequireIdentical)
        .map_err(|error| match error {
            publish::Error::Mismatch | publish::Error::Exists => Error::Mismatch,
            publish::Error::Unsupported => Error::Unsupported,
            _ => Error::Failed,
        })
}
