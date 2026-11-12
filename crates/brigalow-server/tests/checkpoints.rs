#![cfg(feature = "integration")]
//! AT-AUD-03 against real Postgres: crash-safe checkpoint publication and read-only recovery.
use brigalow_core::{
    audit::{Entry, SignedCheckpoint, Verifier},
    Purpose,
};
use brigalow_crypto::{software::Software, Algorithm, DigestAlgorithm, Key, KeyBackend};
use brigalow_server::{
    audit_checkpoint::{self, Error, Phase, AUDIT, BYTES, CHECKPOINT, MARKER, SIGNATURE},
    publish::Published,
};
use brigalow_store::{Store, Tenant};
use sqlx::{
    postgres::{PgConnectOptions, PgSslMode},
    types::Json,
    ConnectOptions, PgPool,
};
use std::{
    path::Path,
    sync::atomic::{AtomicUsize, Ordering},
};
use uuid::Uuid;

/// Counts every signing call so recovery can prove it never reaches a key backend.
struct Counting {
    inner: Software,
    signs: AtomicUsize,
}
impl KeyBackend for Counting {
    fn generate(&self, algorithm: Algorithm, purpose: Purpose) -> brigalow_crypto::Result<Key> {
        self.inner.generate(algorithm, purpose)
    }
    fn public_key(&self, key: &Key) -> brigalow_crypto::Result<Vec<u8>> {
        self.inner.public_key(key)
    }
    fn sign_digest(
        &self,
        key: &Key,
        algorithm: DigestAlgorithm,
        digest: &[u8],
    ) -> brigalow_crypto::Result<Vec<u8>> {
        self.signs.fetch_add(1, Ordering::SeqCst);
        self.inner.sign_digest(key, algorithm, digest)
    }
    fn sign_message(&self, key: &Key, message: &[u8]) -> brigalow_crypto::Result<Vec<u8>> {
        self.signs.fetch_add(1, Ordering::SeqCst);
        self.inner.sign_message(key, message)
    }
    fn disable(&self, key: &Key) -> brigalow_crypto::Result<()> {
        self.inner.disable(key)
    }
    fn is_lab(&self) -> bool {
        true
    }
}

struct Fixture {
    admin: PgPool,
    store: Store,
    backend: Counting,
    key: Key,
    public: Vec<u8>,
}

fn options(user: &str, variable: &str) -> PgConnectOptions {
    let secret =
        std::fs::read_to_string(std::env::var(variable).expect("run scripts/e2e.py")).unwrap();
    PgConnectOptions::new()
        .host("127.0.0.1")
        .port(
            std::env::var("BRIGALOW_TEST_DB_PORT")
                .unwrap()
                .parse()
                .unwrap(),
        )
        .ssl_mode(PgSslMode::VerifyFull)
        .ssl_root_cert(std::env::var("BRIGALOW_TEST_DB_CA_FILE").unwrap())
        .database("brigalow")
        .username(user)
        .password(&secret)
        .disable_statement_logging()
}

async fn fixture() -> Fixture {
    let admin = PgPool::connect_with(options("postgres", "BRIGALOW_TEST_ADMIN_PASSWORD_FILE"))
        .await
        .unwrap();
    let store = Store::connect(options(
        "brigalow_runtime",
        "BRIGALOW_TEST_APP_PASSWORD_FILE",
    ))
    .await
    .unwrap();
    let backend = Counting {
        inner: Software::new(true).unwrap(),
        signs: AtomicUsize::new(0),
    };
    let key = backend.generate(Algorithm::P256, Purpose::Test).unwrap();
    let public = backend.public_key(&key).unwrap();
    Fixture {
        admin,
        store,
        backend,
        key,
        public,
    }
}

impl Fixture {
    async fn org(&self, events: usize) -> (Uuid, Tenant) {
        let org = Uuid::new_v4();
        sqlx::query("INSERT INTO brigalow.organisations VALUES ($1,'checkpoint-test')")
            .bind(org)
            .execute(&self.admin)
            .await
            .unwrap();
        let tenant = self.store.tenant(org);
        for i in 0..events {
            tenant
                .record(
                    "test",
                    "test.event",
                    &i.to_string(),
                    serde_json::json!({"i": i}),
                )
                .await
                .unwrap();
        }
        (org, tenant)
    }
    fn signs(&self) -> usize {
        self.backend.signs.load(Ordering::SeqCst)
    }
    async fn create(
        &self,
        tenant: &Tenant,
        output: &Path,
        fail: Option<Phase>,
    ) -> Result<u64, Error> {
        audit_checkpoint::create(tenant, &self.backend, &self.key, output, &mut |phase| {
            if Some(phase) == fail {
                Err(())
            } else {
                Ok(())
            }
        })
        .await
    }
    async fn persisted(&self, org: Uuid, seq: u64) -> Option<SignedCheckpoint> {
        sqlx::query_scalar::<_, Json<SignedCheckpoint>>(
            "SELECT record FROM brigalow.audit_checkpoints WHERE org_id=$1 AND seq=$2",
        )
        .bind(org)
        .bind(seq as i64)
        .fetch_optional(&self.admin)
        .await
        .unwrap()
        .map(|record| record.0)
    }
}

fn no_stages(parent: &Path) -> bool {
    std::fs::read_dir(parent).unwrap().all(|e| {
        !e.unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".brigalow-stage-")
    })
}

/// Independently re-check a published bundle: exact persisted bytes, pinned key, prefix, marker.
fn check_bundle(dir: &Path, expected: &SignedCheckpoint, public: &[u8]) {
    use sha2::Digest;
    use std::os::unix::fs::PermissionsExt;
    assert_eq!(
        std::fs::metadata(dir).unwrap().permissions().mode() & 0o7777,
        0o700
    );
    let json = std::fs::read(dir.join(CHECKPOINT)).unwrap();
    assert_eq!(json, serde_json::to_vec(expected).unwrap());
    assert_eq!(
        std::fs::read(dir.join(BYTES)).unwrap(),
        expected.checkpoint.message().unwrap()
    );
    assert_eq!(
        std::fs::read(dir.join(SIGNATURE)).unwrap(),
        expected.signature
    );
    let signed: SignedCheckpoint = serde_json::from_slice(&json).unwrap();
    brigalow_crypto::audit::verify(&signed, public).unwrap();
    let mut verifier = Verifier::default();
    for line in std::fs::read_to_string(dir.join(AUDIT)).unwrap().lines() {
        verifier
            .push(&serde_json::from_str::<Entry>(line).unwrap())
            .unwrap();
    }
    assert!(verifier.matches_checkpoint(&signed.checkpoint));
    let marker: serde_json::Value =
        serde_json::from_slice(&std::fs::read(dir.join(MARKER)).unwrap()).unwrap();
    assert_eq!(marker["format"], "brigalow.audit.checkpoint-bundle.v1");
    assert_eq!(marker["org_id"], signed.checkpoint.org_id.to_string());
    assert_eq!(marker["seq"], signed.checkpoint.seq);
    assert_eq!(marker["entry_hash"], signed.checkpoint.entry_hash);
    for name in [AUDIT, CHECKPOINT, BYTES, SIGNATURE] {
        let digest = format!(
            "{:x}",
            sha2::Sha256::digest(std::fs::read(dir.join(name)).unwrap())
        );
        assert_eq!(marker["sha256"][name], digest, "{name}");
    }
    let mut names: Vec<_> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    names.sort();
    assert_eq!(names, [MARKER, AUDIT, BYTES, CHECKPOINT, SIGNATURE]);
}

#[tokio::test]
async fn at_aud_03_interrupted_publication_recovers_without_resigning() {
    let f = fixture().await;
    let temp = tempfile::tempdir().unwrap();
    let d = temp.path();
    let (org, tenant) = f.org(1205).await;
    // Normal publication; the bundle is the exact persisted record.
    let seq = f.create(&tenant, &d.join("first"), None).await.unwrap();
    assert_eq!((seq, f.signs()), (1205, 1));
    let record = f.persisted(org, seq).await.unwrap();
    check_bundle(&d.join("first"), &record, &f.public);
    // Duplicate scheduling at the same head refuses before signing.
    assert_eq!(
        f.create(&tenant, &d.join("duplicate"), None).await,
        Err(Error::AlreadyPersisted(seq))
    );
    assert_eq!(f.signs(), 1);
    assert!(!d.join("duplicate").exists());
    // Duplicate (org, seq) insertion conflicts even with a fresh valid signature.
    let resigned =
        brigalow_crypto::audit::sign(&f.backend.inner, &f.key, record.checkpoint.clone()).unwrap();
    assert!(matches!(
        tenant.save_checkpoint(&resigned).await,
        Err(brigalow_store::Error::Conflict)
    ));
    // A head whose stored entry hash differs is a distinct outcome, not a duplicate.
    let mut changed = record.checkpoint.clone();
    changed.entry_hash = "0".repeat(64);
    let changed = brigalow_crypto::audit::sign(&f.backend.inner, &f.key, changed).unwrap();
    assert!(matches!(
        tenant.save_checkpoint(&changed).await,
        Err(brigalow_store::Error::Audit)
    ));
    // Rejected before any write: another organisation's checkpoint.
    let mut foreign = record.checkpoint.clone();
    foreign.org_id = Uuid::new_v4();
    let foreign = brigalow_crypto::audit::sign(&f.backend.inner, &f.key, foreign).unwrap();
    assert!(matches!(
        tenant.save_checkpoint(&foreign).await,
        Err(brigalow_store::Error::Invalid)
    ));
    // Existing output is never replaced, and no signature is produced for it.
    tenant
        .record("test", "test.event", "x", serde_json::json!({}))
        .await
        .unwrap();
    assert_eq!(
        f.create(&tenant, &d.join("first"), None).await,
        Err(Error::OutputExists)
    );
    assert_eq!(f.signs(), 1);
    // Fault after DB commit and after each staged file: nothing published, record durable.
    let phases = [
        Phase::Persisted,
        Phase::Staged(CHECKPOINT),
        Phase::Staged(BYTES),
        Phase::Staged(SIGNATURE),
    ];
    for (i, phase) in phases.into_iter().enumerate() {
        if i > 0 {
            tenant
                .record("test", "test.event", "y", serde_json::json!({}))
                .await
                .unwrap();
        }
        let output = d.join(format!("interrupted-{i}"));
        let error = f.create(&tenant, &output, Some(phase)).await.unwrap_err();
        let Error::NotPublished(seq) = error else {
            panic!("unexpected outcome");
        };
        assert!(!output.exists(), "partial output must not be published");
        assert!(no_stages(d));
        let record = f.persisted(org, seq).await.unwrap();
        let signs = f.signs();
        // Read-only recovery: verified with the pinned key, no backend involvement at all.
        assert_eq!(
            audit_checkpoint::recover(&tenant, org, seq, &f.public, &output)
                .await
                .unwrap(),
            Published::Created
        );
        assert_eq!(f.signs(), signs, "recovery must never sign");
        check_bundle(&output, &record, &f.public);
        // Re-running recovery onto the complete directory verifies byte-for-byte.
        assert_eq!(
            audit_checkpoint::recover(&tenant, org, seq, &f.public, &output)
                .await
                .unwrap(),
            Published::Identical
        );
        // New events after the checkpoint do not change the recovered exact prefix.
        tenant
            .record("test", "test.event", "z", serde_json::json!({}))
            .await
            .unwrap();
        let again = d.join(format!("again-{i}"));
        audit_checkpoint::recover(&tenant, org, seq, &f.public, &again)
            .await
            .unwrap();
        for name in [AUDIT, CHECKPOINT, BYTES, SIGNATURE, MARKER] {
            assert_eq!(
                std::fs::read(output.join(name)).unwrap(),
                std::fs::read(again.join(name)).unwrap()
            );
        }
    }
    // A different existing directory is never accepted or replaced.
    let seq_first = 1205;
    assert_eq!(
        audit_checkpoint::recover(&tenant, org, seq_first, &f.public, &d.join("interrupted-0"))
            .await,
        Err(Error::Mismatch)
    );
    // Concurrent recoveries to one destination: one creates, the other verifies identity.
    let shared = d.join("shared");
    let (a, b) = tokio::join!(
        audit_checkpoint::recover(&tenant, org, seq_first, &f.public, &shared),
        audit_checkpoint::recover(&tenant, org, seq_first, &f.public, &shared),
    );
    let mut outcomes = [a.unwrap(), b.unwrap()];
    outcomes.sort_by_key(|o| *o == Published::Identical);
    assert_eq!(outcomes, [Published::Created, Published::Identical]);
    check_bundle(
        &shared,
        &f.persisted(org, seq_first).await.unwrap(),
        &f.public,
    );
    assert!(no_stages(d));
    f.store.close().await;
    f.admin.close().await;
}

#[tokio::test]
async fn at_aud_03_concurrent_checkpoint_publishers_persist_one_head() {
    let f = fixture().await;
    let temp = tempfile::tempdir().unwrap();
    let d = temp.path();
    let (org, tenant) = f.org(3).await;
    let (first, second) = (d.join("a"), d.join("b"));
    let (a, b) = tokio::join!(
        f.create(&tenant, &first, None),
        f.create(&tenant, &second, None),
    );
    let results = [a, b];
    assert_eq!(results.iter().filter(|r| **r == Ok(3)).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|r| **r == Err(Error::AlreadyPersisted(3)))
            .count(),
        1
    );
    assert_eq!(
        usize::from(d.join("a").exists()) + usize::from(d.join("b").exists()),
        1
    );
    let winner = if d.join("a").exists() { "a" } else { "b" };
    check_bundle(
        &d.join(winner),
        &f.persisted(org, 3).await.unwrap(),
        &f.public,
    );
    assert!(no_stages(d));
    f.store.close().await;
    f.admin.close().await;
}

#[tokio::test]
async fn at_aud_03_recovery_fails_closed() {
    let f = fixture().await;
    let temp = tempfile::tempdir().unwrap();
    let d = temp.path();
    let (org, tenant) = f.org(4).await;
    let seq = f.create(&tenant, &d.join("ok"), None).await.unwrap();
    let record = f.persisted(org, seq).await.unwrap();
    let signs = f.signs();
    let recover = |tenant: Tenant, org: Uuid, seq: u64, public: Vec<u8>, name: &'static str| {
        let output = d.join(name);
        async move {
            let result = audit_checkpoint::recover(&tenant, org, seq, &public, &output).await;
            assert!(
                !output.exists() || result.is_ok(),
                "failed recovery must publish nothing"
            );
            result
        }
    };
    // Absent record: says so, without claiming anything about HSM state.
    assert_eq!(
        recover(tenant.clone(), org, 3, f.public.clone(), "absent").await,
        Err(Error::Absent)
    );
    assert!(Error::Absent
        .to_string()
        .contains("does not show that the HSM did not sign"));
    // Wrong organisation: RLS hides the record; a mismatched org argument is rejected.
    let (other, other_tenant) = f.org(4).await;
    assert_eq!(
        recover(
            other_tenant.clone(),
            other,
            seq,
            f.public.clone(),
            "wrong-org"
        )
        .await,
        Err(Error::Absent)
    );
    assert_eq!(
        recover(
            tenant.clone(),
            other,
            seq,
            f.public.clone(),
            "wrong-org-arg"
        )
        .await,
        Err(Error::Verification)
    );
    // Wrong pinned key.
    let other_key = f
        .backend
        .inner
        .generate(Algorithm::P256, Purpose::Test)
        .unwrap();
    let wrong = f.backend.inner.public_key(&other_key).unwrap();
    assert_eq!(
        recover(tenant.clone(), org, seq, wrong, "wrong-key").await,
        Err(Error::Verification)
    );
    assert_eq!(
        recover(
            tenant.clone(),
            org,
            seq,
            b"not a key".to_vec(),
            "garbage-key"
        )
        .await,
        Err(Error::Verification)
    );
    // Tampered signature, tampered payload and malformed records (inserted out of band by an
    // attacker with DB write) fail verification.
    let insert = |org: Uuid, seq: u64, record: serde_json::Value| {
        let admin = f.admin.clone();
        async move {
            sqlx::query(
                "INSERT INTO brigalow.audit_checkpoints(org_id,seq,record) VALUES($1,$2,$3)",
            )
            .bind(org)
            .bind(seq as i64)
            .bind(Json(record))
            .execute(&admin)
            .await
            .unwrap();
        }
    };
    let mut bad_sig = record.clone();
    bad_sig.checkpoint.seq = 1;
    bad_sig.checkpoint.entry_hash = tenant.audit_page(0, 1).await.unwrap()[0].entry_hash.clone();
    insert(org, 1, serde_json::to_value(&bad_sig).unwrap()).await;
    assert_eq!(
        recover(tenant.clone(), org, 1, f.public.clone(), "tampered-payload").await,
        Err(Error::Verification)
    );
    let mut flipped = record.clone();
    flipped.checkpoint.seq = 2;
    flipped.checkpoint.entry_hash = tenant.audit_page(1, 1).await.unwrap()[0].entry_hash.clone();
    let mut signed =
        brigalow_crypto::audit::sign(&f.backend.inner, &f.key, flipped.checkpoint).unwrap();
    let last = signed.signature.len() - 1;
    signed.signature[last] ^= 1;
    insert(org, 2, serde_json::to_value(&signed).unwrap()).await;
    assert_eq!(
        recover(
            tenant.clone(),
            org,
            2,
            f.public.clone(),
            "tampered-signature"
        )
        .await,
        Err(Error::Verification)
    );
    insert(
        other,
        1,
        serde_json::json!({"checkpoint": {}, "signature": []}),
    )
    .await;
    assert_eq!(
        recover(
            other_tenant.clone(),
            other,
            1,
            f.public.clone(),
            "malformed"
        )
        .await,
        Err(Error::Verification)
    );
    // A record whose payload names another organisation/sequence is rejected.
    let mut foreign = record.clone();
    foreign.checkpoint.org_id = org;
    insert(other, 2, serde_json::to_value(&foreign).unwrap()).await;
    assert_eq!(
        recover(other_tenant.clone(), other, 2, f.public.clone(), "foreign").await,
        Err(Error::Verification)
    );
    // Changed prefix: a DB admin rewrites an entry covered by a valid signed checkpoint.
    // The original is restored afterwards so later whole-database drills (AT-OPS-03) still
    // verify every tenant chain.
    let original: Json<serde_json::Value> =
        sqlx::query_scalar("SELECT entry FROM brigalow.audit_entries WHERE org_id=$1 AND seq=3")
            .bind(org)
            .fetch_one(&f.admin)
            .await
            .unwrap();
    sqlx::query("UPDATE brigalow.audit_entries SET entry=jsonb_set(entry,'{details,i}','99') WHERE org_id=$1 AND seq=3")
        .bind(org)
        .execute(&f.admin)
        .await
        .unwrap();
    let changed = recover(tenant.clone(), org, seq, f.public.clone(), "changed-prefix").await;
    sqlx::query("UPDATE brigalow.audit_entries SET entry=$2 WHERE org_id=$1 AND seq=3")
        .bind(org)
        .bind(original)
        .execute(&f.admin)
        .await
        .unwrap();
    assert_eq!(changed, Err(Error::Verification));
    audit_checkpoint::recover(&tenant, org, seq, &f.public, &d.join("restored"))
        .await
        .unwrap();
    assert_eq!(f.signs(), signs, "no failure path signs");
    for error in [
        Error::Verification,
        Error::Absent,
        Error::Mismatch,
        Error::Failed,
    ] {
        let text = error.to_string();
        assert!(!text.contains(&org.to_string()) && !text.contains("postgres"));
    }
    assert!(no_stages(d));
    f.store.close().await;
    f.admin.close().await;
}
