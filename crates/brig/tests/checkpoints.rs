use brigalow_core::{
    audit::{Checkpoint, Entry, Event, GENESIS},
    Purpose,
};
use brigalow_crypto::{audit, software::Software, Algorithm, KeyBackend};
use std::process::Command;
use uuid::Uuid;
#[test]
fn at_aud_02_signed_checkpoint_rejects_replacement_and_suffix_truncation() {
    let temp = tempfile::tempdir().unwrap();
    let d = temp.path();
    let backend = Software::new(true).unwrap();
    let org = Uuid::new_v4();
    let one = Entry::new(
        1,
        GENESIS.into(),
        Event {
            org_id: org,
            at: 1,
            actor: "test".into(),
            action: "test".into(),
            subject: "test".into(),
            details: serde_json::json!({}),
        },
    )
    .unwrap();
    let two = Entry::new(
        2,
        one.entry_hash.clone(),
        Event {
            org_id: org,
            at: 2,
            actor: "test".into(),
            action: "test".into(),
            subject: "test".into(),
            details: serde_json::json!({}),
        },
    )
    .unwrap();
    let export = format!(
        "{}\n{}\n",
        serde_json::to_string(&one).unwrap(),
        serde_json::to_string(&two).unwrap()
    );
    for algorithm in [Algorithm::Rsa3072, Algorithm::P256, Algorithm::Ed25519] {
        let key = backend.generate(algorithm, Purpose::Test).unwrap();
        let public = backend.public_key(&key).unwrap();
        let checkpoint = Checkpoint {
            version: 1,
            org_id: org,
            seq: 2,
            entry_hash: two.entry_hash.clone(),
            at: 2,
            key_id: key.id,
            algorithm,
        };
        let signed = audit::sign(&backend, &key, checkpoint).unwrap();
        audit::verify(&signed, &public).unwrap();
        std::fs::write(
            d.join("checkpoint.json"),
            serde_json::to_vec(&signed).unwrap(),
        )
        .unwrap();
        std::fs::write(d.join("public.der"), &public).unwrap();
        std::fs::write(d.join("audit.jsonl"), &export).unwrap();
        let verify = || {
            Command::new(env!("CARGO_BIN_EXE_brig"))
                .current_dir(d)
                .args([
                    "audit",
                    "verify",
                    "audit.jsonl",
                    "--checkpoint",
                    "checkpoint.json",
                    "--public-key",
                    "public.der",
                ])
                .output()
                .unwrap()
                .status
                .success()
        };
        assert!(verify());
        std::fs::write(
            d.join("audit.jsonl"),
            format!("{}\n", serde_json::to_string(&one).unwrap()),
        )
        .unwrap();
        assert!(!verify());
        std::fs::write(d.join("audit.jsonl"), &export).unwrap();
        let mut tampered = signed.clone();
        tampered.checkpoint.entry_hash = "f".repeat(64);
        std::fs::write(
            d.join("checkpoint.json"),
            serde_json::to_vec(&tampered).unwrap(),
        )
        .unwrap();
        assert!(!verify());
        assert!(audit::verify(&tampered, &public).is_err());
        let other = backend.generate(algorithm, Purpose::Test).unwrap();
        assert!(audit::verify(&signed, &backend.public_key(&other).unwrap()).is_err());
    }
}
