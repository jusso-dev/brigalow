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

fn chain(org: Uuid, count: u64) -> Vec<Entry> {
    let mut entries: Vec<Entry> = vec![];
    for seq in 1..=count {
        let prev = entries
            .last()
            .map_or(GENESIS.to_string(), |e| e.entry_hash.clone());
        entries.push(
            Entry::new(
                seq,
                prev,
                Event {
                    org_id: org,
                    at: seq as i64,
                    actor: "test".into(),
                    action: "test".into(),
                    subject: "test".into(),
                    details: serde_json::json!({}),
                },
            )
            .unwrap(),
        );
    }
    entries
}

fn jsonl(entries: &[Entry]) -> String {
    entries
        .iter()
        .map(|e| serde_json::to_string(e).unwrap() + "\n")
        .collect()
}

#[test]
fn at_aud_03_expected_head_rejects_older_and_substituted_checkpoints() {
    let temp = tempfile::tempdir().unwrap();
    let d = temp.path();
    let backend = Software::new(true).unwrap();
    let key = backend.generate(Algorithm::P256, Purpose::Test).unwrap();
    std::fs::write(d.join("public.der"), backend.public_key(&key).unwrap()).unwrap();
    let org = Uuid::new_v4();
    let entries = chain(org, 3);
    let checkpoint = |seq: u64, org_id: Uuid, entries: &[Entry]| {
        let signed = audit::sign(
            &backend,
            &key,
            Checkpoint {
                version: 1,
                org_id,
                seq,
                entry_hash: entries[seq as usize - 1].entry_hash.clone(),
                at: seq as i64,
                key_id: key.id,
                algorithm: Algorithm::P256,
            },
        )
        .unwrap();
        serde_json::to_vec(&signed).unwrap()
    };
    let head = |org: Uuid, seq: u64, entries: &[Entry]| {
        format!("{org}:{seq}:{}", entries[seq as usize - 1].entry_hash)
    };
    let run = |export: &str, checkpoint: &[u8], extra: &[&str]| {
        std::fs::write(d.join("audit.jsonl"), export).unwrap();
        std::fs::write(d.join("checkpoint.json"), checkpoint).unwrap();
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
            .args(extra)
            .output()
            .unwrap()
    };
    let latest = checkpoint(3, org, &entries);
    let current = head(org, 3, &entries);
    // Exact retained head: accepted and reported as matching it.
    let out = run(&jsonl(&entries), &latest, &["--expected-head", &current]);
    assert!(out.status.success());
    assert!(String::from_utf8_lossy(&out.stdout)
        .contains("matching the independently retained expected head"));
    // Option order is free.
    let out = Command::new(env!("CARGO_BIN_EXE_brig"))
        .current_dir(d)
        .args([
            "audit",
            "verify",
            "audit.jsonl",
            "--expected-head",
            &current,
        ])
        .args([
            "--public-key",
            "public.der",
            "--checkpoint",
            "checkpoint.json",
        ])
        .output()
        .unwrap();
    assert!(out.status.success());
    // No expected head: valid, but freshness is explicitly unknown.
    let out = run(&jsonl(&entries), &latest, &[]);
    assert!(out.status.success());
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("cryptographically valid prefix; freshness unknown"));
    assert!(!text.contains("current") && !text.contains("retained."));
    // Older but perfectly valid checkpoint and prefix (rollback): rejected against the head.
    let older = checkpoint(2, org, &entries);
    let out = run(&jsonl(&entries[..2]), &older, &[]);
    assert!(
        out.status.success(),
        "older prefix is cryptographically valid"
    );
    let out = run(
        &jsonl(&entries[..2]),
        &older,
        &["--expected-head", &current],
    );
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("expected head"));
    // Newer-than-expected and substituted hash or organisation also fail.
    let out = run(
        &jsonl(&entries),
        &latest,
        &["--expected-head", &head(org, 2, &entries)],
    );
    assert!(!out.status.success());
    let other = Uuid::new_v4();
    let foreign = chain(other, 3);
    let out = run(
        &jsonl(&foreign),
        &checkpoint(3, other, &foreign),
        &["--expected-head", &current],
    );
    assert!(!out.status.success());
    let substituted = format!("{org}:3:{}", "e".repeat(64));
    let out = run(
        &jsonl(&entries),
        &latest,
        &["--expected-head", &substituted],
    );
    assert!(!out.status.success());
    // Malformed heads, duplicates and an expected head without a checkpoint are usage errors.
    for extra in [
        vec!["--expected-head", "nonsense"],
        vec!["--expected-head", &current, "--expected-head", &current],
        vec!["--checkpoint", "checkpoint.json"],
        vec!["--unknown", "x"],
        vec!["--expected-head"],
    ] {
        let out = run(&jsonl(&entries), &latest, &extra);
        assert!(!out.status.success());
        assert!(String::from_utf8_lossy(&out.stderr).contains("usage:"));
    }
    let out = Command::new(env!("CARGO_BIN_EXE_brig"))
        .current_dir(d)
        .args([
            "audit",
            "verify",
            "audit.jsonl",
            "--expected-head",
            &current,
        ])
        .output()
        .unwrap();
    assert!(!out.status.success());
    // Chain-only form is unchanged.
    let out = Command::new(env!("CARGO_BIN_EXE_brig"))
        .current_dir(d)
        .args(["audit", "verify", "audit.jsonl"])
        .output()
        .unwrap();
    assert!(out.status.success());
    assert!(String::from_utf8_lossy(&out.stdout).contains("chain integrity only"));
}
