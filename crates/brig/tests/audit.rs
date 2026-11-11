use brigalow_core::audit::{Entry, Event, GENESIS};
use std::{io::Write, process::Command};

fn verify(entries: &[Entry]) -> std::process::Output {
    let mut file = tempfile::NamedTempFile::new().unwrap();
    for entry in entries {
        writeln!(file, "{}", serde_json::to_string(entry).unwrap()).unwrap();
    }
    Command::new(env!("CARGO_BIN_EXE_brig"))
        .args(["audit", "verify"])
        .arg(file.path())
        .output()
        .unwrap()
}

#[test]
fn at_aud_01_cli_verifies_1000_entries_and_detects_tampering() {
    let org = uuid::Uuid::new_v4();
    let mut entries = Vec::new();
    let mut prev = GENESIS.to_string();
    for seq in 1..=1000 {
        let entry = Entry::new(
            seq,
            prev,
            Event {
                org_id: org,
                at: seq as i64,
                actor: "test".into(),
                action: "created".into(),
                subject: "project".into(),
                details: serde_json::json!({"name":"original"}),
            },
        )
        .unwrap();
        prev = entry.entry_hash.clone();
        entries.push(entry);
    }
    assert!(verify(&entries).status.success());
    let mut tampered = entries.clone();
    tampered[499].details["name"] = "Original".into();
    let result = verify(&tampered);
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("seq 500"));
    entries.remove(9);
    let result = verify(&entries);
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("seq 10"));
}

#[test]
fn canonical_hash_matches_openssl() {
    let entry = Entry::new(
        1,
        GENESIS.into(),
        Event {
            org_id: uuid::Uuid::nil(),
            at: 0,
            actor: "test".into(),
            action: "created".into(),
            subject: "project".into(),
            details: serde_json::json!({"nested":{"z":2,"a":1}}),
        },
    )
    .unwrap();
    let mut file = tempfile::NamedTempFile::new().unwrap();
    file.write_all(&entry.canonical_bytes().unwrap()).unwrap();
    let out = Command::new("openssl")
        .args(["dgst", "-sha256"])
        .arg(file.path())
        .output()
        .unwrap();
    assert!(out.status.success());
    assert!(String::from_utf8_lossy(&out.stdout).contains(&entry.entry_hash));
}
