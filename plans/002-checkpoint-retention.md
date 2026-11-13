# Plan 002: Design independently retained audit checkpoints

> **Executor:** Design/spike only; write outcome under `plans/`. Drift check: `git diff --stat 89cf46697091a1b175435f1971ba74a3131db7d1..HEAD -- crates/brigalow-server/src/bin/brigalow-audit.rs crates/brigalow-store/src/checkpoints.rs crates/brig/tests/checkpoints.rs docs/operations.md docs/threat-model.md`. Stop if excerpts materially changed.

## Status

Priority P1; effort M–L; risk MEDIUM; direction; depends on none. Planned at `89cf466`, 2026-11-12. Outcome `plans/002-checkpoint-retention-outcome.md`.

## Why and current state

`brigalow-audit checkpoint` signs a tenant audit prefix with a dedicated PKCS#11 key, persists the signed checkpoint, then writes local public outputs (`crates/brigalow-server/src/bin/brigalow-audit.rs:63–123`). `crates/brigalow-store/src/checkpoints.rs` prevents duplicate org/sequence insertion. `brig audit verify` checks the supplied checkpoint with an independently pinned public key; `docs/operations.md:32–34` requires retaining the latest checkpoint outside the DB and warns that a verifier cannot detect a newer withheld head without independent evidence. `crates/brig/tests/checkpoints.rs` tests wrong key, tampering and suffix truncation.

Operators need a reproducible local export, retention and freshness procedure that still works air-gapped. A checkpoint stored only beside the database is not independent. Never imply that signatures alone prove the latest head, or that local file placement guarantees off-host retention.

## Scope and constraints

Read `crates/brigalow-server/src/bin/brigalow-audit.rs`, `crates/brigalow-store/src/checkpoints.rs`, `crates/brig/tests/checkpoints.rs`, `scripts/backup_restore.py`, `docs/operations.md` and `docs/threat-model.md`; write only the outcome document. No network transfer, messages, external services, cloud accounts, production deployment, private-key export, or new cryptography. Do not assume an append-only target is immutable unless the operator configures and verifies it independently.

Later implementation gates: `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets --all-features -- -D warnings`, `cargo test --workspace`, and `python3 scripts/e2e.py --context <explicit-local-context>` must exit 0. The latter runs AT-AUD-01/02 and AT-OPS-03 with generated keys and OpenSSL. If Cargo builds/tests/checks are run, finish with `cargo clean` in each workspace.

## Steps

1. Map existing create/export/persist order and all failure windows, especially DB commit followed by file-write interruption and an already-persisted `(org,seq)`. **Verify:** `rg -n 'checkpoint_head|save_checkpoint|create_new|checkpoint.sig|matches_checkpoint' crates/brigalow-server/src/bin/brigalow-audit.rs crates/brigalow-store/src/checkpoints.rs` exits 0. Record exact current recovery capabilities versus unknowns; do not claim the CLI can retrieve a persisted record until proven.
2. Specify an operator-triggered, bounded local workflow: independently configured pinned public key, atomic staged bundle and completion marker, directory permissions, no overwrite, observable failure, crash-safe resume of the *same* persisted signed checkpoint without re-signing. Define an externally maintained expected latest `(org,seq,hash)` and stale/rollback detection; the storage/transport mechanism is explicitly operator-controlled. **Verify:** outcome contains `## Publication and recovery contract` and `## Independent trust and freshness`.
3. Specify test cases: OpenSSL verifies generated SoftHSM signatures, interrupted DB/file phases and duplicate scheduling, concurrent publication, stale/older head, wrong key/org, tampered data, absent external expected head, permission/symlink/partial-write failure, and restoration with a retained external head. No test uses committed secrets. **Verify:** outcome contains `## Acceptance tests` and `## Future implementation boundaries`.
4. Define scheduler integration as optional operator-owned invocation and monitoring via local exit status; no hidden network egress or email. Identify trust-model updates. **Verify:** `test -s plans/002-checkpoint-retention-outcome.md && rg -n '^## (Publication and recovery contract|Independent trust and freshness|Acceptance tests|Future implementation boundaries|Residual risks)' plans/002-checkpoint-retention-outcome.md` finds all five headings.

## Done and STOP conditions

Done: outcome explicitly explains retained-head provenance and cannot equate an included public key with identity; all five sections exist and only `plans/` changes. Stop if the solution needs signing the same uncertain head again, writing private keys, promising off-host immutability without evidence, or contacting real infrastructure. Later reviewers must retain AT-AUD-01/02 and AT-OPS-03.
