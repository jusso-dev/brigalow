# Audit checkpoint retention: design outcome

Reviewed source `89cf46697091a1b175435f1971ba74a3131db7d1`. Proposed local, operator-triggered workflow; no remote storage is configured or claimed. This is a design, not implemented or tested behaviour.

## Publication and recovery contract

Current order (`crates/brigalow-server/src/bin/brigalow-audit.rs:63–120`): create a new output directory; read public key reference; get a tenant head under the audit lock; write and verify the complete JSONL prefix and fsync it; sign; `save_checkpoint` inserts `(org,seq,record)` under the audit lock if the current entry hash matches; write `checkpoint.json`, canonical bytes and signature with create-new and fsync. `save_checkpoint` refuses an existing `(org,seq)`. A failure after its commit can leave only a partial output directory while the signed record is durable. No operator command currently retrieves that persisted record; do not repeat `checkpoint` assuming it recovers it.

Add a separate read-only tenant-scoped `recover` path in a future implementation. Given exact org and seq, query the already-saved record, verify its canonical signature against an **operator-supplied independently pinned public key**, reconstruct and verify the exact audit prefix, and export identical public checkpoint bytes/signature. It must never invoke the HSM or create a new checkpoint. A missing record, changed prefix, wrong org/key, malformed record or stale schema fails closed. If no checkpoint was persisted after an uncertain pre-commit signing attempt, report that fact and do not assert the HSM did not sign; no implicit re-sign.

Stage files in a newly created private sibling directory on the same filesystem; create new regular files, reject symlinks/path escapes, fsync each file, then write and fsync a completion marker binding version/org/seq/hash and file digests. Atomically publish the **whole directory** with no replacement using a platform-provided no-replace primitive; fsync the parent. If no safe no-replace primitive exists on a target, fail rather than emulate it with a racy existence check. Recovery verifies every existing file/marker byte-for-byte; conflict fails, and no partially staged directory is treated as retained. The marker authenticates neither publisher nor latestness by itself.

## Independent trust and freshness

The operator provisions the audit public key through an independently trusted channel and records expected `(org,seq,entry_hash)` outside the Brigalow DB and signing host. The local exporter reports success only for its own complete verified bundle; off-host transport, immutability and update of the expected-head record are separate operator-controlled operations. A local file on the same host or a public key supplied in the same bundle cannot establish independence.

Verifier accepts an explicit expected head from the independent store, checks exact organisation/sequence/hash and signature, and rejects an older or substituted valid checkpoint. If no expected head is available, report **cryptographically valid prefix; freshness unknown**, not current/retained. If the external expected head is unavailable or not advanced, do not declare off-host retention or a current audit state. Record key rotations with independently pinned old and new keys and explicit transition policy; a `key_id` alone is not a trust anchor.

A scheduler may invoke the existing checkpoint command and the recovery/export verifier as separate operator-owned local jobs. Each uses explicit bounded intervals, local exit status and operator monitoring; no implicit email, network destination, cloud account, or failure-swallowing retry. Off-host transfer is out of scope.

## Acceptance tests

Propose **AT-AUD-03**. Using generated SoftHSM key and disposable DB: verify checkpoint/prefix with OpenSSL and existing `brig audit verify`; inject failure after DB commit and after each file write, recover exact bytes without a second backend sign, then verify atomic marker/publish. Test two concurrent exporters, duplicate seq, wrong org, changed prefix, tampered signature/payload, wrong pinned key, absent persisted record, symlink/directory traversal, partial marker, no-overwrite collision, permissions and crash restart. Restore a disposable DB snapshot and compare against an independently held test head: an older valid snapshot fails current-head verification; with no independent head it reports freshness unknown. Retain AT-AUD-01/02 and AT-OPS-03 full Compose gates.

## Future implementation boundaries

Candidate files: `crates/brigalow-store/src/checkpoints.rs` (tenant-scoped retrieval), `crates/brigalow-server/src/bin/brigalow-audit.rs` (recovery/export), `crates/brig/src/` verifier interface if expected-head validation belongs there, `crates/brig/tests/checkpoints.rs`, generated-credential Compose harness, `docs/acceptance-tests.md`, `docs/operations.md` and `docs/threat-model.md`. Maintain insert-only grants and RLS, no HSM key export, bounded paged audit reads and generic error output. Review platform-specific atomic publication with supported OS semantics before promising portability.

## Residual risks

An independently pinned key and externally retained latest head require a genuinely separate administrative trust boundary. This design cannot guarantee operator-managed storage or transport durability, nor detect a newer head that no independent verifier has learned. Device/HSM backup and production restore remain operator qualification tasks. Proposed AT-AUD-03 has not been implemented or run.
