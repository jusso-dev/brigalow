# Brigalow direction plans

Prepared with the `shadcn/improve next` workflow on 2026-11-12, against `89cf46697091a1b175435f1971ba74a3131db7d1`. The user selected all five recommendations. These began as **design/spike plans**; they are not permission to access production infrastructure. On 12-11-2026 a first implementation slice of each was built and passed `cargo fmt --check`, `cargo clippy --workspace --all-targets --all-features -D warnings`, `cargo test --workspace`, `scripts/test_release.py`, `scripts/test_helm.py` and the full local `scripts/e2e.py --context orbstack` harness together. Hosted CI passed and the slices merged to `main` as PR #1 (`0733252`) on 13-11-2026, followed by the Azure Artifact Signing backend as PR #2 (`fde7ebb`). Blocked items below remain unimplemented by design.

| Order | Plan | Priority | Effort | Depends on | Status |
| --- | --- | --- | --- | --- | --- |
| 1 | [Interrupted-request reconciliation](001-interrupted-request-recovery.md) | P1 | L | — | IMPLEMENTED (read-only inspection, AT-REC-01); terminal resolution BLOCKED pending a fencing/quiescence design |
| 2 | [Checkpoint retention](002-checkpoint-retention.md) | P1 | M–L | — | IMPLEMENTED (read-only recover, no-replace publication, expected-head check, AT-AUD-03); off-host transfer is operator-owned |
| 3 | [GitLab workload identity](003-gitlab-workload-identity.md) | P1 | L | — | IMPLEMENTED (test-purpose profile, AT-ID-04); release and attestation BLOCKED pending a reviewed provenance/claim contract |
| 4 | [Shared login state and HA](004-high-availability.md) | P2 | L | 001 design | IMPLEMENTED (encrypted shared login state, AT-HA-01); AT-HA-02 not implemented; multi-replica production BLOCKED, Helm still enforces one replica |
| 5 | [Operator-owned release signing](005-operator-release-signing.md) | P2 | M–L | 002 for retained checkpoint evidence; 001 for interruption semantics | IMPLEMENTED (v2 operator manifest, strict verifier, single-attempt workflow, AT-REL-03); no production HSM qualified, no publication |
| 6 | [Fencing and resolution of stranded requests](006-fencing-and-resolution.md) | P1 | L | 001 | DESIGN FOR REVIEW (AT-REC-02, AT-HA-02 specified); unblocks 001 resolution and 004 AT-HA-02 |
| 7 | [Release signing decisions](007-release-signing-decisions.md) | P2 | M | 005 | RECOMMENDATIONS FOR REVIEW (key rotation, expected revision, algorithm profile, atomic output) |

## Decisions recorded 13-11-2026

- **001 resolution:** write the fencing/quiescence design first (plan 006); no code until it is reviewed.
- **003 GitLab:** stay test-purpose only. Revisit release and attestation when a real GitLab instance is available to confirm token shapes.
- **004 HA:** build AT-HA-02 only after plan 006 is reviewed. One replica stays enforced until it passes.
- **005 release signing:** record recommended choices for the four open items (plan 007) for review.
- **Azure:** the operator runs the first real deployment from [the runbook](../docs/runbooks/azure-first-deployment.md); it has not been exercised against real Azure.

## Dependency and execution notes

- Draft 001–003 independently. Complete 001's concurrency and no-retry contract before finalising 004. Draft 005 in parallel, but its final evidence/recovery story depends on 001 and 002.
- A completed design is not authorisation to enrol with a real CA, purchase certificates, create cloud accounts, deploy, send messages or use real credentials. Security controls and automated AT tests ship with any later implementation. Never export private keys, add bulk approval or silently fall back to software signing.
- The repository's standard later implementation gates are `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets --all-features -- -D warnings`, `cargo test --workspace`, and the full `python3 scripts/e2e.py --context <explicit-local-context>` acceptance harness. Use generated keys, Postgres/SoftHSM/test IdP/TSA and OpenSSL. Run `cargo clean` in every workspace built before handing back.
- `docs/product/scope.md` keeps self-hosted and outside-CA trust distinct. No feature may claim public trust, FIPS validation or compliance certification. `docs/threat-model.md` must change whenever a trust boundary changes.
- Existing accepted deployment is one server replica. The HA plan does not itself loosen that guard or qualify vendor HSMs, ingress/CNI or a real restore.

## Considered and not proposed

- Real CA enrolment, public-CA operation, paid/cloud signing accounts and production rollout: outside the authorised scope and/or product non-goals.
- Replacing the HSM with software on failure or retrying an uncertain signature: conflicts with custody and no-replay invariants.
- Treating a bundled lab public key as publisher authentication: does not provide independently established trust.
- Increasing Helm replicas immediately: process-local login state and unqualified concurrent HSM operations make a replica count change insufficient.
