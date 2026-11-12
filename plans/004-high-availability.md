# Plan 004: Design shared OIDC state and a safe HA boundary

> **Executor:** Design/spike only. Do not change code, chart replicas, infrastructure, or deployment. Drift check: `git diff --stat 89cf46697091a1b175435f1971ba74a3131db7d1..HEAD -- crates/brigalow-server/src/auth crates/brigalow-server/src/signing.rs crates/brigalow-store/src deploy/helm/brigalow/templates/deployment.yaml docs/operations.md docs/threat-model.md`; stop on material mismatch.

## Status

Priority P2; effort L; risk HIGH; direction; depends on 001 recovery design. Planned at `89cf466`, 2026-11-12. Outcome `plans/004-ha-outcome.md`.

## Why and current state

`crates/brigalow-server/src/auth/oidc.rs:33–56` generates PKCE/nonce and stores browser-bound pending login state in an in-process map; `:76–87` consumes it once. `deploy/helm/brigalow/templates/deployment.yaml:1–12` rejects replicas other than one and uses Recreate. `docs/operations.md:54–58` says active sessions and intents are in Postgres, pending logins restart after process restart, and there is no exactly-once hardware-signature guarantee. Cross-replica login state is necessary but insufficient for HA: HSM sessions, in-flight signing, maintenance, migrations and recovery need independent analysis.

## Scope and constraints

Read the listed files, `docs/architecture.md`, `docs/product/scope.md`, `crates/brigalow-server/src/main.rs`, and both `plans/001-interrupted-request-recovery.md` and its completed `plans/001-recovery-outcome.md` before finalising; write only the outcome. Preserve the existing single-replica prohibition until a separately approved implementation passes real qualification. No actual HSM/cluster, cloud account, private-key export, bulk approve, automatic replay, software fallback, or production deployment. Any encryption must use approved vetted crates/HSM mechanisms; never invent crypto.

Later code gates: `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets --all-features -- -D warnings`, `cargo test --workspace`, `python3 scripts/test_helm.py`, and `python3 scripts/e2e.py --context <explicit-local-context>`; all exit 0. Add a disposable multi-instance integration suite and independent OpenSSL signatures before proposing replica changes. Run `cargo clean` in built workspaces after verification.

## Steps

1. Map every per-process datum (at least pending PKCE/nonce/state, JWKS cache, HSM session and expiry task), durable state and their trust boundaries. Assess shared Postgres failure, partitions and clocks; distinguish factual source evidence from unknown vendor behaviour. **Verify:** `rg -n 'pending:|keys:|Mutex|expire_requests|replicas|Recreate' crates/brigalow-server/src/auth crates/brigalow-server/src/main.rs deploy/helm/brigalow/templates/deployment.yaml` exits 0.
2. Specify alternatives for browser-bound, expiring, single-use pending state across replicas, including protection of the PKCE verifier, key distribution/rotation, tenant isolation, size limits, atomic consumption and crash handling. Select no storage encryption primitive without a crate and key-management threat assessment. **Verify:** outcome contains `## Shared-login design` and `## Secrets and trust boundaries`.
3. Define an explicit safety matrix for duplicate signing, gate completion, approval expiry, caps, audit chain, startup/rollout/migrations and failure recovery under concurrent instances. Use 001's reconciliation design as prerequisite; do not promise distributed exactly-once hardware signatures. Define an observable no-retry rule when operation outcome is unknown. **Verify:** outcome contains `## Concurrency and failure matrix` and `## Migration and rollout`.
4. Specify two-instance generated-JWKS and SoftHSM tests for cross-instance callback, replay races, expiry, restart, revocation, failed DB, concurrent cap and audit ordering, and backend failures. Identify what cannot be inferred from emulated HSM tests and requires separate vendor/CNI qualification. **Verify:** `test -s plans/004-ha-outcome.md && rg -n '^## (Shared-login design|Secrets and trust boundaries|Concurrency and failure matrix|Migration and rollout|Acceptance tests|External qualification)' plans/004-ha-outcome.md` finds all six headings.

## Done and STOP conditions

Done: outcome makes every cross-process guarantee, threat boundary and qualification limit explicit; no replica guard is removed. Stop if any design requires a silent retry after an uncertain HSM operation, shared plaintext secrets without a threat/key-management decision, untested trust-boundary changes, or real infrastructure. Update threat model as part of later implementation; keep AT-ID-01/03, AT-APR/REL, AT-AUD and AT-TEN gates.
