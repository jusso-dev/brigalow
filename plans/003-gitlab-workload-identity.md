# Plan 003: Design GitLab workload identity integration

> **Executor:** Design/spike only; outcome under `plans/`. Drift check: `git diff --stat 89cf46697091a1b175435f1971ba74a3131db7d1..HEAD -- crates/brigalow-server/src/auth crates/brigalow-core/src/policy.rs crates/brigalow-crypto/src/attestation.rs actions/sign docs/integrations/github-actions.md docs/product/scope.md docs/threat-model.md`. Stop on material mismatch.

## Status

Priority P1; effort L; risk HIGH; direction; depends on none. Planned at `89cf466`, 2026-11-12. Outcome `plans/003-gitlab-outcome.md`.

## Why and current state

`docs/product/scope.md:30` names GitLab after GitHub for workload OIDC. `crates/brigalow-server/src/auth/workload.rs:49–76` selects a pinned issuer, verifies the `brigalow:<org>` audience, limits token lifetime and checks configured exact raw claims. `crates/brigalow-server/src/auth/mod.rs:281–292` copies only a fixed list into `Principal.claims`, which policies and provenance use. `crates/brigalow-core/src/policy.rs:70–77` requires repository, ref, environment and `ref_protected=true` for release; attestation also requires verified repository, SHA and workflow. The existing GitHub wrapper and generated mock issuer are examples, not proof of GitLab semantics.

## Scope and constraints

Read the files above, `docs/attestation-v1.md`, `deploy/dev/test_idp.py`, `crates/brigalow-server/tests/identity.rs`, `docs/threat-model.md` and `docs/acceptance-tests.md`; write only the outcome. No GitLab account, real pipeline, real token, hosted runner, cloud service, production endpoint, external message or committed credential. No Node. Do not weaken release claims to accommodate a provider.

Later implementation gates: `cargo fmt --all -- --check`; `cargo clippy --workspace --all-targets --all-features -- -D warnings`; `cargo test --workspace`; `python3 scripts/e2e.py --context <explicit-local-context>`. All exit 0; e2e uses an HTTPS mock issuer/JWKS, Postgres, SoftHSM and independent OpenSSL. Run `cargo clean` in every built workspace when finished.

## Steps

1. Inventory raw-claim matching versus claims retained for policy and DSSE; cite each line and describe current issuer, audience, time, project and policy binding. **Verify:** `rg -n 'verify_workload|brigalow:|claims: \[|ref_protected|attestation_claims_required' crates/brigalow-server/src/auth crates/brigalow-core/src/policy.rs` exits 0.
2. Research current GitLab ID-token documentation through Context7 (resolve the library ID and query the relevant concepts) without credentials or contacting a real issuer. Record documentation URL, retrieval date, supported versions, exact types/semantics and any claims whose equivalence is uncertain. Write a table from *verified provider claim* to Brigalow claim, with issuer-specific rules. Do not map `ref_protected`, environment protection, repository or workflow merely because names look similar; missing or ambiguous values fail closed. Explicitly decide interaction with existing release-policy and DSSE semantics. **Verify:** outcome contains `## Provider claim mapping` and `## Trust and policy contract`; every mapped release claim has cited provider documentation or is marked unresolved.
3. Specify a minimal self-hosted CI example and mock token fixtures generated at runtime, never as checked-in keys/tokens. Require issuer/audience/signature/expiry, cross-tenant, project/ref/environment/protected-ref mismatches, metadata spoofing and incompatible claim types. Require GitHub regressions and verify DSSE claims/signature with independent OpenSSL. **Verify:** outcome contains `## Integration and test matrix` and `## Compatibility`.
4. Record explicit unknowns, non-goals, threat-model boundary changes, prospective AT ID and implementation files. **Verify:** `test -s plans/003-gitlab-outcome.md && rg -n '^## (Provider claim mapping|Trust and policy contract|Integration and test matrix|Compatibility|Open questions)' plans/003-gitlab-outcome.md` finds all five headings.

## Done and STOP conditions

Done: all mapped authoritative values derive from verified issuer-signed claims; no configuration silently promotes unverified metadata; tests and compatibility are specified; only `plans/` changes. Stop if reliable provider evidence for a protected release claim is unavailable; document the missing claim and scope the design to a fail-closed/test-only path, never create a real account. Later work must maintain AT-ID-01..03, AT-POL-02, AT-ATT-01 and AT-TEN-01.
