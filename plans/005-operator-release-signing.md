# Plan 005: Design operator-owned release-signing workflow

> **Executor:** Design/spike only; write outcome under `plans/`. No real signing key, production deployment, publication or external service. Drift check: `git diff --stat 89cf46697091a1b175435f1971ba74a3131db7d1..HEAD -- .github/workflows/release.yml scripts/package_release.py scripts/test_release.py scripts/verify_release.py docs/operations.md docs/product/scope.md docs/threat-model.md`; stop on a material mismatch.

## Status

Priority P2; effort M–L; risk HIGH; direction; depends on 001 for interruption semantics and 002 for retained checkpoint evidence; drafting may proceed in parallel. Planned at `89cf466`, 2026-11-12. Outcome `plans/005-release-signing-outcome.md`.

## Why and current state

`./.github/workflows/release.yml` builds a Linux archive and SBOM, then uses a disposable lab control plane. `scripts/package_release.py:33–35` records revision, SHA-256 payload digests and `trust="lab"`. `scripts/verify_release.py` checks a manifest signature and each local filename/digest; an included lab key alone does not authenticate a publisher. `docs/operations.md:66–72` explicitly distinguishes lab integrity evidence from an operator-owned release process. Brigalow's core purpose is controlled digest signing, not public CA issuance.

## Scope and constraints

Read the listed files, `crates/brig/src/sign.rs`, `docs/integrations/github-actions.md`, `docs/decisions/0003-trust-tiers.md`, and `docs/acceptance-tests.md`; write only the outcome. The proposal may use only disposable locally generated test identities, mock IdP/TSA and SoftHSM in later tests. No real CA enrolment, certificate purchase, cloud account, real key/token, production deployment, publishing, outbound messages or key export. Never claim public trust, FIPS or certification. No source, workflow or release changes in this spike.

Later gates: `python3 scripts/test_release.py`; `cargo fmt --all -- --check`; `cargo clippy --workspace --all-targets --all-features -- -D warnings`; `cargo test --workspace`; `python3 scripts/e2e.py --context <explicit-local-context>`. All exit 0, generated credentials only. Run `cargo clean` in each built workspace when finished. GitHub Actions must remain full-SHA pinned and use hosted runners; do not create a self-hosted runner.

## Steps

1. Trace the existing manifest, exact signed bytes, bundled public key, verification and payload/SBOM flow; distinguish integrity from publisher identity. **Verify:** `rg -n 'trust="lab"|manifest|public-key|verify_release|lab-signed' scripts/package_release.py scripts/verify_release.py .github/workflows/release.yml docs/operations.md` exits 0.
2. Specify an operator-controlled, offline-capable workflow that takes an independently pinned public key and signs the exact manifest digest via the existing policy/approval/HSM path. Define lab versus operator trust labels, subject/revision/SBOM binding, certificate chain limits, signing outputs and versioning without asserting public trust. Do not add a bypass route or allow a supplied key to establish its own trust. **Verify:** outcome contains `## Trust and identity` and `## Manifest and verification contract`.
3. Specify failure semantics for interrupted signing, signature/timestamp failure, output overwrite and approvals; use 001's recovery boundary rather than retrying uncertain work. Clarify this design creates no release, deploys nothing and changes no credentials. **Verify:** outcome contains `## Failure and operator workflow`.
4. Define local integration tests: generated-key lab and SoftHSM paths, OpenSSL independent verification, independently pinned wrong/replaced key, altered manifest/SBOM/archive/revision, malformed paths, absent output on required timestamp/gate failure, interrupted signing and unchanged lab workflow. Propose AT ID and review checklist for future implementation. **Verify:** `test -s plans/005-release-signing-outcome.md && rg -n '^## (Trust and identity|Manifest and verification contract|Failure and operator workflow|Acceptance tests|Residual risks)' plans/005-release-signing-outcome.md` finds all five headings.

## Done and STOP conditions

Done: design separates test/lab from operator authenticity, names the verifier's independent trust source, specifies all five sections and leaves source untouched. Stop if signing a release requires a real account, a private key export, trusting a co-delivered key without independent authentication, automatic retry of an uncertain signature, or publishing/deploying. Later implementation must retain AT-SIGN-01..03, AT-AUD-02 and phase 8 release checks.
