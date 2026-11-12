# Security review: 12 November 2026

Reviewed commit: `4b67b41adf2cd5eeb49089e3140db6bc5f98eea8` (clean `main`).

A separate, read-only Codex reviewer (`/root/security_review`, reviewer role) inspected the committed source against [the checklist](security-review-checklist.md). The implementation agent independently examined the authentication and dependency findings. This is an AI-assisted source review, not an external professional audit or certification.

## Scope and limitations

Source review covered tenant RLS, composite references, restricted database roles, OIDC/PKCE, workload claims, session/credential handling, CSRF, approval/window/gate transitions, HSM and client PKCS#11 boundaries, CSC mock, certificates/CSR/private CA/CRL, audit checkpoints/restore, rate budgets, workflows and chart configuration. No further source-backed exploitable defect was identified. This does not establish absence of defects.

The independent reviewer ran no builds, tests, Docker, database/HSM probes, fuzzing, hosted CI or external services. No actual vendor HSM, deployment, real CA or paid service was assessed. Historical phase acceptance evidence remains in issues #1–#10. Remediation validation below is separate evidence from the implementation agent.

## SR-01: workload lifetime overflow

At the reviewed commit, `crates/brigalow-server/src/auth/workload.rs:63–66` subtracts signed `iat` from `exp` without checking overflow. A correctly signed token from a configured issuer with `iat = -9223372036854775808` and future `exp` panics in debug builds. With ordinary release overflow checks disabled, the difference wraps negative and bypasses the intended one-hour lifetime limit. Issuer, audience, signature and configured claim checks still apply; an unauthenticated caller cannot forge this token. Exploitation therefore requires a malformed token signed by the trusted issuer or compromise of that issuer.

Remediation: checked subtraction and an inclusive `1..=3600` lifetime bound. Signed-token integration regression covers the extreme timestamp, zero/negative lifetime, future issuance and a 3601-second lifetime, including HTTP 401 responses. This strengthens AT-ID-02/03 without changing the identity trust boundary.

## Dependency review

`cargo audit --json` and `cargo audit --no-fetch --file fuzz/Cargo.lock --json` used RustSec database commit `fd6f39814c4d3c359fdbe223d0280dec4933f78f` (updated 11 November 2026). Both returned nonzero.

- `RUSTSEC-2026-0387`: `crypto-bigint 0.5.5` through P-256/P-384. Secret-dependent arithmetic in the lab software P-256 backend is relevant. Production signing uses PKCS#11; public-key verification alone does not expose a private scalar.
- `RUSTSEC-2023-0071`: `rsa 0.9.10` timing advisory. The lab backend performs private RSA operations. Other direct and OIDC/JWT uses are public-key parsing/verification. No RSA decryption endpoint exists.
- `RUSTSEC-2026-0459`: root lockfile contains optional `libsqlite3-sys 0.30.1`. `cargo tree --workspace --all-features --target all -i libsqlite3-sys` prints no dependency path. The application builds only SQLx/Postgres; the SQLite database/WAL attack surface is not built. This advisory is absent from the fuzz lockfile.
- `RUSTSEC-2026-0374`: root warning for unmaintained `basic-toml 0.1.10` via Askama build tooling; not a demonstrated runtime exploit.

Private operations now use `rsa 0.10.0` and `p256 0.14.0`, with `crypto-bigint 0.7.11` in both lockfiles. Separate dependency names keep this migration limited to the lab backend; public verification and existing ASN.1 encoders retain their compatible versions. RSA signing retains OS-random blinding; P-256 generation uses the OS CSPRNG and propagates entropy errors. Existing OpenSSL acceptance tests validate generated public keys and signatures.

**Residual audit status:** the raw audit still returns nonzero for the legacy public-verification dependency graph and the unbuilt SQLite package. No advisory is suppressed or represented as fixed merely because it is unreachable for private operations. Updating the remaining OIDC/encoding dependency families and Askama build tooling is follow-up maintenance. Reassess this classification before adding any private operation or SQLite feature to those paths.

## Remediation validation

The signed-token regression was added before the fix and run through `python3 scripts/e2e.py --context orbstack`. The original compiled workload implementation failed exactly at the unchecked subtraction with `attempt to subtract with overflow`; the identity suite reported seven passes and one failure. The temporary Compose stack was removed by the harness. Release-build wrapping is established by Rust integer overflow semantics; a separate release-mode exploit was not run.

Post-fix local gates passed:

- `cargo fmt --all -- --check` and `cargo clippy --locked --workspace --all-targets --all-features -- -D warnings`.
- `cargo test --locked --workspace`: 21 tests, zero failures.
- `python3 scripts/e2e.py --context orbstack`: full Compose suite, including the workload regression and all 33 AT IDs, native signing tools, SoftHSM2, mock CSC, private CA, independent OpenSSL verification and backup/restore.
- `python3 scripts/fuzz.py` with cargo-fuzz 0.13.2 and 15-second limits: requests 917,731 executions, certificates 118,962, audit 1,100,516; no crash.
- Source snapshot gitleaks 8.30.1 scan: zero findings; action, release packaging/tamper and Helm tests passed.

Hosted CI and rebuilt lab release evidence will be recorded on the Phase 8 tracking issue for this remediation commit. Historical phase closures are not a substitute for that new run. The raw dependency audit remains nonzero as classified above.
