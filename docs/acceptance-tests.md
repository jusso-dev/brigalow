# Acceptance tests

Each test must be automated. "Run" says where it lives once built. Integration tests use `deploy/dev/compose.yml` (Postgres + SoftHSM2) and run with `cargo test --workspace --features integration`. Use `scripts/e2e.sh --context <local-context>` to generate credentials and TLS keys, start Compose, set the test environment, run integration and end-to-end tests, then clean up. Missing integration configuration fails rather than silently skipping tests. None of these need a real CA, a cloud account or a purchased certificate.

Verification uses independent tools where possible (OpenSSL), so we aren't only testing our code against itself.

## Operations and config

- **AT-OPS-01 Secrets stay out of logs and config.** Start the server with an HSM PIN and DB password from env. Trigger an error path that logs config. Assert neither value appears in stdout, stderr or `/debug` output. CI runs a secret scanner (for example gitleaks) over the repo and fails on findings. Run: `crates/brigalow-server/tests/redaction.rs`, CI job `secrets`.
- **AT-OPS-02 Rate limiting.** 200 requests in 1 s from one credential: requests beyond the configured limit get HTTP 429 and an audit entry; other credentials unaffected.
- **AT-OPS-03 Backup and restore.** Dump DB, wipe, restore; audit chain verifies; pending requests still pending; HSM key handles still resolve.

## Audit

- **AT-AUD-01 Chain integrity.** Append 1,000 entries, export JSONL, `brig audit verify` passes. Change one byte in entry 500, verify fails and names seq 500. Delete entry 10, verify fails.
- **AT-AUD-02 Checkpoints.** Checkpoint signature verifies with the audit public key using `openssl pkeyutl -verify`; tampering with the checkpoint hash fails verification. App DB role has no UPDATE/DELETE on `audit_entries` (assert via `information_schema.role_table_grants`).

## Tenancy

- **AT-TEN-01 Isolation.** Two orgs, A and B, each with a project, key, policy and request. For every API route, a credential from A addressing B's object IDs gets 404 (not 403, to avoid existence leaks) and no data. Generated from the route table so new routes are covered automatically.

## Identity

- **AT-ID-01 Human OIDC.** Against a local test IdP container, sign-in with PKCE works; a token with wrong `aud` or expired `exp` is rejected; group claim maps to the configured role.
- **AT-ID-02 Workload OIDC.** With a local JWKS server, a correctly signed CI token matching a submitter rule is accepted. Rejected: unknown issuer, bad signature, `alg: none`, wrong audience, expired, claim mismatch on repo, ref or environment.
- **AT-ID-03 Replay.** Reusing a request ID returns 409. A token past expiry is rejected even if previously accepted.

## Keys and certificates

- **AT-KEY-01 Mode guard.** In `production` mode, configuring the lab software backend fails at startup with a clear error. In `lab` mode, binding a software key to a `release` policy fails.
- **AT-KEY-02 Algorithm policy.** Generating RSA-2048 or requesting SHA-1 digest signing is rejected by default policy; RSA-3072, P-256 and Ed25519 (where the backend supports it) succeed.
- **AT-KEY-03 Non-exportable.** Generate a key on SoftHSM2. Assert `CKA_EXTRACTABLE=false` and `CKA_SENSITIVE=true`. Assert no API route returns private key material (route table scan + response schema check).
- **AT-CERT-01 CSR and import.** Generate CSR from HSM key; sign it with a test CA made by OpenSSL in the test; import chain; Brigalow validates it. Importing a cert whose public key doesn't match the HSM key is rejected.
- **AT-CERT-02 Trust tier labelling.** A chain to a configured private anchor is labelled `private`. A chain to no configured anchor is labelled `untrusted` and cannot be bound to a `release` policy. Nothing is ever labelled publicly trusted by Brigalow itself.

## Policy and signing

- **AT-POL-01 Purpose binding.** Release key on test policy: rejected at bind time. Direct DB tampering to force it: rejected again at sign time.
- **AT-POL-02 Submitter claims.** Policy allows `repo=acme/app, ref=refs/heads/main, environment=release`. Same token with `ref=refs/heads/feature-x` is rejected with an audit entry naming the failed claim.
- **AT-POL-03 Unknown policy or project.** Returns 404, logs an audit entry, never signs.
- **AT-SIGN-01 Raw signature.** `brig sign --policy test --format raw file.bin` produces a signature that `openssl pkeyutl -verify` accepts with the exported public key. The server receives only the digest (assert request body size and content in a test hook).
- **AT-SIGN-02 Detached CMS.** `brig sign --format cms` output verifies with `openssl cms -verify -binary -content file.bin -CAfile test-ca.pem`.
- **AT-SIGN-03 Timestamp.** With a local test TSA, the CMS carries an RFC 3161 token; `openssl ts -verify` succeeds against the TSA cert. With the TSA down and `timestamp=required`, signing fails and nothing is returned.

## Approvals and release windows

- **AT-APR-01 k-of-n, deny wins.** Policy needs 2 of 3. One approve: still pending. Second approve: signed. New request: one approve then one deny: rejected, no signature.
- **AT-APR-02 Exclusions.** The requester and key custodians cannot approve (403 from API, button absent in UI, and rejected in core if called directly).
- **AT-APR-03 Expiry.** Request with 2-minute expiry (test override) and no decisions moves to `expired`; a late approval is rejected.
- **AT-REL-01 Window.** Offline key with a window 10:00-10:30: signing at 10:31 is rejected; inside the window succeeds.
- **AT-REL-02 Cap.** Window with cap 5: 20 concurrent sign requests yield exactly 5 signatures and 15 rejections.

## Gates and attestation

- **AT-GATE-01 Fail closed.** Gate returns pass: signed. Gate returns fail: rejected. Gate times out or returns a bad HMAC: rejected.
- **AT-GATE-02 Hash validation gate.** Reference gate rebuilds a fixture deterministically and compares digests; mismatch rejects.
- **AT-ATT-01 Provenance.** Produced DSSE envelope verifies with the policy key; the in-toto subject digest equals the signed digest; builder and source fields come from verified OIDC claims, not request metadata.

## Integrations and CA

- **AT-INT-01 Tool compatibility.** In CI on Linux: osslsigncode signs a test PE through the PKCS#11 module and `osslsigncode verify` passes against the test CA; cosign signs and verifies a blob; GPG signs and verifies a file.
- **AT-CA-01 Short-lived certs.** Private CA issues a leaf valid for 72h with the configured profile OID; a CMS signed then timestamped still verifies after a simulated clock 5 days later.
- **AT-CA-02 Revocation.** Revoke one day's leaf; CRL lists it; verification of a signature made with that leaf fails with CRL checking on; other days' signatures still verify.
- **AT-PUB-01 Remote CA backend (mock).** Against a mock CSC-style API, credential listing, authorisation and hash signing work end to end; no real endpoint is contacted (network egress blocked in the test).

## Web

- **AT-WEB-01 Browser safety.** Every state-changing form rejects requests without a valid CSRF token. Responses carry a CSP with no `unsafe-inline` script, `X-Content-Type-Options: nosniff`, and cookies flagged `Secure; HttpOnly; SameSite=Strict`. Template output escapes `<script>` in project names.

## Phase 0 automation

- AT-OPS-01: `crates/brigalow-server/tests/redaction.rs` starts the real binary with generated environment secrets, forces a database startup error and checks both output streams. Config unit tests cover strict parsing, env precedence, secret-file permissions and symlink/source rejection. `scripts/e2e.py` checks live `/healthz` and absent `/debug` responses, lab labelling and database failure. CI job `secrets` scans full git history with checksum-pinned gitleaks and redacted findings.
- AT-AUD-01: `crates/brig/tests/audit.rs` verifies 1,000 entries through the CLI, rejects a one-byte change at seq 500 and deletion at seq 10, and cross-checks SHA-256 with OpenSSL. Store integration persists 1,000 entries and exports them in 137-entry pages; the end-to-end harness repeats the CLI tamper checks on that database-backed export.
- AT-TEN-01 (store level): `crates/brigalow-store/tests/foundations.rs` covers every object lookup kind in both tenant directions, pool reuse, RLS without query filters, cross-tenant inserts/references, restricted grants, rollback on failed audit insertion and concurrent chain appends. Key/policy/request rows are metadata placeholders; their feature semantics and API isolation arrive in later phases.
- AT-AUD-02 is not complete: append-only grants are tested now, but signed checkpoints require the key backend. No other phase's acceptance test is claimed complete.

## Phase 1 automation

`crates/brigalow-server/tests/identity.rs`, under the integration feature, exercises the actual axum router against the HTTPS Compose IdP/JWKS and real Postgres. AT-ID-01 covers PKCE, browser-bound single-use state, nonce, audience, expiry and mapped group permissions. AT-ID-02 covers valid workload claims, unknown issuer, signature/algorithm attacks, audience/expiry/nbf and repository/ref/environment/workflow mismatches. AT-ID-03 rechecks expiry after a prior success and rejects duplicate project request IDs with 409. AT-WEB-01 covers CSRF, cookie attributes, CSP, nosniff and Askama escaping. AT-TEN-01 generates object and mutation route checks from the registries used by router construction. API-token tests assert hashed storage, scope, expiry requirement and revocation. Pure RBAC tests enforce custodian separation.

## Phase 2 automation

`crates/brigalow-crypto/tests/custody.rs` generates all keys at test time. Default tests verify software RSA-3072/P-256/Ed25519 signatures and CSRs with OpenSSL, issue temporary OpenSSL CA leaves, and check matching keys, configured/unconfigured anchors, signature corruption and expiry. The Compose SoftHSM image builds the same Rust client on Linux and runs `pkcs11-tests` against its disposable token: sensitive/non-extractable attributes, independent verification and disable enforcement. Missing HSM settings fail this dedicated suite. `integration` does not load a Linux module on the host; the harness always runs the container test separately.

`config::tests::at_key_01_startup_guard_and_no_fallback` covers production software refusal and HSM errors without fallback. The server integration lifecycle test covers generated lab labels, release refusal, custodian permissions, all registered key mutation routes for cross-tenant access/CSRF, public-only response fields, invalid chain rejection, lifecycle audit and stale writes after retirement. Phase 2 exit is not claimed until these gates pass locally and on hosted CI.
