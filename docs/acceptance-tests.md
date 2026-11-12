# Acceptance tests

Each test must be automated. "Run" says where it lives once built. Integration tests use `deploy/dev/compose.yml` (Postgres + SoftHSM2) and run with `cargo test --workspace --features integration`. Use `scripts/e2e.sh --context <local-context>` to generate credentials and TLS keys, start Compose, set the test environment, run integration and end-to-end tests, then clean up. Missing integration configuration fails rather than silently skipping tests. None of these need a real CA, a cloud account or a purchased certificate.

Verification uses independent tools where possible (OpenSSL), so we aren't only testing our code against itself.

## Operations and config

- **AT-OPS-01 Secrets stay out of logs and config.** Start the server with an HSM PIN and DB password from env. Trigger an error path that logs config. Assert neither value appears in stdout, stderr or `/debug` output. CI runs a secret scanner (for example gitleaks) over the repo and fails on findings. Run: `crates/brigalow-server/tests/redaction.rs`, CI job `secrets`.
- **AT-OPS-02 Rate limiting.** 200 requests in 1 s from one credential: requests beyond the configured limit get HTTP 429 and an audit entry; other credentials unaffected.
- **AT-OPS-03 Backup and restore.** Dump DB, wipe, restore; audit chain verifies; pending requests still pending; HSM key handles still resolve.

- **AT-OPS-04 Owner bootstrap and schema readiness.** Released admin CLI migrates a fresh DB and repeats safely; organisation UUID/name provisioning is atomic/idempotent and conflicting names reject. Restricted runtime cannot use owner tools or change migration history; missing/changed schema checks fail. Automation: `scripts/production_test.py::bootstrap`, `crates/brigalow-store/tests/admin.rs`, embedded-migration parity unit test.
- **AT-OPS-05 Production reference.** Build the real non-root production image; assert no compiler or test HSM. Missing backend/provider startup fails. A disposable test-provider target runs production mode through the real pinned TLS proxy with read-only filesystems, dropped capabilities, body/rate limits and generated-secret redaction. Reject mutable image tags and unsafe configuration permissions through the production entry point; validate Compose syntax and Helm single-replica/network-policy refusals. Automation: `scripts/production_test.py::qualify` via the full Compose gate, `scripts/test_helm.py`.

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
- AT-AUD-02 was deferred at Phase 0; signed checkpoint automation is described under Phase 8 below.

## Phase 1 automation

`crates/brigalow-server/tests/identity.rs`, under the integration feature, exercises the actual axum router against the HTTPS Compose IdP/JWKS and real Postgres. AT-ID-01 covers PKCE, browser-bound single-use state, nonce, audience, expiry and mapped group permissions. AT-ID-02 covers valid workload claims, unknown issuer, signature/algorithm attacks, audience/expiry/nbf and repository/ref/environment/workflow mismatches. AT-ID-03 rechecks expiry after a prior success and rejects duplicate project request IDs with 409. AT-WEB-01 covers CSRF, cookie attributes, CSP, nosniff and Askama escaping. AT-TEN-01 generates object and mutation route checks from the registries used by router construction. API-token tests assert hashed storage, scope, expiry requirement and revocation. Pure RBAC tests enforce custodian separation.

## Phase 2 automation

`crates/brigalow-crypto/tests/custody.rs` generates all keys at test time. Default tests verify software RSA-3072/P-256/Ed25519 signatures and CSRs with OpenSSL, issue temporary OpenSSL CA leaves, and check matching keys, configured/unconfigured anchors, signature corruption and expiry. The Compose SoftHSM image builds the same Rust client on Linux and runs `pkcs11-tests` against its disposable token: sensitive/non-extractable attributes, independent verification and disable enforcement. Missing HSM settings fail this dedicated suite. `integration` does not load a Linux module on the host; the harness always runs the container test separately.

`config::tests::at_key_01_startup_guard_and_no_fallback` covers production software refusal and HSM errors without fallback. The server integration lifecycle test covers generated lab labels, release refusal, custodian permissions, all registered key mutation routes for cross-tenant access/CSRF, public-only response fields, invalid chain rejection, lifecycle audit and stale writes after retirement. Phase 2 exit is not claimed until these gates pass locally and on hosted CI.

## Phase 3 automation

The crypto custody suite independently verifies detached CMS from both software and SoftHSM keys with OpenSSL. `tests/timestamps.rs` obtains generated-key OpenSSL RFC 3161 replies and rejects nonce/imprint/signature/trust/time attacks. Server integration drives `brig sign` as a real process over a loopback HTTPS proxy into axum, captures request bodies to prove digest-only transport, and verifies raw/CMS/timestamp files with OpenSSL. It exercises purpose binding at creation and after direct policy tampering, unknown IDs and replay, CSRF and cross-tenant routes, verified workload claim rejection with named audit reason, and required TSA failure with no persisted or returned signature. Phase completion still requires local and hosted gates.

## Phase 4 automation

Core tests exercise the exact two-minute approval deadline and half-open 10:00–10:30 window. Server integration covers AT-APR-01–03 and AT-REL-01–02 through the actual axum router/Postgres: individual 2-of-3 approval, deny, duplicates, requester and combined custodian exclusions, missing buttons, HTML escaping/CSRF and successful form submissions, durable expiry, and late decisions. Twenty concurrent requests against cap five produce exactly five signatures and fifteen denials. A window expiring during review is rechecked at final approval. Route-registry tests cover tenant isolation. A generated-secret loopback HTTPS receiver independently verifies notification HMAC with Python, checks minimal tenant-bound payloads, and proves redirects are not followed or treated as approval. Phase completion requires these tests in local Compose and hosted CI.

## Phase 5 automation

`at_gate_01_02_and_att_01_signed_checks_and_claim_bound_provenance` uses real axum/Postgres plus a generated-secret HTTPS Python gate. AT-GATE-01 covers pass, fail, timeout, bad HMAC, replayed nonce, mismatched digest, oversized signed response and redirect. A counting backend proves failures make zero signing calls; they have no output and no `request.signing` audit transition. AT-GATE-02 executes the reference deterministic fixture builder and rejects mismatching digests. AT-ATT-01 mints a real local-JWKS workload token, injects conflicting user metadata, and checks that subject/source/builder fields derive only from the signed digest/verified claims. Independent Python reconstructs DSSE PAE and OpenSSL verifies the policy-key signature, then rejects tampering. Missing workload claims cannot be replaced by metadata. Local and hosted gates are required before closing the phase.


## Phase 6 automation

`at_int_01_native_tools_through_remote_pkcs11` runs in the Linux tools container, reached by the full Compose harness and CI. It creates a policy/key/certificate using the real router, exposes HTTPS locally, and drives OpenSSL, osslsigncode, jsign, cosign and GPG through the compiled module. OpenSSL verifies raw signatures, osslsigncode independently verifies both PE signers, and cosign/GPG verify their outputs. SHA-1 and private-key read attempts fail. Captured submissions contain digests only. A generated JWKS token and local mock GitHub mint endpoint exercise the action wrapper and real CLI; OpenSSL verifies its result. The tools container has no external egress. Provider unit tests reject malformed DigestInfo and invalid ABI buffers; action unit tests cover audience, redirect refusal and credential isolation. Phase completion requires the complete suite locally and on hosted CI.


## Phase 7 automation

`crates/brigalow-crypto/tests/private_ca.rs` covers AT-CA-01/02 using generated software lab keys and, separately in the SoftHSM container, HSM-held issuer/leaf keys. OpenSSL checks certificates, signed CRLs, one serial revoked while the next day's leaf remains valid, and timestamp-backed CMS validation at an authenticated historical time after a simulated five-day advance. Ordinary future-time validation must reject the expired leaf. The operator tool container runs the real `brigalow-ca` command across fresh processes against Postgres/SoftHSM, verifying issuer persistence, duplicate-day refusal, committed-output recovery and CRL publication. Store integration proves role separation, tenant isolation, ten concurrent reservations yielding one success, immutable profiles, cancellation of interrupted intents and refusal of stale CRL snapshots. All keys/secrets are ephemeral; tool runtime has no external egress. Phase completion requires local and hosted gates.


## Phase 8 automation

AT-OPS-02 dispatches 200 concurrent real-router requests within one second: with a 100-request window exactly 100 succeed and 100 receive 429, a second credential succeeds, and one exhaustion event is audited. Postgres persists budgets across router instances. AT-OPS-03 runs `scripts/backup_restore.py` inside the full Compose harness: scratch-only wipe/restore, every tenant audit chain and checkpoint preserved, pending requests unchanged and restored HSM handle independently verified by OpenSSL.

AT-AUD-02 is covered by `crates/brig/tests/checkpoints.rs` (RSA/P-256/Ed25519, wrong key, tampered checkpoint and suffix truncation) and the Linux operator tool test (dedicated HSM audit key, persisted checkpoint, real offline CLI and OpenSSL `pkeyutl` verification with tamper rejection). Existing DB tests assert no UPDATE/DELETE on audit entries; checkpoint records receive SELECT/INSERT only. Three parser fuzz targets run for a bounded time in hosted CI. Single-instance Helm lint/render/unsafe-config refusals and release SBOM/package/payload-tamper tests run without deployment; the native tool suite signs a release manifest through the actual lab control plane. The manual release workflow must also pass before the phase is closed.

## Phase 9 automation

AT-PUB-01 runs `tests/support/csc.rs` through the Linux tools acceptance suite. The real router/Postgres registers an operator-scoped remote reference, creates policy and signs a locally hashed artifact through generated-key CSC list/info/authorize/signHash endpoints. OpenSSL independently verifies output. Tests reject production mode, non-loopback origin, wrong certificate pin, foreign organisation/project references, policy denial, expired or denied authorisation, wrong/multiple signatures, redirects and oversized replies. Duplicate registration must not disable the original key. Failure outputs are absent in HTTP and persistence; disabled keys and policy denial cause no remote call. Captured public observations prove digest-only payloads. The runtime network blocks external egress; all credentials/keys are generated. Local and hosted gates are required before phase closure.

## Dependency remediation regressions

AT-ID-01/02 additionally reject signed tokens with invalid nonce, issued-at/azp/multiple audiences, unsupported critical/type headers and incompatible/duplicate JWKS entries. Root and fuzz lockfiles pass `cargo audit --deny warnings` without exceptions in the dependency-audit workflow. All 35 acceptance IDs require local and hosted gates; image tests use only generated local test credentials, never vendor devices or production services.
