# Threat model

Method: STRIDE over the data flows in [architecture.md](architecture.md), plus supply-chain abuse cases drawn from the research. Review this file whenever a trust boundary changes.

## Assets

1. Private signing keys (highest value; compromise means attacker-signed software).
2. The authority to cause a signature (credentials, approvals, release windows).
3. Audit history (needed to scope an incident).
4. Policy configuration (who may sign what).
5. Certificates and trust anchors.

## Trust boundaries

- B1 Build machine / CI job to Brigalow API.
- B2 Browser (human) to Brigalow UI.
- B3 Brigalow server to key backend (HSM over PKCS#11, cloud KMS).
- B4 Brigalow server to Postgres.
- B5 Brigalow server to gates (webhooks) and TSA.
- B6 Operator to host (deploy, config, secrets).

## Threats and controls

| ID | Threat | STRIDE | Control | Test |
| --- | --- | --- | --- | --- |
| T1 | Attacker steals a key from a build agent or laptop | I | Keys never leave the backend; clients only send digests. No export API. | AT-KEY-03 |
| T2 | Compromised CI job requests a release signature for a malicious build | S/E | Submitter rules match verified OIDC claims (repo, ref, workflow, environment). Release policies restricted to protected refs. Optional approvals and gates. | AT-POL-02, AT-POL-03 |
| T3 | Attacker forges CI identity claims | S | Verify OIDC token signature against issuer JWKS, `iss`, `aud`, `exp`, `nbf`; reject unknown issuers; cache JWKS with bounded TTL. | AT-ID-02 |
| T4 | Replay of a captured token or request | S | Short token lifetimes; request IDs are single-use; tokens bound to audience `brigalow:<org>`. | AT-ID-03 |
| T5 | Insider approves their own request | E | Requester and custodians excluded from approver set; enforced in core, not UI. | AT-APR-02 |
| T6 | Approval fatigue / rubber-stamping | E | Approver sees digest, artifact name, verified claims, policy, key and gate results; no bulk approve; deny wins. | AT-APR-01 |
| T7 | Test policy used to sign with a release key | E | Policy purpose must match key purpose; enforced at bind time and at sign time. | AT-POL-01 |
| T8 | Offline key used outside its release window or beyond its cap | E | Window and cap checked in the same transaction as the sign decision; cap decrement is atomic. | AT-REL-01, AT-REL-02 |
| T9 | Cross-tenant data access | I | `org_id` on every tenant table; tenant-scoped store handle; per-endpoint cross-tenant tests. | AT-TEN-01 |
| T10 | Audit tampering by a DB admin or attacker with DB write | T/R | Hash chain, signed checkpoints, insert-only grants, offline verifier, export to external log store. | AT-AUD-01, AT-AUD-02 |
| T11 | Gate spoofing or gate outage used to bypass checks | S/D | Gate webhooks signed (HMAC with per-gate secret) both ways; timeout fails closed. | AT-GATE-01 |
| T12 | HSM PIN leak via config or logs | I | PIN from env or `0600` file; redaction in logs and debug output; secret-scanning in CI. | AT-OPS-01 |
| T13 | Signing a digest that doesn't match the claimed artifact | T | Out of the server's sight by design. Mitigated by origin rules, rebuild/hash-validation gates, and attestation that binds digest to verified CI claims. Documented residual risk. | AT-GATE-02 |
| T14 | Algorithm downgrade (weak hash, small key) | T | Allow-list of digest and signature algorithms per policy; reject SHA-1 and RSA < 3072 for new keys by default. | AT-KEY-02 |
| T15 | Denial of service by request flood | D | Per-credential rate limits, request size limits, bounded queues. | AT-OPS-02 |
| T16 | Software keys used in production | E/I | `production` mode refuses to load the lab backend; `lab` mode refuses `release` purpose and shows a banner. | AT-KEY-01 |
| T17 | Misleading trust claims (operator thinks a private-CA signature is public) | R | Trust tier shown per key and cert; chain validation against configured anchors; docs separate tiers. | AT-CERT-02 |
| T18 | Compromise of Brigalow's own release artifacts | T | Signed releases, SBOM, pinned CI actions by SHA, reproducible builds as a later goal. | Phase 8 |
| T19 | Web UI attacks (CSRF, XSS, session theft) | S/T | Server-rendered templates with auto-escaping, CSRF tokens on all state changes, `SameSite=Strict` secure cookies, CSP without inline script. | AT-WEB-01 |

## Residual risks we accept and document

- Brigalow signs digests. It cannot prove the digest matches a benign artifact. Origin rules, gates and attestations reduce, not remove, this risk.
- A fully compromised Brigalow host with an activated HSM session can request signatures while it stays compromised. HSM-side key use policies, short release windows and caps limit the damage.
- Public trust depends on the CA's own controls and revocation.

## Phase 0 implementation boundaries

- B4: runtime database credentials inherit the non-owning `brigalow_app` role. Migrations run separately as an owner; the server must reject superuser, BYPASSRLS, role-management and table-owner credentials. Every tenant operation uses a transaction-local organisation context, explicit `org_id` predicates and forced row-level security. Composite foreign keys prohibit cross-tenant and cross-project references. The tenant handle is a trusted internal API, not authentication: Phase 0 has no tenant HTTP routes; Phase 1 must derive its organisation from verified identity.
- Project creation and its audit entry commit together. Per-organisation transaction advisory locks serialise audit appends, including the first append. Audit grants permit only SELECT and INSERT; tests also attempt UPDATE, DELETE and TRUNCATE as the runtime login.
- The chain uses RFC 8785 and SHA-256. Phase 0 does not yet implement signed checkpoints: an owner can rewrite the full chain or truncate its suffix without detection by the standalone verifier. Retain an independently authenticated head; AT-AUD-02 remains pending.
- Local Compose uses generated passwords, a loopback-only random Postgres port, ephemeral database storage and an isolated SoftHSM2 token directory. SoftHSM2 is a test dependency, not hardware-backed custody or a production fallback. Test IdP/JWKS and TSA services arrive with Phases 1 and 3 respectively.

- B6: configuration accepts non-secret settings and paths only. PINs/passwords come from environment variables or regular, non-symlink `0600` files (maximum 4096 bytes). Secret wrappers redact Debug; parser and driver errors are replaced with static messages. Only application logging targets are enabled, so `RUST_LOG=trace` cannot enable dependency diagnostics. The server exposes no `/debug` route. Config defaults to `production`; lab mode prints a warning and health responses label the mode. Neither mode can sign in Phase 0.
- B4 transport: server database connections require TLS with hostname and CA verification (`verify-full`), including lab mode. The acceptance harness generates a local test certificate and private key with OpenSSL, never commits either, and supplies the certificate as its trust anchor.
- B1/B2: `/healthz` is the only HTTP route, binds to loopback by default, returns no tenant data or configuration, and reports 503 when the database is unavailable. Authentication and browser sessions are not yet implemented. Do not expose this development skeleton as a production signing service.
