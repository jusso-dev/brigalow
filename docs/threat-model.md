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

## Phase 1 identity boundaries

- B1/B2: API access now uses an authenticated organisation, exact OIDC issuer/audience validation and a deny-by-default RBAC policy. Custodian roles cannot submit or approve, even in combination with other roles; they cannot issue submitter API credentials. API tokens are limited to a project and policy, generated with 256 random bits, stored only as SHA-256 digests, expire within 30 days, and support audited revocation. Session credentials are also hashed, expire no later than the ID token or one hour, and are revoked at logout.
- B2: public-client OIDC uses S256 PKCE, nonce verification and single-use state bound to a separate browser cookie. The callback renders an escaped, same-origin completion form so `SameSite=Strict` cookies work after a cross-site IdP redirect. Completion checks Origin and the browser-bound state; ordinary mutation forms and cookie-authenticated JSON APIs check Origin and a constant-time CSRF comparison. All cookies use Secure, HttpOnly, SameSite=Strict and host-only Path=/. Responses have no-store, no-referrer, nosniff and restrictive CSP without inline script. Askama escapes user text.
- B5 (identity provider): issuer/JWKS/authorization/token URLs come only from operator configuration, require HTTPS with verified CA/hostname, and never follow redirects. JWKS cache lifetime is 60 seconds, at most 32 keys per issuer, with response and token size bounds. Unknown token issuers never cause discovery/network calls. Workload RS256 tokens require issuer, audience `brigalow:<org>`, subject, expiry and issued-at; nbf is checked when present. Exact repository/ref/workflow/environment rules constrain scoped access. Expiry is rechecked on each request, including cache hits.
- B4: credentials and replay IDs are tenant-owned, forced-RLS tables. Project creation, request-ID reservation and audit append share one transaction. Credential issuance/revocation are audited in the same transaction. Trust configuration remains owner-controlled; a session retains its verified role snapshot until expiry/revocation. Login pending state is bounded, expires in five minutes and is process-local: a restart invalidates pending logins. Shared login coordination/HA is future operations work.
- The local test IdP deliberately exposes token minting and invalid-token controls for acceptance tests. It binds only to a random loopback host port, creates signing keys in memory at startup, and is never a deployment component.

## Phase 2 custody boundaries

- B3: configured PKCS#11 module and exact token label are operator-owned. Startup failures never choose software. Generated RSA-3072/P-256 private objects are token-resident, sensitive and non-extractable; attributes are checked after generation. Object lookup requires exactly one class/UUID match. Public APIs return SPKI, CSRs, certificates and lifecycle metadata only. HSM PIN diagnostics remain static/redacted. SoftHSM is a disposable test emulator, not a hardware assurance claim.
- B6: `backend=software` is accepted only in lab mode; lab refuses release purpose. Software keys live in process memory and disappear on restart. Persisted metadata cannot reactivate a missing key. RSA, P-256 and Ed25519 use RustCrypto; Ed25519 raw digest signatures sign the SHA-256 digest bytes as a message, while PKCS#10 signs its complete request-info message. The HSM adapter currently supports RSA-3072/P-256, with unsupported algorithms rejected explicitly.
- B1/B2/B4: only human key custodians may generate, request CSRs, import certificates, activate, disable or retire keys. Cookie mutations require Origin and CSRF checks. Tenant resolution precedes backend access; immutable project/backend identity and optimistic revisions prevent stale metadata writes overwriting revocation. Metadata transitions and their audit entries commit together. Disable revokes database authority before disabling HSM signing. Retired keys cannot reactivate. Offline is recorded now; Phase 3 must reject offline signing until Phase 4 adds windows.
- B3/B4 have no distributed transaction: a crash during generation can leave an inaccessible orphan HSM object. Generation failure after metadata insertion is prevented by resolving the public key first; failed insertion attempts disable the object. Operator inventory/reconciliation is required for crash orphans. No automatic token resets or deletion occur. A backend-disable failure leaves the database key disabled and can be retried.
- B3/B6: imported leaf SPKI must match the generated key. RFC 5280 path, signatures, validity and required code-signing EKU are checked by rustls-webpki against configured anchors. Anchors have explicit names and `private`/`external-ca` classification. Unrecognised roots remain untrusted, software always remains lab, and neither can authorise release. No automatic public-trust classification. Revocation distribution is future Phase 7 work; this import check is not ongoing revocation monitoring.

## Phase 3 signing boundaries

- B1/B4: policies bind an active key of the same purpose and project. Binding is checked on policy creation and again against persisted rows at the signing decision; changing policy JSON directly cannot bypass it. Policies match only verified identity claims. API credentials have no synthetic OIDC claims. Release policies require explicit repository/ref/environment and `ref_protected=true`; custodians remain unable to submit. Offline keys fail closed until release-window authorisation exists.
- B3/B4: a unique request ID, immutable input/identity/policy/key snapshots and `signing` intent commit with audit before backend access. A crash leaves a stranded `signing` request; it is never automatically retried. Revocation and signing intent are serialised at the database decision: already-authorised in-flight calls may finish after a later disable. Backend and database do not share a distributed transaction. A failed final commit returns no signature, even if a backend already produced one; reconciliation uses durable intent and HSM audit, not blind re-signing.
- B1/B3: only a 32-byte SHA-256 digest, bounded artifact name and explicitly self-reported metadata enter submission. RustCrypto CMS signed attributes bind digest and data content type. Raw Ed25519 signs digest bytes; CMS currently supports RSA/P-256 only because Ed25519 CMS requires SHA-512. The CLI streams the artifact through SHA-256 locally, requires verified HTTPS, follows no redirects, takes credentials from environment rather than command arguments, and never overwrites result files.
- B5: TSA URL/certificate trust is operator-configured. HTTPS verifies hostname and CA; redirects/proxies are disabled, timeout is five seconds and response limit one MiB. RFC 3161 responses require successful status, matching unpredictable nonce and signature imprint, recent generation time, a pinned signer with critical timestamp-only EKU, a valid path to configured anchors, matching CMS content-type/message-digest attributes and a verified RSA/P-256 SHA-256 signature. Token-supplied certificates cannot choose the signer or trust root. `required` failures persist a failed request and return no signature; optional omissions are explicit as an absent timestamp.
- Certificate leaf validity, code-signing EKU and digital-signature key usage are checked even when issuer trust is unknown; trusted paths are additionally validated by webpki. Signing rechecks the imported chain, preventing use after certificate expiry or anchor removal. The test TSA creates no enduring keys and has no external signing dependency.
