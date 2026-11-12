# Local development

The development server authenticates humans/workloads and signs digests using lab or PKCS#11 keys, with policy, approvals, release windows and audit. Do not deploy it to production.

## Automated acceptance run

Install current stable Rust with rustfmt/clippy, Python 3, OpenSSL and Docker Compose. Select a local Docker context explicitly:

```sh
scripts/e2e.sh --context orbstack
# GitHub-hosted Linux runner:
# scripts/e2e.sh --context default
```

The harness uses random Compose project names and loopback-only database ports. All credentials, TLS keys, test records and tokens are disposable. Its `finally` cleanup removes only its own containers, network, locally built SoftHSM image and temporary files; database/token data lives in tmpfs. SoftHSM2 is an in-process PKCS#11 library, so the container provides the test environment, not a remote HSM API. The Linux container generates a disposable token and runs the Rust cryptoki/OpenSSL acceptance client. The harness includes an HTTPS test IdP/JWKS service; a generated-key HTTPS OpenSSL TSA verifies timestamping.

`cargo test --workspace` runs pure/CLI/config/redaction tests. `--features integration` additionally requires the harness environment and never silently skips missing infrastructure. CI runs format, clippy (including integration code), unit tests, Compose acceptance tests and a separate full-history secret scan. All Actions are SHA-pinned and runners are GitHub-hosted.

## Server configuration

Set `BRIGALOW_CONFIG` to a TOML file, optionally starting from `deploy/dev/brigalow.example.toml`. Unknown fields are rejected, including inline `db_password` and `hsm_pin`. Environment overrides non-secret file fields. Defaults: production mode, loopback port 8080, database `brigalow`, user `brigalow_runtime`.

| TOML field | Environment override |
| --- | --- |
| `mode` (`lab` or `production`) | `BRIGALOW_MODE` |
| `bind` (socket address) | `BRIGALOW_BIND` |
| `db_host`, `db_port` | `BRIGALOW_DB_HOST`, `BRIGALOW_DB_PORT` |
| `db_name`, `db_user` | `BRIGALOW_DB_NAME`, `BRIGALOW_DB_USER` |
| `db_ca_file` (trusted PEM certificate) | `BRIGALOW_DB_CA_FILE` |
| `db_password_file` | `BRIGALOW_DB_PASSWORD_FILE` |
| `hsm_pin_file` | `BRIGALOW_HSM_PIN_FILE` |

Alternatively supply secret values in `BRIGALOW_DB_PASSWORD` and `BRIGALOW_HSM_PIN`. The password is required; the PIN is optional until a backend is configured. Configuring both a value and file for one secret fails closed. Secret files require Unix, regular-file type, no symlink, exact mode `0600`, at most 4096 bytes and non-empty UTF-8 content. One terminal newline is removed. Errors never echo raw input, file paths, database diagnostics or secret values. Non-Unix hosts must use environment secrets.

Database TLS always verifies both CA and hostname. Use the database CA certificate via `db_ca_file`; never bypass TLS verification. Local tests generate their own one-day certificate with loopback subject alternative names.

## Database setup for manual development

Use a dedicated PostgreSQL database with verified TLS. Run `brigalow-admin migrate` with separate owner credentials to apply every embedded SQLx migration under its migration lock. Do not apply SQL files manually or mix migration tracking systems. Run `brigalow-admin org-create --org <UUID> --name <name>` to provision an organisation and its initial audit record atomically. Repeated matching provisioning is idempotent; conflicting names fail.

Provision a separate runtime login with membership in `brigalow_app`, no superuser, BYPASSRLS, replication, role/database creation or table ownership. Set its password through a secure administrative prompt or secret provisioner. The server refuses schema drift and never migrates at startup. See the [production reference](../deploy/production/README.md) for owner/runtime separation and configuration.

```sh
cargo run -p brigalow-server
```

`GET /livez` checks process liveness. `GET /healthz` reports `status`, `mode` and `signing_available`; production checks the database and authenticated HSM session. There is no debug/config endpoint. Tenant APIs require a valid session, scoped API token or verified workload identity. Shutdown handles SIGTERM and Ctrl-C. Runtime database failure returns 503. Logs accept application targets only; `RUST_LOG` cannot expose dependency debug output.

## Audit format and limits

Each organisation has its own sequence starting at 1, an all-zero genesis hash, and RFC 8785 canonical JSON hashed with SHA-256. Hash input is the entire entry except `entry_hash`. `at` is Unix milliseconds; details must use exact JSON integers within ±(2^53−1), strings for larger numbers and no floating-point values. Hashes use lowercase hexadecimal.

The store serialises appends with a transaction advisory lock. Project creation and its audit entry commit together. Export through the tenant handle's bounded `audit_page` method, in sequence order, one JSON object per line. Verify with `brig audit verify <export.jsonl>`. CLI lines are limited to 1 MiB; empty or malformed exports fail. A hash chain alone does not authenticate its final head or detect suffix truncation/full replacement; use independently retained signed checkpoints for authenticated prefix verification (see [operations](operations.md)).

## Identity setup (Phase 1)

Set `BRIGALOW_IDENTITY_FILE` to an operator-owned JSON document with `public_url` (the HTTPS origin of Brigalow, no path), optional `ca_file` (PEM CA for a private IdP) and `authorities`. Each authority contains `org_id`, unique `name`, exact `issuer`, `jwks_url`, optional `human`, and `workloads`. All endpoint URLs require HTTPS and verified certificates; put the HTTP listener behind your TLS reverse proxy. Do not expose the test IdP outside the disposable test harness.

Human settings: `client_id`, `authorization_url`, `token_url`, and `group_roles` mapping exact IdP group names to `org_admin`, `key_custodian`, `project_admin`, `approver`, `submitter` or `auditor`. Register a public OIDC client with S256 PKCE and exact redirect `https://<brigalow-origin>/auth/<org>/<name>/callback`. Enter through `/auth/<org>/<name>/login`. The explicit Continue step preserves Strict cookie semantics. No group match means no access. No implicit administrator or bootstrap authentication bypass exists; provision organisations with the owner tooling first.

Each workload rule has `project`, `policy` and non-empty `claims` mapping verified claim names to exact string values. GitHub examples use `repository`, `ref`, `workflow` and `environment`; use the actual issuer's claim names. Workload audience must be `brigalow:<org>`, with a maximum one-hour lifetime. Configuration is loaded at startup; changing trusted issuers requires restart. Initial identity support uses RS256 and public-client PKCE.

JSON APIs: `GET /v1/orgs/<org>/{projects,keys,policies,requests}/<id>`; `POST /v1/orgs/<org>/projects` with name and unique request_id; `POST /v1/orgs/<org>/tokens` with project, policy and expires_at (Unix seconds); `DELETE /v1/orgs/<org>/tokens/<id>`. Token issuance requires an org admin; credentials are returned only once. Cookie-authenticated mutations require the configured Origin and `X-CSRF-Token`; HTML forms carry the same session CSRF value. Bearer API tokens can only read/submit within their binding and cannot administer projects or credentials.

## Key custody setup (Phase 2)

Backends default to `disabled`. Configure `backend = "pkcs11"`, stable `backend_id`, `hsm_module` (installed provider path), `hsm_token` (exact unique label), and the existing PIN secret source. Environment overrides: `BRIGALOW_BACKEND`, `BRIGALOW_BACKEND_ID`, `BRIGALOW_HSM_MODULE`, `BRIGALOW_HSM_TOKEN`. Provision tokens through operator tooling; the server never initialises one. Keep backend ID bound to the same provider/token across restarts. HSM failure aborts startup. For disposable lab use, `mode = "lab"` and `backend = "software"`; software keys disappear on restart and cannot be used for release.

Optional TOML `[[trust_anchors]]` entries have `name`, `tier = "private"` or `"external-ca"`, and `file` pointing to a DER certificate. Only operator configuration can classify anchors. `external-ca` is configuration evidence, never a public-trust assertion. Imported chains require code-signing EKU. Software keys retain lab classification even after valid certificate import.

Custodian JSON API: `POST /v1/orgs/<org>/projects/<project>/keys` with `algorithm` (`rsa3072`, `p256`, `ed25519` where supported), `purpose` (`test`/`release`) and `offline` boolean. Read public metadata at `GET /v1/orgs/<org>/keys/<key>`. Lifecycle POST routes below that key: `/csr` with `subject` (RFC 4514 distinguished name); `/certificate` with `chain` (leaf-first arrays of DER bytes); `/activate`, `/disable`, `/retire` with `{}`. All require the existing session Origin/CSRF protection. Certificate import precedes activation for release keys. Disable is permanent; retire requires disabled state. There is no export route. Offline keys require an active release window.

## Digest signing (Phase 3)

An org/project admin creates a named policy using `POST /v1/orgs/<org>/projects/<project>/policies`: `name` (lowercase letters/digits/hyphens), `key`, `purpose`, `claims` (exact verified claim matches), `algorithms`, and `timestamp` (`disabled`, `optional`, `required`). Release policies require repository/ref/environment rules and `ref_protected = "true"`; only an IdP-verified claim can satisfy this. API credentials carry no invented workload claims, so use a policy that explicitly allows their scope. Policies are immutable in this initial API. Read by UUID through the existing policy route or by name through `/projects/<project>/policies/<name>`.

`POST /v1/orgs/<org>/projects/<project>/sign-requests` accepts `request_id`, `policy` UUID, `digest_alg = "sha256"`, `digest` (32 bytes), `artifact_name`, `format` (`raw` or `cms`) and optional self-reported `metadata`. No artifact upload field exists. Request IDs never retry a signature. Query `/v1/orgs/<org>/requests/<request>` after interruption; a stranded `signing` request needs operator reconciliation. Required timestamp failure produces a failed record with no output. Offline keys require an active release window.

For a TSA, add `[tsa]` with `url`, optional `tls_ca_file` (PEM), `signer_file` (pinned DER TSA certificate) and `anchors` (DER CA paths). The signer must have critical, exclusive timeStamping EKU. This configuration is independent of code-signing trust anchors. No real TSA is needed for tests: Compose includes a generated-key HTTPS OpenSSL TSA.

```sh
# Supply BRIGALOW_TOKEN securely in the environment, never as a command argument.
brig sign --server https://signing.example --org <uuid> --project <uuid> \
  --policy test --format cms --output artifact.cms artifact.bin
```

Use `--ca-file` for a private HTTPS CA. Results never overwrite existing files; a successful timestamp is also saved as `<output>.tsr` (DER token). The CLI receives and sends only public metadata and the artifact digest. CMS supports RSA/P-256; raw also supports Ed25519 over SHA-256 digest bytes, not Ed25519ph.

For independent verification, `openssl pkeyutl -verify` checks raw signatures and `openssl cms -verify -binary -inform DER -content artifact.bin -in artifact.cms -CAfile test-ca.pem -purpose any` checks detached CMS. OpenSSL defaults CMS verification to S/MIME purpose; `-purpose any` avoids incorrectly requiring emailProtection on a codeSigning certificate. Brigalow itself requires codeSigning EKU. `openssl ts -verify -token_in` checks the timestamp against the signature bytes and configured TSA CA.

## Approvals and release windows (Phase 4)

Policies may include `approval = { approvers = ["<actor-id>", ...], required = 2, ttl_seconds = 86400 }` (JSON uses the equivalent object). Use the exact issuer-qualified actor IDs shown in verified identity/audit, not display names. Up to 32 distinct approvers, quorum at least one, expiry at most seven days. Requesters and custodians cannot decide, including combined roles. Ensure enough independent eligible people remain to meet quorum.

Submission returns HTTP 202 while pending. `brig sign` polls for up to five minutes; its printed request ID remains authoritative after timeout. Query that ID instead of resubmitting. Review individually at `/orgs/<org>/requests` and `/orgs/<org>/requests/<request>`; POST JSON `{"decision":"approve"}` or `{"decision":"deny"}` to `/v1/orgs/<org>/requests/<request>/decisions`. One deny rejects while pending; once quorum commits the signing intent, decisions close. Duplicate/late decisions return 409. Expiry maintenance runs each second for configured organisations (up to 100 due requests per pass); reads/decisions also enforce expiry.

Custodians create windows at `POST /v1/orgs/<org>/keys/<key>/windows` with `name`, `starts_at`, `ends_at` (Unix seconds) and optional `cap`. Duration is at most seven days. Intervals include start and exclude end; overlapping open windows on the same key are rejected. Read `/v1/orgs/<org>/windows/<window>`; POST `{}` to its `/close` route. Quorum completion rechecks current key/policy/window. Each committed signing attempt consumes one slot, including later backend/TSA failure, so failures never replenish authority. Already committed signing attempts may finish after closure/expiry.

Optional operator-owned TOML `[[notifications]]` entries contain `org`, `url` (HTTPS), `secret_file` (regular 0600 file, generated random secret of at least 32 bytes), and optional `tls_ca_file` (PEM). One endpoint per org. No endpoint can be supplied by an API caller. A pending approval triggers one best-effort attempt with a three-second timeout, no redirects/proxies, and verified TLS. Failure is audited and does not decide or cancel the request. A process interruption can lose this notification; the pending queue remains authoritative. No delivery retries or emails.

Notification JSON contains only `version`, `event = "approval.requested"`, `org`, `project`, `request`, random `event_id` and Unix-second `at`. Header `X-Brigalow-Signature` is standard Base64 HMAC-SHA256 over the exact bytes `brigalow.notification.v1\n` followed by the raw body. Receivers must verify before parsing, reject stale timestamps and deduplicate event IDs. Notifications are informational: their secret cannot approve or sign. `deploy/dev/test_notifications.py` is a loopback-only independent Python HMAC verifier, never a deployment component.

## Pre-sign gates and provenance (Phase 5)

Configure operator-owned TOML `[[gates]]` entries: `org`, unique `name` (lowercase letters/digits/hyphens), HTTPS `url`, `secret_file` (0600 generated random secret, at least 32 bytes), optional PEM `tls_ca_file`, and `timeout_ms` (100–30000). Each gate has its own secret. Policy JSON `gates: ["rebuild", ...]` references up to eight configured names in order; unknown names are rejected at creation and fail closed if configuration later disappears. No caller-supplied endpoint or source URL is fetched.

After approvals, the request durably enters `gating`. Gates execute in order and stop on first failure. Request HMAC-SHA256 signs `brigalow.gate.request.v1\n` plus exact JSON body; response HMAC signs `brigalow.gate.response.v1\n` plus exact response body. Both headers use standard Base64 in `X-Brigalow-Signature`. Request fields: `version`, `org`, `project`, `policy`, `request`, `digest_alg`, `digest`, random `nonce`, Unix-second `at`, and `verified_claims`. Gate responses must contain exactly `nonce`, `request`, `digest`, and boolean `pass`. Nonce/request/digest must match; response bodies are capped at 8192 bytes. TLS is verified; redirects/proxies are disabled. No retry. Timeout, HTTP error, bad HMAC, mismatch, malformed/oversized response, missing gate or explicit fail rejects without signing. Outcomes appear on the request page and audit chain. Window/key authority is rechecked after gates; failed gates do not reserve cap slots.

`examples/gates/hash_validation.py` demonstrates the signed protocol with a deterministic locally rebuilt fixture; `--fixture` emits its reproducible bytes. Run it only locally with generated TLS/secret files. This is not a general-purpose build service. A real gate must pin source/build inputs independently, isolate untrusted build execution, and authorise organisation/project/policy/verified identity for its own checks. Do not execute request-provided commands or fetch arbitrary URLs.

Policy `attestation: true` requires verified workload source/builder claims and returns DSSE provenance signed by the policy key. See [the v1 schema and limitations](attestation-v1.md). No SLSA assurance level is claimed. `brig sign` saves an additional `.dsse.json` file. A crash in `gating` or `signing` leaves durable evidence and never triggers automatic re-execution; reconcile before issuing a new request.


## Native tools and GitHub Actions (Phase 6)

See [PKCS#11 recipes](integrations/pkcs11.md) and [the OIDC action](integrations/github-actions.md). The full acceptance harness builds pinned cosign/jsign plus distribution OpenSSL, osslsigncode and GPG in a disposable Linux image. Runtime tools use an internal Compose network without external egress. For focused iteration only, use `scripts/e2e.sh --context orbstack --tools-only`; this does not replace the full phase gate. No Node toolchain is required.


## Optional private CA (Phase 7)

See [private CA operations](private-ca.md). `brigalow-ca` uses a separate restricted CA login and HSM issuer token; it does not run inside the HTTP service. The full Compose harness tests its real command across process restarts and verifies certificates/CRLs with OpenSSL. No root private key is loaded by Brigalow.


## Operations checks (Phase 8)

See [operations](operations.md) for credential budgets, signed checkpoints, recovery, fuzzing, the single-instance chart and lab release workflow. The full Compose harness includes scratch-only backup/restore and HSM reference recovery. `python3 scripts/test_release.py` and `python3 scripts/test_helm.py` check packaging and local chart rendering.

## Remote signing mock

`backend="csc_mock"` is available only in lab mode against literal-loopback HTTPS. See [CSC configuration and protocol limits](integrations/csc-mock.md), [outside-CA HSM attestation planning](integrations/hsm-ca-attestation.md), and [Azure evaluation](integrations/azure-evaluation.md). The mock cannot enrol with or contact a real CA.
