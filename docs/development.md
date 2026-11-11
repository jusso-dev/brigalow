# Local development

Phase 0 provides a development server, a tenant store and an offline audit verifier. It authenticates users and workloads but cannot yet sign artifacts. Do not deploy it to production.

## Automated acceptance run

Install current stable Rust with rustfmt/clippy, Python 3, OpenSSL and Docker Compose. Select a local Docker context explicitly:

```sh
scripts/e2e.sh --context orbstack
# GitHub-hosted Linux runner:
# scripts/e2e.sh --context default
```

The harness uses random Compose project names and loopback-only database ports. All credentials, TLS keys, test records and tokens are disposable. Its `finally` cleanup removes only its own containers, network, locally built SoftHSM image and temporary files; database/token data lives in tmpfs. SoftHSM2 is an in-process PKCS#11 library, so the container provides the test environment, not a remote HSM API. The Linux container generates a disposable token and runs the Rust cryptoki/OpenSSL acceptance client. The harness includes an HTTPS test IdP/JWKS service; a test TSA arrives with signing.

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

Use a dedicated empty PostgreSQL database with TLS enabled. Apply `crates/brigalow-store/migrations/0001_foundations.sql` as the database owner using your existing administrative connection tooling, with stop-on-error and one transaction. It creates the `brigalow` schema and non-login `brigalow_app` role. Subsequent managed migrations use the exported sqlx `MIGRATOR`; do not mix manual SQL application and sqlx migration tracking in the same database.

Provision a separate login named `brigalow_runtime`, with membership in `brigalow_app`, no superuser, BYPASSRLS, role/database creation or table ownership. Set its password through a secure administrative prompt or secret provisioner, never through checked-in SQL or command-line values. The server uses only this login and never migrates schema at startup. Organisation provisioning remains an owner-only development operation until authenticated administration exists.

```sh
cargo run -p brigalow-server
```

`GET /healthz` reports `status`, `mode` and `signing_available: false`. There is no debug/config endpoint. Tenant APIs require a valid session, scoped API token or verified workload identity. Shutdown handles SIGTERM and Ctrl-C. Runtime database failure returns 503. Logs accept application targets only; `RUST_LOG` cannot expose dependency debug output.

## Audit format and limits

Each organisation has its own sequence starting at 1, an all-zero genesis hash, and RFC 8785 canonical JSON hashed with SHA-256. Hash input is the entire entry except `entry_hash`. `at` is Unix milliseconds; details must use exact JSON integers within ±(2^53−1), strings for larger numbers and no floating-point values. Hashes use lowercase hexadecimal.

The store serialises appends with a transaction advisory lock. Project creation and its audit entry commit together. Export through the tenant handle's bounded `audit_page` method, in sequence order, one JSON object per line. Verify with `brig audit verify <export.jsonl>`. CLI lines are limited to 1 MiB; empty or malformed exports fail. A hash chain alone does not authenticate its final head or detect suffix truncation/full replacement; signed checkpoints are still pending.

## Identity setup (Phase 1)

Set `BRIGALOW_IDENTITY_FILE` to an operator-owned JSON document with `public_url` (the HTTPS origin of Brigalow, no path), optional `ca_file` (PEM CA for a private IdP) and `authorities`. Each authority contains `org_id`, unique `name`, exact `issuer`, `jwks_url`, optional `human`, and `workloads`. All endpoint URLs require HTTPS and verified certificates; put the HTTP listener behind your TLS reverse proxy. Do not expose the test IdP outside the disposable test harness.

Human settings: `client_id`, `authorization_url`, `token_url`, and `group_roles` mapping exact IdP group names to `org_admin`, `key_custodian`, `project_admin`, `approver`, `submitter` or `auditor`. Register a public OIDC client with S256 PKCE and exact redirect `https://<brigalow-origin>/auth/<org>/<name>/callback`. Enter through `/auth/<org>/<name>/login`. The explicit Continue step preserves Strict cookie semantics. No group match means no access. No implicit administrator or bootstrap authentication bypass exists; provision organisations with the owner tooling first.

Each workload rule has `project`, `policy` and non-empty `claims` mapping verified claim names to exact string values. GitHub examples use `repository`, `ref`, `workflow` and `environment`; use the actual issuer's claim names. Workload audience must be `brigalow:<org>`, with a maximum one-hour lifetime. Configuration is loaded at startup; changing trusted issuers requires restart. Initial identity support uses RS256 and public-client PKCE.

JSON APIs: `GET /v1/orgs/<org>/{projects,keys,policies,requests}/<id>`; `POST /v1/orgs/<org>/projects` with name and unique request_id; `POST /v1/orgs/<org>/tokens` with project, policy and expires_at (Unix seconds); `DELETE /v1/orgs/<org>/tokens/<id>`. Token issuance requires an org admin; credentials are returned only once. Cookie-authenticated mutations require the configured Origin and `X-CSRF-Token`; HTML forms carry the same session CSRF value. Bearer API tokens can only read/submit within their binding and cannot administer projects or credentials. Signing itself arrives in Phase 3.

## Key custody setup (Phase 2)

Backends default to `disabled`. Configure `backend = "pkcs11"`, stable `backend_id`, `hsm_module` (installed provider path), `hsm_token` (exact unique label), and the existing PIN secret source. Environment overrides: `BRIGALOW_BACKEND`, `BRIGALOW_BACKEND_ID`, `BRIGALOW_HSM_MODULE`, `BRIGALOW_HSM_TOKEN`. Provision tokens through operator tooling; the server never initialises one. Keep backend ID bound to the same provider/token across restarts. HSM failure aborts startup. For disposable lab use, `mode = "lab"` and `backend = "software"`; software keys disappear on restart and cannot be used for release.

Optional TOML `[[trust_anchors]]` entries have `name`, `tier = "private"` or `"external-ca"`, and `file` pointing to a DER certificate. Only operator configuration can classify anchors. `external-ca` is configuration evidence, never a public-trust assertion. Imported chains require code-signing EKU. Software keys retain lab classification even after valid certificate import.

Custodian JSON API: `POST /v1/orgs/<org>/projects/<project>/keys` with `algorithm` (`rsa3072`, `p256`, `ed25519` where supported), `purpose` (`test`/`release`) and `offline` boolean. Read public metadata at `GET /v1/orgs/<org>/keys/<key>`. Lifecycle POST routes below that key: `/csr` with `subject` (RFC 4514 distinguished name); `/certificate` with `chain` (leaf-first arrays of DER bytes); `/activate`, `/disable`, `/retire` with `{}`. All require the existing session Origin/CSRF protection. Certificate import precedes activation for release keys. Disable is permanent; retire requires disabled state. There is no export route. Digest signing arrives in Phase 3; offline keys remain unavailable until release-window controls exist.
