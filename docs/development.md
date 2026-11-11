# Local development

Phase 0 provides a development server, a tenant store and an offline audit verifier. It cannot authenticate users or sign artifacts. Do not deploy it to production.

## Automated acceptance run

Install current stable Rust with rustfmt/clippy, Python 3, OpenSSL and Docker Compose. Select a local Docker context explicitly:

```sh
scripts/e2e.sh --context orbstack
# GitHub-hosted Linux runner:
# scripts/e2e.sh --context default
```

The harness uses random Compose project names and loopback-only database ports. All credentials, TLS keys, test records and tokens are disposable. Its `finally` cleanup removes only its own containers, network, locally built SoftHSM image and temporary files; database/token data lives in tmpfs. SoftHSM2 is an in-process PKCS#11 library, so the container provides the test environment, not a remote HSM API. Token/key generation is Phase 2. Mock IdP/JWKS and TSA services will be added with the features that use them.

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

`GET /healthz` reports `status`, `mode` and `signing_available: false`. There is no debug/config endpoint or tenant HTTP API. Shutdown handles SIGTERM and Ctrl-C. Runtime database failure returns 503. Logs accept application targets only; `RUST_LOG` cannot expose dependency debug output.

## Audit format and limits

Each organisation has its own sequence starting at 1, an all-zero genesis hash, and RFC 8785 canonical JSON hashed with SHA-256. Hash input is the entire entry except `entry_hash`. `at` is Unix milliseconds; details must use exact JSON integers within ±(2^53−1), strings for larger numbers and no floating-point values. Hashes use lowercase hexadecimal.

The store serialises appends with a transaction advisory lock. Project creation and its audit entry commit together. Export through the tenant handle's bounded `audit_page` method, in sequence order, one JSON object per line. Verify with `brig audit verify <export.jsonl>`. CLI lines are limited to 1 MiB; empty or malformed exports fail. A hash chain alone does not authenticate its final head or detect suffix truncation/full replacement; signed checkpoints are still pending.
