# 0002: Rust server, Postgres, server-rendered UI

Date: 2026-11-11. Status: accepted.

## Decision
- Rust (stable) Cargo workspace.
- `axum` + `tokio` for HTTP; `askama` templates with `htmx` vendored as a static file for the admin UI. No Node.js build.
- PostgreSQL via `sqlx` with checked-in migrations.
- PKCS#11 through the `cryptoki` crate; SoftHSM2 for tests.
- X.509, CMS and hashing through RustCrypto crates (`x509-cert`, `cms`, `sha2`, `hmac`, `p256`, `rsa`, `ed25519-dalek`) or `aws-lc-rs` where a backend needs it. TLS via `rustls`.
- `brig` CLI in the same workspace.

## Why
- Memory safety and a single static binary suit a security control plane.
- Postgres gives transactional guarantees for atomic cap decrements and audit-in-transaction.

## Constraints
- No hand-written cryptographic primitives. Wrap libraries and HSM mechanisms.
- Keep `brigalow-core` free of I/O so policy and approval logic is unit-testable.
