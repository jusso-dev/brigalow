# 0003: Audit-clean dependency boundaries

Date: 2026-11-12. Status: accepted.

The application and fuzz lockfiles must pass `cargo audit --deny warnings`, without advisory exceptions. A pinned cargo-audit workflow checks both on pushes, pull requests and daily schedules. Keep lockfiles committed and use `--locked` for builds.

- All direct RSA/P-256 operations now use RustCrypto rsa 0.10 / p256 0.14 and patched crypto-bigint. Remove the temporary split between old public-verification and new private-signing dependencies.
- jsonwebtoken 11 uses its vetted AWS-LC backend: its RustCrypto feature still depends on advisory-bearing older RSA/P-256 releases. AWS-LC is a library dependency, not an AWS service or a validation/compliance claim.
- openidconnect 4.1 still requires the old RSA dependency. Brigalow's already narrow, pinned-endpoint RS256 authorization-code profile now uses the same underlying oauth2 5 PKCE/authorization URL library and the shared JWT verifier. Explicit OIDC checks require nonce, integer issuance time, exact single audience, issuer, expiry, subject and matching `azp` when present. Unsupported critical/content/type headers and ambiguous or incompatible JWK metadata fail closed. No implicit/hybrid flow, dynamic discovery, symmetric JWT or handwritten cryptographic primitive is introduced. Browser/state binding and single-use pending login state are unchanged. Integration tests exercise these checks with generated, genuinely signed IdP tokens.
- SQLx 0.9 requires stable Rust 1.94 or newer. Its umbrella/macro dependency graph still resolves the vulnerable optional SQLite native library. `brigalow-postgres` is a small re-export surface over the official SQLx core and Postgres crates; it contains no database implementation. Only PostgreSQL is supported. Embedded migrations use SQLx's `Migration`/`Migrator` APIs; a test compares every embedded version, description, SQL byte, checksum and transaction flag with SQLx's directory resolver. New migration files must be added to the embedded list. The migration history table and existing checksums are preserved.
- Askama 0.16 runs without its unused TOML configuration feature, removing unmaintained basic-toml. HTML autoescaping stays enabled and tested.

Do not reintroduce a legacy crypto or unused database family to bypass this boundary. Update the actual dependency or design the integration against a maintained backend. Cargo advisories do not cover vendor HSM modules, container operating-system packages or the operator's deployment configuration; qualify those separately.

## 2026-11-17: remove the unused OAuth2/Chrono dependency chain

RUSTSEC-2026-0543 marks every Chrono version unmaintained. The released oauth2
5.0.0 and the inspected upstream development manifest both require Chrono;
disabling default features does not remove it. Brigalow used neither OAuth2
transport nor its time-bearing token types: only authorization URL construction,
random state and the PKCE challenge helper.

Remove that dependency without adding a fork or suppressing advisories. Use
the existing 32-byte `OsRng` helper for independent verifier/state values,
RustCrypto `sha2` and `base64` for the RFC 7636 S256 transformation, and `url`
for query encoding. These are existing library primitives, not a new hash,
cipher or random generator. Scope stays `openid groups`; authorization-code
flow, nonce, redirect URI and S256 remain mandatory. The verifier stays in the
encrypted pending-login record and only goes to the pinned token endpoint.
JWT validation, browser binding, expiry, consumption and token exchange do
not change. This supersedes the OAuth2-library choice above.

The regression uses RFC 7636 Appendix B's independent vector and checks query
encoding for reserved characters, Unicode and existing endpoint parameters.
AT-ID-01 and AT-HA-01 retain real generated IdP coverage, including wrong PKCE
verifiers and single-use, browser-bound shared state. No warning exemptions
are permitted.
