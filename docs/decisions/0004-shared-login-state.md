# 0004: Shared pending-login state in Postgres with an operator key ring

Date: 2026-11-12. Status: accepted for the shared-login slice of plan 004. This does **not** enable multiple replicas.

## Decision

Pending OIDC logins move from a process-local map to tenant-owned Postgres rows (`brigalow.pending_logins`, migration 0010). Any server instance that shares the database and key ring can complete a login another instance started. The PKCE verifier and ID-token nonce are stored only as AEAD ciphertext.

- **Row:** org UUID, SHA-256 of the OAuth state (key), provider, SHA-256 of the browser-binding cookie, DB-clock expiry (five minutes), key ID, format version, 12-byte nonce, ciphertext with tag. Forced RLS. `brigalow_app` gets SELECT/INSERT/DELETE only; there is no UPDATE.
- **Cipher:** AES-256-GCM through `aws-lc-rs` `aead::RandomizedNonceKey`. The library generates every nonce (AWS-LC `EVP_aead_aes_256_gcm_randnonce`), so Brigalow never builds a nonce itself. `aws-lc-rs` is already in the lockfile through jsonwebtoken and is named in [0002](0002-stack.md). No new cryptographic implementation is added.
- **Associated data:** a domain-separation prefix, version, org UUID, length-prefixed provider, state hash, browser hash, expiry and length-prefixed key ID. Moving a ciphertext to another row, tenant, provider, browser or expiry fails authentication.
- **Per-key usage limit:** a shared counter (`pending_login_key_usage`) allows at most 2^31 committed seals per key ID. That is half of the NIST SP 800-38D limit for random 96-bit nonces; the margin covers rolled-back seals that are never counted. When the limit is reached, logins fail closed until the key is rotated.
- **Insert:** one transaction-scoped advisory lock serialises all pending-login inserts. Inside it: bounded expired-row cleanup, then per-tenant (1024) and global (4096) counts of live rows, then the key-usage increment, seal and insert. There is no check-then-insert race between instances. The global inventory table holds only a random slot UUID and expiry, never tenant, state or secret data.
- **Callback:** one tenant-RLS transaction runs `DELETE … RETURNING` on the exact `(org, state_hash)` row. This takes the row lock, so concurrent callbacks block on it. Inside the transaction the server checks DB-clock liveness, provider, version, constant-time browser-hash equality and AEAD authentication. It commits (consumes) only if every check passes. Otherwise it rolls back, so a wrong browser, provider, key or tampered row cannot destroy another browser's valid state. Consumption commits **before** the outbound token exchange. A DB error rejects the login; there is no in-memory fallback.
- **Cleanup:** bounded batches of 100 expired rows, deleted on the DB clock, both on insert and from the existing per-organisation maintenance loop.
- **Key ring:** the operator supplies an active `{id, file}` and up to four explicitly configured previous `{id, file}` entries under `[login_keys]`. Each file goes through the existing secret-file loader (regular file, no symlinks, mode 0600, at most 4096 bytes) and must decode as base64 of exactly 32 bytes. IDs must be unique and keys distinct. New logins use the active key; previous keys only open. An unknown key ID or failed authentication rejects the login. A key is never generated automatically or per instance. Human OIDC login refuses to start without a key ring.

## Why

- The design outcome (`plans/004-ha-outcome.md`) requires shared, single-use, browser-bound state as a prerequisite for any future HA work.
- Postgres already serialises tenant state and supplies the clock used for approvals and budgets.
- Encrypting the verifier keeps a database reader (backup, replica, owner operator) from completing a login with a stolen authorisation code, unless they also hold the operator key and the victim's browser cookie.
- `RandomizedNonceKey` is the API aws-lc-rs recommends over `LessSafeKey`. Random nonces avoid cross-instance counter coordination.

## Alternatives considered

- **Browser-held encrypted state:** still needs a server-side single-use ledger to stop replay, and puts ciphertext in front of the attacker. Rejected.
- **Sticky sessions:** do not survive instance failure and are not HA. Rejected.
- **Plaintext verifier in the DB:** widens the DB/operator compromise boundary with no key-management control. Rejected.
- **AES-GCM-SIV / ChaCha20-Poly1305:** viable. AES-256-GCM with a library-generated random nonce and an enforced per-key budget is the more widely reviewed choice in the existing stack.

## Boundaries

- One server replica remains the only supported topology. The Helm `replicas=1`/Recreate guard is unchanged. AT-HA-02 (multi-process signing, gates, caps, expiry and crash races) is **not implemented**. HSM concurrency/fencing and the recovery blockers in plan 001 are unresolved.
- A compromised application process holds the key ring and sees plaintext during login; encryption at rest does not protect against that.
- Rolling back to a binary that predates migration 0010 is refused by the exact-schema check. Restore through the documented recovery procedure.
