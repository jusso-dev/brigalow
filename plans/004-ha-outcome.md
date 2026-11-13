# Shared login state and HA: design outcome

Reviewed `89cf46697091a1b175435f1971ba74a3131db7d1`; incorporates the blocked terminal-resolution boundary from `plans/001-recovery-outcome.md`. **Do not enable multiple production replicas based on this document.** This is a design, not implemented or tested behaviour.

## Shared-login design

Current `Identity.pending` is a `Mutex<HashMap>` per process (`auth/mod.rs:58–63`); `auth/oidc.rs:33–56` stores a browser-bound state hash, plaintext-in-memory PKCE verifier/nonce and five-minute process-clock expiry. `:76–87` validates the cookie hash in constant time and removes the pending record before token exchange. A callback routed to another instance cannot find it. `Identity.keys` caches JWKS per process for 60 seconds; it is bounded but instances may briefly observe different key sets. `main.rs` starts expiry maintenance in each process. The PKCS#11 adapter has process-local logged-in native sessions. Sessions, rate budgets, requests, approvals, windows and audit entries live in Postgres; shared DB does not make native HSM operations transactional.

Recommended experiment: tenant-scoped Postgres pending-login rows keyed by hash of random state, storing provider, browser-binding hash, DB-clock expiry, version/key ID and an authenticated encrypted payload containing verifier and nonce. A login's insert and per-tenant/global bounds must be enforced atomically, not with a check-then-insert count race. Callback begins a transaction, sets tenant RLS context, locks the exact row, checks org/provider/expiry and browser hash (constant-time comparison) and atomically consumes it before outbound token exchange; a wrong browser must not consume another browser's valid state. Two callbacks on different instances yield at most one exchange. DB failure rejects login; no local-memory fallback. Cleanup deletes only expired rows in bounded batches under a restricted role.

Alternative: browser-held authenticated/encrypted state still needs a server-side single-use replay ledger; encrypted payload alone does not stop replay. Sticky sessions are not HA and do not survive failure. Keep the existing chart `replicas=1`/Recreate guard until the full acceptance and operator qualification below pass.

## Secrets and trust boundaries

The DB currently receives no PKCE verifier. Persisting it changes the DB/operator compromise boundary. Use a vetted AEAD implementation from the approved RustCrypto/AWS-LC stack only after independent review of its documented nonce/key API; no home-grown cipher. An operator-provisioned, dedicated 256-bit key must be separate from HSM PINs, signing keys and DB credentials, loaded via existing redacted secret-file conventions, never in values/logs/fixtures. All participating instances need the same active key and key ID. Bind ciphertext with authenticated associated data including a version, org UUID, provider, state hash and expiry; generate nonces via vetted secure API and enforce reviewed per-key usage limits. Authentication failure rejects the login.

Define a key-ring rollout: accept current and explicitly configured previous key IDs only, use the active key for new entries, retain an old key through maximum five-minute pending lifetime plus clock/rollout margin, and fail closed for missing/unknown key IDs. Rotation and emergency compromise invalidate affected pending logins; existing authenticated sessions follow their existing revocation/expiry rules. No silently generated per-instance keys. DB read access must be least privilege and RLS forced; encrypted ciphertext plus browser binding does not protect a compromised application process. TLS and operator-owned configuration are unchanged. Update `docs/threat-model.md` and a decision record before implementation.

## Concurrency and failure matrix

| Boundary | Required behaviour / unresolved qualification |
| --- | --- |
| Login callback/replay | Exactly one row consumption; failed browser binding does not consume; expired/unknown key/state fails; DB partition fails closed. |
| Gate completion and signing | A unique DB state transition serialises ownership, but once a worker crosses into a native HSM call, DB fencing cannot cancel it. Never automatically retry uncertain work. 001 terminal reconciliation remains blocked until a real fence/quiescence protocol is established. |
| Concurrent approvals/window caps | Existing tenant audit advisory lock and row locks are intended to serialise decisions/cap increments; prove with two separate app processes and actual Postgres. No cap refund for a failed or uncertain backend operation. |
| Audit chain | Each tenant append holds transaction advisory lock; verify cross-instance sequence continuity, RLS and independent checkpoints under crash/rollback. |
| Expiry tasks | Per-instance tasks may both run; prove row/advisory locks prevent duplicate expiry transitions/audit. Do not assume a leader based on local time. |
| HSM | Independent sessions and vendor parallelism/login limits, device timeouts, shared token state, partition recovery and device-side fencing are unknown until separately qualified. SoftHSM cannot establish vendor guarantees. |
| JWKS | Each instance has a 60-second bounded cache; test key rotation/expiry and no unknown-kid network amplification. Different caches may temporarily accept different valid key sets within configured policy. |
| Ingress/rate limits | Shared authenticated DB budgets do not provide a distributed unauthenticated IP budget. Qualify external ingress limits, CNI enforcement and health-check behaviour separately. |

## Migration and rollout

Use an owner-controlled checked-in SQLx migration before starting a compatible version; no per-replica migrations. Roll out the shared-state code in single-instance mode first, with new config/key validation and rollback plan. Old in-memory pending logins must finish or expire before switching; do not attempt to read old process memory from another node. Preserve existing durable sessions. A schema or config rollback must be tested, with backup and audit heads retained independently; exact-schema startup rules constrain mixed-version rolling updates.

Only after AT-HA-01/02, recovery/fencing resolution, concurrent workload tests, operations review and actual HSM/ingress/restore qualification should a separate change propose relaxing the Helm replica guard. No exactly-once native signature promise follows from this design, and no vendor qualification is performed here.

## Acceptance tests

Propose **AT-HA-01**: run two actual router/server instances against the same disposable TLS Postgres and generated IdP; initiate login at A, callback/complete at B, race callbacks, wrong browser, cross-org/provider, DB-clock expiration, restarts, unknown/rotated AEAD keys, invalid ciphertext/AAD, DB outage and no secrets in logs. Inspect DB to prove no plaintext verifier/nonce. Bound state inventory under concurrent creation.

Propose **AT-HA-02**: separate processes against Postgres and SoftHSM/counting backend, simultaneous decisions/gates, 20 requests against cap five, audit sequence and replay, parallel expiry, SIGTERM/crash at boundaries and stalled backend. Demonstrate no duplicate invocation and no output from an uncommitted result; do not claim fencer can stop a call already inside provider code. Independently verify completed signatures with OpenSSL. Test old/new schema rollout and Helm's current replica refusal. Existing AT-ID-01..03, AT-APR/REL, AT-AUD, AT-OPS-02/03 and AT-TEN remain mandatory locally and in hosted CI.

## External qualification

Production HSM vendor session concurrency, HA/failover, transport timeouts, device audit and backup, real DB and HSM restore, ingress/CNI enforcement, capacity and operator secret rotation are outside the disposable suite. Provider availability and an enforceable fence around already-entered native calls remain design blockers; keep single-instance guard until resolved. No real cluster, account or device was touched during this spike.
