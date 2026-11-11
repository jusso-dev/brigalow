# Architecture

Status: Phase 0 foundations implemented: config, health endpoint, tenant store, audit chain and offline verifier. Identity, signing, approvals, gates, UI and signed audit checkpoints remain planned.

## Components

```
            humans (browser)                     CI jobs / dev machines
                 | OIDC                                | OIDC workload token or API token
                 v                                     v
        +--------------------------------------------------------+
        |                    brigalow-server                     |
        |  axum HTTP API  |  admin UI (askama + htmx, no Node)   |
        |  authn / authz  |  policy engine  |  approvals         |
        |  release windows|  gate runner    |  audit chain       |
        +-----------+----------------------+---------------------+
                    |                      |
             sqlx (Postgres)        KeyBackend trait
                    |              /       |        \
               Postgres      PKCS#11    lab-soft    (later) cloud KMS,
                             (HSM /     (dev only)  remote CA API
                             SoftHSM2)
                    |
           external RFC 3161 TSA (configured URL)

   brig CLI: hashes locally, submits digest, waits for approval, writes signature / CMS / timestamp
```

## Crates (Cargo workspace)

| Crate | Role |
| --- | --- |
| `brigalow-core` | Domain types, policy evaluation, approval state machine, audit chain. Pure, no I/O. Most unit tests live here. |
| `brigalow-crypto` | `KeyBackend` trait, PKCS#11 backend (`cryptoki`), lab software backend, CSR and chain validation, CMS building, RFC 3161 client. Uses RustCrypto / `x509-cert` / `cms` crates; no hand-rolled primitives. |
| `brigalow-store` | Postgres persistence with `sqlx` migrations. Every tenant-owned table carries `org_id`; queries go through a tenant-scoped handle. |
| `brigalow-server` | axum app, OIDC, RBAC, admin UI templates, webhook gates, metrics. |
| `brig` | CLI client. |

Phase 0 adds `brigalow-store`. Add `brigalow-crypto` when backend code first needs it. Key, policy and request tables currently contain tenant-linked metadata placeholders only; they confer no signing authority.

## Signing request lifecycle

```
submitted -> authorised -> (awaiting_approval) -> (gating) -> signing -> signed
     \             \                 \                \            \
      rejected      rejected          denied/expired   gate_failed   failed
```

1. **Submit**: client sends `{project, policy, digest_alg, digest, artifact_name, metadata}` plus its credential. The digest is the only artifact data that leaves the build.
2. **Authorise**: credential verified (OIDC signature, issuer, audience, expiry). Submitter rules matched against verified claims. Policy purpose and key binding checked. Release window and signature cap checked for offline keys.
3. **Approve** (if policy needs it): approvers notified; any deny rejects; k approvals advance; expiry rejects. Requester and key custodians are excluded.
4. **Gate** (if configured): each gate gets a signed webhook with the request summary and must answer pass/fail before its timeout. Timeout or error fails closed.
5. **Sign**: backend signs the digest with the bound key. The server never sees a private key.
6. **Timestamp** (optional): client or server obtains an RFC 3161 token from the configured TSA over the signature.
7. **Record**: every transition appends to the audit chain inside the same database transaction as the state change.

## Audit chain

- Each entry: `seq`, `org_id`, `at`, `actor`, `action`, `subject`, `details` (JSON), `prev_hash`, `entry_hash = SHA-256(canonical(entry without entry_hash))`.
- Encoding v1 uses RFC 8785 canonical JSON, lowercase hex SHA-256, Unix milliseconds, sequence numbers starting at 1 and an all-zero genesis hash. Each export contains one organisation. JSON numbers must be integers within ±(2^53−1); use strings for larger values.
- Chain verification detects altered entries, reordering and interior deletion. Without an independently retained head or signed checkpoint it cannot detect suffix truncation or a fully rewritten chain.
- Periodic checkpoint (planned): `{seq, entry_hash}` signed by a dedicated audit key held in a backend.
- `brig audit verify <export.jsonl>` re-computes the chain and checks checkpoint signatures offline.
- The table is insert-only for the app's database role (no UPDATE or DELETE grants).

## Identity and tenancy

- Humans: OIDC authorisation code + PKCE with any standards-compliant IdP. Group claims can map to roles.
- Workloads: OIDC ID tokens from CI (GitHub Actions first). Trust is configured per org as `{issuer, audience}` plus claim rules per submitter.
- API tokens: for systems without OIDC. Hashed at rest, scoped to one project and one policy, mandatory expiry.
- Tenancy: `org_id` on every tenant table, enforced in the store layer and tested by cross-tenant access tests on every endpoint.

## Configuration and secrets

- Config file plus environment variables. No secrets in the config file: HSM PINs and DB passwords come from env or a file path with `0600` permissions.
- Modes: `lab` (software keys allowed, banner shown everywhere, refuses `release` purpose) and `production` (software backend refuses to load).

## Deliberate non-features

- No private key export endpoint, even for admins.
- No "approve all" bulk action.
- No silent fallback from HSM to software keys.
