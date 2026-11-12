# Plan 006: Signing fence, invocation ledger and operator resolution

Date: 13-11-2026. Reviewed source: `fde7ebb` (main after PR #2). Status: **design for review. Nothing here is implemented or tested.** It unblocks terminal resolution from plan 001 and AT-HA-02 from plan 004, but neither is to be built until a reviewer accepts this document. It does not loosen the Helm `replicas=1`/Recreate guard.

## Summary

Three separate mechanisms, as `plans/001-recovery-outcome.md` requires:

1. **Fence (stop new invocations).** A per-organisation fence row with a monotonic `epoch`. Every transaction that commits `signing` records the current epoch on the request. Immediately before each backend call, the worker runs a short transaction that rechecks state, fence and epoch and inserts an invocation row. Raising the fence bumps the epoch, so no request authorised under an earlier epoch can ever start a backend call, even after the fence is lifted.
2. **Invocation ledger (identify unknown outcomes).** Insert-only rows record each backend call before it starts and its result class after it returns. A started row with no result row is "issued, outcome unknown". Once the fence is raised, that set can only shrink.
3. **Resolution (human-only terminal state).** A new action, compare-and-set on the request state and the exact set of open invocations, one atomic state change plus audit append. `signing` resolves to a new terminal `failed_unknown`; `gating` resolves to `rejected`. No output, refund, ID release, import or retry is possible.

No application fence cancels code already inside a vendor HSM or remote service call. The fence guarantees only that Brigalow starts no *new* call. Quiescence of calls already issued must be established out of band and is recorded as operator attestation, not proven.

## 1. Problem and current state machine

After a crash a request can stay in `gating` or `signing` indefinitely. Nothing restarts it (poll/read paths never call `complete`), but nothing can close it either. AT-REC-01 inspection (`crates/brigalow-server/src/recovery.rs:43-79`) is read-only and always reports `outcome_unknown=true`. Operators can only stop submission and wait (`docs/operations.md:83`). Multiple replicas would make this worse: a second process could be alive inside a backend call while an operator acts.

States are `awaiting_approval`, `gating`, `expired`, `signing`, `signed`, `failed`, `rejected` (`crates/brigalow-core/src/policy.rs:154-162`). There is no DB `CHECK` on state values; the only constraint ties `record->>'state'` to the column (`migrations/0004_signing.sql:7`).

| Transition | Committed by | Locks (in order) | Work outside any transaction |
| --- | --- | --- | --- |
| new → `awaiting_approval`/`gating`/`signing`/`rejected` | `prepare_sign` (`crates/brigalow-store/src/signing.rs:73-185`); `signing` only after `claim_window` (`:140-141`) | org advisory lock (`:84`), `request_ids` insert (`:85-94`), key row `FOR UPDATE` (`:123`), window row `FOR UPDATE` (`approvals.rs:99`) | none |
| `awaiting_approval` → `gating`/`signing`/`rejected`/`expired` | `decide` (`crates/brigalow-store/src/approvals.rs:149-240`; quorum path `:201-226`) and `expire_requests` (`:241-254`) | advisory lock (`:160`), request row `FOR UPDATE` (`:161-167`), key, window | `crates/brigalow-server/src/approvals.rs:79-80` then calls `complete` |
| `gating` → `signing`/`rejected` | `finish_gates` (`crates/brigalow-store/src/gates.rs:9-92`) | advisory lock (`:16`), request row `FOR UPDATE` (`:17-23`), state check (`:25-27`), key, window (`:74`) | gate webhooks (`crates/brigalow-server/src/signing.rs:218`, `gates.rs:102-189`) run before this transaction |
| `signing` → `signed`/`failed` | `finish_sign` (`crates/brigalow-store/src/signing.rs:186-219`) | advisory lock (`:191`), `UPDATE … WHERE state='signing'` (`:197`), `Conflict` if 0 rows (`:198-200`) | everything in `produce` (`crates/brigalow-server/src/signing.rs:234`) |

Inside `produce`, backend calls run in `spawn_blocking` tasks that keep running if the request future is dropped:

- Pinned keys: one task calls `public_key` then `sign_digest` or `cms::detached` (`signing.rs:387-403`). With attestation enabled, a second task signs provenance (`:434-444`). This is a second backend signature for the same request.
- Rotating keys (Azure Artifact Signing): one task submits once and polls, writing a `request.remote_accepted` audit entry from inside the task as soon as an operation ID arrives (`:321-350`, record at `:322-332`).
- The TSA call (`:418-428`) is outside the backend but also outside any transaction.

`persist_request` updates without a state predicate (`approvals.rs:130-131`). Its compare-and-set relies on the caller's `FOR UPDATE` lock and the state check in Rust. The PKCS#11 adapter holds one logged-in session per process behind a `Mutex` (`crates/brigalow-crypto/src/pkcs11.rs:16`, `:216`), so a stuck native call blocks every later call in that process. Readiness uses `try_lock` (`:77`) for that reason.

## 2. Fencing design

### 2a. Preventing new backend invocations

`brigalow.signing_fences` holds one row per organisation: `epoch bigint`, `fenced boolean`, `changed_at`, `changed_by`. `brigalow-admin create_org` (`crates/brigalow-store/src/admin.rs:38-60`) inserts it; migration backfills existing organisations with `epoch=0, fenced=false`. A missing row is treated as fenced (fail closed), not open.

`sign_requests` gains `fence_epoch bigint NOT NULL DEFAULT 0`. The three transactions that can commit `signing` (`prepare_sign`, `decide` at quorum, `finish_gates`) read the fence row after taking the org advisory lock and before `claim_window`:

- open: set `fence_epoch` to the current epoch in the same insert/update that commits `signing`;
- fenced: commit `rejected` with reason `signing_fenced`. `claim_window` is never reached, so no cap is consumed. The request ID stays consumed.

Every fence change also holds the org advisory lock, so a plain read under that lock is consistent. No extra row lock is needed. As defence in depth, owner-defined triggers (section 5) refuse a transition into `signing` unless the fence is open and `NEW.fence_epoch` equals the current epoch.

**Pre-invocation check.** Immediately before each `spawn_blocking` that can reach the backend (`signing.rs:321`, `:387`, `:439`), the worker runs `begin_invocation(request, n, kind)` in one transaction: advisory lock, request row `FOR UPDATE`, require `state='signing'`, fence open, `fence_epoch` equal to the current epoch, then insert `backend_invocations(n, kind, epoch, worker_id, started_at)` and append audit `request.backend_invoking`. Only after commit does the task start. If the check fails, no task is started and the worker calls `finish_sign` with `failed` and reason `fenced_before_invocation`. That outcome is definite, because the ledger shows no call. A request authorised in epoch *e* can never invoke once the epoch is above *e*, even if the fence was lifted again.

### 2b. Identifying invocations already issued

After the backend task returns, success or error, the worker inserts `backend_invocation_results(n, outcome, at, operation_id)` in its own short transaction, then continues to TSA and `finish_sign`. `outcome` is a class only (`returned`, `error`). Signature bytes are never stored there. The insert does not check the fence or state, so a result arriving after resolution is still recorded and audited as `request.late_backend_result`. That record exposes a false quiescence attestation; it never produces output.

An invocation is **open** when it has a start row and no result row. The time between the start commit and the native call (including waiting on the per-process PKCS#11 mutex) counts as issued. That is conservative but correct. Once the fence is raised, no new start row can be inserted for any request with an older epoch, so the open set for those requests can only shrink. That is the observable form of "quiescence" Brigalow can offer.

`worker_id` is a random UUID generated at process start and logged once at startup, with an optional operator-configured instance label (at most 64 characters, `[a-z0-9-]`). It lets an operator match an open invocation to a host or pod. It is not a liveness signal: plan 001 forbids inferring quiescence from heartbeats or clocks, and this design adds none.

### 2c. Human, audited, compare-and-set resolution

`POST /v1/orgs/{org}/requests/{id}/resolution` with a `deny_unknown_fields` body:

| Field | Rule |
| --- | --- |
| `expected_state` | `gating` or `signing`; must equal current state |
| `expected_open_invocations` | exact list of open invocation numbers the operator inspected; must equal the ledger |
| `expected_fence_epoch` | required for `signing`; must equal current epoch |
| `reason` | 1–500 bytes, UTF-8, no control characters |
| `evidence_ref` | opaque reference to evidence held elsewhere (ticket, vendor log export ID); 1–128 bytes of `[A-Za-z0-9._:/#-]`; never a URL with credentials, never log content |
| `attest` | `{processes_stopped, hsm_sessions_closed, device_logs_reviewed}`; all must be `true` when any invocation is open, otherwise the request is refused |

Preconditions for `signing`: the fence is raised and `request.fence_epoch < current epoch`, so no new invocation is possible. Result: state `failed_unknown`, `failure="operator_resolved_unknown"`, no output, one `request_resolutions` row, one audit `request.resolved` entry listing the open invocations, their worker IDs, the attestation flags, reason and `evidence_ref`. All of this commits together.

Preconditions for `gating`: none beyond the CAS, because `finish_gates` rechecks state under the row lock (`gates.rs:25-27`) and a gating request has never invoked a backend or claimed a window (`gates.rs:74`). Result: `rejected` with `failure="operator_resolved"`. A live gate worker's later `finish_gates` returns `Conflict`, which `complete` surfaces as 409 (`server/signing.rs:223-229`, `web.rs:42`).

**Out of band, before attesting.** Operators must establish, using vendor tooling and not Brigalow: every server process that held an open invocation has exited (not just stopped serving HTTP; `with_graceful_shutdown` at `main.rs:147` does not stop `spawn_blocking` tasks); its PKCS#11 sessions are closed on the device, or the remote operation has reached a final state in the provider's logs (look up the audited operation ID); and device or provider logs for that key object around `started_at` have been reviewed for a signature. The HSM token is shared across organisations within a process (`pkcs11.rs:16`), so device evidence must be filtered by the key object UUID. Brigalow records only the operator's assertion and the opaque reference. It cannot verify either.

**Fence control.** `POST …/signing-fence/raise` (`reason`, optional `evidence_ref`) increments `epoch` and sets `fenced=true`. `POST …/signing-fence/lift` (`expected_epoch`, `reason`) is refused with 409 while any `signing` request with `fence_epoch < epoch` remains, so a replacement request cannot be signed while an old attempt is unresolved. This is plan 001's quiescence-before-replacement rule. `GET …/signing-fence` returns epoch, state and counts. Each change commits with its audit entry.

## 3. Authority

Two new actions in `crates/brigalow-core/src/rbac.rs` (current list `:15-23`). `Action::Audit` (`:57`) is not reused, so auditor read access never grants a write.

| Action | Allowed | Used by |
| --- | --- | --- |
| `Action::Fence` | human `OrgAdmin` or `KeyCustodian` | raise fence |
| `Action::Resolve` | human `OrgAdmin` only | resolve request, lift fence |
| `Action::Audit` (unchanged) | human `OrgAdmin`/`Auditor` | inspection and fence `GET` |

Custodians may raise the fence because they already own incident response for keys and can disable them (`server/keys.rs:284-288`). Raising grants no signing authority. The requester of a request cannot resolve it (`request.requester == p.actor` → 403), which mirrors the self-approval rule. API credentials and workload tokens are not human and get 403.

Request handling follows `recovery.rs:43-64`: authenticate with `mutating=true`, which enforces Origin plus constant-time CSRF for cookie sessions (`web.rs:192-199`); check permission before lookup (403 reveals nothing); unknown, placeholder or cross-tenant IDs and out-of-scope sessions return 404; non-interrupted states and every CAS mismatch return 409; malformed bodies, out-of-range `reason`/`evidence_ref` and missing attestation return 400. The organisation comes only from the authenticated path and `Tenant` (`crates/brigalow-store/src/lib.rs:117-124`).

**Lock order** for every new write is the existing one: org advisory lock (`lib.rs:171-187`), then fence row (read), then request row `FOR UPDATE`, then ledger rows, then audit append (`lib.rs:188-223`). The worker's `begin_invocation`, `finish_sign`, `finish_gates`, `decide` and resolution all take the advisory lock first, so they serialise per organisation and cannot deadlock on row order.

## 4. Invariants

| Invariant | Enforcement |
| --- | --- |
| No refund of release-window capacity | Resolution never touches `release_windows`; the runtime grant is `UPDATE(used,closed)` (`0005:11`), so tests assert `used` is unchanged byte for byte |
| No release of request IDs | `request_ids` grant is `SELECT, INSERT` only (`0002:26`); resolution adds no delete path; original-ID replay stays 409 |
| No import of a purported signature | Resolution body has no output field (`deny_unknown_fields`); invocation results store a class and operation ID only; new `CHECK (state='signed' OR coalesce(record->'output','null'::jsonb)='null'::jsonb)` |
| No automatic retry | `failed_unknown` is terminal; terminal-state trigger refuses any update from `signed`, `failed`, `failed_unknown`, `rejected`, `expired`; no code path reads stranded requests for work |
| No output for unknown/failed outcomes | Late `finish_sign` hits `WHERE state='signing'` → `Conflict` (`store/signing.rs:197-200`) → 409 with no body; output is only ever returned after a committed `signed` |
| Fence cannot be bypassed by a stale worker | Epoch check in `begin_invocation` and trigger on ledger insert; lifting does not restore older epochs |

## 5. Schema, migration and rollout

Migration `0011_signing_fences.sql`, embedded in `crates/brigalow-store/src/migrations.rs` (the embed test at `:86-105` enforces this):

- `signing_fences(org_id PK REFERENCES organisations, epoch bigint NOT NULL CHECK(epoch>=0), fenced boolean NOT NULL, changed_at bigint, changed_by text CHECK(length<=200))`. Grants: `SELECT`, `UPDATE(epoch,fenced,changed_at,changed_by)`. No runtime `INSERT`/`DELETE`.
- `sign_requests.fence_epoch bigint NOT NULL DEFAULT 0`; grant `INSERT` (already table-wide) and `UPDATE(fence_epoch)`.
- `backend_invocations(org_id, request_id, n smallint CHECK(n BETWEEN 1 AND 2), kind text CHECK(kind IN ('sign','attestation','remote')), epoch, worker_id uuid, started_at bigint, PK(org_id,request_id,n), FK(org_id,request_id) → sign_requests)`. `SELECT, INSERT` only.
- `backend_invocation_results(org_id, request_id, n, outcome text CHECK(outcome IN ('returned','error')), at bigint, operation_id text CHECK(length<=256), PK same, FK → backend_invocations)`. `SELECT, INSERT` only.
- `request_resolutions(org_id, request_id PK, from_state, to_state, actor, reason, evidence_ref, fence_epoch, open_invocations smallint[], attest jsonb, at)` with length/charset `CHECK`s matching section 2c. `SELECT, INSERT` only.
- Forced RLS with the standard `tenant_isolation` policy (`0001:61-64`) on all new tables. No `DELETE`, `TRUNCATE` or `UPDATE` beyond the columns listed.
- Owner-defined `SECURITY INVOKER` triggers on `sign_requests` (allowed transitions, terminal immutability, fence epoch on entry to `signing`) and on `backend_invocations` (request in `signing`, fence open, epoch equal). These are the first triggers in the schema and are flagged as an open question.
- Backfill: one fence row per existing organisation. Existing stranded `signing` rows keep `fence_epoch=0`, so raising the fence once (epoch 1) makes them resolvable. They have no ledger rows, so resolution must treat "no ledger rows on a pre-0011 request" as *unknown*, not *none*, and require the full attestation.

**Rollout.** `Store::connect` refuses any binary whose embedded migration list differs from `_sqlx_migrations` (`lib.rs:92-96`, `:237-252`), so an old binary cannot start against a migrated database and a new binary cannot start against an unmigrated one. That check runs only at startup. An old process that is *already running* when 0011 is applied would ignore the fence. The runbook is therefore: stop every server process (Recreate already does this for the single replica), apply 0011 with `brigalow-admin`, then start the new version. Mixed old and new servers sharing one database are not supported, and AT-HA-02 tests that this is refused. Rollback to a pre-0011 binary is refused by the same check; use the documented restore procedure.

## 6. Acceptance tests

Both suites run in the existing Compose harness (`deploy/dev/compose.yml`, driven by `scripts/e2e.py`) with TLS Postgres, generated IdP/TSA credentials and the `integration` feature. Infrastructure-dependent tests must fail, not skip, when that infrastructure is missing.

### AT-REC-02 Operator resolution (in-process, deterministic)

Location: `crates/brigalow-server/tests/identity.rs` next to `at_rec_01_…` (`:3655`), reusing `CountSigning` (`:2372`), plus grant and trigger checks in `crates/brigalow-store/tests/`. Barriers are test-only async hook points (`after_gate_commit`, `before_begin_invocation`, `inside_backend`, `after_backend_return`, `before_finish_sign`) compiled only under `cfg(feature="integration")`. A wrapper backend blocks inside `sign_digest` on a channel. Audit failure is injected by an owner-installed test trigger on `audit_entries` in the disposable database.

| Case | Asserts |
| --- | --- |
| Authority | Auditor, Approver, Submitter, Custodian → 403 for resolve; Custodian → 200 for raise; requester-as-OrgAdmin → 403; API credential and workload token → 403; missing Origin/CSRF → 403; cross-tenant, unknown and placeholder IDs → 404; permission checked before lookup |
| Validation | empty or 501-byte `reason`, control characters, bad `evidence_ref` charset or length, missing attestation, unknown field → 400; no row or audit change |
| CAS | wrong `expected_state`, `expected_open_invocations` or `expected_fence_epoch` → 409; resolving `signing` without a raised fence → 409; `signed`/`failed`/`awaiting_approval` → 409 |
| Barrier 1: gate commit vs resolution | both orders: resolution first → later `finish_gates` 409, window `used` unchanged, zero backend calls; `finish_gates` first → resolution of `gating` 409 |
| Barrier 2: backend entered vs resolution | worker held at `inside_backend` with an open invocation; resolution succeeds only after raise; on release the late result is recorded, `finish_sign` returns `Conflict`, client gets 409 with no output, audit has `request.late_backend_result`. Variant at `before_begin_invocation`: worker refused, state `failed`/`fenced_before_invocation`, call count 0 |
| Barrier 3: completion vs two resolvers | worker `finish_sign` and two resolvers concurrently; exactly one terminal transition and one terminal audit entry; losers get 409 |
| Barrier 4: audit failure | injected audit insert failure → 500; request still `signing`, no resolution row, fence unchanged, audit chain verifies |
| Barrier 5: crash and restart | offline key, window cap 1 consumed by a stranded request; rebuild `Store`/`AppState`; call count stays 0; resolve; new request on that window rejected as exhausted; original ID replay 409; fence lift refused until resolved; after lift, a new ID for the same digest signs once and verifies with OpenSSL |
| Fence entry points | while fenced, `prepare_sign`, quorum `decide` and `finish_gates` commit `rejected`/`signing_fenced` with window `used` unchanged; an epoch-*e* request cannot invoke after lift |
| Attestation | fence raised between the first signature and provenance → second invocation refused, request `failed`, no output, invocation 1 result present |
| Remote | Azure mock: operation accepted, polling stalled; inspection shows invocation `remote` with operation ID; resolution lists it |
| DB grants | runtime role cannot `UPDATE`/`DELETE` resolutions, invocations or results, nor `DELETE` `request_ids`; triggers reject `failed_unknown`→`signing`, `signing` entry while fenced and output on `failed_unknown`; cross-tenant RLS on every new table |

After every successful resolution: exactly one `request.resolved` entry, audit chain verifies with `brig audit verify`, `request_ids` and `release_windows` rows unchanged, inspection now returns 409.

### AT-HA-02 Multi-process signing races (depends on this fence)

Location: new `crates/brigalow-server/tests/ha.rs` plus an `e2e.py` stage. Two separate `brigalow-server` OS processes (A, B), built with `integration`, share the Compose Postgres. Backends: a lab-only `counting-blocking` test backend (refused in production mode, like `software`) that appends one line per call to a per-process `O_APPEND` file, independent of the ledger, and blocks on a configured FIFO when told to. A SoftHSM sub-case runs inside the Compose network where the module is available, as `hsm_test.py` does, with each process holding its own session. DB-side pauses use a session-level hold of the org advisory lock from the admin connection, observed through `pg_locks`. Advisory-lock grant order between two waiting processes is not asserted; each case asserts invariants for whichever order occurs. Exact interleavings are covered by AT-REC-02.

| Case | Asserts |
| --- | --- |
| Cap race | 20 requests split across A and B against an offline window with cap 5 → exactly 5 `signing`, `used=5`, 15 rejected, 5 ledger rows, counter files total 5, 5 signatures verify with OpenSSL |
| Approval race | final approvals from two approvers on A and B at once → one quorum transition, one invocation |
| Replay | same request ID to A and B at once → one 2xx, one 409, one invocation |
| Parallel expiry | both maintenance loops (`main.rs:111-133`) on one batch → exactly one `request.expired` per request |
| Cross-process fence | B blocked inside backend; A raises fence; B's next request fails `fenced_before_invocation` with no counter increment; releasing B completes the in-flight request as `signed` (allowed, verifies with OpenSSL) |
| Crash | `SIGKILL` B while blocked → `signing` with one open invocation carrying B's `worker_id`; restart B → no counter change; A inspects and resolves → `failed_unknown`; restarted B cannot complete it |
| SIGTERM | graceful stop of B mid-invocation → request is either `signed` or stranded with an open invocation; never two calls |
| False attestation | B blocked, A raises and resolves, then B released → late result recorded, B's client gets 409 and no output |
| DB outage | Postgres paused between invocation start and `finish_sign` → no output to client; afterwards `signing` with an open invocation |
| Audit continuity | export after all cases verifies with `brig audit verify`; sequence contiguous across both processes |
| Rollout | pre-0011 binary refuses the migrated DB; new binary refuses an unmigrated DB |
| Topology guard | `scripts/test_helm.py` still rejects `replicas != 1` |

Existing AT-ID-01..03, AT-APR, AT-REL, AT-SIGN, AT-AUD, AT-OPS-02/03, AT-TEN and AT-REC-01 remain mandatory locally and in hosted CI. SoftHSM and mocks cannot qualify vendor session concurrency, device timeouts or device-side fencing.

## 7. Threat model, residual risks and open questions

**Threat-model changes** (`docs/threat-model.md`). Update the Phase 3 inspection bullet (`:86`) to describe the new write path. Add:

- T22, a malicious or mistaken admin resolves to hide a signature: resolution writes only `failed_unknown` and never deletes; late results are recorded; the requester cannot resolve; covered by AT-REC-02.
- T23, a stale or old-version worker bypasses the fence: DB triggers, epoch check and exact-schema startup refusal; covered by AT-REC-02 and AT-HA-02.
- T24, fence used for denial of service: custodian or admin can halt signing for an organisation; audited; lifting is admin-only; accepted as residual.

B2/B4 gain a write path. B3 is unchanged: no new device interaction.

**Residual risks.** Quiescence is operator-asserted, never proven. `evidence_ref` is unverified and only as trustworthy as the system it points to. A DB owner can bypass triggers and grants. A process frozen for a long time (VM pause, swap) can resume inside a native call after resolution; that is recorded but not prevented. A signature may exist in the device with no Brigalow output, as today. The per-organisation fence does not quiesce the shared HSM token for other organisations.

**Open questions for the reviewer.**

1. Fence scope: per organisation (proposed), per key, or deployment-wide for HA rollouts?
2. A request reaching the signing decision while fenced is `rejected`, which discards collected approvals. Should it instead stay in its prior state?
3. Should resolution need two people (for example a custodian attestation plus an admin resolution)?
4. Is the strict lift rule (no stranded older-epoch `signing` requests) right, or is an audited override needed?
5. Are owner-defined plpgsql triggers acceptable as the first triggers in the schema, or should enforcement stay in the application?
6. Should `brigalow-admin` offer an offline fence raise for when HTTP is unavailable?
7. Should a key disable also fence that key's invocations? Today it only revokes DB authority before the backend disable (`server/keys.rs:285-288`).
8. Is `rejected` the right terminal for resolved `gating`, or should both use `failed_unknown` for uniformity?

**Candidate files for a later, separately authorised implementation.** `crates/brigalow-core/src/rbac.rs`, `crates/brigalow-core/src/policy.rs` (`FailedUnknown`); `crates/brigalow-store/migrations/0011_signing_fences.sql`, `src/migrations.rs`, new `src/fences.rs`, `src/signing.rs`, `src/gates.rs`, `src/approvals.rs`, `src/admin.rs`; `crates/brigalow-server/src/signing.rs` (invocation guard around `:321`, `:387`, `:439`), `src/recovery.rs`, `src/lib.rs` (routes), `src/main.rs` and config (worker ID and label); tests in `crates/brigalow-server/tests/identity.rs`, new `tests/ha.rs`, `crates/brigalow-store/tests/`, `scripts/e2e.py`; docs `docs/acceptance-tests.md`, `docs/threat-model.md`, `docs/operations.md`, `docs/architecture.md`, a new ADR `docs/decisions/0005-signing-fence.md` and `plans/README.md`.

## Where the code differs from earlier plans

- `plans/001-recovery-outcome.md` item 1 says `prepare_sign` reserves the request ID and then takes the advisory lock. The code takes the lock first (`store/signing.rs:84`, then `:86`). The order is harmless, but this design relies on lock-first.
- Plan 001 names two ways into `signing` (direct `prepare_sign` and `finish_gates`). There is a third: quorum in `decide` commits `signing` directly when the policy has no gates (`approvals.rs:212-226`), and `server/approvals.rs:79-80` then calls `complete`. The fence must cover all three.
- Plan 001 describes `finish_gates`/`persist_request` as a compare-and-set. The `UPDATE` in `persist_request` has no state predicate (`approvals.rs:130-131`); the guarantee comes from the caller's `FOR UPDATE` plus the Rust state check. Resolution must not reuse `persist_request` without its own predicate.
- Plans 001 and 004 predate the rotating backend. The Azure path writes audit from inside the backend task (`server/signing.rs:322-332`), and with attestation enabled one request makes two backend signatures (`:434-444`). The ledger counts calls, not requests.
- Plan 004 refers to process-local HSM "sessions". There is exactly one session per process behind a mutex (`pkcs11.rs:16`, `:216`), so a stuck call blocks every later call in that process. It also says each process runs expiry maintenance; that happens only when identity is configured, and only for organisations listed in identity authorities (`main.rs:111-117`).
