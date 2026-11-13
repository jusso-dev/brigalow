# Interrupted-request recovery: design outcome

Reviewed source: `89cf46697091a1b175435f1971ba74a3131db7d1`. Status: **read-only inspection design recommended; terminal resolution blocked pending an enforceable quiescence/fencing design**. This is a design, not implemented or tested behaviour.

## State and concurrency contract

1. `prepare_sign` reserves `(org_id, request_id)` in `request_ids`, takes the organisation transaction advisory lock and persists a request/audit before any gate/HSM call (`crates/brigalow-store/src/signing.rs`). `awaiting_approval` is not an interrupted signing operation and is outside this feature.
2. `finish_gates` begins a tenant transaction, takes the audit lock, locks the request row `FOR UPDATE`, requires `gating`, rechecks policy/key/window, and commits `signing` or `rejected` plus audit (`gates.rs`). After that commit, `signing::complete` calls `produce` outside the transaction. Consequently, changing the DB row to `failed` after gate commit **cannot prevent** that worker from entering the HSM.
3. For a direct request, the initial transaction has already committed `signing` before `produce`. An HSM operation, TSA call or attestation operation can occur while another transaction runs. `finish_sign` then takes the tenant advisory lock and uses `UPDATE ... WHERE state='signing'`; one update plus its audit entry commits. A different terminal state makes the late DB write fail, but does not undo any signature already performed.
4. A process crash may leave either `gating` or `signing`; the presence of a row alone does not establish whether an HSM signature happened. Poll/read operations must not call `complete` or restart work. The system cannot infer quiescence from a clock, heartbeat timeout, or a stopped HTTP listener, because native calls may be uninterruptible.

## Authority and audit

First implementation slice: a **read-only**, organisation-scoped inspection operation for authenticated human `OrgAdmin` or `Auditor` under existing `Action::Audit`; retain existing scoped/404 tenant semantics and CSRF rules for any future mutation. Return only request ID, project, state, relevant timestamps if actually persisted, policy/key IDs, audit sequence/event summaries and an explicit `outcome_unknown` indicator; avoid exposing raw identity tokens, secret material or unbounded evidence strings. Reuse existing authorised request read if it already supplies a field; extend only if a field is unavailable. Avoid privileged owner credentials in the web service.

Future resolution, if later designed and tested, requires a distinct human-only action, a bounded non-secret reason and opaque evidence reference, organisation/request-specific compare-and-set, and one atomic state plus audit append under the established advisory-lock then row-lock order. Auditor read permission must not silently grant write permission. Owner DB operators are inherently powerful, but that fact is not a substitute for application authorisation or an audited workflow.

## No-repeat guarantee

The first slice makes **no** state transition, signs nothing and cannot release request IDs or refund window capacity. Existing request ID uniqueness prevents replay of that ID; it does not prevent a user from submitting a different new ID for the same digest. Operators must stop submission and independently establish that all old workers and their HSM/device operations are quiescent before considering any replacement request. Device-side evidence and session/credential revocation semantics are vendor-specific; no expiry or database flag proves cancellation.

Terminal `failed/unknown` resolution is deferred. A future proposal must add an enforceable maintenance/fencing mechanism and distinguish (a) preventing any new backend invocation, (b) identifying already-issued invocations whose outcome is unknown, and (c) operator-confirmed resolution. Do not claim application fencing cancels already-entered vendor code. If quiescence cannot be established, remain unresolved; do not import a purported signature, refund a cap or automatically retry. This is also a prerequisite for HA design.

## Acceptance tests

Propose **AT-REC-01** for a later implementation: authenticated authorised read of `gating` and `signing`; unknown IDs/cross-tenant return 404; unauthorised roles cannot inspect; malformed IDs fail; result is bounded and contains no token/PIN. Verify no DB mutation, audit chain remains intact, counting backend records zero additional invocations and the original request ID remains consumed. Reuse route-registry cross-tenant tests in `crates/brigalow-server/tests/identity.rs` and real Postgres integration in `crates/brigalow-store/tests/`.

Before enabling future resolution, add deterministic barriers for (1) gate result commit versus attempted resolution, (2) backend invocation already entered versus attempted resolution, (3) completion commit versus two competing resolvers, (4) audit insertion failure rolls back resolution, and (5) crash/restart with consumed window cap and no duplicate backend call. Test wrong org/role, replay, no output for unknown/failed outcome, and actual signature verification with OpenSSL only for a genuinely completed request. Exercise all existing AT-APR, AT-REL, AT-SIGN and AT-TEN tests in full Compose and hosted CI.

## Implementation boundaries

Candidate files for a separately authorised implementation: `crates/brigalow-core/src/rbac.rs` (only if a new action is necessary), `crates/brigalow-server/src/approvals.rs`/router and identity integration tests, `crates/brigalow-store/src/signing.rs` (bounded read), `docs/acceptance-tests.md`, `docs/operations.md` and `docs/threat-model.md`. Scope must be confirmed against actual existing request read and DB columns. The initial slice requires no schema migration unless existing evidence lacks required fields; missing timestamps should be omitted, not invented.

## Residual risks

No software-only record proves whether a native HSM call completed, or that an operator truly stopped another isolated instance. An external device may hold or expose evidence beyond Brigalow's control. A crash can occur after signing and before persistence, and no HSM-to-DB atomic transaction exists. Read-only visibility improves incident handling but intentionally does not make a stranded operation safely retryable. A new trust boundary for reconciliation/fencing requires a threat-model update and independent review before implementation.
