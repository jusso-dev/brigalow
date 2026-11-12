# Plan 001: Design interrupted-request reconciliation

> **Executor:** This is a design/spike, not authority to implement or deploy. Write the outcome under `plans/` only. Before starting, run `git diff --stat 89cf46697091a1b175435f1971ba74a3131db7d1..HEAD -- crates/brigalow-store/src/signing.rs crates/brigalow-store/src/gates.rs crates/brigalow-store/src/approvals.rs crates/brigalow-server/src/bin/brigalow-admin.rs docs/operations.md docs/threat-model.md`. If any differ, compare the excerpts below and stop on a material mismatch.

## Status

- Priority: P1; effort: L; risk: HIGH; category: direction; depends on: none.
- Planned at: `89cf466`, 2026-11-12. Outcome: `plans/001-recovery-outcome.md`.

## Why

After a crash, `gating` or `signing` records can remain unresolved; an HSM operation may already have happened. Operators need evidence and a safe terminal outcome without inventing a result, repeating a signature, or weakening separation of duties. This design must work without access to any real HSM or production system.

## Current state and invariants

- `crates/brigalow-store/src/signing.rs::prepare_sign` inserts a unique `(org_id, request_id)` before backend use. `finish_sign` updates only rows with `state='signing'` and appends audit in the transaction. `crates/brigalow-store/src/gates.rs::finish_gates` locks the tenant audit and request row, requires `Gating`, then may move to `Signing`.
- `crates/brigalow-store/src/approvals.rs::persist_request` is the established transactional record/audit pattern. Match tenant-scoped queries, RLS and lock order; never replace it with a privileged bypass without a security design.
- `crates/brigalow-server/src/bin/brigalow-admin.rs` is an offline owner-only command, deliberately separate from the HTTP runtime and HSM. Do not assume that owner access is the right authorisation model for reconciliation.
- `docs/operations.md:42–48` requires inspecting backend/audit evidence and explicitly says never automatically repeat a possibly completed signature. Release-window caps consumed by a signing intent cannot be silently refunded. No bulk approve, private-key export, automatic retry, HSM-to-software fallback or arbitrary signature import.

## Scope and commands

Read only the files above, `crates/brigalow-server/src/signing.rs`, `crates/brigalow-store/tests/`, and `docs/acceptance-tests.md`. Create only the outcome document. Out of scope: source, migrations, live services, real credentials, production data, git commits and pushes.

Verification commands for a later implementation: `cargo fmt --all -- --check`; `cargo clippy --workspace --all-targets --all-features -- -D warnings`; `cargo test --workspace`; `python3 scripts/e2e.py --context <explicit-local-context>`. All must exit 0; the Compose suite uses generated credentials and OpenSSL. Tests requiring infrastructure must not silently skip. After any Cargo build/test/check, run `cargo clean` in each built workspace when finished.

## Steps

1. Trace both interleavings: an active `finish_gates`/`finish_sign` races a proposed operator action, and a crashed process has no remaining worker. Document exact transaction/row/advisory lock order, state predicates, remaining authority, response visibility, and whether the HSM may have performed work. **Verify:** `rg -n 'lock_audit|FOR UPDATE|finish_sign|finish_gates|request_ids' crates/brigalow-store/src/{signing,gates,approvals}.rs` exits 0; list each relevant location in the outcome.
2. Specify least-privilege actor and a single-request, tenant-scoped inspect and audited terminal resolution. Require a reason and evidence reference without secrets; use compare-and-set and atomic audit. Specify what happens if the old worker is still alive: do not assert an HSM call can be cancelled, and do not permit a subsequent new signing attempt until operator-controlled quiescence is established. Choose and justify read-only or terminal-failure semantics; no "completed" state without verifiable evidence. **Verify:** outcome has `## State and concurrency contract`, `## Authority and audit`, `## No-repeat guarantee`.
3. Define acceptance tests for races against gate completion and signing completion, two operators, wrong tenant/role, invalid/non-interrupted states, rollback on audit failure, consumed caps, original request-ID replay, process restart and no second HSM invocation. Include mock/counting backend and independent OpenSSL verification only when an actual signature exists. Specify expected HTTP/CLI behaviour and AT ID proposal. **Verify:** outcome has `## Acceptance tests` and `## Implementation boundaries`.
4. State residual uncertainty, operator steps and later implementation file list; propose threat-model update for any changed trust boundary. **Verify:** `test -s plans/001-recovery-outcome.md && rg -n '^## (State and concurrency contract|Authority and audit|No-repeat guarantee|Acceptance tests|Implementation boundaries|Residual risks)' plans/001-recovery-outcome.md` finds all six headings.

## Done and STOP conditions

Done: outcome contains all six sections, explicit state transitions and race expectations, no private data, and no changes outside `plans/`. Stop if safe resolution requires assuming a possibly active HSM call is cancellable, releasing a consumed request ID/cap, or modifying an already-issued signature. Report the missing synchronisation decision instead. Reviewers must compare any later implementation against this plan and AT-APR/REL/SIGN/TEN regression gates.
