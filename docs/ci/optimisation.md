# CI baseline and optimisation

Measured 2026-11-17, starting at `cd03607c4a3d44df03426d8a3a44f7fa0cb8d625`.

## Sources and scope

[Vincent Koc's article](https://vincent.build/openclaw-ci-cost-reduction/)
and its [pinned OpenClaw workflow](https://github.com/openclaw/openclaw/blob/a7d05c7af04aa17ac57c994da238d0c60f058ca6/.github/workflows/ci.yml)
informed this audit. Relevant implementation: PR-only cancellation (lines
100–107), explicit diff inputs and planning, and main-writer/PR-reader cache
trust (lines 1445–1499). Reuse setup before introducing a selector. OpenClaw's
TypeScript ownership graph, runner fleet and reported savings do not establish
Rust dependency coverage or a Brigalow speedup.

Brigalow has seven Cargo workspace members, a separate fuzz workspace, Python
guards, native signing tools, generated certificates and a disposable Postgres /
SoftHSM acceptance stack. Source imports alone do not describe dependencies on
migrations, templates, subprocesses, fixtures and Docker images. All existing
tests run on every PR and main push. Unknown impact therefore always receives
the full suite; no affected-test selector or path filter is introduced.

GitHub reports no main branch protection and no rulesets. Nevertheless, retain
the exact checks `rust`, `secrets`, `fuzz`, `chart`, and `dependencies`, their
triggers and all existing commands. Keep daily advisory refresh and manual lab
release validation. No cloud deployment or signing service is involved.

## Hosted baseline

The [retained JSONL](baseline-2026-11-17.jsonl) contains the latest 30 runs at
capture, including failures, and their job/step timestamps. Fetch method:

```sh
gh api 'repos/jusso-dev/brigalow/actions/runs?per_page=30'
# For each workflow_runs[].id:
gh api 'repos/jusso-dev/brigalow/actions/runs/<id>/jobs?per_page=100'
```

Each response had fewer than 100 jobs. This is a recent convenience sample,
not a matched before/after experiment. There are 13 CI runs (10 successful,
3 failed) and 17 successful dependency audits; no cancelled runs in this window.
Median successful CI feedback is 791.5 s; median sum of its job runtimes is
987 s. Median dependency-audit feedback is 165 s and job runtime is 163 s.
Different commits and machines mean these medians are context, not attribution.

At the exact starting head, [CI run 43373798057](https://github.com/jusso-dev/brigalow/actions/runs/43373798057)
and [audit run 43373797931](https://github.com/jusso-dev/brigalow/actions/runs/43373797931)
both passed:

| Job / step | Seconds |
| --- | ---: |
| CI feedback, creation to final job completion | 749 |
| rust job | 746 |
| Clippy | 36 |
| Default-feature workspace tests | 61 |
| Compose acceptance | 601 |
| fuzz job | 194 |
| Install cargo-fuzz | 34 |
| Fuzz build and three bounded targets | 147 |
| dependencies job | 184 |
| Install cargo-audit | 166 |
| Audit both lockfiles | 4 |
| secrets job | 5 |
| chart job | 5 |
| All five jobs combined | 1134 (18.9 runner-minutes) |

Runtime is completion minus start, summed across jobs; feedback includes queue
time and ends at the last job completion. Step intervals exclude job overhead.
Do not add parallel job durations to claim elapsed feedback. Whole-minute
rounding per job would be 25 minutes for this pair, not 18.9 billed minutes.

This is a public repository using standard `ubuntu-latest` GitHub-hosted
runners. [Standard public-repository compute is free](https://docs.github.com/en/actions/concepts/billing-and-usage).
The compute charge is therefore $0, not an inferred Blacksmith invoice. Cache
storage/transfer and local machine energy are separate, unmeasured quantities.
Keep cache use within the repository's included storage; no paid limit changes.

## Ranked changes

1. Cache pinned audit/fuzz installation and Cargo dependencies. Audit compilation
   alone is 90% of its exact-head job, repeated even for daily advisory checks.
   Always execute `cargo install --locked --version ...` so a missing, partial
   or wrong-version cache falls back to installation. Always run both audits;
   never cache advisory results or the advisory database.
2. Cancel superseded revisions of the same PR, separately per workflow. Keep
   main, scheduled and manual runs independent, including queued runs. The
   historical sample has no cancellations; savings here are prospective.
3. Run quick Python input/wrapper/package guards before Clippy. Same checks and
   job name; earlier failure without another runner or duplicate checkout.
4. Investigate Docker build reuse next. Compose dominates the critical path;
   multiple images separately build Rust and the native tool image builds
   cosign. Exporting all build layers needs size, invalidation and trust checks
   first. Do not cache generated credentials, tokens, databases or HSM state.

Do not remove default-feature tests just because integration tests run later:
feature combinations protect distinct behaviour. Do not lower fuzz budgets,
drop native-tool tests, shrink full-history secret scanning, split tiny chart
and secret jobs further, or replace runners without a measured tradeoff.

## Verification and rollout

Implementation and local results are recorded below as they are verified.
Local macOS timings are not hosted Linux timings. Hosted cache restore/save
overhead and a cold/warm run pair must be measured after publication before
claiming an end-to-end speedup. A green local run cannot establish hosted cache
hit rates or cancellation behaviour.

For a hosted comparison, retain the same run/job/step records as the baseline.
Compare identical source, toolchain, runner image and test inventory; separate
cold, exact-hit and partial-hit cases. Include cache post-step upload duration,
cache bytes, failures and cancellations. Report feedback and summed job seconds
separately. Revert a cache if transfer exceeds compilation saved. Main writes
only on success; PRs restore only. Rollback is removal of cache steps and the
concurrency block; all test commands remain intact.
