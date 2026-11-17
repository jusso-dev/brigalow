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
Median successful CI feedback is 791 s; median sum of its job runtimes is
987 s. Median dependency-audit feedback is 165 s and job runtime is 163 s.
Different commits and machines mean these medians are context, not attribution.

At the exact starting head, [CI run 43373798057](https://github.com/jusso-dev/brigalow/actions/runs/43373798057)
and [audit run 43373797931](https://github.com/jusso-dev/brigalow/actions/runs/43373797931)
both passed:

| Job / step | Seconds |
| --- | ---: |
| CI feedback, creation to final job completion | 748 |
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
   or wrong-version cache does not authorise skipping the tool. Cache misses
   fall back to installation; unusable tools fail the job. Always run both audits;
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

## Implemented safeguards

The cache action is pinned to `Swatinem/rust-cache` v2.9.3 commit
`d1527c8f67ef9af357290475d4af4b0fab8f12e0`, resolved through its annotated tag.
Its pinned `config.ts`, `workspace.ts`, `save.ts`, `cleanup.ts` and `action.yml`
were inspected: keys include installed compiler versions (including nightly),
host architecture, relevant compiler environment, manifests and lockfiles.
Job-specific keys separate the workspace, fuzz and audit caches; tool versions
also enter their keys. Workspace products are pruned by default; dependencies
are reusable. The fuzz cache points to `fuzz/target`, not the root target.
Audit caching excludes target directories. No database, HSM token, generated
certificate directory, test result or advisory database is cached.

PRs only restore. Successful main pushes populate Rust/fuzz caches; successful
main push, schedule or manual audit runs populate the audit cache. Main runs
use unique concurrency groups, so new pushes cannot displace queued main
validation. Only revisions of the same PR and same workflow share a group.
No cache hit controls whether a test executes. A compiler upgrade deliberately
misses the old cache. GitHub's cache service remains required to verify actual
restore/save performance; local archive timing does not emulate that service.

Fuzz verification exposed a stale lockfile: the `brigalow-crypto` dependency
list omitted `url`, although that version was already locked transitively.
`cargo-fuzz` 0.13.2 silently repairs it and has no `--locked` option. Record the
missing edge without changing package versions, then run locked Cargo metadata
after cache restore and before fuzzing. Replaying the original lockfile makes
the new guard fail; the repaired lockfile passes. All three parser targets keep
their 15-second budgets and existing sanitizer settings.

The cheap wrapper, production-input and package guards precede Clippy. Azure's
Bicep checks remain after Clippy: their observed 24-second hosted step is not
cheap enough to put ahead of every lint failure. A packaging failure at the
baseline would be found roughly 36 seconds earlier by this ordering, excluding
cache and runner variance; a Clippy failure waits about 12 seconds longer for
the three guards. Successful runs do the same work.

## Local setup experiment

On macOS arm64 with Rust 1.100.0, install each exact tool into an empty temporary
`--root`, archive `bin`, `.crates.toml` and `.crates2.json`, extract into a second
empty root, then repeat the same pinned install command. An isolated
`CARGO_TARGET_DIR` holds tool builds. Registry downloads may already be cached;
other local acceptance work ran concurrently. These are single observations,
not controlled hosted speedups.

| Tool | Fresh installation | Restored installation | Archive size | Local archive round trip |
| --- | ---: | ---: | ---: | ---: |
| cargo-audit 0.22.2 | 58.646 s | 0.299 s | 7,769,118 bytes | 1.324 s |
| cargo-fuzz 0.13.2 | 10.218 s | 0.340 s | 861,894 bytes | 0.161 s |

Both restored installs succeeded and the restored executables ran their actual
checks. Executables were byte-identical after restoration. Removing only the
restored fuzz binary while retaining its Cargo metadata triggered a successful
reinstall (3.339 s), confirming the partial-cache recovery case. Combined
install time falls from 68.864 to 0.639 seconds; with local
compression/extraction included, the measured setup saving is 66.740 seconds.
Network transfer and the action's registry cache are not included. At the
hosted baseline, those two install steps total 200 seconds (17.6% of combined
job runtime); that is an upper bound before cache costs, not verified savings.
They are off the successful-run critical path. Rust dependency reuse may
improve that path, but no hosted improvement is claimed yet.

Fresh `cargo audit --deny warnings` rejects the unchanged application lockfile:
`chrono 0.4.45`, through `oauth2 5.0.0`, now reports
[RUSTSEC-2026-0543](https://rustsec.org/advisories/RUSTSEC-2026-0543) as
unmaintained. The historical successful audits do not supersede this result.
No warning exemption or authentication dependency change is bundled into CI
optimisation. The repaired fuzz lockfile passes the same advisory database
(1,527 advisories). That initial warning prevented claiming an entirely green gate; the follow-up
remediation below removes it without exemptions.

## Final local validation

[Machine-readable results](local-2026-11-17.json) retain command timings and
outcomes. Rust 1.100.0 was selected explicitly without changing the machine's
default; fuzz instrumentation used installed nightly 1.102.0 (2026-11-10).

| Check | Outcome / elapsed |
| --- | --- |
| Format | pass, 0.989 s |
| Full-workspace, all-target, all-feature Clippy | pass, 22.452 s with empty root target |
| Default-feature workspace tests | 51 passed, 0 failed/ignored; 52.222 s |
| Full Compose acceptance, `--context orbstack` | pass, 581.669 s; 82 Rust test executions plus Python/OpenSSL assertions |
| Warm Clippy / default-feature tests | pass, 1.155 / 20.292 s; same 51 tests |
| Python OIDC / production / release / Azure tests | 2 / 1 / 33 / 13 passed; local Bicep checks enabled |
| Helm lint/render/refusal checks | pass |
| Gitleaks full-history redacted scan | pass, 161 commits at scan time |
| Three fuzz targets, 15-second budget each | pass, 1,116,135 executions; 123.263 s including compilation |
| Fuzz lockfile audit | pass |
| Application lockfile audit, initial CI-only change | **failed** on Chrono; fixed in the follow-up below |
| actionlint and `git diff --check` | pass |
| Original workflow command/trigger/check-name comparison | all preserved; only new executable gate is locked fuzz metadata |

The warm workspace timings retain local workspace products as well as
dependencies; the hosted action prunes workspace products. They demonstrate
that repeated compilation matters, but overstate what dependency-only caching
can promise. The Compose run exercised all default harness stages, including
restricted DB roles, native tools, production-mode image qualification and
scratch backup/restore. Its count includes repeated store/default tests and
must not be presented as 82 distinct acceptance contracts.

At the end of the initial CI-only implementation, no published run existed.
The first hosted run is cold unless a compatible trusted main cache exists;
PRs cannot warm main's cache. After integration, compare subsequent runs with the same-source
cold/warm protocol above. The remaining Docker-build work is the priority for
critical-path improvement. Application dependency remediation was subsequently
authorised and is recorded below; no audit warning was waived to obtain timing
results.

Cleanup completed: `cargo clean` in the root workspace, fuzz workspace and
isolated tool-build target removed 5.6 GiB, 607.5 MiB and 701.0 MiB respectively.
The acceptance harness removed its containers, networks and tagged images;
newly generated fuzz corpus/artifact files were removed without touching older
files. Shared Docker build caches and unrelated resources were not pruned.

## Audit remediation follow-up (2026-11-17)

Justin authorised fixing the warning and pushing the complete change to main.
The released OAuth2 5.0.0 and inspected upstream development code still depend
on Chrono. Remove the unused OAuth2 dependency rather than pinning another
affected Chrono version or adding an advisory exception. The application now
uses its existing OS-random secret helper, RustCrypto SHA-256, base64url and URL
encoding for the same narrow authorization-code request. No new dependency or
cryptographic primitive is introduced. See [ADR 0003](../decisions/0003-dependency-audit.md).

The lockfile removes 13 packages and adds or upgrades none. Both application
(319 crates) and fuzz (220 crates) audits pass with all warnings denied against
the refreshed 1,527-advisory database. The RFC 7636 S256 vector and parameter
encoding regression passes; replacing the challenge with the plain verifier
makes that regression fail. The mutation was restored before the full gates.

The follow-up full-history secret scan also identified the literal public
cache name `fuzz-v1-cargo-fuzz-0.13.2` as a generic API key in the earlier CI
commit. `.gitleaks.toml` permits only that exact matched assignment, not a file,
path or class of keys. Full-history scanning passes; synthetic unrelated
credentials in the same file and on the same line still fail scanning.

[Follow-up results](audit-fix-2026-11-17.json) record the full rerun:
52 default-feature workspace tests and 83 Compose Rust test executions passed,
with no failures or ignored tests. Compose took 531.403 seconds and also passed
the Python/OpenSSL checks, native signing tools, production image qualification
and scratch backup/restore. Format, all-target/all-feature Clippy, all 49 Python
guards, Helm and actionlint passed. All three fuzz targets retained their
15-second budgets and completed 1,232,623 executions without a failure.

These local measurements validate correctness, not a hosted performance gain.
The follow-up changes application source, and local build caches differ from
the original run. Both lockfiles pass the same strict audit gate. The independent
RFC vector detects a plain-verifier mutation, which was reverted before the
full suite. Cleanup again ran `cargo clean` for root, fuzz and isolated tool
targets; the acceptance project's containers, networks and tagged images are
gone, and only newly generated fuzz inputs were removed.
