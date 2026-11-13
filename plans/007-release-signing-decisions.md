# Plan 007: Operator release signing, four open decisions

> **Recommendations for review, 13-11-2026.** Nothing here is accepted or implemented. Written against `fde7ebb` (main after PR #2). Only this file was added; no code, test, workflow or other doc changed.

Plan 005 built the version 2 `operator` manifest, the strict verifier and the single-attempt workflow (AT-REL-03). Its outcome note (`plans/005-release-signing-outcome.md:33`) left five items for review. The manifest version is already settled in code as version 2 (`scripts/verify_release.py:132–133`, `scripts/package_release.py:28–35`). The other four are below, each with today's behaviour, options, a recommendation, the changes it implies and its risks.

Binding constraints for every option: no private key export (`docs/product/scope.md:33`); no public-trust claim (`docs/product/scope.md:25`); no automatic retry of an uncertain signature; lab bundles never pass operator verification; the pinned key comes from a channel independent of the bundle. Operators pin keys themselves; Brigalow has no way to push trust changes to consumers.

| # | Decision | Recommendation (one line) |
| --- | --- | --- |
| 1 | Key rotation | One pinned key per verification. The operator announces a new fingerprint through the same independent channel before first use, retires the old key in Brigalow after the overlap, and old releases stay valid under the old key unless it is compromised. |
| 2 | Expected revision | Make `--expected-revision` mandatory in operator verify mode and in the workflow. Verification gets an explicit `--revision-unchecked` opt-out whose report says the commit was not compared. |
| 3 | Algorithm profile | Keep P-256 and RSA-3072 PKCS#1 v1.5 with SHA-256 for v2, and enforce the pinned key type in the verifier. Any new algorithm needs a new manifest version with a required `signature_algorithm` field that is checked but never used to select. |
| 4 | Atomic output | Keep the whole-directory staging plus no-replace rename, which already mirrors plan 002. Harden signal handling, macOS durability and fd-relative paths, add kill-point tests, and add no completion marker. |

## 1. Key-rotation policy

**Today.** The verifier takes exactly one `--public-key` and an optional `--expected-key-sha256` of its DER SPKI (`scripts/verify_release.py:174–175`, `:243–246`), and refuses a key inside the bundle (`:106–108`, `:192–194`). The v2 manifest has no key ID, fingerprint or certificate (`:25`), so nothing in a bundle selects a key. Brigalow has no rotate operation. A release key can be disabled, then retired (`crates/brigalow-server/src/keys.rs:269–282`), and a new key only activates for release with a `private` or `external-ca` tier (`crates/brigalow-core/src/keys.rs:48–59`). The workflow checks the signature against the pinned key only after signing (`scripts/operator_release.py:165`). So a stale pinned key spends a request and a window slot before it fails. The docs leave rotation to the operator (`docs/operations.md:159`, `docs/threat-model.md:169`). Audit-key guidance already says to record rotations with independently pinned old and new keys (`docs/operations.md:70`).

| Option | Assessment |
| --- | --- |
| A. One pinned key per verification. Rotation is announced out of band. | Simple and matches today's verifier. Consumers must keep old public keys to verify old releases. |
| B. Verifier accepts a set of pinned keys. | Any key in the set, including a retired one, verifies any new bundle. Making this safe needs per-key validity rules in the verifier. |
| C. Old key signs a statement endorsing the new key. | Adds a new signed format and trust transfer. It does not help after a compromise, which is the case that matters most. |
| D. Pin an operator CA and validate a chain. | Moves trust to chain and revocation checks, while plan 005 treats the chain as metadata only (`plans/005-release-signing-outcome.md:11`). This is a large change. |

**Recommendation: A, with a published key record.**

- For each release key, the operator publishes a record through the independent channel used for the first key. The record holds the PEM, the SPKI SHA-256, a status (`active`, `retired` or `compromised`), the activation and retirement dates (`DD-MM-YYYY`) and the last source commit signed with the key.
- **Planned rotation:**
  - Generate a new release key in the HSM, then certify and activate it.
  - Create a new release policy bound to it.
  - Publish its record at least one release cycle before the first bundle it signs. The operator chooses the overlap length.
  - During the overlap, new releases are signed by the old key only. There is no dual signing, because v2 has one `manifest.sig` and an exact file set (`scripts/verify_release.py:188–190`).
  - At cutover, disable then retire the old key in Brigalow so it can never sign again. Mark its record `retired`.
- **Old releases** stay valid under the retired key. Consumers verify them with that key's record. Nothing is re-signed.
- **Compromise:**
  - Disable the key at once and mark its record `compromised`.
  - Consumers stop accepting every bundle that key signed. An attacker can sign a manifest naming any old commit.
  - Copies a consumer verified and recorded by digest before the compromise date are only as trustworthy as that record.
  - Releases that are still needed are rebuilt from their recorded commit and released again under the new key, into a new output directory, through the normal policy and approvals.
- **Lost HSM key:** treat as a planned rotation without overlap. There is no export or restore path.

**Changes if accepted.** Add a "Rotating the release key" subsection to `docs/operations.md` after line 159, covering the record format, overlap, cutover, compromise and lost key. Add one line on retired versus compromised to the `docs/threat-model.md:164–169` boundaries. No verifier change. In `scripts/test_release.py`, add one case: an old-key bundle passes with the old key and fails with the new key, and the reverse. This extends `test_wrong_and_co_delivered_keys` at `:195`. Optional follow-up: a pre-submission check that the pinned SPKI equals the policy's bound key. That can only happen if the workload credential may read the key record through `GET /v1/orgs/{org}/keys/{id}` (`crates/brigalow-server/src/web.rs:66–71`), which has not been confirmed.

**Risks.** Consumers who never re-check the channel keep trusting a compromised key. No revocation reaches them through Brigalow. The channel is the real trust root. Operators must keep old public keys and records indefinitely. Overlap length is a judgement the operator owns.

## 2. Expected-revision source

**Today.** The workflow takes the commit from `HEAD` of a clean checkout (`scripts/package_release.py:43–51`) and rechecks it after packaging (`:75–76`). Its `--expected-revision` is optional (`scripts/operator_release.py:188`). When given, it is checked before submission (`:130–131`, `:145–146`). The verifier's `--expected-revision` is also optional (`scripts/verify_release.py:176–177`, `:200–201`), although its help text says "required" (`:245`). Without the flag the verifier exits 0 and prints the declared commit (`:205–209`). It gives no sign that the commit was not compared. The CI token carries a verified `sha` claim (`crates/brigalow-crypto/src/attestation.rs:18`). But `brig` sends only a digest, and policy claims are static exact matches (`crates/brigalow-core/src/policy.rs:121–125`). So the server cannot tie that claim to `source_commit`.

| Option | Assessment |
| --- | --- |
| A. Keep the flag optional (status quo). | Any older, validly signed bundle passes silently. This is a downgrade path. |
| B. Require the flag in operator mode, with an explicit opt-out. | Small change. Consumers must supply a value or knowingly waive the check. |
| C. Verifier resolves a tag or branch. | Needs git access and a trusted repository. Tags are mutable, and signed tags add a second trust root. |
| D. Version or tag field in the manifest. | Needs v3. The value is still declared by the signer, and consumers still need an expected value from somewhere. |
| E. Server compares the CI `sha` claim with the manifest. | The server would have to parse the manifest. That breaks the digest-only model. |

**Recommendation: B.** Operator verify mode requires `--expected-revision <full commit>` or `--revision-unchecked`. With the opt-out, the report says the source commit is declared by the signer, was not compared with an expected value, and that an older validly signed release would also pass. The workflow requires `--expected-revision` with no opt-out: the operator states the commit they intend to release. Consumers take the expected commit from the same independent channel as the key record. That can be trusted release notes, or `git rev-parse <tag>^{commit}` in their own clone of a repository they trust. That lookup is the consumer's step, not the verifier's. Without an expected revision, a pass means only this: the signature is valid for the pinned key, every payload matches, and the bundle declares `operator` origin. It does not mean this is the release the consumer wanted, the latest one, or not a rollback (`docs/operations.md:159`).

**Changes if accepted.**
- `scripts/verify_release.py`: argument checks in `main` (`:238–249`), report wording (`:205–209`) and the help text at `:245`.
- `scripts/operator_release.py:188`: make the flag required.
- `scripts/test_release.py`, three new cases:
  - verification without the flag is rejected;
  - the opt-out passes and prints the warning;
  - a workflow run without the flag fails with zero `brig` calls.
- `crates/brigalow-server/tests/support/operator_release.rs:356` already passes the flag.
- `docs/operations.md:137–141`, `:152–156`: describe the opt-out.
- AT-REL-03 (`docs/acceptance-tests.md:60`): add "a missing expected revision is refused unless explicitly waived".

**Risks.** Consumer scripts that omit the flag break, but no operator release has been published yet (`docs/operations.md:128`). The opt-out may become a habit. The commit is a signer claim: without reproducible builds it does not prove the archive was built from that commit.

## 3. Algorithm profile

**Today.**
- **Manifest.** `digest_algorithm` must be `sha256` (`scripts/verify_release.py:138–139`). There is no signature-algorithm field.
- **Verifier.** It runs `openssl dgst -sha256 -verify` with the pinned key (`:115–126`) and never checks the key type. A spot check on OpenSSL 4.1.0 with generated keys showed that RSA-2048, P-384 and RSA-PSS keys all verify through that command. So "P-256 and RSA-3072 only" holds on the server side, not in the verifier.
- **Server.** PKCS#11 generates RSA-3072 (exponent 65537) and P-256 keys (`crates/brigalow-crypto/src/pkcs11.rs:109–121`). It signs RSA as PKCS#1 v1.5 over DigestInfo and P-256 as DER ECDSA (`:219–231`). Ed25519 is refused (`:122`, `:232`). The software backend is lab-only and refuses release (`docs/threat-model.md:77`). The Azure rotating backend is RSA-3072 but has no pinnable key (`docs/threat-model.md:173`), so it cannot serve this bundle.
- **Tests.** Both test suites use P-256 only (`scripts/test_release.py:71`, `crates/brigalow-server/tests/support/operator_release.rs:154`, `:230`). The RSA-3072 operator path is untested.

| Option | Assessment |
| --- | --- |
| A. Implicit v2 profile from the pinned key type, enforced in the verifier. | No schema change. Closes the gap. The consumer's key decides the algorithm. |
| B. Add `signature_algorithm` to v2 now. | Possible because nothing is published, but A is enough for v2 and the field adds nothing it does not already enforce. |
| C. Accept anything OpenSSL verifies (status quo). | Contradicts the documented profile (`docs/operations.md:132`). Weak keys pass. |
| D. Add P-384, Ed25519 or ML-DSA now. | Each needs HSM mechanisms, policy support and a different OpenSSL command. Brigalow's raw Ed25519 signs the digest bytes (`docs/threat-model.md:77`), so `dgst -sha256` is the wrong check for it. |

**Recommendation: A for v2. New algorithms only through a new manifest version.**

- **Fixed v2 profile.** Version 2 means `ecdsa-p256-sha256` or `rsa3072-pkcs1v15-sha256`, and nothing else.
- **Key check before verifying.** Before OpenSSL runs, the verifier checks that the pinned DER SPKI is exactly one of the two encodings the PKCS#11 backend produces. P-256 is 91 bytes with a fixed 27-byte prefix ending in `0004`. RSA-3072 with exponent 65537 is 422 bytes with a fixed 32-byte prefix and a `0203010001` suffix. Anything else is rejected, including RSA-PSS keys, other sizes and curves, and Ed25519. This is a byte comparison, not new cryptography. Reading the key type from OpenSSL output is the fallback if reviewers prefer it.
- **Future algorithms.** A future algorithm gets version 3 with a required `signature_algorithm` from a closed list. The verifier selects the algorithm from the consumer's pinned key, never from the manifest. After the signature verifies, it requires the field to match. Unknown versions already fail closed (`scripts/verify_release.py:132–133`); unknown algorithm names will too. Version 2 never gains an algorithm.
- **Work an addition needs.** Each new algorithm also needs the HSM mechanism in `pkcs11.rs`, a policy `algorithms` value, an independent OpenSSL command and generated-key tests.

**Changes if accepted.**
- `scripts/verify_release.py`: add the key-type check after `pinned_key` (`:98–112`), plus an `unsupported key algorithm` rejection.
- `scripts/test_release.py`, using generated keys:
  - an RSA-3072 success path;
  - rejection of RSA-2048, RSA-4096, P-384, RSA-PSS and Ed25519 pinned keys.
- Optional: an RSA-3072 run in the Compose test, at some runtime cost.
- `docs/operations.md:132`, `:159`: state the profile.
- AT-REL-03: the "unsupported algorithm" case now covers the key type as well as `digest_algorithm`.

**Risks.** Adding an algorithm needs a code change and a release, which is intended. PKCS#1 v1.5 is older than PSS, but it is deterministic, widely supported and acceptable for signatures. There is no post-quantum option until a version 3 is defined. If an HSM emits a valid but differently encoded SPKI (for example a P-256 key with explicit curve parameters), the exact-encoding check rejects it. That fails closed and is visible.

## 4. Safe atomic output

**Today.**
- **Staging.** `scripts/operator_release.py` stages in a 0700 `mkdtemp` beside the output (`:136`). It proves no-replace rename works there before signing (`:138–141`).
- **Writing.** The archive, SBOM and manifest are written with exclusive create (`scripts/package_release.py:38–40`, `:70`), then set to 0444 (`scripts/operator_release.py:147–148`). `brig` writes the signature create-new, 0600, with fsync, into a private `signing/` directory (`crates/brig/src/sign.rs:26–42`). The workflow then moves it into the bundle (`scripts/operator_release.py:162`) and verifies it (`:165`).
- **Publication.** In `scripts/operator_release.py`, each file and the directory are fsynced (`:168–171`). The directory is renamed with `renameat2(RENAME_NOREPLACE)` or `renamex_np(RENAME_EXCL)` (`:38–54`, `:172`) and the parent is fsynced (`:174`).
- **Failure handling.** Staging is removed in `finally` (`:175–176`). A failure after the rename is reported as "durability uncertain" (`:206–207`).

Plan 002's `crates/brigalow-server/src/publish.rs` uses the same structure: a private stage with an owner and mode check (`:135–175`), whole-directory no-replace rename, parent fsync and no cleanup after rename (`:238–244`), and fail closed on unsupported platforms (`:117–130`). The two differ as follows:

| Aspect | `publish.rs` (plan 002) | `operator_release.py` |
| --- | --- | --- |
| Paths | Relative to a parent dir fd, `O_NOFOLLOW` (`:186–203`) | Absolute paths through `AT_FDCWD` (`:43–47`) |
| File sync on macOS | `File::sync_all` (Rust std uses `F_FULLFSYNC` on Apple) | `os.fsync`, which does not flush the drive cache |
| Completion marker | `COMPLETE.json` with digests, written last (`:225–237`, `audit_checkpoint.rs:17`, `:96–106`) | None. `manifest.sig` plus the verifier's exact file set |
| Existing target | `Refuse` or `RequireIdentical` (`:245–251`) | Refuse only |
| Modes | 0700 directory, 0400 files | Published 0755 directory, 0444 files (`:148`, `:170`) |
| Interruption | `Drop` removes the stage | `finally` only. SIGTERM or SIGKILL leaves staging, and a `brig` child keeps polling after SIGTERM to the parent alone |

Before the rename, nothing exists at `--output`. Between `:162` and `:172`, the hidden staging directory holds a signed bundle. That bundle is authentic or fails verification, but it is not published output.

**Options.** (A) Keep the Python primitive and harden it. (B) Expose `publish.rs` through a small Rust binary. This gives one implementation, but adds a CLI surface for one script. (C) Plain `os.rename`. Rejected: it silently replaces an empty directory, as `scripts/test_release.py:420` shows.

**Recommendation: A, matching plan 002's semantics where they apply.**

1. Handle SIGINT, SIGTERM and SIGHUP the same way: terminate and reap `brig`, remove staging, print the request ID and "outcome uncertain". Today SIGINT runs `finally` but bypasses the failure report (`:204` catches `Exception` only), and SIGTERM skips both.
2. On macOS, use `fcntl(F_FULLFSYNC)` for files and directories. Linux is unchanged.
3. Open the parent once with `O_DIRECTORY|O_NOFOLLOW`. Do staging and the rename relative to that fd. Check the staging owner and 0700 mode, as `publish.rs:151–157` does.
4. Add no completion marker. The signature is the authenticity proof, and the v2 verifier already requires the exact file set (`scripts/verify_release.py:188–190`). A marker would be unauthenticated and would change the v2 layout.
5. Keep refuse-only. `RequireIdentical` makes no sense for a fresh ECDSA signature and would invite reruns.
6. Keep the published 0755/0444 modes for public artefacts, and document them.
7. At start, warn about leftover `.brigalow-operator-*` siblings. Do not delete them, because they may be evidence for an uncertain request. Do not count them as output.

**Changes if accepted.**
- `scripts/operator_release.py`: `publish_no_replace`, `fsync_path` and `run`, plus a signal handler.
- `scripts/test_release.py`, kill-point tests:
  - SIGKILL after the signature lands leaves `--output` absent;
  - SIGTERM reaps the fake `brig`, removes staging and prints the request ID;
  - a symlinked parent is refused;
  - leftover staging produces a warning.
- `docs/operations.md:143–150` and `docs/threat-model.md:169`: describe the interruption and durability behaviour.

**Risks.** Power loss between the rename and the parent fsync can lose a published directory after a signature was spent. The no-retry rule accepts that: the operator queries the request rather than rerunning. SIGKILL still leaves staging behind. Network filesystems may reject the no-replace rename. That fails closed, but may block some operators.

## Code that differs from plan 005's outcome note

- **Algorithm.** The note promises P-256 and RSA-3072 only, with unsupported algorithms failing closed. The verifier checks only the `digest_algorithm` string and accepts any key OpenSSL verifies. RSA-3072 is untested (decision 3).
- **Expected revision.** The note says verification checks the expected revision. It is optional in both scripts, and the verifier help text calls it "required" (`scripts/verify_release.py:245`) (decision 2).
- **Timestamps.** The note describes optional timestamps authenticated against pinned TSA trust. The workflow refuses any timestamp or attestation output (`scripts/operator_release.py:157–159`, `docs/operations.md:149`).
- **Crash tests.** The note asks for crash-recovery tests. Only the collision race (`scripts/test_release.py:354`) and the primitive test (`:420`) exist.
- **Timeout reporting.** `brig` stops polling after a fixed 300 s (`crates/brig/src/sign.rs:192`, `:198`). So `--timeout` (default 360 s, `scripts/operator_release.py:196`) never fires on a long approval. That case is then reported as "brig signing failed (denied, …)" (`:104–105`), not "outcome uncertain", although the request may still be approved later. The request ID and the no-resubmit instruction are still printed.

## For reviewers

Accept, amend or reject each recommendation. Implementing any of them needs the plan 005 gates (`scripts/test_release.py`, `cargo fmt`, `clippy`, `cargo test --workspace`, the full Compose `scripts/e2e.py`), generated keys only, and AT-REL-03 text updated in the same change.
