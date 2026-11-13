# Operations and hardening

Brigalow is self-hosted. These are operator procedures and a tested single-instance deployment reference, not a production deployment or a security/compliance certification. Run the complete acceptance suite and commission an independent review of your exact configuration/revision before production use.

## Request budgets and ingress

The server accepts at most 64 KiB request bodies. Configure a trusted TLS reverse proxy with connection/header/time limits and network controls; unauthenticated login/token verification and health traffic need ingress limits independently of authenticated budgets.

Operator TOML may include:

```toml
[rate_limit]
requests = 600
period_seconds = 60
```

Both values must be positive; maxima are 100,000 requests and 3,600 seconds. A fixed window starts at the credential's first use and resets on the database clock. API credentials and browser sessions have individual budgets. Workload tokens share a budget for their verified actor and authorised scope, so refreshing a JWT cannot reset it. Cross-tenant calls do not share another tenant's budget. Every authenticated API/UI request consumes a slot, including subsequently denied policy actions. Exhausted budgets return 429 and audit once per window; subsequent rejects do not flood the audit chain. Database errors fail closed. Old counters are removed in bounded batches after an hour beyond reset. Keep configuration consistent through controlled restarts.

Postgres serialises budget decisions with the existing tenant audit lock; this prioritises deterministic security over peak throughput. Benchmark your expected tenant load and HSM latency. Database-shared budgets do not imply support for horizontal replicas. No caller-controlled forwarding/IP header grants a different authenticated identity.

## Signed audit checkpoints

The [Azure reference](../deploy/azure/README.md) has no signed audit checkpoints. It configures no PKCS#11 HSM, so there is no audit key, and `brig audit verify` on its exports checks chain integrity only.

Use a dedicated HSM audit key and operator configuration, separate from policy and CA issuer keys. The operator command uses the restricted normal application DB role and appends checkpoint records; it never updates/deletes audit entries. Do not register the audit key as a signing-policy key.

```sh
brigalow-audit init --output audit-key
brigalow-audit checkpoint --org <UUID> --key audit-key/audit-key.json --output checkpoint-001
brig audit verify checkpoint-001/audit.jsonl \
  --checkpoint checkpoint-001/checkpoint.json --public-key audit-key/audit-public.der
```

Init emits only a public key and public HSM reference. Checkpoint creation reads a DB-clock head, verifies and exports the complete prefix, signs a domain-separated canonical record, persists it, then publishes the public outputs. New events may arrive afterward; this checkpoint authenticates precisely its recorded prefix. Its payload binds version, organisation, sequence, entry hash, timestamp, key ID and algorithm. The offline verifier requires the exact prefix and independently supplied public key, rejecting suffix truncation, mixed tenants, wrong key and modified checkpoint. `brig audit verify` without checkpoint remains explicitly chain-integrity-only.

### Output bundle

Both `checkpoint` and `recover` stage output in a new private (0700) sibling directory on the same filesystem, create each file exclusively (0400, symlinks refused), fsync it, then write `COMPLETE.json` last. The marker binds format version, organisation, sequence, entry hash and the SHA-256 of `audit.jsonl`, `checkpoint.json`, `checkpoint.bytes` and `checkpoint.sig`. The whole directory is then published with a kernel no-replace rename (Linux `renameat2` `RENAME_NOREPLACE`, macOS `renameatx_np` `RENAME_EXCL`) and the parent is fsynced. An existing output path is never replaced. Other platforms fail before signing; there is no existence-check emulation. An interrupted run leaves no published directory, though a `.brigalow-stage-*` directory may remain after a crash. Treat that as incomplete and delete it. The marker proves completeness only, not who wrote the bundle or whether it is the latest head.

### Freshness

A valid signature does not show a checkpoint is current. Record each published head as `<org>:<seq>:<entry_hash>` (from `checkpoint.json`) in a store outside the Brigalow DB and signing host, then verify against it:

```sh
brig audit verify checkpoint-001/audit.jsonl --checkpoint checkpoint-001/checkpoint.json \
  --public-key /independent/audit-public.der --expected-head <org>:<seq>:<entry_hash>
```

Before replacing the recorded head with a newer one, run the command above against the new bundle with `--expected-head` set to the new head, then confirm the new `audit.jsonl` still contains the previously recorded entry: the line at the old sequence must carry the old `entry_hash`. Only then update the external record. If either check fails, keep the old head and treat the chain as tampered: a DB writer may have replaced history before the new checkpoint was signed.

The verifier rejects an older, newer or substituted checkpoint. Without `--expected-head` it reports "cryptographically valid prefix; freshness unknown". Do not treat that result as current or retained. If the external head is unavailable or was not advanced, do not declare off-host retention or a current audit state.

### Recovering an interrupted checkpoint

If `checkpoint` fails after reporting that persistence succeeded or is unconfirmed, do not re-run it for that head. Recover the persisted record instead:

```sh
brigalow-audit recover --org <UUID> --seq <SEQ> \
  --public-key /independent/audit-public.der --output checkpoint-001-recovered
```

1. Use the sequence from the failure message, or the head you expected. Pin the public key from your independent copy, never from a partial output directory.
2. `recover` is read-only. It loads no key backend (`backend = "disabled"` is fine, and no HSM module or PIN is needed), never signs and never inserts a record. It verifies the stored signature with the pinned key, rebuilds the exact audit prefix with bounded paged reads, and publishes an identical bundle.
3. Running it onto an existing complete directory checks it byte-for-byte; any difference fails and nothing is replaced.
4. A missing record, wrong organisation or key, changed prefix, or malformed or tampered record fails with a generic message. "No persisted checkpoint is visible" means nothing was retained for that sequence. It does not show that the HSM did not sign during the interrupted attempt. Investigate with HSM and audit evidence rather than assuming no signature exists.
5. If nothing was persisted, a later `checkpoint` run signs the then-current head as a new record. Re-signing an already persisted head is refused (the command reports it and directs you to `recover`).

### Scheduling and retention

Scheduling is operator-owned. A local scheduler may run `checkpoint` and the `recover`/`brig audit verify` check as separate jobs at explicit intervals, with monitoring on local exit status. Brigalow sends no email, contacts no network destination and does not retry failures silently. Copying bundles off the host, making storage immutable, and updating the expected-head record are operator procedures outside Brigalow. A bundle on the signing host is not independent retention.

Retain the latest checkpoint outside the database and pin the audit public key through an independent trusted channel. A public key delivered alongside an untrusted replacement export does not establish authenticity. Preserve keys/checkpoints through rotation and disaster recovery. Record key rotations with independently pinned old and new keys; a `key_id` alone is not a trust anchor. OpenSSL can verify `checkpoint.sig` over the SHA-256 digest of `checkpoint.bytes` using `pkeyutl -verify -pubin -keyform DER -pkeyopt digest:sha256` for the initial P-256 audit key.

## Backup and recovery

Back up Postgres with an operator-controlled, encrypted and access-restricted backup system. Include all schemas/migration history, organisations, policy/approval/window records, credential hashes, audit entries/checkpoints and optional CA issuance/revocation/CRL ledger. Back up non-secret configuration and public certificate/key-reference files separately. Protect DB passwords, HSM PINs, OIDC/session configuration and webhook secrets using your secret manager; never place them in repository fixtures or logs.

The HSM's keys remain in the HSM. Use only its supported operator backup/HA procedures; Brigalow provides no private-key export. Preserve stable token/backend IDs and key UUIDs. A DB-only backup cannot recover missing HSM keys. Lab software keys are intentionally ephemeral and are not a production recovery mechanism.

Recovery sequence:

1. Stop signing and CA issuance. Retain current externally stored audit checkpoints and CRLs. Restore into an isolated database using the owner role; restore restricted runtime roles/grants and verify TLS configuration.
2. Verify every audit chain and the latest independently retained signed checkpoint with `--expected-head` from the external record; a restored older snapshot fails that check. Compare snapshot age, CA revocations, CRL numbers and consumed release-window caps against external evidence. An older DB snapshot can lose revocations or consumed authority; reconcile before enabling service.
3. Confirm every required HSM key reference resolves to the expected public key and remains sensitive/non-exportable. Do not silently generate replacements or select software keys.
4. Confirm pending approvals remain pending. Investigate interrupted `gating`, `signing`, CA issuance and CRL intents using backend/audit evidence. Never automatically repeat a possibly completed signature. An org admin or auditor can read a stranded request with `GET /v1/orgs/{org}/requests/{id}/inspection`; it reports state, policy/key and audit events, always marks the outcome unknown and changes nothing. Before submitting any replacement request, stop submission and independently confirm with the HSM vendor's tooling that the old worker and its device operations have stopped. Brigalow cannot mark the request resolved and does not refund consumed window capacity.
5. Reconcile credentials, policies, windows and configuration, then re-enable only the intended services. Test operator-owned recovery procedures periodically.

`scripts/backup_restore.py` is a harness-only destructive drill. `scripts/e2e.sh --context <local-context>` invokes it against uniquely named disposable Compose resources. It dumps the generated test DB, restores a scratch copy, wipes only that scratch DB, restores again, verifies all audit chains/checkpoints and exact request states, and proves the restored HSM reference can sign a digest independently verified by OpenSSL. The source DB is never dropped. This does not test a vendor HSM backup or a production restore.

## Single-instance deployment and readiness

Use the [production reference](../deploy/production/README.md) for the container image, TLS Compose configuration, Helm chart, separate migration command and organisation bootstrap. Production startup requires PKCS#11, configured identity and the exact applied migration set/checksums. The runtime cannot apply migrations or rewrite their history. `brigalow-admin` is a separate owner-only process; its credentials must never reach the server.

Only one server replica is supported. Pending OIDC logins are now stored in Postgres (see below), so a restart within five minutes no longer invalidates unfinished logins. This does not enable HA: Helm still rejects additional replicas and uses Recreate updates. Multi-process signing, gate, cap and expiry races (AT-HA-02), HSM session concurrency and the recovery/fencing blockers are not implemented or qualified. A shared database does not qualify vendor HSM failover. There is no exactly-once hardware-signature guarantee across crashes.

## Login state key

Human OIDC login requires a dedicated 256-bit key protecting pending-login PKCE verifiers and nonces in Postgres ([ADR 0004](decisions/0004-shared-login-state.md)). The server refuses to start with a human authority and no key ring. Keep this key separate from HSM PINs, signing keys and DB credentials. Never put it in TOML, Helm values, logs or fixtures.

Provision it as a private file containing base64 of 32 random bytes, for example `(umask 077 && openssl rand -base64 32 > login_key)`, which creates the file as 0600 from the start, run inside your secret-management process. Reference it by path:

```toml
[login_keys]
active = { id = "2026-11", file = "/run/brigalow/login_key" }
previous = [{ id = "2026-08", file = "/run/brigalow/login_key_previous" }]
```

IDs are 1–32 characters of `[A-Za-z0-9_-]`, unique, with distinct key material and at most four previous entries. Files must be regular, non-symlink, mode 0600 and at most 4096 bytes. In Helm, add the file to the runtime Secret; the init container copies it to a private 0600 file.

Rotation: generate a new key with a new ID, make it `active` and move the old one to `previous`, then do a controlled restart. Keep the old entry for at least the five-minute pending lifetime plus restart margin, then remove it. Logins sealed with a removed or unknown key ID are rejected, and the user signs in again. After a suspected key compromise, remove the key immediately: pending logins sealed with it are invalidated, and existing sessions follow their normal expiry and revocation. Each key ID allows 2^31 committed logins; past that, logins fail closed until you rotate. Reusing an ID with new material is not a rotation, because the usage counter is per ID. Back up the key through your secret manager. A database backup alone cannot open pending rows, which expire within five minutes anyway.

`/livez` checks process liveness; `/healthz` also checks Postgres and the logged-in HSM session in production. An unavailable/busy HSM makes readiness fail without signing. Vendor transport timeouts remain operator-owned because native calls cannot be forcibly cancelled safely.

The chart requires a digest-pinned provider image, runtime-only Secret and explicit egress rules. It supplies a default-deny NetworkPolicy, private ClusterIP service and restricted container. Projected secrets are copied into memory-backed regular 0600 files; changes require rollout. A real cluster must enforce the policy through its CNI and supply trusted TLS ingress. Local rendering and disposable Compose tests do not establish cluster or vendor-device readiness. No production service has been deployed.

## Parser fuzzing

Application code builds on stable Rust. Fuzz instrumentation alone uses nightly and pinned `cargo-fuzz 0.13.2`. Run `python3 scripts/fuzz.py` after installing those tools. Targets cover request/policy JSON, X.509/CMS/CSR wrappers and audit/checkpoint parsing. Public certificate seeds are generated at run time; private generation material is temporary and discarded. Inputs are capped at 64 KiB with time/memory limits. CI gives each target 15 seconds; extend locally with `BRIGALOW_FUZZ_SECONDS` (maximum 300). Bounded fuzzing is regression evidence, not proof of parser safety. Reproduce/minimise crashes before committing a regression fixture, and ensure it contains no secrets.

## Lab-signed release artifacts

The manual `lab-signed release bundle` workflow builds Linux binaries/provider with stable Rust and locked dependencies, packages them with LICENSE, emits a CycloneDX 1.6 SBOM from Cargo metadata, and creates a SHA-256 manifest. The disposable Compose lab control plane signs that manifest through the normal digest API; OpenSSL verifies it and payload hashes before upload as a workflow artifact. It does not create a GitHub release, enrol with a CA, contact Sigstore or deploy anything. All Actions are pinned by full SHA and use GitHub-hosted runners.

The generated key is ephemeral and the manifest explicitly says `lab`. Its included public key enables integrity checks but does not independently authenticate the publisher; consumers must establish key/source trust themselves. This workflow makes no release-key custody, public-trust or certification claim. A production release process must use your reviewed HSM/policy/trust configuration under separate operational authorisation.

`python3 scripts/test_release.py` tests archive/SBOM packaging and payload tamper rejection with generated fixture binaries. The full Compose tool test separately verifies signing through the real local control plane and rejects a modified manifest. `scripts/verify_release.py <directory> --mode lab --public-key <independently-trusted-PEM>` verifies signature and all listed payload digests. The mode is required; a lab bundle never passes operator mode.

## Operator-signed release bundles

`scripts/operator_release.py` is a local operator command, separate from the lab workflow. It creates no GitHub release, publishes nothing to a network, contacts only the configured Brigalow server and never retries. This repository has not signed or published any operator release, and running the command does not qualify a production HSM.

Before use, the operator separately provisions:

- a P-256 ECDSA or RSA-3072 (exponent 65537) `release` key generated in their PKCS#11 device, with a certificate chain to a configured private or external-CA anchor and (for `offline` keys) a release window;
- a `release`-purpose policy with the approvals, gates and claims they require, and a workload OIDC token in `BRIGALOW_TOKEN` from a CI job matching that policy's workload rule. Release policies require verified repository, ref, environment and `ref_protected` claims, which API credentials do not carry;
- the release public key, exported from Brigalow and distributed to consumers through an independently trusted channel. Record its SPKI SHA-256 fingerprint for `--expected-key-sha256`. Publish the source commit of each release through the same channel, so consumers have an expected revision to compare.

```sh
python3 scripts/operator_release.py --binaries target/release --output dist/brigalow-<commit> \
  --public-key <pinned-release-public.pem> --expected-key-sha256 <reviewed-fingerprint> \
  --expected-revision <full-commit> --server https://<brigalow> --org <UUID> --project <UUID> \
  --policy <release-policy> --ca-file <server-ca.pem>
```

`--expected-revision` is required and has no opt-out: state the full commit you intend to release. The command requires a clean git checkout at exactly that commit. It packages the archive and SBOM into a private staging directory beside `--output` and writes a frozen version 2 manifest: `trust: "operator"`, `provenance: "self-hosted"`, the full source commit, `digest_algorithm: "sha256"` and exactly two artifacts (`brigalow-linux.tar.gz`, `sbom.cdx.json`) with SHA-256 hashes. The manifest is canonical JSON; those exact bytes are hashed locally by one `brig sign --format raw` call and the server receives only the digest. The command prints the request ID, waits for approvals, gates and windows as normal, verifies the signature and every payload against the pinned key, then publishes the complete directory with an atomic no-replace rename (`renameat2(RENAME_NOREPLACE)` on Linux, `renameatx_np(RENAME_EXCL)` on macOS). Other platforms fail closed.

The output parent is opened once with `O_DIRECTORY|O_NOFOLLOW`; a symlinked parent is refused before any request. Staging (`.brigalow-operator-<random>`) is created relative to that descriptor and checked to be a 0700 directory owned by the current user. Publication renames it relative to the same descriptor, after checking that the paths used by packaging, `brig` and the verifier still name the same directories. Files and directories are flushed with `fsync` on Linux and `fcntl(F_FULLFSYNC)` on macOS, which also flushes the drive cache; a filesystem that refuses either fails the run before publication. The published directory is 0755 and its files 0444, because they are public artefacts. There is no completion marker: `manifest.sig` and the verifier's exact file set are the completeness check.

Failure handling:

- Existing output is refused before any request is submitted and is never modified. A target created during signing makes publication fail and stays untouched.
- Denial, rejection, gate failure, expiry, a signing failure or `--timeout` exits non-zero, removes staging and prints the request ID. A timeout means the outcome is uncertain: query that request ID on the server. Do not rerun the command to "retry"; a new run creates a new request and may consume more release-window capacity.
- `--timeout` (default 360 s, at most 86400) is the only deadline that matters. The command passes `brig sign --wait` 60 s more than it, so `brig` never gives up first. If `brig` still stops polling (its own deadline or a lost status connection), the result is also reported as outcome uncertain, with the request ID.
- SIGINT, SIGTERM and SIGHUP terminate and reap `brig`, remove staging, print the request ID and report the outcome as uncertain: the request may still be approved and signed on the server.
- SIGKILL or power loss cannot be handled. Nothing appears at `--output` before the final rename, but a staging directory (possibly holding a signature) stays behind. Later runs warn about any `.brigalow-operator-*` directory beside `--output` and never delete it, since it may be evidence for an uncertain request. Check that run's request ID, then remove it yourself.
- Timestamp and attestation outputs are not yet part of the version 2 bundle. A policy that returns them makes the command fail rather than drop evidence silently. Use `timestamp = "disabled"` until a later manifest version binds timestamp tokens.
- If the final directory sync fails after the rename, the command exits non-zero and says the bundle needs verification before use. A power loss between the rename and that sync can lose a published directory after its signature was spent; query the request rather than rerunning.

Consumers verify with the separately pinned key, never a key shipped beside the bundle:

```sh
python3 scripts/verify_release.py <bundle> --mode operator --public-key <pinned.pem> \
  --expected-key-sha256 <fingerprint> --expected-revision <full-commit>
```

Operator mode requires `--expected-revision <full commit>`, taken from the same independent channel as the key (trusted release notes, or `git rev-parse <tag>^{commit}` in your own clone of a repository you trust). The verifier never resolves tags itself. `--revision-unchecked` knowingly waives the comparison: the verifier then warns that the commit was declared by the signer and not compared, so an older validly signed release (a rollback) would also pass. Without a compared revision a pass means only that the signature is valid for the pinned key, every payload matches and the bundle declares `operator` origin; it does not mean this is the release you wanted or the latest one.

Version 2 has a fixed signature profile, `ecdsa-p256-sha256` or `rsa3072-pkcs1v15-sha256`. Before OpenSSL runs, the pinned key's DER SPKI must be exactly the P-256 (named curve, uncompressed point) or RSA-3072 `rsaEncryption` (exponent 65537) encoding the PKCS#11 backend produces. Anything else fails with `unsupported key algorithm`, including RSA-2048 and RSA-4096, other exponents, P-384, RSA-PSS keys, Ed25519 and P-256 keys with explicit curve parameters. A new algorithm needs a new manifest version.

Operator mode also rejects keys inside the bundle, symlinked or non-regular entries, missing or extra files, duplicate JSON keys, non-canonical encoding, unknown fields, versions, trust labels, provenance or algorithms, non-basename names and manifests over 64 KiB. OpenSSL (`dgst -sha256 -verify`) checks the signature over the exact manifest bytes before the manifest is parsed. A pass reports cryptographic validity and the declared `operator` origin only. It is not a public-trust, CA or platform-trust decision, and it cannot show that a newer release was withheld. Key rotation, revocation and the trusted distribution channel for the pinned key remain operator responsibilities.

Rotating the release key is an operator procedure; Brigalow cannot push trust changes to consumers. Each verification pins exactly one key. Publish the new key's PEM and SPKI SHA-256 through the same independent channel at least one release before its first bundle, keep signing with the old key during that overlap, then disable and retire the old key in Brigalow at cutover. Older bundles stay verifiable with the old key, so consumers keep its record. If a key is compromised, disable it at once and tell consumers to stop accepting every bundle it signed, since it can sign a manifest naming any commit; rebuild the releases still needed under the new key.
