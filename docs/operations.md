# Operations and hardening

Brigalow is self-hosted. These are operator procedures and a draft deployment design, not a production deployment or a security/compliance certification. Run the complete acceptance suite and commission an independent review of your exact configuration/revision before production use.

## Request budgets and ingress

The server accepts at most 64 KiB request bodies. Configure a trusted TLS reverse proxy with connection/header/time limits and network controls; unauthenticated login/token verification and health traffic need ingress limits independently of authenticated budgets.

Operator TOML may include:

```toml
[rate_limit]
requests = 600
period_seconds = 60
```

Both values must be positive; maxima are 100,000 requests and 3,600 seconds. A fixed window starts at the credential's first use and resets on the database clock. API credentials and browser sessions have individual budgets. Workload tokens share a budget for their verified actor and authorised scope, so refreshing a JWT cannot reset it. Cross-tenant calls do not share another tenant's budget. Every authenticated API/UI request consumes a slot, including subsequently denied policy actions. Exhausted budgets return 429 and audit once per window; subsequent rejects do not flood the audit chain. Database errors fail closed. Old counters are removed in bounded batches after an hour beyond reset. Coordinate configuration across replicas.

Postgres serialises budget decisions with the existing tenant audit lock; this prioritises deterministic security over peak throughput. Benchmark your expected tenant load and HSM latency. Horizontal replicas do not multiply a credential's allowance. No caller-controlled forwarding/IP header grants a different authenticated identity.

## Signed audit checkpoints

Use a dedicated HSM audit key and operator configuration, separate from policy and CA issuer keys. The operator command uses the restricted normal application DB role and appends checkpoint records; it never updates/deletes audit entries. Do not register the audit key as a signing-policy key.

```sh
brigalow-audit init --output audit-key
brigalow-audit checkpoint --org <UUID> --key audit-key/audit-key.json --output checkpoint-001
brig audit verify checkpoint-001/audit.jsonl \
  --checkpoint checkpoint-001/checkpoint.json --public-key audit-key/audit-public.der
```

Init emits only a public key and public HSM reference. Checkpoint creation reads a DB-clock head, verifies and exports the complete prefix, signs a domain-separated canonical record, persists it, then writes public signature outputs. New events may arrive afterward; this checkpoint authenticates precisely its recorded prefix. Its payload binds version, organisation, sequence, entry hash, timestamp, key ID and algorithm. The offline verifier requires the exact prefix and independently supplied public key, rejecting suffix truncation, mixed tenants, wrong key and modified checkpoint. `brig audit verify` without checkpoint remains explicitly chain-integrity-only.

Retain the latest checkpoint outside the database and pin the audit public key through an independent trusted channel. A public key delivered alongside an untrusted replacement export does not establish authenticity. Offline verification cannot know a newer checkpoint was withheld unless the verifier already knows its expected sequence/head. Preserve keys/checkpoints through rotation and disaster recovery. Recover persisted checkpoints after output interruption rather than blindly re-signing the same head. OpenSSL can verify `checkpoint.sig` over the SHA-256 digest of `checkpoint.bytes` using `pkeyutl -verify -pubin -keyform DER -pkeyopt digest:sha256` for the initial P-256 audit key.

## Backup and recovery

Back up Postgres with an operator-controlled, encrypted and access-restricted backup system. Include all schemas/migration history, organisations, policy/approval/window records, credential hashes, audit entries/checkpoints and optional CA issuance/revocation/CRL ledger. Back up non-secret configuration and public certificate/key-reference files separately. Protect DB passwords, HSM PINs, OIDC/session configuration and webhook secrets using your secret manager; never place them in repository fixtures or logs.

The HSM's keys remain in the HSM. Use only its supported operator backup/HA procedures; Brigalow provides no private-key export. Preserve stable token/backend IDs and key UUIDs. A DB-only backup cannot recover missing HSM keys. Lab software keys are intentionally ephemeral and are not a production recovery mechanism.

Recovery sequence:

1. Stop signing and CA issuance. Retain current externally stored audit checkpoints and CRLs. Restore into an isolated database using the owner role; restore restricted runtime roles/grants and verify TLS configuration.
2. Verify every audit chain and the latest independently retained signed checkpoint. Compare snapshot age, CA revocations, CRL numbers and consumed release-window caps against external evidence. An older DB snapshot can lose revocations or consumed authority; reconcile before enabling service.
3. Confirm every required HSM key reference resolves to the expected public key and remains sensitive/non-exportable. Do not silently generate replacements or select software keys.
4. Confirm pending approvals remain pending. Investigate interrupted `gating`, `signing`, CA issuance and CRL intents using backend/audit evidence. Never automatically repeat a possibly completed signature.
5. Reconcile credentials, policies, windows and configuration, then re-enable only the intended services. Test operator-owned recovery procedures periodically.

`scripts/backup_restore.py` is a harness-only destructive drill. `scripts/e2e.sh --context <local-context>` invokes it against uniquely named disposable Compose resources. It dumps the generated test DB, restores a scratch copy, wipes only that scratch DB, restores again, verifies all audit chains/checkpoints and exact request states, and proves the restored HSM reference can sign a digest independently verified by OpenSSL. The source DB is never dropped. This does not test a vendor HSM backup or a production restore.

## HA and draft Helm chart

Application instances are stateless except for live backend sessions and in-flight work. Shared Postgres holds sessions, credentials, budgets, approvals, release-window caps and signing intents. Use the same reviewed identity/policy/provider configuration on every replica. HSM vendor libraries, token sessions, supported HA and network controls are operator dependencies. Scale only after testing the actual HSM and DB capacity; no exactly-once hardware-signature guarantee exists across crashes.

The draft chart is `deploy/helm/brigalow`. It requires a reviewed immutable image digest and an existing Kubernetes Secret. It provides a ClusterIP service only, no public ingress, CA process or migrations. Mount config paths under `/run/brigalow`; the init container copies projected Secret symlinks into a memory-backed volume as regular 0600 files owned by the non-root runtime. The reviewed image must include POSIX sh/cp/chmod and the configured HSM library. Secret changes require a controlled rollout; copying is startup-only. Supply your TLS proxy, network policy, external Postgres, secret provisioning and vendor HSM integration. Never put secret values into Helm values or rendered output.

Local rendering is tested with `python3 scripts/test_helm.py`; no Kubernetes cluster is contacted. The chart has not been deployed or claimed production-ready. Use a migration owner job separately and complete migrations before rolling out compatible server revisions. Never run migrations from each application replica.

## Parser fuzzing

Application code builds on stable Rust. Fuzz instrumentation alone uses nightly and pinned `cargo-fuzz 0.13.2`. Run `python3 scripts/fuzz.py` after installing those tools. Targets cover request/policy JSON, X.509/CMS/CSR wrappers and audit/checkpoint parsing. Public certificate seeds are generated at run time; private generation material is temporary and discarded. Inputs are capped at 64 KiB with time/memory limits. CI gives each target 15 seconds; extend locally with `BRIGALOW_FUZZ_SECONDS` (maximum 300). Bounded fuzzing is regression evidence, not proof of parser safety. Reproduce/minimise crashes before committing a regression fixture, and ensure it contains no secrets.

## Lab-signed release artifacts

The manual `lab-signed release bundle` workflow builds Linux binaries/provider with stable Rust and locked dependencies, packages them with LICENSE, emits a CycloneDX 1.6 SBOM from Cargo metadata, and creates a SHA-256 manifest. The disposable Compose lab control plane signs that manifest through the normal digest API; OpenSSL verifies it and payload hashes before upload as a workflow artifact. It does not create a GitHub release, enrol with a CA, contact Sigstore or deploy anything. All Actions are pinned by full SHA and use GitHub-hosted runners.

The generated key is ephemeral and the manifest explicitly says `lab`. Its included public key enables integrity checks but does not independently authenticate the publisher; consumers must establish key/source trust themselves. This workflow makes no release-key custody, public-trust or certification claim. A production release process must use your reviewed HSM/policy/trust configuration under separate operational authorisation.

`python3 scripts/test_release.py` tests archive/SBOM packaging and payload tamper rejection with generated fixture binaries. The full Compose tool test separately verifies signing through the real local control plane and rejects a modified manifest. `scripts/verify_release.py <directory> --public-key <independently-trusted-PEM>` verifies signature and all listed payload digests.
