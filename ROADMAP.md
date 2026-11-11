# Roadmap

Phased so each phase ends with something runnable and tested. Acceptance test IDs refer to [docs/acceptance-tests.md](docs/acceptance-tests.md). One GitHub issue tracks each phase.

Rule for every phase: security controls ship with the feature they protect, not later.

## Phase 0: Foundations
Workspace, CI (fmt, clippy, test, secret scan), config loading with `lab`/`production` modes, health endpoint, Postgres + migrations, tenancy model, audit chain in `brigalow-core` with tests, docker compose for Postgres and SoftHSM2.
Exit: AT-OPS-01, AT-AUD-01, AT-TEN-01 (store level).

## Phase 1: Identity and access
OIDC sign-in for humans, sessions with CSRF protection, roles, API tokens (hashed, scoped, expiring), CI workload OIDC verification with configured issuers and claim rules.
Exit: AT-ID-01..03, AT-WEB-01, AT-TEN-01 (API level).

## Phase 2: Keys and certificates
`KeyBackend` trait, PKCS#11 backend against SoftHSM2, lab software backend, key purpose and online/offline state, CSR generation, certificate chain import and validation, trust tier labelling.
Exit: AT-KEY-01..03, AT-CERT-01..02.

## Phase 3: Signing requests and policy
Projects, signing policies, submitter rules, digest signing API, `brig sign` (hash locally, raw signature and detached CMS), RFC 3161 timestamping via configured TSA.
Exit: AT-POL-01..03, AT-SIGN-01..03.

## Phase 4: Approvals and release windows
Async k-of-n approvals with deny-wins and expiry, approver exclusions, approval UI, release windows with signature caps, outbound notification webhooks.
Exit: AT-APR-01..03, AT-REL-01..02.

## Phase 5: Gates and attestations
Signed webhook gates (fail closed), reference gate for rebuild/hash validation, in-toto statement with SLSA provenance in a DSSE envelope bound to verified CI claims.
Exit: AT-GATE-01..02, AT-ATT-01.

## Phase 6: Client integrations
PKCS#11 provider module for existing tools, GitHub Action wrapper, documented recipes for osslsigncode, jsign, cosign, GPG, OpenSSL. Each recipe has an automated test in CI on Linux.
Exit: AT-INT-01.

## Phase 7: Private CA and short-lived certificates
Optional internal CA (root offline or in HSM), short-lived leaf certs per signing profile (default 72h), operator-configured durable profile OID, CRL publication, revocation by day.
Exit: AT-CA-01..02.

## Phase 8: Hardening and operations
Rate limits, fuzzing of parsers, backup and restore drill, HA notes, Helm chart, signed release artefacts with SBOM, external security review checklist.
Exit: AT-OPS-02..03.

## Phase 9: Public-trust integrations (needs outside accounts)
Remote-signing backend for CA services with a published API (for example the CSC API), a guide for HSM key attestation with a CA, and an evaluation of delegating to Azure Artifact Signing. Built and tested against mocks. No real enrolment, purchase or production use without Justin's explicit go-ahead.
Exit: AT-PUB-01 (mock only).
