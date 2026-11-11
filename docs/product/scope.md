# Product scope

## One line

Brigalow is an open-source, self-hosted signing control plane. Build systems send a digest, Brigalow checks who is asking and whether policy allows it, has a key in an HSM sign it, and writes a tamper-evident record.

## Who it's for

- Platform and security teams who need to take signing keys off build agents and laptops.
- Organisations that want to run their own signing service, including air-gapped, without a SaaS dependency.
- Teams that sign internal software (scripts, containers, firmware, internal apps) with a private PKI, and separately sign public releases with a CA-issued certificate.

## Two trust tiers, kept separate

This is the most important line in the product and every screen, doc and API response must respect it.

| | **Self-hosted trust** (Brigalow can deliver this alone) | **Public trust** (needs an outside CA, usually with paid enrolment) |
| --- | --- | --- |
| Who trusts the signature | Machines you configure: your MDM, App Control/WDAC policy, container admission controller, firmware root of trust, package repo keys | Operating systems and browsers out of the box (for example Windows SmartScreen, macOS Gatekeeper) |
| Where the certificate comes from | Brigalow's optional private CA, or your existing internal CA | A publicly trusted CA after identity validation (for example DigiCert, Sectigo, SSL.com, Microsoft via Azure Artifact Signing) |
| Key custody | HSM via PKCS#11 recommended; software keys allowed only in `lab` mode | Whatever the CA's rules require (certified hardware). Brigalow can hold the key in your HSM if the CA accepts key attestation from it, or delegate signing to the CA's own service |
| Cost | Your infrastructure | Usually a certificate purchase and validation, and often a signing subscription or HSM attestation fee. Some programmes, such as SignPath Foundation for open-source projects, provide certificates under their own terms |
| What Brigalow adds | Everything: keys, policy, approvals, audit, short-lived certs | Policy, approvals and audit in front of a key or service that the CA governs |

Brigalow never claims a signature is publicly trusted. It reports the trust tier of each key and certificate as configured by the operator, and flags certificates whose chain does not lead to a configured trust anchor.

## In scope (v1)

1. Organisations and projects with strict tenant isolation.
2. Human sign-in by OpenID Connect; workload identity by OIDC tokens from CI platforms (GitHub Actions first, GitLab next).
3. Roles: org admin, key custodian, project admin, approver, submitter, auditor. Requesters can't approve their own requests. Custodians can't sign.
4. Key backends behind one trait: PKCS#11 (tested against SoftHSM2), a software backend for `lab` mode only, then cloud KMS backends.
5. Key lifecycle: generate in backend, CSR, import issued chain, validate chain, activate, disable, retire. No private key export, ever.
6. Signing policies with a **purpose** (`test` or `release`). Release keys can't be bound to test policies.
7. Submitter rules that match verified OIDC claims (issuer, repository, ref, workflow, environment), not self-reported metadata.
8. Asynchronous k-of-n approvals where one deny rejects the request. Configurable expiry, default 24 hours.
9. Release windows: named, time-boxed authorisations for `offline` keys with an optional signature cap.
10. Pre-sign gates as signed webhooks (malware scan, rebuild check). A gate that times out fails closed.
11. Digest signing API and `brig` CLI that hashes locally. Outputs: raw signature, detached CMS/PKCS#7, and RFC 3161 timestamp tokens from a configured TSA.
12. Append-only, hash-chained audit log with signed checkpoints and an offline verifier.
13. Server-rendered admin web UI. No Node.js toolchain.

## Later (planned, not v1)

- PKCS#11 provider module so osslsigncode, jsign, cosign, GPG and OpenSSL can sign through Brigalow unchanged.
- Optional private CA issuing short-lived (default 72h) leaf certs per signing profile, with a durable profile identifier under an OID arc the operator owns.
- in-toto / SLSA provenance and signed SBOMs in DSSE envelopes.
- Remote-signing backends for CA services that publish an API (for example the Cloud Signature Consortium API). Tested with mocks only until a real account is provided.
- HA deployment, backup/restore drills, Helm chart.

## Out of scope

- Being a public CA, or issuing anything presented as publicly trusted.
- Certificate lifecycle management for TLS (that's a CLM product's job; see BlakCert).
- A UI over Azure Key Vault (that's Keyring).
- Uploading whole artifacts by default. Deep signing of nested packages is a later, opt-in feature.
- Inventing cryptography. Brigalow uses vetted libraries and HSM mechanisms only.
- FIPS or Common Criteria claims. Brigalow can run against a validated HSM; Brigalow itself is not validated.

## Product name

**Brigalow** (*Acacia harpophylla*) is a hard-wooded Australian tree. Checks on 2026-11-11 found no software or signing product using the name.
