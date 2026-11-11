# Brigalow provenance v1

Build type: `https://github.com/jusso-dev/brigalow/blob/main/docs/attestation-v1.md`.

This records the identity and source claims verified by Brigalow when a workload submitted a digest. It does not assert that Brigalow observed the build, fetched the source, or established any SLSA level. An independently operated rebuild gate can provide additional evidence. No build sandbox or provenance certification is implied.

An immutable policy enables `attestation: true`. Submissions then require non-empty verified OIDC `iss`, `sub`, `repository`, `sha`, and `workflow` claims. API tokens and human identities missing those claims cannot substitute self-reported metadata. Optional `ref` comes from the same verified identity. The issuer identifies the claimed builder authority; the workflow and source remain explicitly recorded parameters, not inferred from artifact names.

The in-toto Statement v1 subject contains the submitted SHA-256 digest and artifact name. The artifact name is a submitter-provided label. The SLSA provenance v1 predicate includes:

- `buildDefinition.buildType`: this document's identifier.
- `externalParameters`: verified repository, commit, workflow and optional ref.
- `resolvedDependencies`: repository name and verified `gitCommit` digest.
- `runDetails.builder.id`: verified issuer.
- `metadata.invocationId`: Brigalow request UUID.
- `byproducts`: a Base64 JSON descriptor of verified issuer, subject and workflow.

The DSSE payload type is `application/vnd.in-toto+json`. Signatures cover the standard pre-authentication encoding `DSSEv1 <type-byte-length> <type> <payload-byte-length> <payload>`, with single ASCII spaces between components and decimal lengths. Payload/signature use standard Base64; `keyid` is the policy key UUID. RSA uses PKCS#1 v1.5/SHA-256, P-256 uses ECDSA/SHA-256 (DER), and Ed25519 signs the whole PAE message. These use the existing RustCrypto/HSM backend, with no private-key export.

The server returns the envelope in `attestation` only after all required checks, artifact signing, timestamping and envelope signing succeed and commit. A failure returns neither signature nor envelope. `brig sign` writes `<output>.dsse.json` alongside its signature, without overwriting existing files. One authorised signing request may produce the artifact signature and its provenance signature; a release-window cap counts authorised requests, not low-level HSM operations.

Consumers must pin the expected policy public key independently, verify the DSSE signature and payload type, compare the subject digest to their local artifact, and validate issuer/source/workflow claims against their own policy. `keyid` alone is not a trust anchor. The acceptance suite reconstructs PAE with independent Python code and verifies signatures using OpenSSL, including tamper rejection.
