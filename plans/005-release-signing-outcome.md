# Operator-owned release signing: design outcome

Reviewed `89cf46697091a1b175435f1971ba74a3131db7d1`, with recovery and checkpoint constraints from outcomes 001 and 002. **No release was signed or published by this spike.** This describes a later locally testable workflow; it does not qualify a production HSM or authenticate a publisher by itself.

## Trust and identity

Current `scripts/package_release.py` emits `manifest.json` containing version 1, source revision, `trust="lab"` and hashes for `brigalow-linux.tar.gz`/`sbom.cdx.json`; `scripts/verify_release.py` requires `trust=lab`, verifies OpenSSL signature and listed digests with an explicit public key. The manual release workflow signs with a generated ephemeral lab control plane and uploads a temporary workflow artifact. Its included key checks integrity only. It creates no stable publisher identity.

Proposed separate operator workflow: an operator independently provisions a P-256 or RSA-3072 signing key on their PKCS#11 device, separately configures a release-purpose policy, protected workload or human authorisation, approvals/gates/window and certificate/trust anchors, and pins its public key or an independently reviewed fingerprint for consumers. The operator controls that key through existing Brigalow custody; no private material enters the build. First implementation supports raw SHA-256 signatures using only algorithms independently verified by the existing OpenSSL `dgst -sha256 -verify` contract. Do not silently reuse lab identities or claim OS/browser public trust. Lab continues labelling its output `lab`.

The public key must come from an independently trusted channel, not the bundle or an untrusted manifest `key_id`; a bundled convenience copy cannot establish identity. A certificate chain, if provided, is metadata and independently configured trust policy remains authoritative. The verifier reports cryptographic validity and declared `operator` origin, not CA/platform trust or certification.

## Manifest and verification contract

Keep exact manifest bytes fixed before signing; `brig sign` already hashes the selected file locally and sends only its SHA-256 digest. Define a versioned operator manifest distinct from v1 lab; include immutable source commit, digest algorithm, exact archive/SBOM names and SHA-256 hashes, and explicit `operator` (self-hosted) provenance. Validate revision syntax, maximum item count/size, allowed basename-only paths, duplicate keys, supported algorithms and strict schema before verification. Reject symlinks/non-regular payloads and path traversal; do not read files outside the selected bundle. Sign the exact bytes, not a separately reserialized JSON object.

Verification uses a separately pinned public key, verifies signature over manifest bytes independently with OpenSSL, then checks every required payload digest and expected revision. Unknown versions, trust labels, algorithms, duplicate entries, missing required payloads or unexpected file types fail closed. Lab v1 remains supported only through an explicit lab verification mode; no default promotion of a lab bundle to operator identity. An independently retained audit checkpoint can authenticate a request/audit prefix under plan 002's separate external-head rules, but a valid checkpoint alone does not assert publisher or latestness.

## Failure and operator workflow

Build archive/SBOM in an isolated temporary output directory; freeze the manifest; submit one request through the normal `brig sign --format raw` policy path; record the printed request ID without exposing credentials; wait for approval/gates/window normally. On success verify against the separately pinned public key and all payload digests, then publish the complete local directory atomically without overwriting existing output. No network publication or GitHub release is part of this proposed command.

On timeout, cancellation, required TSA/gate failure or uncertain HSM outcome, return failure and do not claim a complete authenticated bundle. The existing CLI creates a new request ID for each invocation and explicitly tells operators to query the submitted ID; never blindly rerun it. Plan 001's inspection-only design does not prove a native call has stopped or authorise a replacement attempt. Preserve any consumed window capacity. No automatic retry, private-key export, direct HSM bypass, hidden signing policy or production credentials in CI. Optional timestamps must be authenticated against operator-pinned TSA trust; if required and invalid/absent, produce no completed bundle.

## Acceptance tests

Propose **AT-REL-03**. In disposable Compose, generate a mock IdP and local PKCS#11/SoftHSM key and use the real server's release-purpose policy, approvals/gates/windows and an independently exported public key. Verify the exact manifest signature independently with OpenSSL and all archive/SBOM digests. Include explicit lab-mode isolation: lab output cannot pass operator-mode verification; test fixtures must not imply that lab software keys can bind release policies.

Reject a co-delivered replacement key when a different pinned key is required, wrong org/policy/key, tampered manifest/revision/SBOM/archive, extra/missing files, malformed or duplicate JSON keys, traversal/symlink payloads, unsupported version/trust/algorithm and stale expected revision. Simulate uncertain signing, approval denial, gate failure, required timestamp outage and output collision; assert no successful final bundle and no duplicate HSM call. Preserve existing `scripts/test_release.py`, AT-SIGN-01..03, AT-AUD-02 and full hosted release workflow. Add a race test for staging/output no-replace and crash-recovery semantics. All keys, certs and credentials generated at test time.

## Residual risks

An operator may configure the wrong policy, grant excessive authority, lose an HSM key, expose a runtime credential or independently pin an attacker key; this proposal cannot solve those operational risks. Certificate import/validation is not proof of public trust. Timestamping adds another trust authority, not a substitute for pinning a publisher key. The `operator` manifest version, expected-revision source, algorithm profile, key-rotation policy and safe atomic output primitive need review before coding. No real release-signing service, account, CA or device was contacted.
