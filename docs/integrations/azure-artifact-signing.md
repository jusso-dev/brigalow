# Azure Artifact Signing backend

Backend name: `artifact_signing`. It puts Brigalow's identity, policy, approval, gate, window and audit controls in front of a Microsoft-managed Artifact Signing certificate profile. Microsoft holds and rotates the key. Brigalow never sees or exports it, and the service offers no key import or export.

Status: implemented and tested against a local contract mock only (AT-AZ-01). It has not been exercised against a real Artifact Signing account. Facts below come from Microsoft documentation and the open-source Jsign client, as read on 2026-11-12. Recheck them before relying on this backend: the data-plane API version is a preview.

Brigalow never labels a signature publicly trusted. A key registered through this backend is `external-ca` only when its pinned anchor is a configured `external-ca` trust anchor, and every signature is validated to that anchor before output. Whether any operating system or platform accepts the signature is decided by that platform and Microsoft's programme, not by Brigalow. See [trust tiers](../decisions/0003-trust-tiers.md).

## Service contract used

| Item | Value |
| --- | --- |
| Sign | `POST https://<region>.codesigning.azure.net/codesigningaccounts/{account}/certificateprofiles/{profile}/sign?api-version=2022-06-15-preview` with `{"signatureAlgorithm":"RS256","digest":"<base64 SHA-256>"}` |
| Poll | `GET .../sign/{operationId}?api-version=2022-06-15-preview` until `status` is `Succeeded`. `InProgress` keeps polling, and any other value fails. |
| Result | `signature` (base64) and `signingCertificate`, which is base64 of a base64 (or PEM) PKCS#7 or X.509 bundle. |
| Token | Entra access token for resource `https://codesigning.azure.net`. The caller needs the built-in role **Artifact Signing Certificate Profile Signer** (role ID `2837e146-70d7-4cfd-ad55-7efa6464f958`, data action `Microsoft.CodeSigning/certificateProfiles/Sign/action`), scoped to the profile. |
| Rotation | Microsoft renews the key and certificate daily, and each certificate is valid for 72 hours. The durable identity is a profile-specific EKU under `1.3.6.1.4.1.311.97.` plus code signing (`1.3.6.1.5.5.7.3.3`). |

## Rotating-key contract

The other backends (PKCS#11, software, CSC mock) have a stable public key, and `produce` checks `backend.public_key == key.public_key` before signing. A rotating key has no stable public key, so that check cannot hold. The contract is explicit in `brigalow-crypto::rotating`:

1. The backend reports `rotates() = true` and returns, per operation, an untrusted signature plus certificate bundle. It has no `public_key`, `sign_digest` or `sign_message` path: those return `Unavailable`, so no caller can obtain an unchecked signature.
2. Before accepting a result, Brigalow:
   - (a) parses the returned bundle (bounded size and count, exactly one non-CA leaf, order not trusted);
   - (b) checks the leaf (CA=false, valid now, code-signing EKU, digital-signature usage, RSA-3072). It validates the path with webpki to the operator-pinned anchor only, at the current time, and requires the configured profile EKU in the leaf. Intermediates may omit EKU, but when one is present it must include code signing;
   - (c) verifies the RSASSA-PKCS1-v1_5 SHA-256 signature over the exact submitted digest (or CMS signed-attribute digest) with the leaf public key, using the RustCrypto `rsa` crate;
   - (d) records the leaf certificate with the request (`remote.certificate`, `remote.certificate_sha256`). It audits the operation ID and leaf fingerprint in `request.signed` or `request.failed`.
3. Any failure produces no output. The request is persisted as `failed`, with any operation ID received, and HTTP returns 502.

PKCS#11, software and CSC mock keep the original pinned-key path byte for byte. Their requests carry no `remote` field, and their audit details are unchanged.

## Algorithms and outputs

- Key algorithm: RSA-3072 only, and the leaf must carry an RSA-3072 key. Requests use `RS256`.
- Raw: the returned signature over the submitted SHA-256 digest.
- Detached CMS: Brigalow builds the signed attributes (content type, message digest), submits their SHA-256 digest once, verifies the result as above, and assembles SignedData from the validated chain. OpenSSL `cms -verify` against the pinned root checks it in AT-AZ-01.
- Refused at policy creation: any algorithm other than `rsa3072`, and `attestation = true`. DSSE provenance needs message signing with a stable key. Registration refuses generation, a CSR or a chain import for these keys.

## Async operation, timeouts and no retry

- One `POST` per request. Polling uses a 50 ms delay growing to 1 s, bounded by `operation_timeout_seconds` (default 20, maximum 25). Each HTTP call also has its own timeout. The reference proxy waits 30 seconds for the upstream: the default leaves room for a token fetch (3 s) and an HTTPS TSA call (5 s). Raising the timeout towards 25 seconds with a TSA configured can make the proxy give up first. The request then still completes or fails durably in Brigalow. `brig` reports the interruption and prints the request ID at submission, so check its status instead of resubmitting.
- Timeout, a lost or malformed response, a mismatched operation ID, a redirect or any status other than `Succeeded` fails the request and audits the operation ID if one was received.
- Brigalow never resubmits automatically. A timed-out operation may still complete at Microsoft and produce a signature that Brigalow never returned. Reconcile using the audited operation ID and the account's own logs. A new request needs a new request ID and goes through policy, approval and windows again.
- A 401 or 403 drops the cached token. The current request still fails; the next one fetches a fresh token.

## Managed identity and the IMDS trust boundary

The access token comes from Azure Instance Metadata Service at `http://169.254.169.254/metadata/identity/oauth2/token`. This is the only plain-HTTP call in Brigalow:

- The address is a compile-time constant, not configuration. The only selectable value is `managed_identity_client_id`, a non-secret identifier for a user-assigned identity.
- Requests send `Metadata: true`, use no proxy (environment proxies are ignored), follow no redirects and time out after 3 seconds total. Responses are capped at 64 KiB.
- Tokens are cached in memory until 5 minutes before `expires_on`. A token already inside that margin, or claiming more than 48 hours of life, is refused. Tokens are never logged, audited or persisted. Owned copies are zeroised where practical, but HTTP and JSON libraries may make transient copies.
- Trust: anything able to answer on the VM's link-local address can mint tokens for that identity. That means the hypervisor, or local code with enough network privilege on the VM. Treat the VM as part of the signing boundary, scope the identity's role to one profile, and do not run untrusted workloads on the host.
- Tests replace IMDS with a loopback plain-HTTP mock through `ArtifactSigning::for_tests`. That constructor exists only with the `integration` feature or in unit tests. It is not reachable from TOML, environment or the release image.

## Configuration

No credentials appear in TOML. The anchor is the issuing root you pin, as DER. Obtain it through a channel independent of the signing responses and check its fingerprint against Microsoft's published material for your profile type. A root copied from a returned bundle proves nothing on its own.

```toml
mode = "production"
backend = "artifact_signing"
backend_id = "azure-artifact-signing"

[[trust_anchors]]
name = "artifact-signing-root"
tier = "external-ca"
file = "/run/brigalow/artifact-signing-root.der"

[artifact_signing]
endpoint = "https://eus.codesigning.azure.net"
managed_identity_client_id = "00000000-0000-0000-0000-000000000000"
operation_timeout_seconds = 20

[[artifact_signing.bindings]]
id = "11111111-1111-4111-8111-111111111111"       # Brigalow key UUID you choose
org = "22222222-2222-4222-8222-222222222222"
project = "33333333-3333-4333-8333-333333333333"
purpose = "release"
account = "brigalow-signing"
profile = "brigalow-release"
anchor = "artifact-signing-root"                  # must name an external-ca trust anchor
profile_eku = "1.3.6.1.4.1.311.97.000000000.0.0"  # your profile's EKU (placeholder)
```

Rules enforced at startup (no fallback):

- `endpoint` must be `https://<region>.codesigning.azure.net`, with a lowercase alphanumeric region, no port, path, query or userinfo. Lab mode alone may use a literal loopback HTTPS origin with `tls_ca_file`. Production refuses `tls_ca_file` and loopback.
- `account` and `profile` follow the ARM name patterns (letters, digits, single hyphens). Each account and profile pair maps to exactly one Brigalow key.
- `anchor` must name a configured `external-ca` anchor that parses as a CA certificate. `profile_eku` must be a canonical OID under `1.3.6.1.4.1.311.97.`.
- `backend = "artifact_signing"` is accepted in production mode, alongside `pkcs11`. Readiness (`/healthz`) checks that a managed-identity token is available and never signs.

Obtaining the anchor and EKU is an operator step outside Brigalow. Microsoft's `Az.CodeSigning` PowerShell module provides `Get-AzCodeSigningRootCert` (root currently used by an account/profile) and `Get-AzCodeSigningCustomerEku` (the profile EKU). Convert the root to DER (`openssl x509 -in root.cer -outform DER`) if needed. Cross-check both against an independent source, such as a leaf from a reviewed earlier signature or Microsoft's published root fingerprints, before pinning, and record them with the profile. Microsoft documents that a recreated profile receives a new EKU, so recreating a profile requires updating this binding. Microsoft can also change its issuing root. Brigalow then fails closed until you pin the new root after the same review.

## Registration

A key custodian registers a configured binding through the existing endpoint. Org and project must match the binding, otherwise 404:

```json
{"remote_key":"11111111-1111-4111-8111-111111111111","algorithm":"rsa3072","purpose":"release","offline":false}
```

The record has an empty `public_key` and chain, `trust = external-ca` and `anchor = <name>` when the pinned anchor is a configured external-ca anchor (otherwise `untrusted`, which cannot activate for release). Activation then follows the usual rules. Release purpose is refused in lab mode, as for every backend. At signing, a release request also rechecks that the key's anchor name is still configured as `external-ca` with the same DER the backend pins.

Disable stops Brigalow's authority only. It does not revoke the role assignment, the profile or the certificate. Remove the role assignment in Azure as well when retiring or responding to compromise.

## Timestamping and the 72-hour certificate

Microsoft's timestamp service is `http://timestamp.acs.microsoft.com`, which is HTTP only. Brigalow's TSA client accepts HTTPS only and this backend does not change that. Choose one:

- Configure an HTTPS RFC 3161 TSA you trust (`[tsa]`, with a pinned signer) and set the policy `timestamp = "required"` (or `"optional"`).
- Set the policy `timestamp = "disabled"` (or `"optional"` with no TSA) and timestamp separately with a tool you trust.

Plain consequence: each signing certificate is valid for 72 hours. Without a trusted timestamp, verifiers that check certificate validity at verification time reject the signature after that certificate expires, usually within three days of signing. A trusted timestamp is what lets a verifier accept it later. Whether a given platform accepts your chosen TSA is the platform's decision.

## Verification

`at_az_01_artifact_signing_rotating_chain_verified_fail_closed` in `crates/brigalow-server/tests/support/artifact_signing.rs` runs the real router and Postgres against `deploy/dev/test_artifact_signing.py`. `crates/brigalow-crypto/tests/rotating.rs` covers the acceptance checks without a database. See AT-AZ-01 in [acceptance tests](../acceptance-tests.md). All keys and CAs are generated at test time; nothing contacts Azure.
