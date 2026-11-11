# CSC remote signing: local mock only

Phase 9 implements a narrow synchronous profile of [CSC API v2.0.0.2](https://cloudsignatureconsortium.org/wp-content/uploads/2023/04/csc-api-v2.0.0.2.pdf), published through the [CSC specifications page](https://cloudsignatureconsortium.org/download-api-specifications/). It is an interoperability starting point, not a tested vendor integration or a claim of CSC conformance. No real account or service was contacted.

The backend name is `csc_mock`. Both configuration and runtime reject production mode. Only literal loopback HTTPS origins are accepted; DNS names, userinfo, paths, query strings and fragments are rejected. TLS certificates are verified. HTTP proxies, redirects and application retries are disabled. The Compose tool runtime has no external egress.

## Configuration and registration

Use generated test certificates and a generated access token in a regular mode-0600 file. Do not put credentials in TOML. The TLS CA is PEM; the pinned signing leaf is DER. UUIDs below must be replaced with the existing organisation/project and a new operator-selected key reference.

```toml
mode = "lab"
backend = "csc_mock"
backend_id = "local-csc-v1"

[csc_mock]
url = "https://127.0.0.1:8444"
tls_ca_file = "/run/brigalow/csc-tls-ca.pem"
access_token_file = "/run/brigalow/csc-token"

[[csc_mock.bindings]]
id = "11111111-1111-4111-8111-111111111111"
org = "22222222-2222-4222-8222-222222222222"
project = "33333333-3333-4333-8333-333333333333"
credential_id = "mock-key"
certificate_file = "/run/brigalow/csc-leaf.der"
```

Startup lists credentials, fetches each configured credential's information, requires an enabled RSA-3072 key, and pins the exact certificate and public key. The leaf must be currently valid with code-signing usage. Unknown references, duplicate mappings, paginated listings and mismatching certificates fail startup. Updating a certificate requires explicit operator configuration and restart; there is no unattended certificate rotation.

An authenticated key custodian registers a configured reference through the existing key endpoint:

```json
{"remote_key":"11111111-1111-4111-8111-111111111111","algorithm":"rsa3072","purpose":"test","offline":false}
```

`POST /v1/orgs/{org}/projects/{project}/keys` checks the configured organisation and project before registration; mismatches return 404. Omitting `remote_key` cannot generate a remote key. Duplicate registration returns 409 without disabling the existing reference. The ordinary certificate import, activation, policy, approval, gate, release-window and disable controls still apply. Import the pinned leaf and its local CA chain for CMS output. A disabled key cannot sign through Brigalow; this does not revoke the upstream credential or certificate. Revoke upstream separately if compromise is suspected.

## Protocol and limits

Only `credentials/list`, `credentials/info`, `credentials/authorize` and `signatures/signHash` are used under `/csc/v2/`. Authorisation binds one base64 SHA-256 digest to one credential; `numSignatures=1`, `hashAlgorithmOID=2.16.840.1.101.3.4.2.1`, and `signAlgo=1.2.840.113549.1.1.1`. `operationMode=S` requests a synchronous RSA PKCS#1 v1.5 signature. Returned signatures are verified with RustCrypto against the pinned public key and the exact digest before being returned or persisted. OpenSSL independently verifies the acceptance-test output.

The mock profile requires explicit authorisation with an empty `auth.objects` list and `SCAL=2`. That field is protocol data, not an assurance or certification claim. Interactive OTP, OAuth token acquisition/refresh, MFA, OOB authorisation, asynchronous jobs, batching, pagination, enrolment, remote key generation and vendor extensions are unsupported. A service requiring these controls must fail; never remove them to make a real service fit this mock.

The token and SAD stay in memory, never audit/log records. Owned token/SAD buffers are zeroised where practical; HTTP/JSON libraries may allocate temporary copies, so this is not a process-memory secrecy guarantee. Responses are capped at 1 MiB, connection timeout is two seconds, total request timeout five seconds. Unexpected status, invalid/expired authorisation, malformed output or transport ambiguity fails the durable signing request with no output. No automatic retry: an upstream signature might have occurred even if its response was lost.

The backend always labels keys `lab`, even with an imported anchor. Elsewhere, `external-ca` means only that an operator configured an outside-CA anchor and the imported chain validates to it. It is not a statement about operating-system acceptance, reputation or public trust. See [trust tiers](../decisions/0003-trust-tiers.md).

## Verification

Run `python3 scripts/e2e.py --context orbstack` (or `--context default` on a hosted CI runner). `at_pub_01_tool_csc_digest_only_fail_closed` runs the real router/Postgres and a generated-key HTTPS mock within the isolated Linux tools container. It checks scoped reference registration, duplicate safety, lab guards, certificate pinning, digest-only transport, policy denial without remote calls, authorisation/signature faults, disable enforcement and OpenSSL verification. No persistent test keys or bearer tokens are fixtures.
