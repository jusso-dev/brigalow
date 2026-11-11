# Optional private CA

`brigalow-ca` is an operator command, separate from the HTTP signing service. It issues private code-signing leaves valid for exactly 72 hours and publishes signed CRL files. It does not create public trust. The root stays offline (or in an independently operated root HSM); the online intermediate key must be in a PKCS#11 HSM. SoftHSM2 is for tests. Software issuer fallback is refused, including in lab mode.

## Provisioning

Build `cargo build --locked -p brigalow-server --bin brigalow-ca`. Apply the normal database migrations as owner. Provision a dedicated restricted login inheriting `brigalow_ca`, without `brigalow_app`, superuser, BYPASSRLS, schema ownership or role/database creation. Supply its password through the existing environment/0600-file secret mechanism. The HTTP runtime has no permission on CA ledger tables; the CA login cannot mutate projects, policies or signing keys. Both append to the existing tenant audit chain.

Use a separate operator `BRIGALOW_CONFIG` with `backend = "pkcs11"`, the CA token/module, stable backend ID, CA database user and verified database TLS settings. Reuse the documented configuration syntax, not the signing service's secret files or token. Protect the configuration and issuer files with operator-only write access. Run only on the CA administration host. The command opens no network listener and connects only to the configured Postgres service; PKCS#11 is local/provider-managed.

Generate a non-exportable P-256 intermediate key and CSR:

```sh
brigalow-ca init --subject 'CN=Internal signing intermediate' --output issuer-request
```

`issuer-key.json` contains only the key UUID, algorithm and purpose; retain it for HSM lookup. `issuer.csr` contains the public CSR. Have the independently operated offline root issue an intermediate with critical `CA:TRUE,pathlen:0`, critical `keyCertSign,cRLSign`, `codeSigning` EKU and a subject key identifier. The issuer must remain valid throughout each leaf/CRL lifetime. Keep root keys outside Brigalow. Convert the issued intermediate and explicitly trusted root certificates to DER. Never register the issuer key as an artifact-signing key or bind it to a signing policy.

Configure an operator-owned JSON document:

```json
{
  "org": "<existing organisation UUID>",
  "issuer_key_file": "/operator/issuer-key.json",
  "chain": ["/operator/intermediate.der"],
  "anchors": ["/operator/private-root.der"],
  "profiles": [{
    "id": "<durable profile UUID>",
    "oid": "1.3.6.1.4.1.<your PEN>.1",
    "subject": "CN=Internal application signing"
  }]
}
```

Replace the OID with an actual assigned private-enterprise arc you own. Obtaining and governing an IANA PEN is the operator's responsibility; Brigalow cannot verify allocation ownership. Tests alone use documentation PEN 32473. The noncritical extension contains a DER UTF8String holding the durable profile UUID. No subject or extension requested by a CSR overrides this profile. A profile's complete record becomes immutable on first issuance; changed identity/OID requires a new UUID. Issuer rotation may retain the same profile.

## Daily issuance and signing

For each day's release, generate a new signing key through the existing custodian API and obtain its CSR. The CA verifies CSR proof of possession, accepts only RSA-3072/P-256/Ed25519 public keys, and ignores CSR identity/extension requests. Run:

```sh
brigalow-ca --ca /operator/profiles.json issue \
  --profile <UUID> --csr daily-key.csr --output daily-certificate
```

The DB clock chooses the UTC day (days since Unix epoch), serial and issuance time. A transaction commits an issuance intent before any CA signature. At most one leaf exists per organisation/profile/day, including across issuer rotation. Ten concurrent attempts produce one reservation. A crash or signing failure retains the reservation; no blind retry or automatic reissue. Investigate the ledger/audit and HSM state before operator recovery.

The output directory contains `leaf.der`, `chain.pem`, and a `chain.json` request body for the existing certificate-import API. Files/directories must not exist beforehand. Import into the matching generated signing key, activate, and create the day's policy using the existing separation of custodian and policy roles. Configure the private root as a private trust anchor in the signing service. Software signing keys still retain the lab label. Profile identity survives daily key/certificate/policy rotation; this command does not silently replace active policies. Operators schedule this explicit workflow daily with their existing job tooling.

If publication was interrupted after the commit, recover identical public outputs without invoking the HSM:

```sh
brigalow-ca --ca /operator/profiles.json export \
  --profile <UUID> --day <UTC-day-number> --output recovered-certificate
```

Exports report whether the ledger records revocation. A pending issuance with no committed chain cannot be exported. Keep the database ledger and HSM key references together in recovery plans; no key export is required.

## Revocation and CRL publication

```sh
brigalow-ca --ca /operator/profiles.json revoke --profile <UUID> --day <UTC-day-number>
brigalow-ca --ca /operator/profiles.json crl --output crl-<number>.der
```

Revocation affects that day's certificate serial only, including an interrupted issuance intent. CRLs include every revoked serial for the configured issuer, have monotonically increasing ledger numbers and expire after 24 hours. A revocation after a CRL snapshot invalidates its commit; create a fresh CRL. Concurrent publications cannot commit an older number after a newer reservation. No ledger deletion, expiry pruning or automatic unrevocation exists. After issuer rotation, retain the old issuer configuration/HSM key to publish its CRL until all issued certificates and retention needs have expired.

The command commits the CRL before writing its DER file. Publish that public file atomically using your existing internal static-file distribution; refresh before `nextUpdate` and immediately after revocation. No deployment or external publication is performed by Brigalow. Consumers must obtain fresh CRLs and enable checking, for example OpenSSL `verify -crl_check -CRLfile issuer.crl.pem`. A timestamp never overrides revocation policy. CRL file publication and consumer freshness monitoring are operator responsibilities.

## Verification and limits

The acceptance suite uses an ephemeral OpenSSL root, SoftHSM issuer and independent OpenSSL verification. It checks exact 72-hour validity and profile OID, CSR tampering, unknown roots, duplicate-day reservations, process restart recovery, append-only permissions, isolated database roles and one-day revocation without rejecting another day's leaf.

For historical CMS validation after leaf expiry, first verify its RFC 3161 token signature, trusted TSA path and message imprint. Only then use that authenticated token's `genTime` for signing-certificate path validation (`openssl cms -verify -attime <verified-time>`). The tests advance the verifier five days, prove ordinary current-time validation rejects the expired leaf, authenticate the TSA token at that future clock, and verify CMS at its authenticated signing time. OpenSSL CMS does not automatically perform this archival policy merely because a timestamp attribute is present. Consumers must additionally apply their revocation, TSA retention and trust policies; a caller-provided signing time is not evidence.
