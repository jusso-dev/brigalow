# PKCS#11 client provider

Status: Phase 6 implementation under acceptance testing. Supported initial signing profile: RSA-3072 and SHA-256 on Linux. This client module is distinct from the server's HSM backend. It stores no private key, creates no certificate, and claims no hardware assurance or public trust. Use an HSM-backed server key for real custody; software remains lab-only.

Build with `cargo build --locked -p brigalow-pkcs11`. The module is `target/debug/libbrigalow_pkcs11.so` on Linux. Point `BRIGALOW_PKCS11_CONFIG` to a non-secret TOML file:

```toml
server = "https://signing.example"
org = "<organisation UUID>"
project = "<project UUID>"
policy = "<policy UUID>"
ca_file = "/operator/path/https-ca.pem" # omit for system HTTPS roots
```

Supply a scoped, expiring API token or workload OIDC token through `BRIGALOW_TOKEN`, never a command argument or configuration value. The authenticated process can sign only through that one policy. Token rotation requires restarting the client process, including GPG's agent. There is no credential fallback. The module verifies HTTPS, follows no redirects and uses no environment proxy. Protect the client host and configuration as part of the build trust boundary.

The module exposes one slot/token (`Brigalow`) and policy-bound public/private-reference/certificate objects named `brigalow`. The private object is a reference, never key material. Mechanisms: `CKM_RSA_PKCS` accepts only a strict SHA-256 DigestInfo; `CKM_SHA256_RSA_PKCS` hashes locally, including streaming input. Signing sends exactly a SHA-256 digest to Brigalow. Algorithms such as SHA-1 and raw RSA are rejected. No generation, import, wrapping, private export, decryption or key mutation operation exists.

Authentication comes from the environment credential verified at initialization and every server request. The token does not require a PIN; PKCS#11 login adds no authority. Existing tools may call login, but no PIN replaces the API/OIDC credential. Each signing call submits a new request ID and polls pending approval for up to five minutes. Length queries and undersized output buffers never submit signatures. A transport interruption fails; it does not automatically resubmit. Reconcile server audit before an explicit retry.

The C ABI is the workspace's only narrowly allowed unsafe module. Callers must honour PKCS#11's valid, aligned buffer contract. Null/length checks, bounded session state, bounded input chunks and panic containment protect normal foreign callers. A malicious native process already controls its credentials and address space; this library is not a sandbox. A server or HSM outage never loads a software signing key in the client.

## OpenSSL

Install the distribution's PKCS#11 engine (for example `libengine-pkcs11-openssl`). Set `PKCS11_MODULE_PATH` to the absolute Brigalow module path. URI: `pkcs11:token=Brigalow;object=brigalow;type=private`.

```sh
openssl dgst -sha256 -binary artifact.bin > artifact.digest
openssl pkeyutl -engine pkcs11 -keyform engine \
  -inkey 'pkcs11:token=Brigalow;object=brigalow;type=private' \
  -sign -pkeyopt digest:sha256 -in artifact.digest -out artifact.sig
openssl pkeyutl -verify -pubin -inkey public.pem \
  -pkeyopt digest:sha256 -in artifact.digest -sigfile artifact.sig
```

`public.pem` must be independently obtained from the intended policy key. The generated test checks that SHA-1 and private-key reads fail.

## Authenticode: osslsigncode and jsign

Both tools need a code-signing certificate already imported into Brigalow. No CA enrolment occurs. For osslsigncode, use the installed default PKCS#11 engine and pass `-pkcs11module`, `-key` with the URI above, `-certs leaf.pem`, and `-h sha256`. Verify using `osslsigncode verify -CAfile <private-root.pem> -in signed.exe`. The test builds its own tiny PE fixture with MinGW and verifies against the generated test CA.

For jsign, create a SunPKCS11 file with `name = Brigalow`, `library = <absolute-module-path>`, and `slot = 1`. Use `--storetype PKCS11 --keystore <configuration> --alias brigalow --alg SHA-256`. The acceptance suite independently checks jsign's output using osslsigncode.

## cosign and GPG

The Linux harness builds cosign with `pkcs11key` support. Use the token/object URI and `module-path` query, with the standard PKCS#11 module environment setting. The acceptance suite disables transparency-log upload and verifies the blob locally with the exported public key. It does not enrol with Fulcio or contact Rekor.

GPG uses `gnupg-pkcs11-scd` as its smartcard bridge. Configure that daemon's provider library path and point `gpg-agent.conf` at the daemon. The certificate and private reference share their CKA_ID. With GnuPG 2.2, run `gpg --card-status`, obtain the existing keygrip using `gpg-connect-agent "SCD LEARN" /bye`, and register an OpenPGP identity with batch `Key-Type: RSA`, `Key-Grip: <existing grip>`, `Key-Usage: sign`, `Name-Real` and `Expire-Date`. Use `--cert-digest-algo SHA256` during registration and `--digest-algo SHA256` for detached signatures; never generate or back up a private key through the bridge. Detailed executable tool recipes and their verification commands live in `deploy/dev/test_tools.py`.

The tools container is disposable and receives generated keys/certificates only at runtime. Test CA trust is explicit; signatures are not asserted to be publicly trusted. These recipes cover the pinned/tested tool versions, not arbitrary tool/version compatibility.
