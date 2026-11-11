# Key custody library

`KeyBackend` exposes generation, public SPKI, digest/message signing and permanent disable. No private-key export API exists. RSA-3072/P-256 are supported by PKCS#11; lab software also supports Ed25519. Software refuses production construction and release purpose. Ed25519 digest signatures sign digest bytes as a message, not Ed25519ph; protocol messages such as CSRs use message signing.

PKCS#11 selects an existing exact-label token and creates sensitive, non-extractable UUID-addressed objects. It never initialises operator tokens or falls back to software. Software keys are ephemeral in-memory test data.

PKCS#10 uses RustCrypto encoders. Certificate import requires matching SPKI; rustls-webpki validates paths with mandatory code-signing EKU. An unknown issuer produces `untrusted`; accepted configured anchors produce `private`, with external anchor classification applied only by operator configuration in the server.

`cargo test -p brigalow-crypto` uses generated keys and OpenSSL verification. `scripts/e2e.sh --context <context>` also runs the dedicated Linux `pkcs11-tests` suite in a disposable SoftHSM container. No real CA or external signing service is contacted.
