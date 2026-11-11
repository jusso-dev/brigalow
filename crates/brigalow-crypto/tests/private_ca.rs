use brigalow_core::Purpose;
use brigalow_crypto::{
    certificates, cms,
    private_ca::{self, Issuer, Profile},
    software::Software,
    timestamp, Algorithm, KeyBackend,
};
use der::{Decode, DecodePem, Encode};
use sha2::{Digest, Sha256};
use std::{
    path::Path,
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};
use uuid::Uuid;
use x509_cert::Certificate;
fn command(dir: &Path, args: &[&str], success: bool) {
    let out = Command::new("openssl")
        .current_dir(dir)
        .args(args)
        .output()
        .unwrap();
    assert_eq!(
        out.status.success(),
        success,
        "OpenSSL: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}
fn exercise(backend: &dyn KeyBackend) {
    let temp = tempfile::tempdir().unwrap();
    let d = temp.path();
    command(
        d,
        &[
            "req",
            "-x509",
            "-newkey",
            "ec",
            "-pkeyopt",
            "ec_paramgen_curve:P-256",
            "-nodes",
            "-keyout",
            "root.key",
            "-out",
            "root.pem",
            "-days",
            "30",
            "-subj",
            "/CN=Ephemeral private root",
            "-addext",
            "basicConstraints=critical,CA:TRUE",
            "-addext",
            "keyUsage=critical,keyCertSign,cRLSign",
        ],
        true,
    );
    let ca_key = backend.generate(Algorithm::P256, Purpose::Test).unwrap();
    std::fs::write(
        d.join("issuer.csr"),
        certificates::csr(backend, &ca_key, "CN=Ephemeral HSM issuer").unwrap(),
    )
    .unwrap();
    std::fs::write(d.join("issuer.ext"), "basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\nextendedKeyUsage=codeSigning\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n").unwrap();
    command(
        d,
        &[
            "x509",
            "-req",
            "-in",
            "issuer.csr",
            "-CA",
            "root.pem",
            "-CAkey",
            "root.key",
            "-set_serial",
            "1",
            "-days",
            "20",
            "-extfile",
            "issuer.ext",
            "-out",
            "issuer.pem",
        ],
        true,
    );
    let root = Certificate::from_pem(std::fs::read(d.join("root.pem")).unwrap())
        .unwrap()
        .to_der()
        .unwrap();
    let intermediate = Certificate::from_pem(std::fs::read(d.join("issuer.pem")).unwrap())
        .unwrap()
        .to_der()
        .unwrap();
    let ca = Issuer::new(
        backend,
        &ca_key,
        vec![intermediate.clone()],
        vec![root.clone()],
    )
    .unwrap();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    // 32473 is the reserved documentation PEN, never a production allocation.
    let profile = Profile {
        id: Uuid::new_v4(),
        oid: "1.3.6.1.4.1.32473.1".into(),
        subject: "CN=Ephemeral daily signer".into(),
    };
    let first = backend.generate(Algorithm::P256, Purpose::Test).unwrap();
    let csr = x509_cert::request::CertReq::from_pem(
        certificates::csr(backend, &first, "CN=Ignored untrusted subject").unwrap(),
    )
    .unwrap()
    .to_der()
    .unwrap();
    assert_eq!(
        private_ca::csr_public_key(&csr).unwrap(),
        backend.public_key(&first).unwrap()
    );
    let mut bad = csr;
    *bad.last_mut().unwrap() ^= 1;
    assert!(private_ca::csr_public_key(&bad).is_err());
    let chain = ca
        .issue(
            &backend.public_key(&first).unwrap(),
            &[1; 16],
            &profile,
            now,
        )
        .unwrap();
    let cert = Certificate::from_der(&chain[0]).unwrap();
    assert_eq!(
        cert.tbs_certificate
            .validity
            .not_after
            .to_unix_duration()
            .as_secs()
            - cert
                .tbs_certificate
                .validity
                .not_before
                .to_unix_duration()
                .as_secs(),
        72 * 3600
    );
    let extension = cert
        .tbs_certificate
        .extensions
        .as_ref()
        .unwrap()
        .iter()
        .find(|e| e.extn_id.to_string() == profile.oid)
        .unwrap();
    let value = der::asn1::Utf8StringRef::from_der(extension.extn_value.as_bytes()).unwrap();
    assert_eq!(value.as_str(), profile.id.to_string());
    std::fs::write(d.join("first.der"), &chain[0]).unwrap();
    command(
        d,
        &[
            "x509",
            "-inform",
            "DER",
            "-in",
            "first.der",
            "-out",
            "first.pem",
        ],
        true,
    );
    let second = backend.generate(Algorithm::P256, Purpose::Test).unwrap();
    let next = ca
        .issue(
            &backend.public_key(&second).unwrap(),
            &[2; 16],
            &profile,
            now + 86400,
        )
        .unwrap();
    std::fs::write(d.join("second.der"), &next[0]).unwrap();
    command(
        d,
        &[
            "x509",
            "-inform",
            "DER",
            "-in",
            "second.der",
            "-out",
            "second.pem",
        ],
        true,
    );
    let crl = ca.crl(1, &[([1; 16], now + 86400)], now + 86400).unwrap();
    std::fs::write(d.join("crl.der"), crl).unwrap();
    command(
        d,
        &["crl", "-inform", "DER", "-in", "crl.der", "-out", "crl.pem"],
        true,
    );
    command(
        d,
        &[
            "crl",
            "-in",
            "crl.pem",
            "-verify",
            "-CAfile",
            "issuer.pem",
            "-noout",
        ],
        true,
    );
    let tomorrow = (now + 86401).to_string();
    for (file, valid) in [("first.pem", false), ("second.pem", true)] {
        command(
            d,
            &[
                "verify",
                "-purpose",
                "any",
                "-attime",
                &tomorrow,
                "-CAfile",
                "root.pem",
                "-untrusted",
                "issuer.pem",
                "-CRLfile",
                "crl.pem",
                "-crl_check",
                file,
            ],
            valid,
        );
    }
    // Long-term validation: authenticate the RFC3161 token at the simulated future
    // clock, then use its authenticated genTime for the signing certificate path.
    std::fs::write(d.join("artifact"), b"ephemeral artifact").unwrap();
    let bundle = ["root.pem", "issuer.pem", "crl.pem"]
        .into_iter()
        .flat_map(|file| std::fs::read(d.join(file)).unwrap())
        .collect::<Vec<_>>();
    std::fs::write(d.join("revocation-trust.pem"), bundle).unwrap();
    for (key, certificates, valid) in [(&first, &chain, false), (&second, &next, true)] {
        let cms = cms::detached(
            backend,
            key,
            &Sha256::digest(b"ephemeral artifact"),
            certificates,
        )
        .unwrap();
        std::fs::write(d.join("day.cms"), cms.der).unwrap();
        command(
            d,
            &[
                "cms",
                "-verify",
                "-binary",
                "-inform",
                "DER",
                "-in",
                "day.cms",
                "-content",
                "artifact",
                "-CAfile",
                "revocation-trust.pem",
                "-purpose",
                "any",
                "-attime",
                &tomorrow,
                "-crl_check",
                "-out",
                "verified",
            ],
            valid,
        );
    }
    let mut signed = cms::detached(
        backend,
        &first,
        &Sha256::digest(b"ephemeral artifact"),
        &chain,
    )
    .unwrap();
    command(
        d,
        &[
            "req",
            "-new",
            "-newkey",
            "ec",
            "-pkeyopt",
            "ec_paramgen_curve:P-256",
            "-nodes",
            "-keyout",
            "tsa.key",
            "-out",
            "tsa.csr",
            "-subj",
            "/CN=Ephemeral test TSA",
        ],
        true,
    );
    std::fs::write(d.join("tsa.ext"), "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=critical,timeStamping\n").unwrap();
    command(
        d,
        &[
            "x509",
            "-req",
            "-in",
            "tsa.csr",
            "-CA",
            "root.pem",
            "-CAkey",
            "root.key",
            "-set_serial",
            "2",
            "-out",
            "tsa.pem",
            "-days",
            "20",
            "-extfile",
            "tsa.ext",
        ],
        true,
    );
    std::fs::write(d.join("serial"), "01").unwrap();
    std::fs::write(d.join("tsa.cnf"),"[tsa]\ndefault_tsa=tsa_config\n[tsa_config]\nserial=serial\ncrypto_device=builtin\nsigner_cert=tsa.pem\ncerts=root.pem\nsigner_key=tsa.key\nsigner_digest=sha256\ndefault_policy=1.2.3.4.1\ndigests=sha256\naccuracy=secs:1\nordering=yes\ntsa_name=yes\ness_cert_id_chain=no\ness_cert_id_alg=sha256\n").unwrap();
    let request = timestamp::request(&signed.signature).unwrap();
    std::fs::write(d.join("query.tsq"), request.to_der().unwrap()).unwrap();
    command(
        d,
        &[
            "ts",
            "-reply",
            "-config",
            "tsa.cnf",
            "-queryfile",
            "query.tsq",
            "-out",
            "reply.tsr",
        ],
        true,
    );
    let tsa = Certificate::from_pem(std::fs::read(d.join("tsa.pem")).unwrap())
        .unwrap()
        .to_der()
        .unwrap();
    let at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let token = timestamp::verify(
        &std::fs::read(d.join("reply.tsr")).unwrap(),
        &request,
        &tsa,
        &[root],
        at,
    )
    .unwrap();
    signed.der = cms::attach_timestamp(&signed.der, &token).unwrap();
    std::fs::write(d.join("signed.cms"), &signed.der).unwrap();
    std::fs::write(d.join("token.der"), &token).unwrap();
    let future = (at + 5 * 86400).to_string();
    command(
        d,
        &[
            "cms",
            "-verify",
            "-binary",
            "-inform",
            "DER",
            "-in",
            "signed.cms",
            "-content",
            "artifact",
            "-CAfile",
            "root.pem",
            "-purpose",
            "any",
            "-attime",
            &future,
            "-out",
            "verified",
        ],
        false,
    );
    command(
        d,
        &[
            "ts",
            "-verify",
            "-token_in",
            "-in",
            "token.der",
            "-queryfile",
            "query.tsq",
            "-CAfile",
            "root.pem",
            "-untrusted",
            "tsa.pem",
            "-attime",
            &future,
        ],
        true,
    );
    // genTime is read from the independently verified token, never from caller metadata.
    let info = cms_token_time(&token);
    command(
        d,
        &[
            "cms",
            "-verify",
            "-binary",
            "-inform",
            "DER",
            "-in",
            "signed.cms",
            "-content",
            "artifact",
            "-CAfile",
            "root.pem",
            "-purpose",
            "any",
            "-attime",
            &info.to_string(),
            "-out",
            "verified",
        ],
        true,
    );
    let mut bad_profile = profile.clone();
    bad_profile.oid = "1.2.3.4".into();
    assert!(ca
        .issue(
            &backend.public_key(&first).unwrap(),
            &[3; 16],
            &bad_profile,
            now
        )
        .is_err());
    let untrusted =
        Issuer::new(backend, &ca_key, vec![intermediate], vec![chain[0].clone()]).unwrap();
    assert!(untrusted
        .issue(
            &backend.public_key(&first).unwrap(),
            &[3; 16],
            &profile,
            now
        )
        .is_err());
}
fn cms_token_time(token: &[u8]) -> u64 {
    let content = ::cms::content_info::ContentInfo::from_der(token).unwrap();
    let signed: ::cms::signed_data::SignedData = content.content.decode_as().unwrap();
    let bytes: der::asn1::OctetString = signed
        .encap_content_info
        .econtent
        .unwrap()
        .decode_as()
        .unwrap();
    x509_tsp::TstInfo::from_der(bytes.as_bytes())
        .unwrap()
        .gen_time
        .to_unix_duration()
        .as_secs()
}
#[test]
fn at_ca_01_02_lab_issuance_and_revocation() {
    exercise(&Software::new(true).unwrap());
}
#[cfg(feature = "pkcs11-tests")]
#[test]
fn at_ca_01_02_hsm_issuance_and_revocation() {
    let backend = brigalow_crypto::pkcs11::Hsm::open(
        Path::new(&std::env::var("BRIGALOW_TEST_HSM_MODULE").unwrap()),
        "brigalow-test",
        std::env::var("BRIGALOW_TEST_HSM_PIN").unwrap(),
    )
    .unwrap();
    exercise(&backend);
}
