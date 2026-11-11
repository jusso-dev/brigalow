use brigalow_core::{Purpose, TrustTier};
use brigalow_crypto::{certificates, software::Software, Algorithm, DigestAlgorithm, KeyBackend};
use sha2::{Digest, Sha256};
use std::{
    path::Path,
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

fn openssl(dir: &Path, args: &[&str]) {
    let output = Command::new("openssl")
        .current_dir(dir)
        .args(args)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "OpenSSL failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}
fn exercise(backend: &dyn KeyBackend, algorithms: &[Algorithm]) {
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    let digest = Sha256::digest(b"Brigalow generated test artifact");
    std::fs::write(d.join("artifact"), b"Brigalow generated test artifact").unwrap();
    std::fs::write(d.join("digest"), digest).unwrap();
    for algorithm in algorithms {
        let key = backend.generate(*algorithm, Purpose::Test).unwrap();
        let public = backend.public_key(&key).unwrap();
        std::fs::write(d.join("public.der"), &public).unwrap();
        let signature = backend
            .sign_digest(&key, DigestAlgorithm::Sha256, &digest)
            .unwrap();
        std::fs::write(d.join("signature"), signature).unwrap();
        let mut args = vec![
            "pkeyutl",
            "-verify",
            "-pubin",
            "-inkey",
            "public.der",
            "-keyform",
            "DER",
            "-sigfile",
            "signature",
            "-in",
            "digest",
        ];
        if *algorithm == Algorithm::Ed25519 {
            args.push("-rawin");
        } else {
            args.extend(["-pkeyopt", "digest:sha256"]);
        }
        openssl(d, &args);
        std::fs::write(d.join("digest"), Sha256::digest(b"tampered")).unwrap();
        assert!(!Command::new("openssl")
            .current_dir(d)
            .args(&args)
            .output()
            .unwrap()
            .status
            .success());
        std::fs::write(d.join("digest"), digest).unwrap();
        assert!(backend
            .sign_digest(&key, DigestAlgorithm::Sha256, &[0; 20])
            .is_err());
        {
            let csr =
                certificates::csr(backend, &key, "CN=Brigalow ephemeral signing key").unwrap();
            std::fs::write(d.join("key.csr"), csr).unwrap();
            openssl(d, &["req", "-in", "key.csr", "-verify", "-noout"]);
            openssl(
                d,
                &[
                    "req",
                    "-x509",
                    "-newkey",
                    "rsa:3072",
                    "-nodes",
                    "-keyout",
                    "ca.key",
                    "-out",
                    "ca.pem",
                    "-days",
                    "1",
                    "-subj",
                    "/CN=Ephemeral test CA",
                    "-addext",
                    "basicConstraints=critical,CA:TRUE",
                    "-addext",
                    "keyUsage=critical,keyCertSign,cRLSign",
                ],
            );
            std::fs::write(d.join("leaf.ext"), "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=codeSigning\n").unwrap();
            openssl(
                d,
                &[
                    "x509",
                    "-req",
                    "-in",
                    "key.csr",
                    "-CA",
                    "ca.pem",
                    "-CAkey",
                    "ca.key",
                    "-CAcreateserial",
                    "-out",
                    "leaf.der",
                    "-outform",
                    "DER",
                    "-days",
                    "1",
                    "-extfile",
                    "leaf.ext",
                ],
            );
            openssl(
                d,
                &["x509", "-in", "ca.pem", "-out", "ca.der", "-outform", "DER"],
            );
            let chain = vec![std::fs::read(d.join("leaf.der")).unwrap()];
            let anchors = vec![std::fs::read(d.join("ca.der")).unwrap()];
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();
            if *algorithm != Algorithm::Ed25519 {
                let cms = brigalow_crypto::cms::detached(backend, &key, &digest, &chain).unwrap();
                std::fs::write(d.join("signature.cms"), cms.der).unwrap();
                openssl(
                    d,
                    &[
                        "cms",
                        "-verify",
                        "-binary",
                        "-inform",
                        "DER",
                        "-in",
                        "signature.cms",
                        "-content",
                        "artifact",
                        "-CAfile",
                        "ca.pem",
                        "-purpose",
                        "any",
                        "-out",
                        "verified",
                    ],
                );
                assert_eq!(
                    std::fs::read(d.join("verified")).unwrap(),
                    b"Brigalow generated test artifact"
                );
            }
            assert_eq!(
                certificates::validate_chain(&public, &chain, &anchors, now).unwrap(),
                TrustTier::Private
            );
            assert_eq!(
                certificates::validate_chain(&public, &chain, &[], now).unwrap(),
                TrustTier::Untrusted
            );
            let mut full_chain = chain.clone();
            full_chain.push(anchors[0].clone());
            assert_eq!(
                certificates::validate_chain(&public, &full_chain, &[], now).unwrap(),
                TrustTier::Untrusted
            );
            assert_eq!(
                certificates::validate_chain(&public, &full_chain, &anchors, now).unwrap(),
                TrustTier::Private
            );
            assert!(
                certificates::validate_chain(&public, &chain, &anchors, now + 86400 * 2).is_err()
            );
            let other = backend.generate(*algorithm, Purpose::Test).unwrap();
            assert!(certificates::validate_chain(
                &backend.public_key(&other).unwrap(),
                &chain,
                &anchors,
                now
            )
            .is_err());
            backend.disable(&other).unwrap();
            let mut corrupt = chain.clone();
            *corrupt[0].last_mut().unwrap() ^= 1;
            assert!(certificates::validate_chain(&public, &corrupt, &anchors, now).is_err());
        }
        backend.disable(&key).unwrap();
        assert!(backend
            .sign_digest(&key, DigestAlgorithm::Sha256, &digest)
            .is_err());
    }
}
#[test]
fn at_key_01_02_and_cert_01_02_software() {
    assert!(Software::new(false).is_err());
    let backend = Software::new(true).unwrap();
    assert!(backend
        .generate(Algorithm::Rsa3072, Purpose::Release)
        .is_err());
    assert!(serde_json::from_str::<Algorithm>("\"rsa2048\"").is_err());
    assert!(serde_json::from_str::<DigestAlgorithm>("\"sha1\"").is_err());
    assert!(!certificates::release_allowed(TrustTier::Lab));
    assert!(!certificates::release_allowed(TrustTier::Untrusted));
    exercise(
        &backend,
        &[Algorithm::Rsa3072, Algorithm::P256, Algorithm::Ed25519],
    );
}
#[cfg(feature = "pkcs11-tests")]
#[test]
fn at_key_03_and_cert_01_02_softhsm() {
    use brigalow_crypto::pkcs11::Hsm;
    let pin = std::env::var("BRIGALOW_TEST_HSM_PIN").expect("run Compose test harness");
    let module = std::env::var("BRIGALOW_TEST_HSM_MODULE").expect("module required");
    let backend = Hsm::open(Path::new(&module), "brigalow-test", pin).unwrap();
    for algorithm in [Algorithm::Rsa3072, Algorithm::P256] {
        let key = backend.generate(algorithm, Purpose::Release).unwrap();
        assert_eq!(backend.protections(&key).unwrap(), (true, false));
        backend.disable(&key).unwrap();
    }
    exercise(&backend, &[Algorithm::Rsa3072, Algorithm::P256]);
}
