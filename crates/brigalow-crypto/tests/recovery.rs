#![cfg(feature = "pkcs11-tests")]
use brigalow_core::Purpose;
use brigalow_crypto::{pkcs11::Hsm, Algorithm, DigestAlgorithm, Key, KeyBackend};
use sha2::{Digest, Sha256};
#[test]
fn at_ops_03_restored_key_reference_resolves_without_export() {
    let backend = Hsm::open(
        std::path::Path::new(&std::env::var("BRIGALOW_TEST_HSM_MODULE").unwrap()),
        "brigalow-test",
        std::env::var("BRIGALOW_TEST_HSM_PIN").unwrap(),
    )
    .unwrap();
    if std::env::var_os("BRIGALOW_RECOVERY_CHECK").is_none() {
        let key = backend.generate(Algorithm::P256, Purpose::Test).unwrap();
        let public = backend.public_key(&key).unwrap();
        std::fs::write(
            "/tmp/recovery-key.json",
            serde_json::to_vec(&serde_json::json!({"key":key,"public_key":public})).unwrap(),
        )
        .unwrap();
    } else {
        let value: serde_json::Value =
            serde_json::from_slice(&std::fs::read("/tmp/restored-key.json").unwrap()).unwrap();
        let key: Key = serde_json::from_value(value["key"].clone()).unwrap();
        let public: Vec<u8> = serde_json::from_value(value["public_key"].clone()).unwrap();
        assert_eq!(backend.public_key(&key).unwrap(), public);
        assert_eq!(backend.protections(&key).unwrap(), (true, false));
        let signature = backend
            .sign_digest(
                &key,
                DigestAlgorithm::Sha256,
                &Sha256::digest(b"recovered DB reference"),
            )
            .unwrap();
        brigalow_crypto::audit::verify_message(
            Algorithm::P256,
            &public,
            b"recovered DB reference",
            &signature,
        )
        .unwrap();
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("public.der"), public).unwrap();
        std::fs::write(dir.path().join("signature"), signature).unwrap();
        std::fs::write(
            dir.path().join("digest"),
            Sha256::digest(b"recovered DB reference"),
        )
        .unwrap();
        assert!(std::process::Command::new("openssl")
            .current_dir(dir.path())
            .args([
                "pkeyutl",
                "-verify",
                "-pubin",
                "-keyform",
                "DER",
                "-inkey",
                "public.der",
                "-sigfile",
                "signature",
                "-in",
                "digest",
                "-pkeyopt",
                "digest:sha256"
            ])
            .output()
            .unwrap()
            .status
            .success());
    }
}
