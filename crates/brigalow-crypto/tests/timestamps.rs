use brigalow_crypto::timestamp;
use der::Encode;
use std::{
    path::Path,
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};
fn openssl(dir: &Path, args: &[&str]) {
    let out = Command::new("openssl")
        .current_dir(dir)
        .args(args)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}
#[test]
fn timestamp_nonce_imprint_signature_and_independent_verification() {
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    openssl(
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
            "ca.key",
            "-out",
            "ca.pem",
            "-days",
            "1",
            "-subj",
            "/CN=Test CA",
            "-addext",
            "basicConstraints=critical,CA:TRUE",
            "-addext",
            "keyUsage=critical,keyCertSign,cRLSign",
        ],
    );
    openssl(
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
            "/CN=Test TSA",
        ],
    );
    std::fs::write(d.join("tsa.ext"),"basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=critical,timeStamping\n").unwrap();
    openssl(
        d,
        &[
            "x509",
            "-req",
            "-in",
            "tsa.csr",
            "-CA",
            "ca.pem",
            "-CAkey",
            "ca.key",
            "-CAcreateserial",
            "-out",
            "tsa.pem",
            "-days",
            "1",
            "-extfile",
            "tsa.ext",
        ],
    );
    openssl(
        d,
        &["x509", "-in", "ca.pem", "-outform", "DER", "-out", "ca.der"],
    );
    openssl(
        d,
        &[
            "x509", "-in", "tsa.pem", "-outform", "DER", "-out", "tsa.der",
        ],
    );
    std::fs::write(d.join("serial"), "01").unwrap();
    std::fs::write(d.join("tsa.cnf"),"[tsa]\ndefault_tsa=tsa_config\n[tsa_config]\nserial=serial\ncrypto_device=builtin\nsigner_cert=tsa.pem\ncerts=ca.pem\nsigner_key=tsa.key\nsigner_digest=sha256\ndefault_policy=1.2.3.4.1\ndigests=sha256\naccuracy=secs:1\nordering=yes\ntsa_name=yes\ness_cert_id_chain=no\ness_cert_id_alg=sha256\n").unwrap();
    let request = timestamp::request(b"test signature bytes").unwrap();
    std::fs::write(d.join("query.tsq"), request.to_der().unwrap()).unwrap();
    openssl(
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
    );
    let response = std::fs::read(d.join("reply.tsr")).unwrap();
    let signer = std::fs::read(d.join("tsa.der")).unwrap();
    let roots = vec![std::fs::read(d.join("ca.der")).unwrap()];
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let token = timestamp::verify(&response, &request, &signer, &roots, now).unwrap();
    std::fs::write(d.join("token.der"), token).unwrap();
    openssl(
        d,
        &[
            "ts",
            "-verify",
            "-in",
            "token.der",
            "-token_in",
            "-queryfile",
            "query.tsq",
            "-CAfile",
            "ca.pem",
            "-untrusted",
            "tsa.pem",
        ],
    );
    let other = timestamp::request(b"test signature bytes").unwrap();
    assert!(timestamp::verify(&response, &other, &signer, &roots, now).is_err());
    let mut wrong = timestamp::request(b"different signature").unwrap();
    wrong.nonce = request.nonce.clone();
    assert!(timestamp::verify(&response, &wrong, &signer, &roots, now).is_err());
    assert!(timestamp::verify(&response, &request, &signer, &[], now).is_err());
    assert!(timestamp::verify(&response, &request, &signer, &roots, now + 301).is_err());
    let mut corrupt = response;
    *corrupt.last_mut().unwrap() ^= 1;
    assert!(timestamp::verify(&corrupt, &request, &signer, &roots, now).is_err());
}
