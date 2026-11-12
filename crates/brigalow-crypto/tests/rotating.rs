//! Acceptance checks for rotating-key results (AT-AZ-01, crypto level). Every key and CA is
//! generated with OpenSSL at test time; no network.
use brigalow_crypto::rotating::{verify, Expectation, Remote};
use sha2::{Digest, Sha256};
use std::{
    path::Path,
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

const PROFILE_EKU: &str = "1.3.6.1.4.1.311.97.777.1";

fn openssl(dir: &Path, args: &[&str]) -> Vec<u8> {
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
    output.stdout
}
fn ca(d: &Path, name: &str, issuer: Option<&str>) {
    ca_with(d, name, issuer, "")
}
fn ca_with(d: &Path, name: &str, issuer: Option<&str>, extra: &str) {
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
            &format!("{name}.key"),
            "-out",
            &format!("{name}.csr"),
            "-subj",
            &format!("/CN={name}"),
        ],
    );
    std::fs::write(
        d.join(format!("{name}.ext")),
        format!(
            "basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign\nsubjectKeyIdentifier=hash\n{}{extra}",
            if issuer.is_some() { "authorityKeyIdentifier=keyid:always\n" } else { "" }
        ),
    )
    .unwrap();
    let (key, cert) = (format!("{name}.key"), format!("{name}.csr"));
    let mut args = vec!["x509", "-req", "-in", &cert, "-days", "2", "-out"];
    let out = format!("{name}.pem");
    args.push(&out);
    let ext = format!("{name}.ext");
    args.extend(["-extfile", &ext]);
    let issuer_pem = issuer.map(|i| (format!("{i}.pem"), format!("{i}.key")));
    match &issuer_pem {
        Some((pem, k)) => args.extend(["-CA", pem, "-CAkey", k, "-set_serial", "7"]),
        None => args.extend(["-key", &key]),
    }
    openssl(d, &args);
    openssl(
        d,
        &[
            "x509",
            "-in",
            &out,
            "-outform",
            "DER",
            "-out",
            &format!("{name}.der"),
        ],
    );
}
fn leaf(d: &Path, name: &str, key: &str, issuer: &str, eku: &str, days: &str) {
    openssl(
        d,
        &[
            "req",
            "-new",
            "-key",
            key,
            "-out",
            &format!("{name}.csr"),
            "-subj",
            &format!("/CN={name}"),
        ],
    );
    std::fs::write(
        d.join(format!("{name}.ext")),
        format!("basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage={eku}\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid:always\n"),
    )
    .unwrap();
    openssl(
        d,
        &[
            "x509",
            "-req",
            "-in",
            &format!("{name}.csr"),
            "-CA",
            &format!("{issuer}.pem"),
            "-CAkey",
            &format!("{issuer}.key"),
            "-set_serial",
            "9",
            "-days",
            days,
            "-extfile",
            &format!("{name}.ext"),
            "-out",
            &format!("{name}.pem"),
        ],
    );
    openssl(
        d,
        &[
            "x509",
            "-in",
            &format!("{name}.pem"),
            "-outform",
            "DER",
            "-out",
            &format!("{name}.der"),
        ],
    );
}
fn read(d: &Path, name: &str) -> Vec<u8> {
    std::fs::read(d.join(name)).unwrap()
}
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

#[test]
fn at_az_01_rotating_results_require_anchor_profile_eku_and_valid_signature() {
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    ca(d, "root", None);
    ca(d, "intermediate", Some("root"));
    ca(d, "other-root", None);
    ca(d, "other-intermediate", Some("other-root"));
    // An issuer EKU that excludes code signing must break the path.
    ca_with(
        d,
        "tls-intermediate",
        Some("root"),
        "extendedKeyUsage=serverAuth\n",
    );
    for day in ["day0", "day1"] {
        openssl(
            d,
            &[
                "genpkey",
                "-algorithm",
                "RSA",
                "-pkeyopt",
                "rsa_keygen_bits:3072",
                "-out",
                &format!("{day}.key"),
            ],
        );
    }
    openssl(
        d,
        &[
            "genpkey",
            "-algorithm",
            "RSA",
            "-pkeyopt",
            "rsa_keygen_bits:2048",
            "-out",
            "small.key",
        ],
    );
    let eku = format!("codeSigning,{PROFILE_EKU}");
    leaf(d, "day0", "day0.key", "intermediate", &eku, "3");
    leaf(d, "day1", "day1.key", "intermediate", &eku, "3");
    leaf(d, "foreign", "day0.key", "other-intermediate", &eku, "3");
    leaf(
        d,
        "other-profile",
        "day0.key",
        "intermediate",
        "codeSigning,1.3.6.1.4.1.311.97.777.2",
        "3",
    );
    leaf(
        d,
        "no-codesigning",
        "day0.key",
        "intermediate",
        PROFILE_EKU,
        "3",
    );
    leaf(d, "small", "small.key", "intermediate", &eku, "3");
    leaf(d, "tls-issued", "day0.key", "tls-intermediate", &eku, "3");
    let digest = Sha256::digest(b"rotating fixture").to_vec();
    std::fs::write(d.join("digest"), &digest).unwrap();
    let sign = |key: &str, data: &str| {
        openssl(
            d,
            &[
                "pkeyutl",
                "-sign",
                "-inkey",
                key,
                "-pkeyopt",
                "digest:sha256",
                "-in",
                data,
            ],
        )
    };
    let expectation = Expectation::new(read(d, "root.der"), PROFILE_EKU).unwrap();
    let remote = |leaf: &str, intermediate: &str, key: &str| Remote {
        signature: sign(key, "digest"),
        certificates: vec![
            read(d, &format!("{leaf}.der")),
            read(d, &format!("{intermediate}.der")),
        ],
    };
    // Accepted: today's and the rotated leaf. Order of the bundle is not trusted.
    let verified = verify(
        &remote("day0", "intermediate", "day0.key"),
        &expectation,
        &digest,
        now(),
    )
    .unwrap();
    assert_eq!(verified.leaf(), read(d, "day0.der"));
    let mut reordered = remote("day1", "intermediate", "day1.key");
    reordered.certificates.reverse();
    reordered.certificates.push(read(d, "root.der"));
    let rotated = verify(&reordered, &expectation, &digest, now()).unwrap();
    assert_eq!(rotated.leaf(), read(d, "day1.der"));
    assert_eq!(
        rotated.chain.len(),
        2,
        "pinned anchor is not repeated in the chain"
    );
    // Independent check: OpenSSL accepts the signature with the returned leaf key.
    std::fs::write(d.join("signature"), &rotated.signature).unwrap();
    openssl(
        d,
        &[
            "x509",
            "-in",
            "day1.pem",
            "-pubkey",
            "-noout",
            "-out",
            "day1-public.pem",
        ],
    );
    openssl(
        d,
        &[
            "pkeyutl",
            "-verify",
            "-pubin",
            "-inkey",
            "day1-public.pem",
            "-sigfile",
            "signature",
            "-in",
            "digest",
            "-pkeyopt",
            "digest:sha256",
        ],
    );

    let reject = |remote: Remote, expectation: &Expectation, digest: &[u8], at: u64, why: &str| {
        assert!(verify(&remote, expectation, digest, at).is_err(), "{why}");
    };
    // Wrong anchor: a chain to a different root, or pinning that other root.
    reject(
        remote("foreign", "other-intermediate", "day0.key"),
        &expectation,
        &digest,
        now(),
        "foreign chain",
    );
    let other = Expectation::new(read(d, "other-root.der"), PROFILE_EKU).unwrap();
    reject(
        remote("day0", "intermediate", "day0.key"),
        &other,
        &digest,
        now(),
        "other anchor",
    );
    reject(
        remote("tls-issued", "tls-intermediate", "day0.key"),
        &expectation,
        &digest,
        now(),
        "issuer EKU excludes code signing",
    );
    // Missing intermediate: no path.
    reject(
        Remote {
            signature: sign("day0.key", "digest"),
            certificates: vec![read(d, "day0.der")],
        },
        &expectation,
        &digest,
        now(),
        "no intermediate",
    );
    // Missing or wrong profile EKU, or no code-signing EKU.
    reject(
        remote("other-profile", "intermediate", "day0.key"),
        &expectation,
        &digest,
        now(),
        "other profile",
    );
    reject(
        remote("no-codesigning", "intermediate", "day0.key"),
        &expectation,
        &digest,
        now(),
        "no code signing",
    );
    // Expired leaf (simulated clock four days later) and not-yet-valid leaf.
    reject(
        remote("day0", "intermediate", "day0.key"),
        &expectation,
        &digest,
        now() + 4 * 86400,
        "expired",
    );
    reject(
        remote("day0", "intermediate", "day0.key"),
        &expectation,
        &digest,
        now() - 86400,
        "not yet valid",
    );
    // Signature does not verify: other day's key, corrupted, or over a different digest.
    reject(
        remote("day0", "intermediate", "day1.key"),
        &expectation,
        &digest,
        now(),
        "rotated key mismatch",
    );
    let mut corrupt = remote("day0", "intermediate", "day0.key");
    corrupt.signature[10] ^= 1;
    reject(corrupt, &expectation, &digest, now(), "corrupt signature");
    reject(
        remote("day0", "intermediate", "day0.key"),
        &expectation,
        &Sha256::digest(b"other"),
        now(),
        "wrong digest",
    );
    // Unsupported key size, two leaves, CA-only and malformed bundles.
    reject(
        remote("small", "intermediate", "small.key"),
        &expectation,
        &digest,
        now(),
        "RSA-2048",
    );
    let mut two = remote("day0", "intermediate", "day0.key");
    two.certificates.push(read(d, "day1.der"));
    reject(two, &expectation, &digest, now(), "two leaves");
    reject(
        Remote {
            signature: sign("day0.key", "digest"),
            certificates: vec![read(d, "intermediate.der")],
        },
        &expectation,
        &digest,
        now(),
        "CA only",
    );
    let mut malformed = remote("day0", "intermediate", "day0.key");
    malformed.certificates[0].truncate(100);
    reject(malformed, &expectation, &digest, now(), "malformed");
    // Pinned anchors must be CAs and profile EKUs must be under the Artifact Signing arc.
    assert!(Expectation::new(read(d, "day0.der"), PROFILE_EKU).is_err());
    assert!(Expectation::new(read(d, "root.der"), "1.3.6.1.5.5.7.3.3").is_err());
}
