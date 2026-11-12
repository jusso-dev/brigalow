//! Contract for backends whose signing key and certificate rotate (currently `artifact_signing`).
//!
//! Such a backend cannot be checked against a pinned public key. It returns a signature plus the
//! certificate bundle for each operation and acts only as transport. Acceptance is decided here,
//! outside the backend, before any output exists:
//! (a) parse the returned bundle; (b) validate it to the operator-pinned anchor at the current
//! time with code-signing usage and the configured profile EKU (leaf rules shared with every
//! backend; webpki path validation to the pinned anchor only); (c) verify the signature over the
//! submitted digest with the leaf public key (RustCrypto); (d) return the leaf for recording.
use crate::{certificates, check_digest, Algorithm, Error, Key, KeyBackend, Result};
use der::{asn1::ObjectIdentifier, Decode, Encode};
use rsa::pkcs8::DecodePublicKey;
use x509_cert::{
    ext::pkix::{BasicConstraints, ExtendedKeyUsage},
    Certificate,
};

/// Every Artifact Signing profile EKU sits under this Microsoft arc.
pub const PROFILE_EKU_PREFIX: &str = "1.3.6.1.4.1.311.97.";
/// EKUs Microsoft documents as shared, not profile-specific: `.1.0` marks every Public Trust
/// certificate, and the `.1.3.1` / `.1.4.1` arcs are type prefixes. Pinning one of these would
/// accept another subscriber's signature under the same root, so they are refused.
const SHARED_EKUS: [&str; 3] = [
    "1.3.6.1.4.1.311.97.1.0",
    "1.3.6.1.4.1.311.97.1.3.1",
    "1.3.6.1.4.1.311.97.1.4.1",
];
/// DER content octets of id-kp-codeSigning (1.3.6.1.5.5.7.3.3).
const CODE_SIGNING: &[u8] = &[0x2b, 6, 1, 5, 5, 7, 3, 3];
const MAX_CERTIFICATES: usize = 10;
const MAX_CERTIFICATE: usize = 65536;

/// Operator-pinned identity a rotating result must prove. Never taken from the remote service.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Expectation {
    pub anchor: Vec<u8>,
    pub profile_eku: ObjectIdentifier,
}
impl Expectation {
    pub fn new(anchor: Vec<u8>, profile_eku: &str) -> Result<Self> {
        if anchor.is_empty() || anchor.len() > MAX_CERTIFICATE {
            return Err(Error::Certificate);
        }
        let certificate = Certificate::from_der(&anchor).map_err(|_| Error::Certificate)?;
        // The pinned anchor must be a CA certificate, never a leaf.
        if !certificate
            .tbs_certificate
            .get::<BasicConstraints>()
            .map_err(|_| Error::Certificate)?
            .is_some_and(|(_, constraints)| constraints.ca)
        {
            return Err(Error::Certificate);
        }
        let der = rustls_pki_types::CertificateDer::from(anchor.as_slice());
        webpki::anchor_from_trusted_cert(&der).map_err(|_| Error::Certificate)?;
        if SHARED_EKUS.contains(&profile_eku) {
            return Err(Error::Certificate);
        }
        let suffix = profile_eku
            .strip_prefix(PROFILE_EKU_PREFIX)
            .ok_or(Error::Certificate)?;
        if profile_eku.len() > 128
            || suffix.is_empty()
            || !suffix
                .split('.')
                .all(|arc| !arc.is_empty() && arc.bytes().all(|b| b.is_ascii_digit()))
        {
            return Err(Error::Certificate);
        }
        let oid: ObjectIdentifier = profile_eku.parse().map_err(|_| Error::Certificate)?;
        // Reject non-canonical spellings such as leading zeros.
        if oid.to_string() != profile_eku {
            return Err(Error::Certificate);
        }
        Ok(Self {
            anchor,
            profile_eku: oid,
        })
    }
}

/// Untrusted remote output, exactly as received.
pub struct Remote {
    pub signature: Vec<u8>,
    pub certificates: Vec<Vec<u8>>,
}
/// One remote attempt. The operation ID is kept even on failure so it can be audited.
pub struct Attempt {
    pub operation_id: Option<String>,
    pub outcome: Result<Remote>,
}
impl Attempt {
    pub fn failed(operation_id: Option<String>, error: Error) -> Self {
        Self {
            operation_id,
            outcome: Err(error),
        }
    }
}
/// An accepted result: verified signature and the validated chain, leaf first.
#[derive(Debug)]
pub struct Verified {
    pub signature: Vec<u8>,
    pub chain: Vec<Vec<u8>>,
}
impl Verified {
    pub fn leaf(&self) -> &[u8] {
        &self.chain[0]
    }
}

fn is_ca(certificate: &Certificate) -> Result<bool> {
    Ok(certificate
        .tbs_certificate
        .get::<BasicConstraints>()
        .map_err(|_| Error::Certificate)?
        .is_some_and(|(_, constraints)| constraints.ca))
}

/// Steps (a) and (b): parse an untrusted bundle and validate it to the pinned anchor at `at`.
/// Returns the chain (leaf first, pinned anchor and duplicates removed) and the leaf SPKI.
pub fn validate_certificates(
    certificates: &[Vec<u8>],
    expectation: &Expectation,
    at: u64,
) -> Result<(Vec<Vec<u8>>, Vec<u8>)> {
    if certificates.is_empty()
        || certificates.len() > MAX_CERTIFICATES
        || certificates
            .iter()
            .any(|c| c.is_empty() || c.len() > MAX_CERTIFICATE)
    {
        return Err(Error::Certificate);
    }
    // Bundle order is not trusted: exactly one non-CA certificate is the leaf.
    let mut leaf = None;
    let mut intermediates = Vec::new();
    for der in certificates {
        let certificate = Certificate::from_der(der).map_err(|_| Error::Certificate)?;
        if is_ca(&certificate)? {
            if *der != expectation.anchor && !intermediates.contains(der) {
                intermediates.push(der.clone());
            }
        } else if leaf.replace((der.clone(), certificate)).is_some() {
            return Err(Error::Certificate);
        }
    }
    let (leaf_der, leaf) = leaf.ok_or(Error::Certificate)?;
    let public = leaf
        .tbs_certificate
        .subject_public_key_info
        .to_der()
        .map_err(|_| Error::Certificate)?;
    if crate::private_ca::validate_public_key(&public)? != Algorithm::Rsa3072 {
        return Err(Error::Algorithm);
    }
    let mut chain = vec![leaf_der];
    chain.extend(intermediates);
    // Leaf constraints shared with every backend: CA=false, current validity, code-signing EKU
    // present, digital-signature usage and SPKI match. No anchor here, so no trust result yet.
    certificates::validate_chain(&public, &chain, &[], at)?;
    // Path to the pinned anchor only, at `at`, via webpki. Issuer EKUs are optional in RFC 5280
    // (an intermediate may omit the extension) but, when present, must include code signing.
    let leaf_ref = rustls_pki_types::CertificateDer::from(chain[0].as_slice());
    let end = webpki::EndEntityCert::try_from(&leaf_ref).map_err(|_| Error::Certificate)?;
    let issuers: Vec<_> = chain
        .iter()
        .skip(1)
        .map(|c| rustls_pki_types::CertificateDer::from(c.as_slice()))
        .collect();
    let anchor = rustls_pki_types::CertificateDer::from(expectation.anchor.as_slice());
    let roots = [webpki::anchor_from_trusted_cert(&anchor).map_err(|_| Error::Certificate)?];
    end.verify_for_usage(
        webpki::ALL_VERIFICATION_ALGS,
        &roots,
        &issuers,
        rustls_pki_types::UnixTime::since_unix_epoch(std::time::Duration::from_secs(at)),
        webpki::KeyUsage::required_if_present(CODE_SIGNING),
        None,
        None,
    )
    .map_err(|_| Error::Certificate)?;
    let (_, eku) = leaf
        .tbs_certificate
        .get::<ExtendedKeyUsage>()
        .map_err(|_| Error::Certificate)?
        .ok_or(Error::Certificate)?;
    if !eku.0.contains(&expectation.profile_eku) {
        return Err(Error::Certificate);
    }
    Ok((chain, public))
}

/// Accept a remote result only if every check passes. Any failure means no output.
pub fn verify(
    remote: &Remote,
    expectation: &Expectation,
    digest: &[u8],
    at: u64,
) -> Result<Verified> {
    check_digest(digest)?;
    let (chain, public) = validate_certificates(&remote.certificates, expectation, at)?;
    // (c) RSASSA-PKCS1-v1_5 SHA-256 over exactly the submitted digest, with the leaf key.
    if remote.signature.len() != 384 {
        return Err(Error::Backend);
    }
    rsa::PublicKey::from_public_key_der(&public)
        .map_err(|_| Error::Certificate)?
        .pkcs1v15_verify_prehash::<rsa::sha2::Sha256>(digest, &remote.signature)
        .map_err(|_| Error::Backend)?;
    Ok(Verified {
        signature: remote.signature.clone(),
        chain,
    })
}

/// One remote signing attempt followed by independent acceptance checks. Never retried.
/// Certificates are validated at the time the remote attempt finishes, not when it started:
/// a certificate that expires while polling must not be accepted.
pub fn sign(
    backend: &dyn KeyBackend,
    key: &Key,
    digest: &[u8],
    accepted: &dyn Fn(&str) -> Result<()>,
) -> (Option<String>, Result<Verified>) {
    if !backend.rotates() {
        return (None, Err(Error::Unavailable));
    }
    let expectation = match backend.rotating(key) {
        Ok(expectation) => expectation,
        Err(error) => return (None, Err(error)),
    };
    if let Err(error) = check_digest(digest) {
        return (None, Err(error));
    }
    let attempt = backend.sign_rotating(key, digest, accepted);
    let result = attempt.outcome.and_then(|remote| {
        let at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| Error::Backend)?
            .as_secs();
        verify(&remote, &expectation, digest, at)
    });
    (attempt.operation_id, result)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn expectation_rejects_wrong_arc_and_non_ca_anchor() {
        for eku in [
            "",
            "1.3.6.1.4.1.311.97",
            "1.3.6.1.4.1.311.97.",
            "1.3.6.1.4.1.311.98.1",
            "1.3.6.1.5.5.7.3.3",
            "1.3.6.1.4.1.311.97.01",
            "1.3.6.1.4.1.311.97.1..2",
            "1.3.6.1.4.1.311.97.1.x",
        ] {
            assert!(Expectation::new(vec![0x30, 0], eku).is_err());
        }
        // Not a certificate at all.
        assert!(Expectation::new(vec![0x30, 0], "1.3.6.1.4.1.311.97.1.2").is_err());
        assert!(Expectation::new(vec![], "1.3.6.1.4.1.311.97.1.2").is_err());
    }
    #[test]
    fn verify_rejects_empty_or_oversized_bundles_before_parsing() {
        let expectation = Expectation {
            anchor: vec![1],
            profile_eku: "1.3.6.1.4.1.311.97.1".parse().unwrap(),
        };
        for certificates in [vec![], vec![vec![0u8; 10]; 11], vec![vec![]]] {
            let remote = Remote {
                signature: vec![0; 384],
                certificates,
            };
            assert!(verify(&remote, &expectation, &[0; 32], 0).is_err());
        }
        let remote = Remote {
            signature: vec![0; 384],
            certificates: vec![vec![0x30, 0]],
        };
        assert!(verify(&remote, &expectation, &[0; 31], 0).is_err());
        assert!(verify(&remote, &expectation, &[0; 32], 0).is_err());
    }
}
