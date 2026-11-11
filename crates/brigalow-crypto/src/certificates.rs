use crate::*;
use brigalow_core::TrustTier;
use der::{asn1::BitString, Decode, Encode, EncodePem};
use std::str::FromStr;
use x509_cert::{
    name::Name,
    request::{CertReq, CertReqInfo, Version},
    Certificate,
};
/// A PKCS#10 request signed by the backend, without reading private key material.
pub fn csr(backend: &dyn KeyBackend, key: &Key, subject: &str) -> Result<String> {
    let info = CertReqInfo {
        version: Version::V1,
        subject: Name::from_str(subject).map_err(|_| Error::Certificate)?,
        public_key: spki::SubjectPublicKeyInfoOwned::from_der(&backend.public_key(key)?)
            .map_err(|_| Error::Certificate)?,
        attributes: Default::default(),
    };
    let signature = backend.sign_message(key, &info.to_der().map_err(|_| Error::Certificate)?)?;
    CertReq {
        info,
        algorithm: signature_algorithm(key.algorithm),
        signature: BitString::from_bytes(&signature).map_err(|_| Error::Certificate)?,
    }
    .to_pem(der::pem::LineEnding::LF)
    .map_err(|_| Error::Certificate)
}
/// RFC 5280 path validation is delegated to webpki, with a required code-signing EKU.
pub fn validate_chain(
    public_key: &[u8],
    chain: &[Vec<u8>],
    anchors: &[Vec<u8>],
    at: u64,
) -> Result<TrustTier> {
    if chain.is_empty() || chain.len() > 10 || chain.iter().chain(anchors).any(|c| c.len() > 65536)
    {
        return Err(Error::Certificate);
    }
    let leaf = Certificate::from_der(&chain[0]).map_err(|_| Error::Certificate)?;
    if leaf
        .tbs_certificate
        .get::<x509_cert::ext::pkix::BasicConstraints>()
        .map_err(|_| Error::Certificate)?
        .is_some_and(|(_, constraints)| constraints.ca)
    {
        return Err(Error::Certificate);
    }
    let validity = &leaf.tbs_certificate.validity;
    if at < validity.not_before.to_unix_duration().as_secs()
        || at > validity.not_after.to_unix_duration().as_secs()
    {
        return Err(Error::Certificate);
    }
    let (_, eku) = leaf
        .tbs_certificate
        .get::<x509_cert::ext::pkix::ExtendedKeyUsage>()
        .map_err(|_| Error::Certificate)?
        .ok_or(Error::Certificate)?;
    if !eku
        .0
        .contains(&"1.3.6.1.5.5.7.3.3".parse().expect("code-signing OID"))
    {
        return Err(Error::Certificate);
    }
    if let Some((_, usage)) = leaf
        .tbs_certificate
        .get::<x509_cert::ext::pkix::KeyUsage>()
        .map_err(|_| Error::Certificate)?
    {
        if !usage.digital_signature() {
            return Err(Error::Certificate);
        }
    }
    if leaf
        .tbs_certificate
        .subject_public_key_info
        .to_der()
        .map_err(|_| Error::Certificate)?
        != public_key
    {
        return Err(Error::Certificate);
    }
    let leaf_der = rustls_pki_types::CertificateDer::from(chain[0].as_slice());
    let end = webpki::EndEntityCert::try_from(&leaf_der).map_err(|_| Error::Certificate)?;
    for certificate in chain.iter().skip(1) {
        Certificate::from_der(certificate).map_err(|_| Error::Certificate)?;
    }
    // Without a configured anchor, no path can establish trust. In particular, do
    // not treat a supplied self-signed root as an intermediate in an empty trust store.
    if anchors.is_empty() {
        return Ok(TrustTier::Untrusted);
    }
    let intermediates: Vec<_> = chain
        .iter()
        .skip(1)
        .map(|c| rustls_pki_types::CertificateDer::from(c.as_slice()))
        .collect();
    let anchor_der: Vec<_> = anchors
        .iter()
        .map(|c| rustls_pki_types::CertificateDer::from(c.as_slice()))
        .collect();
    let roots: Vec<_> = anchor_der
        .iter()
        .map(|c| webpki::anchor_from_trusted_cert(c).map_err(|_| Error::Certificate))
        .collect::<Result<_>>()?;
    let usage = webpki::KeyUsage::required(&[0x2b, 6, 1, 5, 5, 7, 3, 3]);
    let time = rustls_pki_types::UnixTime::since_unix_epoch(std::time::Duration::from_secs(at));
    match end.verify_for_usage(
        webpki::ALL_VERIFICATION_ALGS,
        &roots,
        &intermediates,
        time,
        usage,
        None,
        None,
    ) {
        Ok(_) => Ok(TrustTier::Private),
        Err(webpki::Error::UnknownIssuer) => Ok(TrustTier::Untrusted),
        Err(_) => Err(Error::Certificate),
    }
}
pub fn release_allowed(tier: TrustTier) -> bool {
    matches!(tier, TrustTier::Private | TrustTier::ExternalCa)
}
