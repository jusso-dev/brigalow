//! Optional private CA encoding. Custody and every signature stay in KeyBackend.
//! The caller must durably reserve issuance before invoking this module.
use crate::{certificates, signature_algorithm, Algorithm, Error, Key, KeyBackend, Result};
use brigalow_core::TrustTier;
use der::{
    asn1::{BitString, OctetString, Utf8StringRef},
    Decode, Encode,
};
use ed25519_dalek::pkcs8::DecodePublicKey as _;
use rsa::pkcs8::DecodePublicKey;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{str::FromStr, time::Duration};
use uuid::Uuid;
use x509_cert::{
    crl::{CertificateList, RevokedCert, TbsCertList},
    ext::{
        pkix::{
            AuthorityKeyIdentifier, BasicConstraints, CrlNumber, ExtendedKeyUsage, KeyUsage,
            KeyUsages, SubjectKeyIdentifier,
        },
        AsExtension, Extension,
    },
    name::Name,
    serial_number::SerialNumber,
    time::{Time, Validity},
    Certificate, TbsCertificate, Version,
};

pub const LEAF_SECONDS: u64 = 72 * 60 * 60;
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    pub id: Uuid,
    pub oid: String,
    pub subject: String,
}
impl Profile {
    pub fn validate(&self) -> Result<()> {
        // Private-enterprise arc only. Allocation/ownership remains the operator's responsibility.
        let parts: Vec<_> = self.oid.split('.').collect();
        if !self.oid.starts_with("1.3.6.1.4.1.")
            || parts.len() < 8
            || parts[6].parse::<u32>().map_or(true, |n| n == 0)
            || self.oid.parse::<der::asn1::ObjectIdentifier>().is_err()
            || self.id.is_nil()
            || self.subject.is_empty()
            || self.subject.len() > 1024
            || Name::from_str(&self.subject).is_err()
        {
            return Err(Error::Certificate);
        }
        Ok(())
    }
}
fn time(at: u64) -> Result<Time> {
    let dt = der::DateTime::from_unix_duration(Duration::from_secs(at))
        .map_err(|_| Error::Certificate)?;
    if dt.year() <= der::asn1::UtcTime::MAX_YEAR {
        Ok(Time::UtcTime(
            der::asn1::UtcTime::from_date_time(dt).map_err(|_| Error::Certificate)?,
        ))
    } else {
        Ok(Time::GeneralTime(
            der::asn1::GeneralizedTime::from_date_time(dt),
        ))
    }
}

pub struct Issuer<'a> {
    backend: &'a dyn KeyBackend,
    key: &'a Key,
    chain: Vec<Vec<u8>>,
    anchors: Vec<Vec<u8>>,
    certificate: Certificate,
}
impl<'a> Issuer<'a> {
    /// The CA key must never be registered as an artifact signing key or policy key.
    pub fn new(
        backend: &'a dyn KeyBackend,
        key: &'a Key,
        chain: Vec<Vec<u8>>,
        anchors: Vec<Vec<u8>>,
    ) -> Result<Self> {
        if chain.is_empty()
            || chain.len() > 8
            || anchors.is_empty()
            || anchors.len() > 8
            || chain.iter().chain(&anchors).any(|c| c.len() > 65536)
        {
            return Err(Error::Certificate);
        }
        let certificate = Certificate::from_der(&chain[0]).map_err(|_| Error::Certificate)?;
        let tbs = &certificate.tbs_certificate;
        if tbs
            .subject_public_key_info
            .to_der()
            .map_err(|_| Error::Certificate)?
            != backend.public_key(key)?
            || !tbs
                .get::<BasicConstraints>()
                .map_err(|_| Error::Certificate)?
                .is_some_and(|(_, c)| c.ca)
            || !tbs
                .get::<KeyUsage>()
                .map_err(|_| Error::Certificate)?
                .is_some_and(|(_, k)| k.key_cert_sign() && k.crl_sign())
        {
            return Err(Error::Certificate);
        }
        Ok(Self {
            backend,
            key,
            chain,
            anchors,
            certificate,
        })
    }
    fn authority_id(&self) -> Result<AuthorityKeyIdentifier> {
        let id = self
            .certificate
            .tbs_certificate
            .get::<SubjectKeyIdentifier>()
            .map_err(|_| Error::Certificate)?
            .map(|(_, id)| id.0);
        Ok(AuthorityKeyIdentifier {
            key_identifier: id,
            authority_cert_issuer: None,
            authority_cert_serial_number: None,
        })
    }
    /// Exactly 72 hours. Profile extension is noncritical UTF8String containing its durable UUID.
    pub fn issue(
        &self,
        public_key: &[u8],
        serial: &[u8; 16],
        profile: &Profile,
        at: u64,
    ) -> Result<Vec<Vec<u8>>> {
        profile.validate()?;
        validate_public_key(public_key)?;
        let expires = at.checked_add(LEAF_SECONDS).ok_or(Error::Certificate)?;
        let issuer = &self.certificate.tbs_certificate;
        if at < issuer.validity.not_before.to_unix_duration().as_secs()
            || expires > issuer.validity.not_after.to_unix_duration().as_secs()
        {
            return Err(Error::Certificate);
        }
        let subject = Name::from_str(&profile.subject).map_err(|_| Error::Certificate)?;
        let extensions = vec![
            BasicConstraints {
                ca: false,
                path_len_constraint: None,
            }
            .to_extension(&subject, &[])
            .map_err(|_| Error::Certificate)?,
            KeyUsage(KeyUsages::DigitalSignature.into())
                .to_extension(&subject, &[])
                .map_err(|_| Error::Certificate)?,
            ExtendedKeyUsage(vec!["1.3.6.1.5.5.7.3.3".parse().unwrap()])
                .to_extension(&subject, &[])
                .map_err(|_| Error::Certificate)?,
            self.authority_id()?
                .to_extension(&subject, &[])
                .map_err(|_| Error::Certificate)?,
            SubjectKeyIdentifier(
                OctetString::new(Sha256::digest(public_key).to_vec())
                    .map_err(|_| Error::Certificate)?,
            )
            .to_extension(&subject, &[])
            .map_err(|_| Error::Certificate)?,
            Extension {
                extn_id: profile.oid.parse().map_err(|_| Error::Certificate)?,
                critical: false,
                extn_value: OctetString::new(
                    Utf8StringRef::new(&profile.id.to_string())
                        .map_err(|_| Error::Certificate)?
                        .to_der()
                        .map_err(|_| Error::Certificate)?,
                )
                .map_err(|_| Error::Certificate)?,
            },
        ];
        let tbs = TbsCertificate {
            version: Version::V3,
            serial_number: SerialNumber::new(serial).map_err(|_| Error::Certificate)?,
            signature: signature_algorithm(self.key.algorithm),
            issuer: issuer.subject.clone(),
            validity: Validity {
                not_before: time(at)?,
                not_after: time(expires)?,
            },
            subject,
            subject_public_key_info: spki::SubjectPublicKeyInfoOwned::from_der(public_key)
                .map_err(|_| Error::Certificate)?,
            issuer_unique_id: None,
            subject_unique_id: None,
            extensions: Some(extensions),
        };
        let signature = self
            .backend
            .sign_message(self.key, &tbs.to_der().map_err(|_| Error::Certificate)?)?;
        let certificate = Certificate {
            tbs_certificate: tbs,
            signature_algorithm: signature_algorithm(self.key.algorithm),
            signature: BitString::from_bytes(&signature).map_err(|_| Error::Certificate)?,
        };
        let mut chain = vec![certificate.to_der().map_err(|_| Error::Certificate)?];
        chain.extend(self.chain.clone());
        // Delegate full RFC 5280 path, constraints and signature validation to webpki.
        if certificates::validate_chain(public_key, &chain, &self.anchors, at)?
            != TrustTier::Private
            || certificates::validate_chain(public_key, &chain, &self.anchors, expires)?
                != TrustTier::Private
        {
            return Err(Error::Certificate);
        }
        Ok(chain)
    }
    /// Revocation input comes only from the committed CA ledger. CRLs expire after one day.
    pub fn crl(&self, number: u64, revoked: &[([u8; 16], u64)], at: u64) -> Result<Vec<u8>> {
        if revoked.len() > 100_000 || number == 0 || revoked.iter().any(|(_, t)| *t > at) {
            return Err(Error::Certificate);
        }
        let validity = &self.certificate.tbs_certificate.validity;
        let next = at.checked_add(86400).ok_or(Error::Certificate)?;
        if at < validity.not_before.to_unix_duration().as_secs()
            || next > validity.not_after.to_unix_duration().as_secs()
        {
            return Err(Error::Certificate);
        }
        let issuer = self.certificate.tbs_certificate.subject.clone();
        let extensions = vec![
            self.authority_id()?
                .to_extension(&issuer, &[])
                .map_err(|_| Error::Certificate)?,
            CrlNumber(der::asn1::Uint::new(&number.to_be_bytes()).map_err(|_| Error::Certificate)?)
                .to_extension(&issuer, &[])
                .map_err(|_| Error::Certificate)?,
        ];
        let tbs = TbsCertList {
            version: Version::V2,
            signature: signature_algorithm(self.key.algorithm),
            issuer,
            this_update: time(at)?,
            next_update: Some(time(next)?),
            revoked_certificates: if revoked.is_empty() {
                None
            } else {
                Some(
                    revoked
                        .iter()
                        .map(|(serial, revoked)| {
                            Ok(RevokedCert {
                                serial_number: SerialNumber::new(serial)
                                    .map_err(|_| Error::Certificate)?,
                                revocation_date: time(*revoked)?,
                                crl_entry_extensions: None,
                            })
                        })
                        .collect::<Result<_>>()?,
                )
            },
            crl_extensions: Some(extensions),
        };
        let signature = self
            .backend
            .sign_message(self.key, &tbs.to_der().map_err(|_| Error::Certificate)?)?;
        CertificateList {
            tbs_cert_list: tbs,
            signature_algorithm: signature_algorithm(self.key.algorithm),
            signature: BitString::from_bytes(&signature).map_err(|_| Error::Certificate)?,
        }
        .to_der()
        .map_err(|_| Error::Certificate)
    }
}

pub fn validate_public_key(public: &[u8]) -> Result<Algorithm> {
    use rsa::traits::PublicKeyParts;
    if rsa::PublicKey::from_public_key_der(public).is_ok_and(|k| k.n().bit_width() == 3072) {
        return Ok(Algorithm::Rsa3072);
    }
    if p256::ecdsa::VerifyingKey::from_public_key_der(public).is_ok() {
        return Ok(Algorithm::P256);
    }
    if ed25519_dalek::VerifyingKey::from_public_key_der(public).is_ok() {
        return Ok(Algorithm::Ed25519);
    }
    Err(Error::Algorithm)
}
/// Verify proof of possession, ignoring all CSR-requested identity/extension values.
pub fn csr_public_key(csr: &[u8]) -> Result<Vec<u8>> {
    if csr.len() > 65536 {
        return Err(Error::Certificate);
    }
    let csr = x509_cert::request::CertReq::from_der(csr).map_err(|_| Error::Certificate)?;
    let public = csr
        .info
        .public_key
        .to_der()
        .map_err(|_| Error::Certificate)?;
    let algorithm = validate_public_key(&public)?;
    if csr.algorithm != signature_algorithm(algorithm) {
        return Err(Error::Algorithm);
    }
    let message = csr.info.to_der().map_err(|_| Error::Certificate)?;
    let sig = csr.signature.as_bytes().ok_or(Error::Certificate)?;
    crate::audit::verify_message(algorithm, &public, &message, sig)?;
    Ok(public)
}
