//! Detached CMS encoding through RustCrypto. The artifact itself is never required.
use crate::*;
use ::cms::{
    cert::{CertificateChoices, IssuerAndSerialNumber},
    content_info::{CmsVersion, ContentInfo},
    signed_data::{
        CertificateSet, EncapsulatedContentInfo, SignedData, SignerIdentifier, SignerInfo,
        SignerInfos,
    },
};
use der::{
    asn1::{ObjectIdentifier, SetOfVec},
    Decode,
};
use x509_cert::{
    attr::{Attribute, Attributes},
    Certificate,
};
pub(crate) fn oid(value: &str) -> ObjectIdentifier {
    value.parse().expect("fixed OID")
}
pub(crate) fn sha256_algorithm() -> AlgorithmIdentifierOwned {
    AlgorithmIdentifierOwned {
        oid: oid("2.16.840.1.101.3.4.2.1"),
        parameters: Some(Any::null()),
    }
}
pub(crate) fn attribute(oid_value: &str, value: Any) -> Result<Attribute> {
    Ok(Attribute {
        oid: oid(oid_value),
        values: SetOfVec::try_from(vec![value]).map_err(|_| Error::Certificate)?,
    })
}
/// Signed attributes bind the digest to the detached data content type.
pub fn signed_attributes(digest: &[u8]) -> Result<Attributes> {
    check_digest(digest)?;
    SetOfVec::try_from(vec![
        attribute(
            "1.2.840.113549.1.9.3",
            Any::encode_from(&oid("1.2.840.113549.1.7.1")).map_err(|_| Error::Certificate)?,
        )?,
        attribute(
            "1.2.840.113549.1.9.4",
            Any::encode_from(&OctetString::new(digest).map_err(|_| Error::Certificate)?)
                .map_err(|_| Error::Certificate)?,
        )?,
    ])
    .map_err(|_| Error::Certificate)
}
pub struct Detached {
    pub der: Vec<u8>,
    pub signature: Vec<u8>,
}
pub fn detached(
    backend: &dyn KeyBackend,
    key: &Key,
    digest: &[u8],
    chain: &[Vec<u8>],
) -> Result<Detached> {
    // RFC 8419 mandates SHA-512 for Ed25519 CMS; this API currently accepts SHA-256 only.
    if key.algorithm == Algorithm::Ed25519 {
        return Err(Error::Algorithm);
    }
    let leaf = Certificate::from_der(chain.first().ok_or(Error::Certificate)?)
        .map_err(|_| Error::Certificate)?;
    if leaf
        .tbs_certificate
        .subject_public_key_info
        .to_der()
        .map_err(|_| Error::Certificate)?
        != backend.public_key(key)?
    {
        return Err(Error::Certificate);
    }
    let attrs = signed_attributes(digest)?;
    let signature = backend.sign_message(key, &attrs.to_der().map_err(|_| Error::Certificate)?)?;
    assemble(attrs, signature, chain, key.algorithm)
}
/// Encode a detached SignedData from signed attributes, their signature and the chain (leaf
/// first). Callers must already have verified the signature against the leaf.
pub fn assemble(
    attrs: Attributes,
    signature: Vec<u8>,
    chain: &[Vec<u8>],
    algorithm: Algorithm,
) -> Result<Detached> {
    let leaf = Certificate::from_der(chain.first().ok_or(Error::Certificate)?)
        .map_err(|_| Error::Certificate)?;
    let signer = SignerInfo {
        version: CmsVersion::V1,
        sid: SignerIdentifier::IssuerAndSerialNumber(IssuerAndSerialNumber {
            issuer: leaf.tbs_certificate.issuer,
            serial_number: leaf.tbs_certificate.serial_number,
        }),
        digest_alg: sha256_algorithm(),
        signed_attrs: Some(attrs),
        signature_algorithm: signature_algorithm(algorithm),
        signature: OctetString::new(signature.clone()).map_err(|_| Error::Certificate)?,
        unsigned_attrs: None,
    };
    let certificates = chain
        .iter()
        .map(|der| {
            Certificate::from_der(der)
                .map(CertificateChoices::Certificate)
                .map_err(|_| Error::Certificate)
        })
        .collect::<Result<Vec<_>>>()?;
    let data = SignedData {
        version: CmsVersion::V1,
        digest_algorithms: SetOfVec::try_from(vec![sha256_algorithm()])
            .map_err(|_| Error::Certificate)?,
        encap_content_info: EncapsulatedContentInfo {
            econtent_type: oid("1.2.840.113549.1.7.1"),
            econtent: None,
        },
        certificates: Some(CertificateSet(
            SetOfVec::try_from(certificates).map_err(|_| Error::Certificate)?,
        )),
        crls: None,
        signer_infos: SignerInfos(
            SetOfVec::try_from(vec![signer]).map_err(|_| Error::Certificate)?,
        ),
    };
    Ok(Detached {
        der: encode(&data)?,
        signature,
    })
}
/// Remote operation ID (if one was received) and the CMS with its validated chain.
pub type RotatingCms = (Option<String>, Result<(Detached, Vec<Vec<u8>>)>);
/// Detached CMS for a rotating-key backend: one remote signature over the signed-attribute
/// digest, accepted only after [`crate::rotating::verify`]. Returns the CMS and validated chain.
pub fn detached_rotating(
    backend: &dyn KeyBackend,
    key: &Key,
    digest: &[u8],
    at: u64,
) -> RotatingCms {
    use sha2::Digest;
    if key.algorithm != Algorithm::Rsa3072 {
        return (None, Err(Error::Algorithm));
    }
    let attrs = match signed_attributes(digest).and_then(|a| {
        let der = a.to_der().map_err(|_| Error::Certificate)?;
        Ok((a, der))
    }) {
        Ok(value) => value,
        Err(error) => return (None, Err(error)),
    };
    let (operation, verified) =
        crate::rotating::sign(backend, key, &sha2::Sha256::digest(&attrs.1), at);
    let result = verified.and_then(|v| {
        let cms = assemble(attrs.0, v.signature, &v.chain, Algorithm::Rsa3072)?;
        Ok((cms, v.chain))
    });
    (operation, result)
}
fn encode(data: &SignedData) -> Result<Vec<u8>> {
    ContentInfo {
        content_type: oid("1.2.840.113549.1.7.2"),
        content: Any::encode_from(data).map_err(|_| Error::Certificate)?,
    }
    .to_der()
    .map_err(|_| Error::Certificate)
}
pub fn attach_timestamp(cms: &[u8], token: &[u8]) -> Result<Vec<u8>> {
    let content = ContentInfo::from_der(cms).map_err(|_| Error::Certificate)?;
    if content.content_type != oid("1.2.840.113549.1.7.2") {
        return Err(Error::Certificate);
    }
    let mut data: SignedData = content
        .content
        .decode_as()
        .map_err(|_| Error::Certificate)?;
    let mut signers = data.signer_infos.0.into_vec();
    if signers.len() != 1 {
        return Err(Error::Certificate);
    }
    let token = ContentInfo::from_der(token).map_err(|_| Error::Certificate)?;
    signers[0].unsigned_attrs = Some(
        SetOfVec::try_from(vec![attribute(
            "1.2.840.113549.1.9.16.2.14",
            Any::encode_from(&token).map_err(|_| Error::Certificate)?,
        )?])
        .map_err(|_| Error::Certificate)?,
    );
    data.signer_infos = SignerInfos(SetOfVec::try_from(signers).map_err(|_| Error::Certificate)?);
    encode(&data)
}
