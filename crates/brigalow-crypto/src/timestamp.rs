//! RFC 3161: bounded HTTPS transport, nonce/imprint binding and pinned TSA signer verification.
use crate::{
    cms::{oid, sha256_algorithm},
    Error, Result,
};
use ::cms::{
    content_info::ContentInfo,
    signed_data::{SignedData, SignerIdentifier},
};
use cmpv2::status::PkiStatus;
use der::{
    asn1::{Int, OctetString, Uint},
    Decode, Encode,
};
use futures_util::StreamExt;
use sha2::{Digest, Sha256};
use x509_cert::{ext::pkix::ExtendedKeyUsage, Certificate};
use x509_tsp::{MessageImprint, TimeStampReq, TimeStampResp, TspVersion, TstInfo};

pub fn request(signature: &[u8]) -> Result<TimeStampReq> {
    let bytes = *uuid::Uuid::new_v4().as_bytes();
    Ok(TimeStampReq {
        version: TspVersion::V1,
        message_imprint: MessageImprint {
            hash_algorithm: sha256_algorithm(),
            hashed_message: OctetString::new(Sha256::digest(signature).to_vec())
                .map_err(|_| Error::Certificate)?,
        },
        req_policy: None,
        nonce: Some(nonce(&bytes)?),
        cert_req: true,
        extensions: None,
    })
}
// Uint removes redundant leading zeros; conversion adds a sign byte only when needed.
// Int::new alone preserves redundant zeros, which a TSA normalises before echoing.
fn nonce(bytes: &[u8]) -> Result<Int> {
    Ok(Uint::new(bytes).map_err(|_| Error::Certificate)?.into())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn nonce_is_canonical_positive_at_every_leading_byte_boundary() {
        for first in 0..=255 {
            for second in [0, 1, 127, 128, 255] {
                let mut bytes = [0u8; 16];
                bytes[0] = first;
                bytes[1] = second;
                bytes[15] = 1;
                let n = nonce(&bytes).unwrap();
                let encoded = n.to_der().unwrap();
                assert_eq!(Int::from_der(&encoded).unwrap(), n);
                assert_eq!(
                    Uint::from_der(&encoded).unwrap(),
                    Uint::new(&bytes).unwrap()
                );
            }
        }
    }
}
/// Only the configured signer is accepted. Token-supplied certificates cannot select trust.
pub fn verify(
    response: &[u8],
    request: &TimeStampReq,
    signer_der: &[u8],
    anchors: &[Vec<u8>],
    now: u64,
) -> Result<Vec<u8>> {
    let error = |_| Error::Certificate;
    let response = TimeStampResp::from_der(response).map_err(error)?;
    if !matches!(
        response.status.status,
        PkiStatus::Accepted | PkiStatus::GrantedWithMods
    ) || response.status.fail_info.is_some()
    {
        return Err(Error::Certificate);
    }
    let token = response.time_stamp_token.ok_or(Error::Certificate)?;
    if token.content_type != oid("1.2.840.113549.1.7.2") {
        return Err(Error::Certificate);
    }
    let data: SignedData = token.content.decode_as().map_err(error)?;
    if data.encap_content_info.econtent_type != oid("1.2.840.113549.1.9.16.1.4")
        || data.signer_infos.0.len() != 1
    {
        return Err(Error::Certificate);
    }
    let content: OctetString = data
        .encap_content_info
        .econtent
        .as_ref()
        .ok_or(Error::Certificate)?
        .decode_as()
        .map_err(error)?;
    let info = TstInfo::from_der(content.as_bytes()).map_err(error)?;
    if info.message_imprint != request.message_imprint
        || info.nonce != request.nonce
        || info.gen_time.to_unix_duration().as_secs().abs_diff(now) > 300
        || info.extensions.is_some()
    {
        return Err(Error::Certificate);
    }
    let cert = Certificate::from_der(signer_der).map_err(error)?;
    let (critical, eku) = cert
        .tbs_certificate
        .get::<ExtendedKeyUsage>()
        .map_err(error)?
        .ok_or(Error::Certificate)?;
    if !critical || eku.0 != vec![oid("1.3.6.1.5.5.7.3.8")] {
        return Err(Error::Certificate);
    }
    let signer = data.signer_infos.0.get(0).ok_or(Error::Certificate)?;
    if signer.sid
        != SignerIdentifier::IssuerAndSerialNumber(::cms::cert::IssuerAndSerialNumber {
            issuer: cert.tbs_certificate.issuer,
            serial_number: cert.tbs_certificate.serial_number,
        })
        || signer.digest_alg.oid != sha256_algorithm().oid
    {
        return Err(Error::Certificate);
    }
    let attrs = signer.signed_attrs.as_ref().ok_or(Error::Certificate)?;
    for (name, expected) in [
        (
            "1.2.840.113549.1.9.3",
            der::Any::encode_from(&data.encap_content_info.econtent_type).map_err(error)?,
        ),
        (
            "1.2.840.113549.1.9.4",
            der::Any::encode_from(
                &OctetString::new(Sha256::digest(content.as_bytes()).to_vec()).map_err(error)?,
            )
            .map_err(error)?,
        ),
    ] {
        let matches: Vec<_> = attrs.iter().filter(|a| a.oid == oid(name)).collect();
        if matches.len() != 1
            || matches[0].values.len() != 1
            || matches[0].values.get(0) != Some(&expected)
        {
            return Err(Error::Certificate);
        }
    }
    let leaf = rustls_pki_types::CertificateDer::from(signer_der);
    let end = webpki::EndEntityCert::try_from(&leaf).map_err(|_| Error::Certificate)?;
    let roots: Vec<_> = anchors
        .iter()
        .map(|a| rustls_pki_types::CertificateDer::from(a.as_slice()))
        .collect();
    let roots = roots
        .iter()
        .map(|a| webpki::anchor_from_trusted_cert(a).map_err(|_| Error::Certificate))
        .collect::<Result<Vec<_>>>()?;
    let intermediates = data
        .certificates
        .as_ref()
        .map(|certs| {
            certs
                .0
                .iter()
                .filter_map(|c| match c {
                    ::cms::cert::CertificateChoices::Certificate(c) => c.to_der().ok(),
                    _ => None,
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    if intermediates.len() > 10 {
        return Err(Error::Certificate);
    }
    let intermediates: Vec<_> = intermediates
        .iter()
        .map(|c| rustls_pki_types::CertificateDer::from(c.as_slice()))
        .collect();
    end.verify_for_usage(
        webpki::ALL_VERIFICATION_ALGS,
        &roots,
        &intermediates,
        rustls_pki_types::UnixTime::since_unix_epoch(std::time::Duration::from_secs(now)),
        webpki::KeyUsage::required(&[0x2b, 6, 1, 5, 5, 7, 3, 8]),
        None,
        None,
    )
    .map_err(|_| Error::Certificate)?;
    let algorithm: &dyn rustls_pki_types::SignatureVerificationAlgorithm =
        match signer.signature_algorithm.oid.to_string().as_str() {
            "1.2.840.113549.1.1.1" | "1.2.840.113549.1.1.11" => {
                webpki::ring::RSA_PKCS1_2048_8192_SHA256
            }
            "1.2.840.10045.4.3.2" => webpki::ring::ECDSA_P256_SHA256,
            _ => return Err(Error::Algorithm),
        };
    end.verify_signature(
        algorithm,
        &attrs.to_der().map_err(error)?,
        signer.signature.as_bytes(),
    )
    .map_err(|_| Error::Certificate)?;
    token.to_der().map_err(error)
}
#[derive(Clone)]
pub struct Client {
    http: reqwest::Client,
    url: reqwest::Url,
    signer: Vec<u8>,
    anchors: Vec<Vec<u8>>,
}
impl Client {
    pub fn new(
        url: &str,
        tls_ca_pem: Option<&[u8]>,
        signer: Vec<u8>,
        anchors: Vec<Vec<u8>>,
    ) -> Result<Self> {
        let url = reqwest::Url::parse(url).map_err(|_| Error::Certificate)?;
        if url.scheme() != "https"
            || url.host_str().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.fragment().is_some()
        {
            return Err(Error::Certificate);
        }
        if signer.len() > 65536 || anchors.len() > 32 || anchors.iter().any(|a| a.len() > 65536) {
            return Err(Error::Certificate);
        }
        let mut builder = reqwest::Client::builder()
            .https_only(true)
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(std::time::Duration::from_secs(5));
        if let Some(ca) = tls_ca_pem {
            builder = builder.add_root_certificate(
                reqwest::Certificate::from_pem(ca).map_err(|_| Error::Certificate)?,
            );
        }
        Ok(Self {
            http: builder.build().map_err(|_| Error::Backend)?,
            url,
            signer,
            anchors,
        })
    }
    pub async fn stamp(&self, signature: &[u8], now: u64) -> Result<Vec<u8>> {
        let request = request(signature)?;
        let response = self
            .http
            .post(self.url.clone())
            .header("content-type", "application/timestamp-query")
            .body(request.to_der().map_err(|_| Error::Certificate)?)
            .send()
            .await
            .map_err(|_| Error::Backend)?;
        if !response.status().is_success()
            || response
                .headers()
                .get("content-type")
                .and_then(|s| s.to_str().ok())
                .is_none_or(|s| s.split(';').next() != Some("application/timestamp-reply"))
        {
            return Err(Error::Certificate);
        }
        let mut stream = response.bytes_stream();
        let mut bytes = vec![];
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|_| Error::Backend)?;
            if bytes.len() + chunk.len() > 1048576 {
                return Err(Error::Certificate);
            }
            bytes.extend_from_slice(&chunk);
        }
        verify(&bytes, &request, &self.signer, &self.anchors, now)
    }
}
/// Decode helper for offline consumers; never substitutes for `verify`.
pub fn token_info(token: &[u8]) -> Result<TstInfo> {
    let token = ContentInfo::from_der(token).map_err(|_| Error::Certificate)?;
    let data: SignedData = token.content.decode_as().map_err(|_| Error::Certificate)?;
    let content: OctetString = data
        .encap_content_info
        .econtent
        .ok_or(Error::Certificate)?
        .decode_as()
        .map_err(|_| Error::Certificate)?;
    TstInfo::from_der(content.as_bytes()).map_err(|_| Error::Certificate)
}
