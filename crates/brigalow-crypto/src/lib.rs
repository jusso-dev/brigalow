//! Signing custody boundary. This API deliberately has no private-key export operation.
pub mod attestation;
pub mod audit;
pub mod certificates;
pub mod cms;
pub mod csc_mock;
pub mod pkcs11;
pub mod private_ca;
pub mod software;
pub mod timestamp;
pub use brigalow_core::keys::{Algorithm, DigestAlgorithm, Key};
use brigalow_core::Purpose;
use der::{
    asn1::{Any, OctetString},
    Encode, Sequence,
};
use spki::AlgorithmIdentifierOwned;
use uuid::Uuid;
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("key backend operation failed")]
    Backend,
    #[error("key not found or disabled")]
    Unavailable,
    #[error("algorithm or digest not allowed")]
    Algorithm,
    #[error("software keys are restricted to lab mode and test purpose")]
    LabOnly,
    #[error("invalid certificate or CSR")]
    Certificate,
}
pub type Result<T> = std::result::Result<T, Error>;
pub trait KeyBackend: Send + Sync {
    /// Explicit pre-provisioned remote reference, scoped by operator configuration.
    fn remote_key(&self, _id: Uuid, _org: Uuid, _project: Uuid) -> Result<Key> {
        Err(Error::Unavailable)
    }
    fn generate(&self, algorithm: Algorithm, purpose: Purpose) -> Result<Key>;
    fn public_key(&self, key: &Key) -> Result<Vec<u8>>;
    fn sign_digest(&self, key: &Key, algorithm: DigestAlgorithm, digest: &[u8]) -> Result<Vec<u8>>;
    /// Message signing for PKCS#10 and other ASN.1 protocols. Ed25519 must override this.
    fn sign_message(&self, key: &Key, message: &[u8]) -> Result<Vec<u8>> {
        use sha2::Digest;
        if key.algorithm == Algorithm::Ed25519 {
            return Err(Error::Algorithm);
        }
        self.sign_digest(key, DigestAlgorithm::Sha256, &sha2::Sha256::digest(message))
    }
    fn disable(&self, key: &Key) -> Result<()>;
    fn is_lab(&self) -> bool;
}
pub fn check_digest(digest: &[u8]) -> Result<()> {
    if digest.len() != 32 {
        Err(Error::Algorithm)
    } else {
        Ok(())
    }
}
pub fn signature_algorithm(algorithm: Algorithm) -> AlgorithmIdentifierOwned {
    let (oid, parameters) = match algorithm {
        Algorithm::Rsa3072 => ("1.2.840.113549.1.1.11", Some(Any::null())),
        Algorithm::P256 => ("1.2.840.10045.4.3.2", None),
        Algorithm::Ed25519 => ("1.3.101.112", None),
    };
    AlgorithmIdentifierOwned {
        oid: oid.parse().expect("fixed OID"),
        parameters,
    }
}
// ASN.1 encoding only; PKCS#1 padding and signing are performed by the HSM.
#[derive(Sequence)]
struct DigestInfo {
    algorithm: AlgorithmIdentifierOwned,
    digest: OctetString,
}
pub(crate) fn digest_info(digest: &[u8]) -> Result<Vec<u8>> {
    check_digest(digest)?;
    DigestInfo {
        algorithm: AlgorithmIdentifierOwned {
            oid: "2.16.840.1.101.3.4.2.1".parse().unwrap(),
            parameters: Some(Any::null()),
        },
        digest: OctetString::new(digest).map_err(|_| Error::Algorithm)?,
    }
    .to_der()
    .map_err(|_| Error::Algorithm)
}
