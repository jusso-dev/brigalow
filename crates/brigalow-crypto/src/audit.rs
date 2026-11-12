use crate::{Error, Key, KeyBackend, Result};
use brigalow_core::audit::{Checkpoint, SignedCheckpoint};
use ed25519_dalek::pkcs8::DecodePublicKey as _;
use rsa::pkcs8::DecodePublicKey;
use rsa::signature::Verifier;
/// Vetted signature verification, shared by checkpoint and CSR consumers.
pub fn verify_message(
    algorithm: crate::Algorithm,
    public: &[u8],
    message: &[u8],
    sig: &[u8],
) -> Result<()> {
    let valid = match algorithm {
        crate::Algorithm::Rsa3072 => {
            use rsa::traits::PublicKeyParts;
            let key =
                rsa::PublicKey::from_public_key_der(public).map_err(|_| Error::Certificate)?;
            if key.n().bit_width() != 3072 {
                return Err(Error::Algorithm);
            }
            rsa::pkcs1v15::VerifyingKey::<rsa::sha2::Sha256>::new(key)
                .verify(
                    message,
                    &rsa::pkcs1v15::Signature::try_from(sig).map_err(|_| Error::Certificate)?,
                )
                .is_ok()
        }
        crate::Algorithm::P256 => p256::ecdsa::VerifyingKey::from_public_key_der(public)
            .map_err(|_| Error::Certificate)?
            .verify(
                message,
                &p256::ecdsa::Signature::from_der(sig).map_err(|_| Error::Certificate)?,
            )
            .is_ok(),
        crate::Algorithm::Ed25519 => ed25519_dalek::VerifyingKey::from_public_key_der(public)
            .map_err(|_| Error::Certificate)?
            .verify_strict(
                message,
                &ed25519_dalek::Signature::try_from(sig).map_err(|_| Error::Certificate)?,
            )
            .is_ok(),
    };
    if valid {
        Ok(())
    } else {
        Err(Error::Certificate)
    }
}
pub fn sign(
    backend: &dyn KeyBackend,
    key: &Key,
    checkpoint: Checkpoint,
) -> Result<SignedCheckpoint> {
    if checkpoint.key_id != key.id || checkpoint.algorithm != key.algorithm {
        return Err(Error::Algorithm);
    }
    let signature =
        backend.sign_message(key, &checkpoint.message().map_err(|_| Error::Certificate)?)?;
    Ok(SignedCheckpoint {
        checkpoint,
        signature,
    })
}
pub fn verify(signed: &SignedCheckpoint, trusted_public_key: &[u8]) -> Result<()> {
    verify_message(
        signed.checkpoint.algorithm,
        trusted_public_key,
        &signed
            .checkpoint
            .message()
            .map_err(|_| Error::Certificate)?,
        &signed.signature,
    )
}
