//! In-memory test-only keys. No persistence, export, production load or release purpose.
use crate::*;
use p256::ecdsa::{Signature, SigningKey};
use rsa::{pkcs8::EncodePublicKey, RsaPrivateKey};
use signature::{hazmat::PrehashSigner, Signer};
use std::{collections::HashMap, sync::Mutex};
enum Material {
    Rsa(Box<RsaPrivateKey>),
    Ec(SigningKey),
    Ed(ed25519_dalek::SigningKey),
}
struct Stored {
    key: Key,
    material: Material,
    disabled: bool,
}
pub struct Software {
    keys: Mutex<HashMap<Uuid, Stored>>,
}
impl Software {
    pub fn new(lab: bool) -> Result<Self> {
        if !lab {
            return Err(Error::LabOnly);
        }
        Ok(Self {
            keys: Mutex::new(HashMap::new()),
        })
    }
    fn with<T>(&self, key: &Key, action: impl FnOnce(&Stored) -> Result<T>) -> Result<T> {
        let keys = self.keys.lock().map_err(|_| Error::Backend)?;
        let stored = keys.get(&key.id).ok_or(Error::Unavailable)?;
        if stored.disabled
            || stored.key.algorithm != key.algorithm
            || stored.key.purpose != key.purpose
        {
            return Err(Error::Unavailable);
        }
        action(stored)
    }
}
impl KeyBackend for Software {
    fn generate(&self, algorithm: Algorithm, purpose: Purpose) -> Result<Key> {
        if purpose != Purpose::Test {
            return Err(Error::LabOnly);
        }
        let mut rng = rand::rngs::OsRng;
        let material = match algorithm {
            Algorithm::Rsa3072 => Material::Rsa(Box::new(
                RsaPrivateKey::new(&mut rng, 3072).map_err(|_| Error::Backend)?,
            )),
            Algorithm::P256 => Material::Ec(SigningKey::random(&mut rng)),
            Algorithm::Ed25519 => Material::Ed(ed25519_dalek::SigningKey::generate(&mut rng)),
        };
        let key = Key {
            id: Uuid::new_v4(),
            algorithm,
            purpose,
        };
        self.keys.lock().map_err(|_| Error::Backend)?.insert(
            key.id,
            Stored {
                key: key.clone(),
                material,
                disabled: false,
            },
        );
        Ok(key)
    }
    fn public_key(&self, key: &Key) -> Result<Vec<u8>> {
        self.with(key, |s| match &s.material {
            Material::Rsa(k) => k
                .to_public_key()
                .to_public_key_der()
                .map(|d| d.as_bytes().to_vec())
                .map_err(|_| Error::Backend),
            Material::Ec(k) => k
                .verifying_key()
                .to_public_key_der()
                .map(|d| d.as_bytes().to_vec())
                .map_err(|_| Error::Backend),
            Material::Ed(k) => k
                .verifying_key()
                .to_public_key_der()
                .map(|d| d.as_bytes().to_vec())
                .map_err(|_| Error::Backend),
        })
    }
    fn sign_digest(
        &self,
        key: &Key,
        _algorithm: DigestAlgorithm,
        digest: &[u8],
    ) -> Result<Vec<u8>> {
        check_digest(digest)?;
        self.with(key, |s| match &s.material {
            Material::Rsa(k) => k
                .sign_with_rng(
                    &mut rand::rngs::OsRng,
                    rsa::Pkcs1v15Sign::new::<sha2::Sha256>(),
                    digest,
                )
                .map_err(|_| Error::Backend),
            Material::Ec(k) => {
                let signature: Signature = k.sign_prehash(digest).map_err(|_| Error::Backend)?;
                Ok(signature.to_der().as_bytes().to_vec())
            }
            Material::Ed(k) => Ok(k.sign(digest).to_bytes().to_vec()),
        })
    }
    fn sign_message(&self, key: &Key, message: &[u8]) -> Result<Vec<u8>> {
        use sha2::Digest;
        if key.algorithm == Algorithm::Ed25519 {
            self.with(key, |stored| match &stored.material {
                Material::Ed(k) => Ok(k.sign(message).to_bytes().to_vec()),
                _ => Err(Error::Algorithm),
            })
        } else {
            self.sign_digest(key, DigestAlgorithm::Sha256, &sha2::Sha256::digest(message))
        }
    }
    fn disable(&self, key: &Key) -> Result<()> {
        let mut keys = self.keys.lock().map_err(|_| Error::Backend)?;
        let stored = keys.get_mut(&key.id).ok_or(Error::Unavailable)?;
        stored.disabled = true;
        Ok(())
    }
    fn is_lab(&self) -> bool {
        true
    }
}
