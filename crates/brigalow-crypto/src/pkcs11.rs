use crate::*;
use cryptoki::{
    context::{CInitializeArgs, CInitializeFlags, Pkcs11},
    mechanism::Mechanism,
    object::{Attribute, AttributeType, ObjectClass, ObjectHandle},
    session::{Session, UserType},
    types::AuthPin,
};
use der::{
    asn1::{ObjectIdentifier, OctetString},
    Decode,
};
use rsa::{pkcs8::EncodePublicKey, BigUint, RsaPublicKey};
use std::{path::Path, sync::Mutex};
pub struct Hsm {
    session: Mutex<Session>,
}
impl Hsm {
    /// Never initialise/reset an operator token here. Select its exact label and log in.
    pub fn open(module: &Path, label: &str, pin: String) -> Result<Self> {
        let context = Pkcs11::new(module).map_err(|_| Error::Backend)?;
        context
            .initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK))
            .map_err(|_| Error::Backend)?;
        let slots = context.get_slots_with_token().map_err(|_| Error::Backend)?;
        let matching: Vec<_> = slots
            .into_iter()
            .filter(|slot| {
                context
                    .get_token_info(*slot)
                    .is_ok_and(|i| i.label() == label)
            })
            .collect();
        if matching.len() != 1 {
            return Err(Error::Backend);
        }
        let session = context
            .open_rw_session(matching[0])
            .map_err(|_| Error::Backend)?;
        session
            .login(UserType::User, Some(&AuthPin::new(pin.into())))
            .map_err(|_| Error::Backend)?;
        Ok(Self {
            session: Mutex::new(session),
        })
    }
    fn find(session: &Session, key: &Key, class: ObjectClass) -> Result<ObjectHandle> {
        let objects = session
            .find_objects(&[
                Attribute::Id(key.id.as_bytes().to_vec()),
                Attribute::Class(class),
            ])
            .map_err(|_| Error::Backend)?;
        if objects.len() != 1 {
            return Err(Error::Unavailable);
        }
        Ok(objects[0])
    }
    pub fn protections(&self, key: &Key) -> Result<(bool, bool)> {
        let s = self.session.lock().map_err(|_| Error::Backend)?;
        let object = Self::find(&s, key, ObjectClass::PRIVATE_KEY)?;
        let attributes = s
            .get_attributes(
                object,
                &[AttributeType::Sensitive, AttributeType::Extractable],
            )
            .map_err(|_| Error::Backend)?;
        Ok((
            attributes.contains(&Attribute::Sensitive(true)),
            attributes.contains(&Attribute::Extractable(true)),
        ))
    }
}
impl KeyBackend for Hsm {
    fn generate(&self, algorithm: Algorithm, purpose: Purpose) -> Result<Key> {
        if algorithm == Algorithm::Ed25519 {
            return Err(Error::Algorithm);
        }
        let key = Key {
            id: Uuid::new_v4(),
            algorithm,
            purpose,
        };
        let mut public = vec![
            Attribute::Token(true),
            Attribute::Private(false),
            Attribute::Verify(true),
            Attribute::Id(key.id.as_bytes().to_vec()),
        ];
        let private = vec![
            Attribute::Token(true),
            Attribute::Private(true),
            Attribute::Sign(true),
            Attribute::Sensitive(true),
            Attribute::Extractable(false),
            Attribute::Id(key.id.as_bytes().to_vec()),
        ];
        let mechanism = match algorithm {
            Algorithm::Rsa3072 => {
                public.push(Attribute::ModulusBits(3072.into()));
                public.push(Attribute::PublicExponent(vec![1, 0, 1]));
                Mechanism::RsaPkcsKeyPairGen
            }
            Algorithm::P256 => {
                public.push(Attribute::EcParams(
                    ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7")
                        .to_der()
                        .map_err(|_| Error::Backend)?,
                ));
                Mechanism::EccKeyPairGen
            }
            Algorithm::Ed25519 => return Err(Error::Algorithm),
        };
        let s = self.session.lock().map_err(|_| Error::Backend)?;
        let (public, private) = s
            .generate_key_pair(&mechanism, &public, &private)
            .map_err(|_| Error::Backend)?;
        let attributes = s
            .get_attributes(
                private,
                &[AttributeType::Sensitive, AttributeType::Extractable],
            )
            .map_err(|_| Error::Backend)?;
        if !attributes.contains(&Attribute::Sensitive(true))
            || !attributes.contains(&Attribute::Extractable(false))
        {
            let _ = s.destroy_object(private);
            let _ = s.destroy_object(public);
            return Err(Error::Backend);
        }
        Ok(key)
    }
    fn public_key(&self, key: &Key) -> Result<Vec<u8>> {
        let s = self.session.lock().map_err(|_| Error::Backend)?;
        let object = Self::find(&s, key, ObjectClass::PUBLIC_KEY)?;
        match key.algorithm {
            Algorithm::Rsa3072 => {
                let a = s
                    .get_attributes(
                        object,
                        &[AttributeType::Modulus, AttributeType::PublicExponent],
                    )
                    .map_err(|_| Error::Backend)?;
                let n = a
                    .iter()
                    .find_map(|a| {
                        if let Attribute::Modulus(v) = a {
                            Some(v)
                        } else {
                            None
                        }
                    })
                    .ok_or(Error::Backend)?;
                let e = a
                    .iter()
                    .find_map(|a| {
                        if let Attribute::PublicExponent(v) = a {
                            Some(v)
                        } else {
                            None
                        }
                    })
                    .ok_or(Error::Backend)?;
                RsaPublicKey::new(BigUint::from_bytes_be(n), BigUint::from_bytes_be(e))
                    .map_err(|_| Error::Backend)?
                    .to_public_key_der()
                    .map(|d| d.as_bytes().to_vec())
                    .map_err(|_| Error::Backend)
            }
            Algorithm::P256 => {
                let a = s
                    .get_attributes(object, &[AttributeType::EcPoint])
                    .map_err(|_| Error::Backend)?;
                let point = a
                    .iter()
                    .find_map(|a| {
                        if let Attribute::EcPoint(v) = a {
                            Some(v)
                        } else {
                            None
                        }
                    })
                    .ok_or(Error::Backend)?;
                let point = OctetString::from_der(point).map_err(|_| Error::Backend)?;
                p256::PublicKey::from_sec1_bytes(point.as_bytes())
                    .map_err(|_| Error::Backend)?
                    .to_public_key_der()
                    .map(|d| d.as_bytes().to_vec())
                    .map_err(|_| Error::Backend)
            }
            Algorithm::Ed25519 => Err(Error::Algorithm),
        }
    }
    fn sign_digest(
        &self,
        key: &Key,
        _algorithm: DigestAlgorithm,
        digest: &[u8],
    ) -> Result<Vec<u8>> {
        check_digest(digest)?;
        let s = self.session.lock().map_err(|_| Error::Backend)?;
        let object = Self::find(&s, key, ObjectClass::PRIVATE_KEY)?;
        match key.algorithm {
            Algorithm::Rsa3072 => s
                .sign(&Mechanism::RsaPkcs, object, &digest_info(digest)?)
                .map_err(|_| Error::Backend),
            Algorithm::P256 => {
                let raw = s
                    .sign(&Mechanism::Ecdsa, object, digest)
                    .map_err(|_| Error::Backend)?;
                Ok(p256::ecdsa::Signature::from_slice(&raw)
                    .map_err(|_| Error::Backend)?
                    .to_der()
                    .as_bytes()
                    .to_vec())
            }
            Algorithm::Ed25519 => Err(Error::Algorithm),
        }
    }
    fn disable(&self, key: &Key) -> Result<()> {
        let s = self.session.lock().map_err(|_| Error::Backend)?;
        let object = Self::find(&s, key, ObjectClass::PRIVATE_KEY)?;
        s.update_attributes(object, &[Attribute::Sign(false)])
            .map_err(|_| Error::Backend)
    }
    fn is_lab(&self) -> bool {
        false
    }
}
