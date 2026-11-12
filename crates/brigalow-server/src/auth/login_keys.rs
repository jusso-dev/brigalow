//! Operator-provisioned key ring protecting pending-login PKCE verifiers and nonces at rest.
//! AES-256-GCM through aws-lc-rs `RandomizedNonceKey`: the library generates every nonce.
use super::AuthError;
use aws_lc_rs::aead::{Aad, Nonce, RandomizedNonceKey, AES_256_GCM, NONCE_LEN};
use std::fmt;
use uuid::Uuid;
use zeroize::Zeroizing;

/// Payload/AAD format version, also stored in the row and bound into the AAD.
pub const VERSION: u8 = 1;
/// Committed encryptions allowed per key ID across all instances. Half of the NIST SP 800-38D
/// 8.3 limit (2^32) for random 96-bit nonces, leaving margin for rolled-back, uncounted seals.
pub const MAX_SEALS_PER_KEY: i64 = 1 << 31;
pub const MAX_PREVIOUS_KEYS: usize = 4;
const AAD_DOMAIN: &[u8] = b"brigalow/pending-login\0";

pub fn valid_key_id(id: &str) -> bool {
    (1..=32).contains(&id.len())
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// Associated data: domain || version || org UUID || u16 provider length || provider ||
/// state hash || browser hash || expiry (i64 big-endian Unix ms, DB clock) ||
/// u8 key ID length || key ID. Hashes are fixed-length lowercase hex.
pub fn aad(
    org: Uuid,
    provider: &str,
    state_hash: &str,
    browser_hash: &str,
    expires_ms: i64,
    key_id: &str,
) -> Vec<u8> {
    let mut aad = Vec::with_capacity(AAD_DOMAIN.len() + 128);
    aad.extend_from_slice(AAD_DOMAIN);
    aad.push(VERSION);
    aad.extend_from_slice(org.as_bytes());
    aad.extend_from_slice(&(provider.len() as u16).to_be_bytes());
    aad.extend_from_slice(provider.as_bytes());
    aad.extend_from_slice(state_hash.as_bytes());
    aad.extend_from_slice(browser_hash.as_bytes());
    aad.extend_from_slice(&expires_ms.to_be_bytes());
    aad.push(key_id.len() as u8);
    aad.extend_from_slice(key_id.as_bytes());
    aad
}

/// Plaintext layout: u8 verifier length || verifier || nonce. Both are ASCII base64url.
pub fn encode_secrets(verifier: &str, nonce: &str) -> Result<Zeroizing<Vec<u8>>, AuthError> {
    if verifier.is_empty() || verifier.len() > 128 || nonce.is_empty() || nonce.len() > 128 {
        return Err(AuthError);
    }
    let mut out = Zeroizing::new(Vec::with_capacity(1 + verifier.len() + nonce.len()));
    out.push(verifier.len() as u8);
    out.extend_from_slice(verifier.as_bytes());
    out.extend_from_slice(nonce.as_bytes());
    Ok(out)
}
pub fn decode_secrets(plaintext: &[u8]) -> Result<(&str, &str), AuthError> {
    let (&len, rest) = plaintext.split_first().ok_or(AuthError)?;
    let len = usize::from(len);
    if len == 0 || rest.len() <= len {
        return Err(AuthError);
    }
    let (verifier, nonce) = rest.split_at(len);
    Ok((
        std::str::from_utf8(verifier).map_err(|_| AuthError)?,
        std::str::from_utf8(nonce).map_err(|_| AuthError)?,
    ))
}

pub struct LoginKeys {
    active: String,
    keys: Vec<(String, RandomizedNonceKey)>,
}
impl fmt::Debug for LoginKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LoginKeys")
            .field("active", &self.active)
            .field("material", &"[REDACTED]")
            .finish()
    }
}
impl LoginKeys {
    /// `previous` lists explicitly configured older key IDs still accepted for opening only.
    pub fn new(active: (&str, &[u8]), previous: &[(&str, &[u8])]) -> Result<Self, AuthError> {
        if previous.len() > MAX_PREVIOUS_KEYS {
            return Err(AuthError);
        }
        let all: Vec<(&str, &[u8])> = std::iter::once(active)
            .chain(previous.iter().copied())
            .collect();
        for (i, (id, material)) in all.iter().enumerate() {
            if !valid_key_id(id) || material.len() != 32 {
                return Err(AuthError);
            }
            // Duplicate IDs are ambiguous; reused material would make rotation meaningless.
            if all[..i]
                .iter()
                .any(|(other, m)| other == id || m == material)
            {
                return Err(AuthError);
            }
        }
        let keys = all
            .into_iter()
            .map(|(id, material)| {
                RandomizedNonceKey::new(&AES_256_GCM, material)
                    .map(|key| (id.to_string(), key))
                    .map_err(|_| AuthError)
            })
            .collect::<Result<_, _>>()?;
        Ok(Self {
            active: active.0.to_string(),
            keys,
        })
    }
    pub fn active_id(&self) -> &str {
        &self.active
    }
    pub fn seal(
        &self,
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<([u8; NONCE_LEN], Vec<u8>), AuthError> {
        let key = &self.keys[0].1;
        let mut buffer = plaintext.to_vec();
        let nonce = key
            .seal_in_place_append_tag(Aad::from(aad), &mut buffer)
            .map_err(|_| AuthError)?;
        Ok((*nonce.as_ref(), buffer))
    }
    /// Unknown key ID, malformed nonce or authentication failure all reject.
    pub fn open(
        &self,
        key_id: &str,
        aad: &[u8],
        nonce: &[u8],
        ciphertext: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, AuthError> {
        let (_, key) = self
            .keys
            .iter()
            .find(|(id, _)| id == key_id)
            .ok_or(AuthError)?;
        let nonce = Nonce::try_assume_unique_for_key(nonce).map_err(|_| AuthError)?;
        let mut buffer = Zeroizing::new(ciphertext.to_vec());
        let plaintext = key
            .open_in_place(nonce, Aad::from(aad), &mut buffer[..])
            .map_err(|_| AuthError)?;
        Ok(Zeroizing::new(plaintext.to_vec()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::RngCore;
    fn material() -> [u8; 32] {
        let mut key = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut key);
        key
    }
    #[test]
    fn seal_open_rotation_and_tamper_rejection() {
        let (old, new) = (material(), material());
        let org = Uuid::new_v4();
        let state = "a".repeat(64);
        let before = LoginKeys::new(("k1", &old), &[]).unwrap();
        let after = LoginKeys::new(("k2", &new), &[("k1", &old)]).unwrap();
        let retired = LoginKeys::new(("k2", &new), &[]).unwrap();
        let browser = "c".repeat(64);
        let aad = aad(org, "valid", &state, &browser, 1000, "k1");
        let (nonce, ciphertext) = before.seal(&aad, b"plaintext secret").unwrap();
        assert_eq!(ciphertext.len(), b"plaintext secret".len() + 16);
        assert!(!ciphertext
            .windows(9)
            .any(|w| w == b"plaintext" || w == b"secret\0\0\0"));
        assert_eq!(
            &after.open("k1", &aad, &nonce, &ciphertext).unwrap()[..],
            b"plaintext secret"
        );
        assert!(retired.open("k1", &aad, &nonce, &ciphertext).is_err());
        assert!(after.open("k2", &aad, &nonce, &ciphertext).is_err());
        assert!(after.open("unknown", &aad, &nonce, &ciphertext).is_err());
        for changed in [
            super::aad(Uuid::new_v4(), "valid", &state, &browser, 1000, "k1"),
            super::aad(org, "other", &state, &browser, 1000, "k1"),
            super::aad(org, "valid", &"b".repeat(64), &browser, 1000, "k1"),
            super::aad(org, "valid", &state, &"d".repeat(64), 1000, "k1"),
            super::aad(org, "valid", &state, &browser, 1001, "k1"),
        ] {
            assert!(before.open("k1", &changed, &nonce, &ciphertext).is_err());
        }
        let mut tampered = ciphertext.clone();
        tampered[0] ^= 1;
        assert!(before.open("k1", &aad, &nonce, &tampered).is_err());
        let mut wrong_nonce = nonce;
        wrong_nonce[0] ^= 1;
        assert!(before.open("k1", &aad, &wrong_nonce, &ciphertext).is_err());
        assert!(before.open("k1", &aad, &nonce[..11], &ciphertext).is_err());
        let (verifier, nonce_value) = ("v".repeat(43), "n".repeat(43));
        let encoded = encode_secrets(&verifier, &nonce_value).unwrap();
        assert_eq!(
            decode_secrets(&encoded).unwrap(),
            (verifier.as_str(), nonce_value.as_str())
        );
        assert!(decode_secrets(&encoded[..44]).is_err());
        assert!(decode_secrets(&[]).is_err());
        assert!(encode_secrets("", &nonce_value).is_err());
        // The library chooses a fresh random nonce for every seal.
        let (second, _) = before.seal(&aad, b"plaintext secret").unwrap();
        assert_ne!(nonce, second);
    }
    #[test]
    fn key_ring_validation_and_redaction() {
        let (a, b) = (material(), material());
        assert!(LoginKeys::new(("k1", &a[..31]), &[]).is_err());
        assert!(LoginKeys::new(("bad id", &a), &[]).is_err());
        assert!(LoginKeys::new(("", &a), &[]).is_err());
        assert!(LoginKeys::new(("k1", &a), &[("k1", &b)]).is_err());
        assert!(LoginKeys::new(("k1", &a), &[("k2", &a)]).is_err());
        let many: Vec<_> = (0..5)
            .map(|i| (format!("p{i}"), material()))
            .collect::<Vec<_>>();
        let refs: Vec<(&str, &[u8])> = many.iter().map(|(i, m)| (i.as_str(), &m[..])).collect();
        assert!(LoginKeys::new(("k1", &a), &refs).is_err());
        assert!(LoginKeys::new(("k1", &a), &refs[..4]).is_ok());
        let keys = LoginKeys::new(("k1", &a), &[("k2", &b)]).unwrap();
        let debug = format!("{keys:?}");
        assert!(debug.contains("[REDACTED]") && debug.contains("k1"));
        use base64::Engine;
        for encoded in [
            base64::engine::general_purpose::STANDARD.encode(a),
            a.iter().map(|b| format!("{b:02x}")).collect::<String>(),
        ] {
            assert!(!debug.contains(&encoded));
        }
    }
}
