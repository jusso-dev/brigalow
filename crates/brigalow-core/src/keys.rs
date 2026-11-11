//! Public key metadata and lifecycle. No private material or I/O.
use crate::{Purpose, TrustTier};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Algorithm {
    Rsa3072,
    P256,
    Ed25519,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DigestAlgorithm {
    Sha256,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Key {
    pub id: Uuid,
    pub algorithm: Algorithm,
    pub purpose: Purpose,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyState {
    Generated,
    Certified,
    Active,
    Disabled,
    Retired,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyRecord {
    pub key: Key,
    pub project: Uuid,
    pub backend: String,
    pub state: KeyState,
    pub offline: bool,
    pub trust: TrustTier,
    pub anchor: Option<String>,
    pub public_key: Vec<u8>,
    pub chain: Vec<Vec<u8>>,
    pub revision: i64,
}
impl KeyRecord {
    pub fn activate(&mut self) -> bool {
        if !matches!(self.state, KeyState::Generated | KeyState::Certified) {
            return false;
        }
        if self.key.purpose == Purpose::Release
            && !matches!(self.trust, TrustTier::Private | TrustTier::ExternalCa)
        {
            return false;
        }
        self.state = KeyState::Active;
        true
    }
}

/// Recheck at both policy binding and each sign decision.
pub fn binding_allowed(key: &KeyRecord, purpose: Purpose, lab: bool) -> bool {
    key.state == KeyState::Active
        && key.key.purpose == purpose
        && (purpose == Purpose::Test
            || (!lab && matches!(key.trust, TrustTier::Private | TrustTier::ExternalCa)))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn release_bindings_require_matching_purpose_active_key_and_trusted_hsm() {
        let mut key = KeyRecord {
            key: Key {
                id: Uuid::new_v4(),
                algorithm: Algorithm::P256,
                purpose: Purpose::Release,
            },
            project: Uuid::new_v4(),
            backend: "hsm".into(),
            state: KeyState::Active,
            offline: false,
            trust: TrustTier::Untrusted,
            anchor: None,
            public_key: vec![],
            chain: vec![],
            revision: 0,
        };
        assert!(!binding_allowed(&key, Purpose::Release, false));
        key.trust = TrustTier::Private;
        assert!(binding_allowed(&key, Purpose::Release, false));
        assert!(!binding_allowed(&key, Purpose::Release, true));
        assert!(!binding_allowed(&key, Purpose::Test, false));
        key.state = KeyState::Disabled;
        assert!(!binding_allowed(&key, Purpose::Release, false));
        key.state = KeyState::Generated;
        key.trust = TrustTier::Untrusted;
        assert!(!key.activate());
    }
}
