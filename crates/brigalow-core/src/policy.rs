//! Policy decisions use verified identity claims, never request metadata.
use crate::{
    keys::{binding_allowed, Algorithm, DigestAlgorithm, KeyRecord},
    rbac::{Action, Principal},
    Purpose,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use uuid::Uuid;
/// Verified-claim name recording a non-default workload provider profile. GitHub and other
/// existing principals never carry it, so their behaviour is unchanged.
pub const PROVIDER_CLAIM: &str = "provider";
/// Principals from a non-default provider profile (currently GitLab) have no reviewed
/// protected-ref, workflow or provenance contract. They may use only test-purpose policies
/// without attestation; every other combination fails closed, whatever the provider value.
pub fn provider_allows(policy: &Policy, principal: &Principal) -> bool {
    !principal.claims.contains_key(PROVIDER_CLAIM)
        || (policy.purpose == Purpose::Test && !policy.attestation)
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Format {
    Raw,
    Cms,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Timestamp {
    Disabled,
    Optional,
    Required,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub id: Uuid,
    pub name: String,
    pub project: Uuid,
    pub key: Uuid,
    pub purpose: Purpose,
    pub claims: BTreeMap<String, String>,
    pub algorithms: Vec<Algorithm>,
    pub timestamp: Timestamp,
    #[serde(default)]
    pub approval: Option<crate::approvals::Rule>,
    #[serde(default)]
    pub gates: Vec<String>,
    #[serde(default)]
    pub attestation: bool,
}
impl Policy {
    pub fn valid(&self) -> bool {
        self.approval.as_ref().is_none_or(|r| r.valid())
            && self.gates.len() <= 8
            && self.gates.iter().all(|g| {
                !g.is_empty()
                    && g.len() <= 64
                    && g.bytes()
                        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            })
            && self
                .gates
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                == self.gates.len()
            && !self.name.is_empty()
            && self.name.len() <= 64
            && self
                .name
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            && !self.algorithms.is_empty()
            && self.algorithms.len() <= 3
            && self.claims.len() <= 16
            && self
                .claims
                .iter()
                .all(|(k, v)| !k.is_empty() && k.len() <= 100 && !v.is_empty() && v.len() <= 1024)
            && (self.purpose == Purpose::Test
                || ["repository", "ref", "environment"]
                    .iter()
                    .all(|key| self.claims.contains_key(*key))
                    && self
                        .claims
                        .get("ref_protected")
                        .is_some_and(|v| v == "true"))
    }
    pub fn authorise(
        &self,
        key: &KeyRecord,
        principal: &Principal,
        lab: bool,
    ) -> Result<(), String> {
        if !principal.allows(Action::Submit) {
            return Err("role".into());
        }
        if !principal.permits_scope(self.project, Some(self.id)) {
            return Err("scope".into());
        }
        if !provider_allows(self, principal) {
            return Err("provider_purpose".into());
        }
        if !self.valid()
            || self.key != key.key.id
            || self.project != key.project
            || !binding_allowed(key, self.purpose, lab)
        {
            return Err("key_binding".into());
        }
        if !self.algorithms.contains(&key.key.algorithm) {
            return Err("algorithm".into());
        }
        if self.attestation
            && ["iss", "sub", "repository", "sha", "workflow"]
                .iter()
                .any(|c| principal.claims.get(*c).is_none_or(|s| s.is_empty()))
        {
            return Err("attestation_claims_required".into());
        }
        for (name, value) in &self.claims {
            if principal.claims.get(name) != Some(value) {
                return Err(format!("claim:{name}"));
            }
        }
        Ok(())
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Submission {
    pub request_id: Uuid,
    pub policy: Uuid,
    pub digest_alg: DigestAlgorithm,
    pub digest: [u8; 32],
    pub artifact_name: String,
    pub format: Format,
    #[serde(default)]
    pub metadata: BTreeMap<String, String>,
}
impl Submission {
    pub fn valid(&self) -> bool {
        !self.artifact_name.is_empty()
            && self.artifact_name.chars().count() <= 200
            && self.metadata.len() <= 16
            && self
                .metadata
                .iter()
                .all(|(k, v)| k.len() <= 100 && v.len() <= 1024)
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RequestState {
    AwaitingApproval,
    Gating,
    Expired,
    Signing,
    Signed,
    Failed,
    Rejected,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignRequest {
    pub submission: Submission,
    pub project: Uuid,
    pub requester: String,
    pub verified_claims: BTreeMap<String, String>,
    pub state: RequestState,
    pub policy: Option<Policy>,
    pub key: Option<KeyRecord>,
    pub output: Option<Vec<u8>>,
    pub timestamp: Option<Vec<u8>>,
    pub failure: Option<String>,
    #[serde(default)]
    pub approval: Option<crate::approvals::Approval>,
    #[serde(default)]
    pub principal: Option<Principal>,
    #[serde(default)]
    pub window: Option<Uuid>,
    #[serde(default)]
    pub gate_results: Vec<crate::gates::Result>,
    #[serde(default)]
    pub attestation: Option<serde_json::Value>,
    /// Rotating-key backends only: evidence of the one remote operation. Absent for others.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote: Option<RemoteEvidence>,
}
/// The remote operation ID (audited even on failure) and, on success, the validated leaf
/// certificate that produced the signature.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemoteEvidence {
    pub operation_id: Option<String>,
    pub certificate: Option<Vec<u8>>,
    /// Lowercase hex SHA-256 of `certificate`.
    pub certificate_sha256: Option<String>,
}

impl RequestState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Gating => "gating",
            Self::Signing => "signing",
            Self::Signed => "signed",
            Self::Failed => "failed",
            Self::Rejected => "rejected",
            Self::AwaitingApproval => "awaiting_approval",
            Self::Expired => "expired",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        keys::{Key, KeyState},
        rbac::{Role, Scope},
        TrustTier,
    };
    fn fixture(purpose: Purpose, attestation: bool) -> (Policy, KeyRecord, Principal) {
        let project = Uuid::new_v4();
        let key = KeyRecord {
            key: Key {
                id: Uuid::new_v4(),
                algorithm: Algorithm::P256,
                purpose,
            },
            project,
            backend: "hsm".into(),
            state: KeyState::Active,
            offline: false,
            trust: TrustTier::Private,
            anchor: None,
            public_key: vec![],
            chain: vec![],
            revision: 0,
        };
        let verified = [
            ("iss", "https://ci.test"),
            ("sub", "job"),
            ("repository", "acme/app"),
            ("ref", "refs/heads/main"),
            ("environment", "release"),
            ("ref_protected", "true"),
            ("sha", "0123456789abcdef0123456789abcdef01234567"),
            ("workflow", "build"),
        ];
        let policy = Policy {
            id: Uuid::new_v4(),
            name: "policy".into(),
            project,
            key: key.key.id,
            purpose,
            claims: verified[2..6]
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            algorithms: vec![Algorithm::P256],
            timestamp: Timestamp::Disabled,
            approval: None,
            gates: vec![],
            attestation,
        };
        let principal = Principal {
            org_id: Uuid::nil(),
            actor: "workload".into(),
            roles: vec![Role::Submitter],
            scope: Some(Scope {
                project,
                policy: policy.id,
            }),
            human: false,
            claims: verified
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
        };
        (policy, key, principal)
    }
    #[test]
    fn existing_principals_keep_release_and_attestation() {
        for (purpose, attestation) in [
            (Purpose::Release, false),
            (Purpose::Release, true),
            (Purpose::Test, true),
            (Purpose::Test, false),
        ] {
            let (policy, key, principal) = fixture(purpose, attestation);
            assert_eq!(policy.authorise(&key, &principal, false), Ok(()));
        }
    }
    #[test]
    fn provider_profiles_are_test_only_without_attestation() {
        // Even a principal that would otherwise satisfy every release claim fails closed.
        for provider in ["gitlab", "github", "", "unknown"] {
            for (purpose, attestation) in [
                (Purpose::Release, false),
                (Purpose::Release, true),
                (Purpose::Test, true),
            ] {
                let (policy, key, mut principal) = fixture(purpose, attestation);
                principal
                    .claims
                    .insert(PROVIDER_CLAIM.into(), provider.into());
                assert!(!provider_allows(&policy, &principal));
                assert_eq!(
                    policy.authorise(&key, &principal, false),
                    Err("provider_purpose".into())
                );
            }
            let (policy, key, mut principal) = fixture(Purpose::Test, false);
            principal
                .claims
                .insert(PROVIDER_CLAIM.into(), provider.into());
            assert_eq!(policy.authorise(&key, &principal, false), Ok(()));
        }
    }
}
