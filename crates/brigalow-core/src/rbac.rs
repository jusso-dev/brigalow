//! Pure authorisation rules. Custodian separation applies even to combined roles.
use serde::{Deserialize, Serialize};
use uuid::Uuid;
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    OrgAdmin,
    KeyCustodian,
    ProjectAdmin,
    Approver,
    Submitter,
    Auditor,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Read,
    ManageProject,
    ManageIdentity,
    ManageKey,
    Submit,
    Approve,
    Audit,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Scope {
    pub project: Uuid,
    pub policy: Uuid,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Principal {
    pub org_id: Uuid,
    pub actor: String,
    pub roles: Vec<Role>,
    pub scope: Option<Scope>,
    pub human: bool,
    #[serde(default)]
    pub claims: std::collections::BTreeMap<String, String>,
}
impl Principal {
    pub fn allows(&self, action: Action) -> bool {
        if self.roles.contains(&Role::KeyCustodian)
            && matches!(action, Action::Submit | Action::Approve)
        {
            return false;
        }
        self.roles.iter().any(|role| match action {
            Action::Read => true,
            Action::ManageIdentity => self.human && *role == Role::OrgAdmin,
            Action::ManageProject => {
                self.human && matches!(role, Role::OrgAdmin | Role::ProjectAdmin)
            }
            Action::ManageKey => self.human && *role == Role::KeyCustodian,
            Action::Submit => *role == Role::Submitter,
            Action::Approve => self.human && *role == Role::Approver,
            Action::Audit => self.human && matches!(role, Role::OrgAdmin | Role::Auditor),
        })
    }
    pub fn permits_scope(&self, project: Uuid, policy: Option<Uuid>) -> bool {
        self.scope
            .as_ref()
            .is_none_or(|s| s.project == project && policy.is_none_or(|p| s.policy == p))
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn least_privilege_and_custodian_separation() {
        let mut p = Principal {
            org_id: Uuid::nil(),
            actor: "test".into(),
            roles: vec![Role::OrgAdmin],
            scope: None,
            human: true,
            claims: Default::default(),
        };
        assert!(p.allows(Action::ManageIdentity));
        assert!(!p.allows(Action::Submit));
        assert!(!p.allows(Action::Approve));
        p.roles = vec![Role::Submitter, Role::Approver, Role::KeyCustodian];
        assert!(!p.allows(Action::Submit));
        assert!(!p.allows(Action::Approve));
        assert!(p.allows(Action::ManageKey));
        p.human = false;
        assert!(!p.allows(Action::ManageKey));
        p.roles.clear();
        assert!(!p.allows(Action::Read));
    }
}
