//! Individual decisions only; no bulk action. Time is supplied by the caller.
use crate::rbac::{Action, Principal};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
fn default_expiry() -> u32 {
    86400
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    pub approvers: Vec<String>,
    pub required: u16,
    #[serde(default = "default_expiry")]
    pub ttl_seconds: u32,
}
impl Rule {
    pub fn valid(&self) -> bool {
        self.required > 0
            && usize::from(self.required) <= self.approvers.len()
            && self.approvers.len() <= 32
            && self.ttl_seconds > 0
            && self.ttl_seconds <= 86400 * 7
            && self
                .approvers
                .iter()
                .all(|s| !s.is_empty() && s.len() <= 2048)
            && self.approvers.iter().collect::<BTreeSet<_>>().len() == self.approvers.len()
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    Approve,
    Deny,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Pending,
    Approved,
    Denied,
    Expired,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Approval {
    pub rule: Rule,
    pub requester: String,
    pub expires_at: i64,
    pub decisions: BTreeMap<String, Decision>,
}
#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    Forbidden,
    Closed,
    Duplicate,
    Invalid,
}
impl Approval {
    pub fn new(rule: Rule, requester: String, now: i64) -> Result<Self, Error> {
        if !rule.valid() {
            return Err(Error::Invalid);
        }
        let expires_at = now
            .checked_add(i64::from(rule.ttl_seconds))
            .ok_or(Error::Invalid)?;
        Ok(Self {
            rule,
            requester,
            expires_at,
            decisions: BTreeMap::new(),
        })
    }
    pub fn status(&self, now: i64) -> Status {
        if self.decisions.values().any(|d| *d == Decision::Deny) {
            return Status::Denied;
        }
        if now >= self.expires_at {
            return Status::Expired;
        }
        if self
            .decisions
            .values()
            .filter(|d| **d == Decision::Approve)
            .count()
            >= usize::from(self.rule.required)
        {
            Status::Approved
        } else {
            Status::Pending
        }
    }
    pub fn may_decide(&self, p: &Principal, now: i64) -> bool {
        self.status(now) == Status::Pending
            && p.allows(Action::Approve)
            && p.actor != self.requester
            && self.rule.approvers.contains(&p.actor)
            && !self.decisions.contains_key(&p.actor)
    }
    pub fn decide(&mut self, p: &Principal, decision: Decision, now: i64) -> Result<Status, Error> {
        if !p.allows(Action::Approve)
            || p.actor == self.requester
            || !self.rule.approvers.contains(&p.actor)
        {
            return Err(Error::Forbidden);
        }
        if self.status(now) != Status::Pending {
            return Err(Error::Closed);
        }
        if self.decisions.contains_key(&p.actor) {
            return Err(Error::Duplicate);
        }
        self.decisions.insert(p.actor.clone(), decision);
        Ok(self.status(now))
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::rbac::Role;
    use uuid::Uuid;
    fn p(actor: &str, roles: Vec<Role>) -> Principal {
        Principal {
            org_id: Uuid::nil(),
            actor: actor.into(),
            roles,
            scope: None,
            human: true,
            claims: Default::default(),
        }
    }
    fn approval() -> Approval {
        Approval::new(
            Rule {
                approvers: vec!["a".into(), "b".into(), "c".into()],
                required: 2,
                ttl_seconds: 120,
            },
            "requester".into(),
            100,
        )
        .unwrap()
    }
    #[test]
    fn at_apr_01_02_03_quorum_deny_exclusions_expiry() {
        let mut a = approval();
        let alice = p("a", vec![Role::Approver]);
        let bob = p("b", vec![Role::Approver]);
        assert_eq!(
            a.decide(&alice, Decision::Approve, 101),
            Ok(Status::Pending)
        );
        assert_eq!(
            a.decide(&alice, Decision::Approve, 101),
            Err(Error::Duplicate)
        );
        assert_eq!(a.decide(&bob, Decision::Approve, 102), Ok(Status::Approved));
        let mut a = approval();
        a.decide(&alice, Decision::Approve, 101).unwrap();
        assert_eq!(a.decide(&bob, Decision::Deny, 102), Ok(Status::Denied));
        assert_eq!(
            a.decide(&p("c", vec![Role::Approver]), Decision::Approve, 103),
            Err(Error::Closed)
        );
        let mut a = approval();
        a.requester = "a".into();
        assert_eq!(
            a.decide(&alice, Decision::Approve, 101),
            Err(Error::Forbidden)
        );
        assert_eq!(
            a.decide(
                &p("b", vec![Role::Approver, Role::KeyCustodian]),
                Decision::Approve,
                101
            ),
            Err(Error::Forbidden)
        );
        assert_eq!(a.status(220), Status::Expired);
        assert_eq!(a.decide(&bob, Decision::Approve, 220), Err(Error::Closed));
    }
}
