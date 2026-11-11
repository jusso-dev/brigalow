//! Core domain types for Brigalow. No I/O lives in this crate.
//!
//! This is a scaffold. See `docs/architecture.md` for the planned modules.

pub mod audit;
pub mod rbac;

/// What a signing policy or key is for. Release keys must never be used by
/// test policies (see threat T7 in `docs/threat-model.md`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Purpose {
    Test,
    Release,
}

/// Returns true when a key with `key` purpose may be bound to a policy with
/// `policy` purpose.
pub fn purpose_compatible(key: Purpose, policy: Purpose) -> bool {
    key == policy
}

/// How far a certificate chain is trusted, as configured by the operator.
/// Brigalow never decides on its own that something is publicly trusted
/// (see `docs/decisions/0003-trust-tiers.md`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustTier {
    Lab,
    Private,
    Untrusted,
    ExternalCa,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn release_key_cannot_bind_to_test_policy() {
        assert!(!purpose_compatible(Purpose::Release, Purpose::Test));
        assert!(!purpose_compatible(Purpose::Test, Purpose::Release));
        assert!(purpose_compatible(Purpose::Release, Purpose::Release));
    }
}
