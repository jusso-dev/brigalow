//! Version 1 audit encoding: RFC 8785 JSON, SHA-256, one chain per organisation.
//! No I/O. Numbers are restricted to exact JSON integers to avoid lossy hashes.
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use uuid::Uuid;

pub const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";
const MAX_INTEGER: u64 = 9_007_199_254_740_991;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Event {
    pub org_id: Uuid,
    /// Unix milliseconds, supplied by the store's database clock.
    pub at: i64,
    pub actor: String,
    pub action: String,
    pub subject: String,
    pub details: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Entry {
    pub seq: u64,
    pub org_id: Uuid,
    pub at: i64,
    pub actor: String,
    pub action: String,
    pub subject: String,
    pub details: Value,
    pub prev_hash: String,
    pub entry_hash: String,
}

#[derive(Debug, thiserror::Error, PartialEq)]
#[error("audit verification failed at seq {seq}: {reason}")]
pub struct AuditError {
    pub seq: u64,
    pub reason: &'static str,
}

fn exact_numbers(value: &Value) -> bool {
    match value {
        Value::Number(n) => {
            n.as_u64().is_some_and(|n| n <= MAX_INTEGER)
                || n.as_i64().is_some_and(|n| n.unsigned_abs() <= MAX_INTEGER)
        }
        Value::Array(values) => values.iter().all(exact_numbers),
        Value::Object(values) => values.values().all(exact_numbers),
        _ => true,
    }
}

impl Entry {
    pub fn new(seq: u64, prev_hash: String, event: Event) -> Result<Self, AuditError> {
        let mut entry = Self {
            seq,
            org_id: event.org_id,
            at: event.at,
            actor: event.actor,
            action: event.action,
            subject: event.subject,
            details: event.details,
            prev_hash,
            entry_hash: String::new(),
        };
        entry.entry_hash = entry.hash()?;
        Ok(entry)
    }

    /// Canonical bytes excluding entry_hash. Useful for independent verification.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, AuditError> {
        let err = |reason| AuditError {
            seq: self.seq,
            reason,
        };
        if self.seq == 0
            || self.seq > MAX_INTEGER
            || self.at.unsigned_abs() > MAX_INTEGER
            || !exact_numbers(&self.details)
        {
            return Err(err("numbers must be exact JSON integers"));
        }
        if self.prev_hash.len() != 64
            || !self
                .prev_hash
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(err("invalid previous hash"));
        }
        let mut value = serde_json::to_value(self).map_err(|_| err("invalid entry"))?;
        value
            .as_object_mut()
            .expect("entry is an object")
            .remove("entry_hash");
        serde_json_canonicalizer::to_vec(&value).map_err(|_| err("invalid canonical JSON"))
    }

    fn hash(&self) -> Result<String, AuditError> {
        Ok(format!("{:x}", Sha256::digest(self.canonical_bytes()?)))
    }
}

#[derive(Default)]
pub struct Verifier {
    count: u64,
    org_id: Option<Uuid>,
    previous: Option<String>,
}

impl Verifier {
    pub fn count(&self) -> u64 {
        self.count
    }

    pub fn push(&mut self, entry: &Entry) -> Result<(), AuditError> {
        let err = |reason| AuditError {
            seq: self.count + 1,
            reason,
        };
        if entry.seq != self.count + 1 {
            return Err(err("sequence gap or reorder"));
        }
        if self.org_id.is_some_and(|org| org != entry.org_id) {
            return Err(err("mixed organisations"));
        }
        if entry.prev_hash != self.previous.as_deref().unwrap_or(GENESIS) {
            return Err(err("previous hash mismatch"));
        }
        if entry.entry_hash != entry.hash()? {
            return Err(err("entry hash mismatch"));
        }
        self.org_id = Some(entry.org_id);
        self.previous = Some(entry.entry_hash.clone());
        self.count += 1;
        Ok(())
    }

    pub fn finish(self) -> Result<u64, AuditError> {
        if self.count == 0 {
            return Err(AuditError {
                seq: 1,
                reason: "empty chain",
            });
        }
        Ok(self.count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn event(details: Value) -> Event {
        Event {
            org_id: Uuid::nil(),
            at: 0,
            actor: "test".into(),
            action: "created".into(),
            subject: "project".into(),
            details,
        }
    }
    #[test]
    fn canonical_objects_and_numeric_limits() {
        let a = Entry::new(1, GENESIS.into(), event(serde_json::json!({"b":2,"a":1}))).unwrap();
        let b = Entry::new(1, GENESIS.into(), event(serde_json::json!({"a":1,"b":2}))).unwrap();
        assert_eq!(a.entry_hash, b.entry_hash);
        assert!(Entry::new(
            1,
            GENESIS.into(),
            event(serde_json::json!({"n":9_007_199_254_740_992_u64}))
        )
        .is_err());
        assert!(Entry::new(1, GENESIS.into(), event(serde_json::json!({"n":1.5}))).is_err());
    }
    #[test]
    fn rejects_wrong_genesis_mixed_tenants_and_reordering() {
        let a = Entry::new(1, GENESIS.into(), event(Value::Null)).unwrap();
        let mut other = event(Value::Null);
        other.org_id = Uuid::new_v4();
        let b = Entry::new(2, a.entry_hash.clone(), other).unwrap();
        let mut v = Verifier::default();
        v.push(&a).unwrap();
        assert_eq!(v.push(&b).unwrap_err().seq, 2);
        assert!(v.push(&a).is_err());
        let wrong = Entry::new(1, "f".repeat(64), event(Value::Null)).unwrap();
        assert!(Verifier::default().push(&wrong).is_err());
        assert!(Verifier::default().finish().is_err());
    }
}

/// Externally retain the latest checkpoint and independently pin its audit public key.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Checkpoint {
    pub version: u8,
    pub org_id: Uuid,
    pub seq: u64,
    pub entry_hash: String,
    pub at: i64,
    pub key_id: Uuid,
    pub algorithm: crate::keys::Algorithm,
}
impl Checkpoint {
    pub fn message(&self) -> Result<Vec<u8>, AuditError> {
        if self.version != 1
            || self.seq == 0
            || self.seq > MAX_INTEGER
            || self.at < 0
            || self.at as u64 > MAX_INTEGER
            || self.org_id.is_nil()
            || self.key_id.is_nil()
            || self.entry_hash.len() != 64
            || !self
                .entry_hash
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(AuditError {
                seq: self.seq,
                reason: "invalid checkpoint",
            });
        }
        let mut bytes = b"brigalow.audit.checkpoint.v1\n".to_vec();
        bytes.extend(
            serde_json_canonicalizer::to_vec(self).map_err(|_| AuditError {
                seq: self.seq,
                reason: "invalid checkpoint",
            })?,
        );
        Ok(bytes)
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedCheckpoint {
    pub checkpoint: Checkpoint,
    pub signature: Vec<u8>,
}
impl Verifier {
    pub fn matches_checkpoint(&self, checkpoint: &Checkpoint) -> bool {
        self.count == checkpoint.seq
            && self.org_id == Some(checkpoint.org_id)
            && self.previous.as_ref() == Some(&checkpoint.entry_hash)
    }
}

/// Latest head an operator retained outside the Brigalow DB and signing host. It is the
/// freshness anchor: a valid signature alone cannot show that no newer head was withheld.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpectedHead {
    pub org_id: Uuid,
    pub seq: u64,
    pub entry_hash: String,
}
impl ExpectedHead {
    /// Parse `<org-uuid>:<seq>:<entry-hash>` (lowercase hex SHA-256).
    pub fn parse(text: &str) -> Option<Self> {
        let mut parts = text.split(':');
        let (org, seq, hash) = (parts.next()?, parts.next()?, parts.next()?);
        if parts.next().is_some()
            || hash.len() != 64
            || !hash
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || !seq.bytes().all(|b| b.is_ascii_digit())
        {
            return None;
        }
        let org_id = Uuid::try_parse(org).ok().filter(|org| !org.is_nil())?;
        let seq = seq
            .parse()
            .ok()
            .filter(|seq| (1..=MAX_INTEGER).contains(seq))?;
        Some(Self {
            org_id,
            seq,
            entry_hash: hash.into(),
        })
    }
    /// Exact match only; an older or substituted checkpoint is never accepted.
    pub fn matches(&self, checkpoint: &Checkpoint) -> bool {
        self.org_id == checkpoint.org_id
            && self.seq == checkpoint.seq
            && self.entry_hash == checkpoint.entry_hash
    }
}

#[cfg(test)]
mod expected_head_tests {
    use super::*;
    #[test]
    fn parses_only_exact_heads() {
        let org = Uuid::new_v4();
        let hash = "a".repeat(64);
        let head = ExpectedHead::parse(&format!("{org}:7:{hash}")).unwrap();
        assert_eq!((head.org_id, head.seq), (org, 7));
        for bad in [
            format!("{org}:0:{hash}"),
            format!("{org}:+7:{hash}"),
            format!("{org}:7:{}", "A".repeat(64)),
            format!("{org}:7:{}", "a".repeat(63)),
            format!("{org}:7:{hash}:x"),
            format!("{}:7:{hash}", Uuid::nil()),
            format!("{org}:9007199254740992:{hash}"),
            format!("{org}:7"),
        ] {
            assert!(ExpectedHead::parse(&bad).is_none(), "{bad}");
        }
        let checkpoint = Checkpoint {
            version: 1,
            org_id: org,
            seq: 7,
            entry_hash: hash.clone(),
            at: 1,
            key_id: Uuid::new_v4(),
            algorithm: crate::keys::Algorithm::P256,
        };
        assert!(head.matches(&checkpoint));
        assert!(!head.matches(&Checkpoint {
            seq: 6,
            ..checkpoint.clone()
        }));
        assert!(!head.matches(&Checkpoint {
            org_id: Uuid::new_v4(),
            ..checkpoint
        }));
    }
}
