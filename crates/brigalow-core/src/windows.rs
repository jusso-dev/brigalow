use serde::{Deserialize, Serialize};
use uuid::Uuid;
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseWindow {
    pub id: Uuid,
    pub key: Uuid,
    pub project: Uuid,
    pub name: String,
    pub starts_at: i64,
    pub ends_at: i64,
    pub cap: Option<u32>,
    pub used: u32,
    pub closed: bool,
}
impl ReleaseWindow {
    pub fn valid(&self) -> bool {
        !self.name.is_empty()
            && self.name.chars().count() <= 200
            && self.starts_at >= 0
            && self.ends_at > self.starts_at
            && self.ends_at - self.starts_at <= 86400 * 7
            && self.cap.is_none_or(|n| n > 0)
    }
    pub fn available(&self, now: i64) -> bool {
        !self.closed
            && self.valid()
            && now >= self.starts_at
            && now < self.ends_at
            && self.cap.is_none_or(|n| self.used < n)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn at_rel_01_window_boundaries() {
        let w = ReleaseWindow {
            id: Uuid::nil(),
            key: Uuid::nil(),
            project: Uuid::nil(),
            name: "release".into(),
            starts_at: 36000,
            ends_at: 37800,
            cap: Some(5),
            used: 0,
            closed: false,
        };
        assert!(w.available(36000));
        assert!(w.available(37799));
        assert!(!w.available(37800));
        assert!(!w.available(37860));
        assert!(!w.available(35999));
    }
}
