//! Shared pending OIDC logins. Rows contain only digests and AEAD ciphertext sealed by the
//! server; this crate never sees plaintext verifiers, nonces or key material.
use crate::{Error, Tenant};
use sqlx::{Postgres, Transaction};

/// Serialises every pending-login insertion so tenant and global bounds are checked and
/// enforced in one critical section (no check-then-insert race across instances).
const INSERT_LOCK: &str = "brigalow.pending_logins";
const CLEANUP_BATCH: i64 = 100;
const NOW_MS: &str = "SELECT (extract(epoch FROM clock_timestamp()) * 1000)::bigint";

#[derive(Clone, Copy, Debug)]
pub struct LoginLimits {
    pub per_org: i64,
    pub global: i64,
    /// Lifetime from the database clock, in milliseconds.
    pub lifetime_ms: i64,
    /// Committed encryptions allowed per key ID, shared by all instances.
    pub max_seals: i64,
}
impl LoginLimits {
    fn valid(&self) -> bool {
        self.per_org > 0
            && self.global > 0
            && (1..=300_000).contains(&self.lifetime_ms)
            && self.max_seals > 0
    }
}
pub struct NewPendingLogin<'a> {
    pub state_hash: &'a str,
    pub provider: &'a str,
    pub browser_hash: &'a str,
    pub key_id: &'a str,
    pub version: i16,
}
pub struct Sealed {
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
}
/// A locked, not-yet-consumed row. Only live (DB-clock unexpired) rows reach callers.
pub struct PendingLogin {
    pub provider: String,
    pub browser_hash: String,
    pub expires_ms: i64,
    pub key_id: String,
    pub version: i16,
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

/// provider, browser hash, expiry, key ID, version, nonce, ciphertext, slot, live.
type Row = (
    String,
    String,
    i64,
    String,
    i16,
    Vec<u8>,
    Vec<u8>,
    uuid::Uuid,
    bool,
);
fn digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

impl Tenant {
    /// Atomically enforces bounds and the key usage limit, then seals with the DB-clock expiry
    /// (bound into the AEAD associated data by `seal`) and inserts the row.
    pub async fn create_pending_login(
        &self,
        new: NewPendingLogin<'_>,
        limits: LoginLimits,
        seal: impl FnOnce(i64) -> Result<Sealed, Error>,
    ) -> Result<i64, Error> {
        if !limits.valid() || !digest(new.state_hash) || !digest(new.browser_hash) {
            return Err(Error::Invalid);
        }
        let mut tx = self.begin().await?;
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
            .bind(INSERT_LOCK)
            .execute(&mut *tx)
            .await?;
        let now: i64 = sqlx::query_scalar(NOW_MS).fetch_one(&mut *tx).await?;
        self.delete_expired(&mut tx, now).await?;
        let (tenant, global): (i64, i64) = sqlx::query_as(
            "SELECT (SELECT count(*) FROM brigalow.pending_logins WHERE org_id=$1 AND expires_ms>$2), \
                    (SELECT count(*) FROM brigalow.pending_login_inventory WHERE expires_ms>$2)",
        )
        .bind(self.org_id)
        .bind(now)
        .fetch_one(&mut *tx)
        .await?;
        if tenant >= limits.per_org || global >= limits.global {
            return Err(Error::Exhausted);
        }
        let used: Option<i64> = sqlx::query_scalar(
            "INSERT INTO brigalow.pending_login_key_usage AS u (key_id,sealed) VALUES ($1,1) \
             ON CONFLICT (key_id) DO UPDATE SET sealed=u.sealed+1 WHERE u.sealed<$2 RETURNING sealed",
        )
        .bind(new.key_id)
        .bind(limits.max_seals)
        .fetch_optional(&mut *tx)
        .await?;
        if used.is_none() {
            return Err(Error::Exhausted);
        }
        let expires = now + limits.lifetime_ms;
        let sealed = seal(expires)?;
        let slot = uuid::Uuid::new_v4();
        sqlx::query("INSERT INTO brigalow.pending_logins (org_id,state_hash,provider,browser_hash,expires_ms,key_id,version,nonce,ciphertext,slot) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)")
            .bind(self.org_id).bind(new.state_hash).bind(new.provider).bind(new.browser_hash).bind(expires)
            .bind(new.key_id).bind(new.version).bind(&sealed.nonce).bind(&sealed.ciphertext).bind(slot)
            .execute(&mut *tx).await?;
        sqlx::query(
            "INSERT INTO brigalow.pending_login_inventory (slot,expires_ms) VALUES ($1,$2)",
        )
        .bind(slot)
        .bind(expires)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(expires)
    }

    /// One transaction: delete-and-lock the exact row, require DB-clock liveness, then let
    /// `accept` check provider/browser binding and decrypt. Commit (consume) only on `Some`;
    /// otherwise roll back so a wrong browser, provider or key cannot consume the row.
    /// Concurrent callers block on the row lock; at most one commits a consumption.
    pub async fn consume_pending_login<T>(
        &self,
        state_hash: &str,
        accept: impl FnOnce(&PendingLogin) -> Option<T>,
    ) -> Result<Option<T>, Error> {
        if !digest(state_hash) {
            return Ok(None);
        }
        let mut tx = self.begin().await?;
        let row: Option<Row> = sqlx::query_as(
            "DELETE FROM brigalow.pending_logins WHERE org_id=$1 AND state_hash=$2 \
             RETURNING provider,browser_hash,expires_ms,key_id,version,nonce,ciphertext,slot, \
             expires_ms > (extract(epoch FROM clock_timestamp()) * 1000)::bigint",
        )
        .bind(self.org_id)
        .bind(state_hash)
        .fetch_optional(&mut *tx)
        .await?;
        let (accepted, slot) = match row {
            Some((
                provider,
                browser_hash,
                expires_ms,
                key_id,
                version,
                nonce,
                ciphertext,
                slot,
                true,
            )) => (
                accept(&PendingLogin {
                    provider,
                    browser_hash,
                    expires_ms,
                    key_id,
                    version,
                    nonce,
                    ciphertext,
                }),
                Some(slot),
            ),
            _ => (None, None),
        };
        let (Some(value), Some(slot)) = (accepted, slot) else {
            tx.rollback().await?;
            return Ok(None);
        };
        sqlx::query("DELETE FROM brigalow.pending_login_inventory WHERE slot=$1")
            .bind(slot)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(Some(value))
    }

    /// Bounded maintenance: deletes at most one batch of DB-clock-expired rows.
    pub async fn cleanup_pending_logins(&self) -> Result<u64, Error> {
        let mut tx = self.begin().await?;
        let now: i64 = sqlx::query_scalar(NOW_MS).fetch_one(&mut *tx).await?;
        let deleted = self.delete_expired(&mut tx, now).await?;
        tx.commit().await?;
        Ok(deleted)
    }

    async fn delete_expired(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        now: i64,
    ) -> Result<u64, Error> {
        let tenant = sqlx::query("DELETE FROM brigalow.pending_logins WHERE org_id=$1 AND state_hash IN (SELECT state_hash FROM brigalow.pending_logins WHERE org_id=$1 AND expires_ms<=$2 ORDER BY expires_ms LIMIT $3)")
            .bind(self.org_id).bind(now).bind(CLEANUP_BATCH).execute(&mut **tx).await?.rows_affected();
        let global = sqlx::query("DELETE FROM brigalow.pending_login_inventory WHERE slot IN (SELECT slot FROM brigalow.pending_login_inventory WHERE expires_ms<=$1 ORDER BY expires_ms LIMIT $2)")
            .bind(now).bind(CLEANUP_BATCH).execute(&mut **tx).await?.rows_affected();
        Ok(tenant + global)
    }
}
