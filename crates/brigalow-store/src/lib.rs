//! Tenant-scoped persistence. The pool is private; each operation opens a scoped transaction.
use brigalow_core::audit::{Entry, Event, GENESIS};
use sqlx::{
    postgres::{PgConnectOptions, PgPoolOptions},
    types::Json,
    ConnectOptions, PgPool, Postgres, Transaction,
};
use std::time::Duration;
use uuid::Uuid;

pub mod approvals;
mod checkpoints;
pub mod identity;
pub mod keys;
pub mod private_ca;
mod rate_limit;
pub mod signing;

pub static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

// Do not expose driver errors: Postgres errors may contain submitted data or credentials.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("decision forbidden")]
    Forbidden,
    #[error("invalid state or policy")]
    Invalid,
    #[error("database operation failed")]
    Database,
    #[error("request already used")]
    Conflict,
    #[error("runtime database role must be restricted and inherit brigalow_app")]
    UnsafeRole,
    #[error("invalid audit event")]
    Audit,
    #[error("object not found")]
    NotFound,
}
impl From<sqlx::Error> for Error {
    fn from(_: sqlx::Error) -> Self {
        Self::Database
    }
}

#[derive(Clone)]
pub struct Store {
    pool: PgPool,
}
#[derive(Clone)]
pub struct Tenant {
    pool: PgPool,
    org_id: Uuid,
}

#[derive(Debug, Clone, Copy)]
pub enum ObjectKind {
    Project,
    Key,
    Policy,
    Request,
}
impl ObjectKind {
    pub const ALL: [Self; 4] = [Self::Project, Self::Key, Self::Policy, Self::Request];
    fn lookup_sql(self) -> &'static str {
        match self {
            Self::Project => "SELECT id FROM brigalow.projects WHERE org_id=$1 AND id=$2",
            Self::Key => "SELECT id FROM brigalow.signing_keys WHERE org_id=$1 AND id=$2",
            Self::Policy => "SELECT id FROM brigalow.policies WHERE org_id=$1 AND id=$2",
            Self::Request => "SELECT id FROM brigalow.sign_requests WHERE org_id=$1 AND id=$2",
        }
    }
}

impl Store {
    pub async fn connect(options: PgConnectOptions) -> Result<Self, Error> {
        let pool = PgPoolOptions::new()
            .max_connections(8)
            .acquire_timeout(Duration::from_secs(3))
            .connect_with(options.disable_statement_logging())
            .await?;
        let safe: bool = sqlx::query_scalar("SELECT NOT rolsuper AND NOT rolbypassrls AND NOT rolcreatedb AND NOT rolcreaterole AND pg_has_role(current_user, 'brigalow_app', 'member') AND NOT EXISTS (SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='brigalow' AND pg_has_role(current_user,c.relowner,'member')) FROM pg_roles WHERE rolname=current_user")
            .fetch_one(&pool).await?;
        if !safe {
            pool.close().await;
            return Err(Error::UnsafeRole);
        }
        // Refuse missing/old schema; migrations never run with application credentials.
        let _: i64 = sqlx::query_scalar("SELECT count(*) FROM brigalow.audit_entries")
            .fetch_one(&pool)
            .await?;
        Ok(Self { pool })
    }
    /// Only call with an organisation established by authenticated server-side identity.
    /// Phase 0 exposes no tenant HTTP endpoints.
    pub fn tenant(&self, org_id: Uuid) -> Tenant {
        Tenant {
            pool: self.pool.clone(),
            org_id,
        }
    }
    pub async fn healthy(&self) -> bool {
        sqlx::query("SELECT 1").execute(&self.pool).await.is_ok()
    }
    pub async fn close(&self) {
        self.pool.close().await;
    }
}

impl Tenant {
    async fn begin(&self) -> Result<Transaction<'static, Postgres>, Error> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("SELECT set_config('brigalow.org_id', $1, true)")
            .bind(self.org_id.to_string())
            .execute(&mut *tx)
            .await?;
        Ok(tx)
    }
    pub async fn find(&self, kind: ObjectKind, id: Uuid) -> Result<Option<Uuid>, Error> {
        let mut tx = self.begin().await?;
        let found = sqlx::query_scalar(kind.lookup_sql())
            .bind(self.org_id)
            .bind(id)
            .fetch_optional(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(found)
    }
    pub async fn create_project(&self, actor: &str, name: &str) -> Result<Uuid, Error> {
        let mut tx = self.begin().await?;
        self.lock_audit(&mut tx).await?;
        let id = Uuid::new_v4();
        sqlx::query("INSERT INTO brigalow.projects (org_id,id,name) VALUES ($1,$2,$3)")
            .bind(self.org_id)
            .bind(id)
            .bind(name)
            .execute(&mut *tx)
            .await?;
        self.append(
            &mut tx,
            actor,
            "project.created",
            &id.to_string(),
            serde_json::json!({"name": name}),
        )
        .await?;
        tx.commit().await?;
        Ok(id)
    }
    pub async fn record(
        &self,
        actor: &str,
        action: &str,
        subject: &str,
        details: serde_json::Value,
    ) -> Result<Entry, Error> {
        let mut tx = self.begin().await?;
        self.lock_audit(&mut tx).await?;
        let entry = self
            .append(&mut tx, actor, action, subject, details)
            .await?;
        tx.commit().await?;
        Ok(entry)
    }
    async fn lock_audit(&self, tx: &mut Transaction<'_, Postgres>) -> Result<(), Error> {
        // Hash collisions only serialise unrelated organisations; they never merge chains.
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
            .bind(self.org_id.to_string())
            .execute(&mut **tx)
            .await?;
        let exists: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM brigalow.organisations WHERE org_id=$1)",
        )
        .bind(self.org_id)
        .fetch_one(&mut **tx)
        .await?;
        if !exists {
            return Err(Error::NotFound);
        }
        Ok(())
    }
    async fn append(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        actor: &str,
        action: &str,
        subject: &str,
        details: serde_json::Value,
    ) -> Result<Entry, Error> {
        let head: Option<(i64, String)> = sqlx::query_as("SELECT seq, entry->>'entry_hash' FROM brigalow.audit_entries WHERE org_id=$1 ORDER BY seq DESC LIMIT 1")
            .bind(self.org_id).fetch_optional(&mut **tx).await?;
        let (seq, prev) = head.map_or((1, GENESIS.to_string()), |(n, h)| (n + 1, h));
        let at: i64 =
            sqlx::query_scalar("SELECT (extract(epoch FROM clock_timestamp()) * 1000)::bigint")
                .fetch_one(&mut **tx)
                .await?;
        let entry = Entry::new(
            seq as u64,
            prev,
            Event {
                org_id: self.org_id,
                at,
                actor: actor.into(),
                action: action.into(),
                subject: subject.into(),
                details,
            },
        )
        .map_err(|_| Error::Audit)?;
        sqlx::query("INSERT INTO brigalow.audit_entries (org_id,seq,entry) VALUES ($1,$2,$3)")
            .bind(self.org_id)
            .bind(seq)
            .bind(Json(&entry))
            .execute(&mut **tx)
            .await?;
        Ok(entry)
    }
    /// Ordered page for a single organisation; callers can stream JSONL without unbounded memory.
    pub async fn audit_page(&self, after: i64, limit: i64) -> Result<Vec<Entry>, Error> {
        let mut tx = self.begin().await?;
        let entries: Vec<Json<Entry>> = sqlx::query_scalar("SELECT entry FROM brigalow.audit_entries WHERE org_id=$1 AND seq>$2 ORDER BY seq LIMIT $3")
            .bind(self.org_id).bind(after).bind(limit.clamp(1,1000)).fetch_all(&mut *tx).await?;
        tx.commit().await?;
        Ok(entries.into_iter().map(|entry| entry.0).collect())
    }
}

mod gates;
