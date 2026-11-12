//! Explicit operator-only bootstrap. Never used by the HTTP runtime.
use crate::{Error, Tenant, MIGRATOR};
use sqlx::{
    postgres::{PgConnectOptions, PgPoolOptions},
    ConnectOptions, PgPool,
};
use uuid::Uuid;

pub struct Admin {
    pool: PgPool,
    actor: String,
}
impl Admin {
    pub async fn connect(options: PgConnectOptions) -> Result<Self, Error> {
        let pool = PgPoolOptions::new()
            .max_connections(1)
            .acquire_timeout(std::time::Duration::from_secs(3))
            .connect_with(options.disable_statement_logging())
            .await?;
        // Bootstrap creates non-login group roles and crosses tenant RLS intentionally.
        // These privileges must never be granted to the runtime login.
        let (name, allowed): (String, bool) = sqlx::query_as(
            "SELECT rolname, (rolsuper OR (rolcreaterole AND rolbypassrls)) AND has_schema_privilege(current_user, 'public', 'CREATE') FROM pg_roles WHERE rolname=current_user"
        ).fetch_one(&pool).await?;
        if !allowed {
            pool.close().await;
            return Err(Error::UnsafeRole);
        }
        Ok(Self {
            pool,
            actor: format!("database-operator:{name}"),
        })
    }
    pub async fn migrate(&self) -> Result<(), Error> {
        MIGRATOR.run(&self.pool).await.map_err(|_| Error::Database)
    }
    /// Same UUID/name is idempotent; conflicts never rename an existing tenant.
    pub async fn create_org(&self, org_id: Uuid, name: &str) -> Result<bool, Error> {
        if name.is_empty() || name.len() > 200 || org_id.is_nil() {
            return Err(Error::Invalid);
        }
        let mut tx = self.pool.begin().await?;
        let created = sqlx::query(
            "INSERT INTO brigalow.organisations(org_id,name) VALUES($1,$2) ON CONFLICT DO NOTHING",
        )
        .bind(org_id)
        .bind(name)
        .execute(&mut *tx)
        .await?
        .rows_affected()
            == 1;
        let actual: String = sqlx::query_scalar(
            "SELECT name FROM brigalow.organisations WHERE org_id=$1 FOR UPDATE",
        )
        .bind(org_id)
        .fetch_one(&mut *tx)
        .await?;
        if actual != name {
            return Err(Error::Conflict);
        }
        if created {
            let tenant = Tenant {
                pool: self.pool.clone(),
                org_id,
            };
            tenant.lock_audit(&mut tx).await?;
            tenant
                .append(
                    &mut tx,
                    &self.actor,
                    "organisation.created",
                    &org_id.to_string(),
                    serde_json::json!({"name": name}),
                )
                .await?;
        }
        tx.commit().await?;
        Ok(created)
    }
    pub async fn close(&self) {
        self.pool.close().await;
    }
}
