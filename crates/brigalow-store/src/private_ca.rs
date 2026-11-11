//! Separate CA database role and durable operator-only issuance/revocation ledger.
use crate::{Error, Tenant};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::{
    postgres::{PgConnectOptions, PgPoolOptions},
    types::Json,
    ConnectOptions,
};
use uuid::Uuid;

#[derive(Clone)]
pub struct CaStore {
    tenant: Tenant,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Leaf {
    pub profile: Uuid,
    pub day: i64,
    pub issuer: Uuid,
    pub serial: [u8; 16],
    pub public_key: Vec<u8>,
    pub issued_at: i64,
    pub chain: Option<Vec<Vec<u8>>>,
    pub revoked_at: Option<i64>,
}
pub struct CrlIntent {
    pub number: i64,
    pub at: i64,
    pub revoked: Vec<([u8; 16], u64)>,
}
impl CaStore {
    pub async fn connect(options: PgConnectOptions, org: Uuid) -> Result<Self, Error> {
        let pool = PgPoolOptions::new()
            .max_connections(2)
            .acquire_timeout(std::time::Duration::from_secs(3))
            .connect_with(options.disable_statement_logging())
            .await?;
        let safe:bool=sqlx::query_scalar("SELECT NOT rolsuper AND NOT rolbypassrls AND NOT rolcreatedb AND NOT rolcreaterole AND pg_has_role(current_user,'brigalow_ca','member') AND NOT pg_has_role(current_user,'brigalow_app','member') AND NOT EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='brigalow' AND pg_has_role(current_user,c.relowner,'member')) FROM pg_roles WHERE rolname=current_user").fetch_one(&pool).await?;
        if !safe {
            pool.close().await;
            return Err(Error::UnsafeRole);
        }
        Ok(Self {
            tenant: Tenant { pool, org_id: org },
        })
    }
    /// A profile is immutable across issuer rotation; changed identity needs a new profile UUID.
    pub async fn reserve(
        &self,
        issuer: Uuid,
        profile: Uuid,
        record: Value,
        public_key: Vec<u8>,
    ) -> Result<Leaf, Error> {
        if profile.is_nil() || issuer.is_nil() || !(32..=65536).contains(&public_key.len()) {
            return Err(Error::Invalid);
        }
        let t = &self.tenant;
        let mut tx = t.begin().await?;
        t.lock_audit(&mut tx).await?;
        sqlx::query("INSERT INTO brigalow.ca_profiles(org_id,profile,record) VALUES($1,$2,$3) ON CONFLICT DO NOTHING").bind(t.org_id).bind(profile).bind(Json(&record)).execute(&mut *tx).await?;
        let existing: Json<Value> = sqlx::query_scalar(
            "SELECT record FROM brigalow.ca_profiles WHERE org_id=$1 AND profile=$2",
        )
        .bind(t.org_id)
        .bind(profile)
        .fetch_one(&mut *tx)
        .await?;
        if existing.0 != record {
            return Err(Error::Conflict);
        }
        let at: i64 =
            sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()))::bigint")
                .fetch_one(&mut *tx)
                .await?;
        let leaf = Leaf {
            profile,
            day: at / 86400,
            issuer,
            serial: *Uuid::new_v4().as_bytes(),
            public_key,
            issued_at: at,
            chain: None,
            revoked_at: None,
        };
        let count=sqlx::query("INSERT INTO brigalow.ca_leaves(org_id,profile,day,issuer,serial,public_key,issued_at) VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT DO NOTHING").bind(t.org_id).bind(profile).bind(leaf.day).bind(issuer).bind(leaf.serial.as_slice()).bind(&leaf.public_key).bind(at).execute(&mut *tx).await?.rows_affected();
        if count != 1 {
            return Err(Error::Conflict);
        }
        t.append(
            &mut tx,
            "ca-operator",
            "ca.issuance_intent",
            &profile.to_string(),
            serde_json::json!({"issuer":issuer,"day":leaf.day,"serial":leaf.serial}),
        )
        .await?;
        tx.commit().await?;
        Ok(leaf)
    }
    pub async fn finish(&self, leaf: &Leaf, chain: Vec<Vec<u8>>) -> Result<(), Error> {
        if chain.is_empty() || chain.len() > 10 || chain.iter().any(|c| c.len() > 65536) {
            return Err(Error::Invalid);
        }
        let t = &self.tenant;
        let mut tx = t.begin().await?;
        t.lock_audit(&mut tx).await?;
        let count=sqlx::query("UPDATE brigalow.ca_leaves SET chain=$5 WHERE org_id=$1 AND profile=$2 AND day=$3 AND serial=$4 AND chain IS NULL AND revoked_at IS NULL").bind(t.org_id).bind(leaf.profile).bind(leaf.day).bind(leaf.serial.as_slice()).bind(Json(chain)).execute(&mut *tx).await?.rows_affected();
        if count != 1 {
            return Err(Error::Conflict);
        }
        t.append(
            &mut tx,
            "ca-operator",
            "ca.issued",
            &leaf.profile.to_string(),
            serde_json::json!({"day":leaf.day,"issuer":leaf.issuer}),
        )
        .await?;
        tx.commit().await?;
        Ok(())
    }
    pub async fn leaf(&self, profile: Uuid, day: i64) -> Result<Option<Leaf>, Error> {
        let t = &self.tenant;
        let mut tx = t.begin().await?;
        #[allow(clippy::type_complexity)]
        let row:Option<(Uuid,Vec<u8>,Vec<u8>,i64,Option<Json<Vec<Vec<u8>>>>,Option<i64>)>=sqlx::query_as("SELECT issuer,serial,public_key,issued_at,chain,revoked_at FROM brigalow.ca_leaves WHERE org_id=$1 AND profile=$2 AND day=$3").bind(t.org_id).bind(profile).bind(day).fetch_optional(&mut *tx).await?;
        tx.commit().await?;
        row.map(
            |(issuer, serial, public_key, issued_at, chain, revoked_at)| {
                Ok(Leaf {
                    profile,
                    day,
                    issuer,
                    serial: serial.try_into().map_err(|_| Error::Invalid)?,
                    public_key,
                    issued_at,
                    chain: chain.map(|c| c.0),
                    revoked_at,
                })
            },
        )
        .transpose()
    }
    pub async fn revoke(&self, profile: Uuid, day: i64) -> Result<(), Error> {
        let t = &self.tenant;
        let mut tx = t.begin().await?;
        t.lock_audit(&mut tx).await?;
        // Also revoke interrupted intents: they must never later become issued.
        let count=sqlx::query("UPDATE brigalow.ca_leaves SET revoked_at=floor(extract(epoch FROM clock_timestamp()))::bigint WHERE org_id=$1 AND profile=$2 AND day=$3 AND revoked_at IS NULL").bind(t.org_id).bind(profile).bind(day).execute(&mut *tx).await?.rows_affected();
        if count != 1 {
            return Err(Error::Conflict);
        }
        t.append(
            &mut tx,
            "ca-operator",
            "ca.revoked",
            &profile.to_string(),
            serde_json::json!({"day":day}),
        )
        .await?;
        tx.commit().await?;
        Ok(())
    }
    pub async fn reserve_crl(&self, issuer: Uuid) -> Result<CrlIntent, Error> {
        let t = &self.tenant;
        let mut tx = t.begin().await?;
        t.lock_audit(&mut tx).await?;
        let (number,at):(i64,i64)=sqlx::query_as("SELECT coalesce(max(number),0)+1,floor(extract(epoch FROM clock_timestamp()))::bigint FROM brigalow.ca_crls WHERE org_id=$1 AND issuer=$2").bind(t.org_id).bind(issuer).fetch_one(&mut *tx).await?;
        let rows:Vec<(Vec<u8>,i64)>=sqlx::query_as("SELECT serial,revoked_at FROM brigalow.ca_leaves WHERE org_id=$1 AND issuer=$2 AND revoked_at IS NOT NULL ORDER BY serial LIMIT 100001").bind(t.org_id).bind(issuer).fetch_all(&mut *tx).await?;
        if rows.len() > 100000 {
            return Err(Error::Invalid);
        }
        let revoked = rows
            .into_iter()
            .map(|(s, at)| Ok((s.try_into().map_err(|_| Error::Invalid)?, at as u64)))
            .collect::<Result<_, Error>>()?;
        sqlx::query(
            "INSERT INTO brigalow.ca_crls(org_id,issuer,number,created_at) VALUES($1,$2,$3,$4)",
        )
        .bind(t.org_id)
        .bind(issuer)
        .bind(number)
        .bind(at)
        .execute(&mut *tx)
        .await?;
        t.append(
            &mut tx,
            "ca-operator",
            "ca.crl_intent",
            &issuer.to_string(),
            serde_json::json!({"number":number}),
        )
        .await?;
        tx.commit().await?;
        Ok(CrlIntent {
            number,
            at,
            revoked,
        })
    }
    pub async fn finish_crl(
        &self,
        issuer: Uuid,
        intent: &CrlIntent,
        der: Vec<u8>,
    ) -> Result<(), Error> {
        let t = &self.tenant;
        let mut tx = t.begin().await?;
        t.lock_audit(&mut tx).await?;
        // A revocation committed after the snapshot invalidates this publication.
        let stale:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM brigalow.ca_leaves WHERE org_id=$1 AND issuer=$2 AND revoked_at IS NOT NULL AND NOT(serial=ANY($3)))").bind(t.org_id).bind(issuer).bind(intent.revoked.iter().map(|(s,_)|s.to_vec()).collect::<Vec<_>>()).fetch_one(&mut *tx).await?;
        if stale {
            return Err(Error::Conflict);
        }
        let count=sqlx::query("UPDATE brigalow.ca_crls SET der=$4 WHERE org_id=$1 AND issuer=$2 AND number=$3 AND der IS NULL AND number=(SELECT max(number) FROM brigalow.ca_crls WHERE org_id=$1 AND issuer=$2)").bind(t.org_id).bind(issuer).bind(intent.number).bind(der).execute(&mut *tx).await?.rows_affected();
        if count != 1 {
            return Err(Error::Conflict);
        }
        t.append(
            &mut tx,
            "ca-operator",
            "ca.crl_published",
            &issuer.to_string(),
            serde_json::json!({"number":intent.number}),
        )
        .await?;
        tx.commit().await?;
        Ok(())
    }
    pub async fn close(&self) {
        self.tenant.pool.close().await;
    }
}
