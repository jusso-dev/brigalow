use crate::{Error, ObjectKind, Tenant};
use brigalow_core::rbac::Principal;
use sqlx::types::Json;
use uuid::Uuid;

pub struct Credential {
    pub id: Uuid,
    pub principal: Principal,
    pub csrf: Option<String>,
    pub expires_at: i64,
}
impl Tenant {
    pub async fn policy_key(&self, id: Uuid) -> Result<Option<Uuid>, Error> {
        let mut tx = self.begin().await?;
        let key =
            sqlx::query_scalar("SELECT key_id FROM brigalow.policies WHERE org_id=$1 AND id=$2")
                .bind(self.org_id)
                .bind(id)
                .fetch_optional(&mut *tx)
                .await?;
        tx.commit().await?;
        Ok(key)
    }

    pub async fn credential(&self, hash: &str, kind: &str) -> Result<Option<Credential>, Error> {
        let mut tx = self.begin().await?;
        let row:Option<(Uuid,Json<Principal>,Option<String>,i64)>=sqlx::query_as("SELECT id,principal,csrf,extract(epoch FROM expires_at)::bigint FROM brigalow.credentials WHERE org_id=$1 AND secret_hash=$2 AND kind=$3 AND NOT revoked AND expires_at>clock_timestamp()")
            .bind(self.org_id).bind(hash).bind(kind).fetch_optional(&mut *tx).await?;
        tx.commit().await?;
        Ok(row.map(|(id, p, csrf, expires_at)| Credential {
            id,
            principal: p.0,
            csrf,
            expires_at,
        }))
    }
    pub async fn issue_credential(
        &self,
        hash: &str,
        principal: &Principal,
        csrf: Option<&str>,
        expires_at: i64,
        actor: &str,
    ) -> Result<Uuid, Error> {
        if principal.org_id != self.org_id
            || principal.human != csrf.is_some()
            || (csrf.is_some() && principal.scope.is_some())
            || (csrf.is_none() && principal.scope.is_none())
        {
            return Err(Error::NotFound);
        }
        let mut tx = self.begin().await?;
        self.lock_audit(&mut tx).await?;
        let id = Uuid::new_v4();
        sqlx::query("INSERT INTO brigalow.credentials (org_id,id,secret_hash,kind,principal,csrf,project_id,policy_id,expires_at) SELECT $1,$2,$3,$4,$5,$6,$7,$8,to_timestamp($9::double precision) WHERE to_timestamp($9::double precision)>clock_timestamp()")
            .bind(self.org_id).bind(id).bind(hash).bind(if csrf.is_some(){"session"}else{"api"}).bind(Json(principal)).bind(csrf)
            .bind(principal.scope.as_ref().map(|s|s.project)).bind(principal.scope.as_ref().map(|s|s.policy)).bind(expires_at as f64)
            .execute(&mut *tx).await?.rows_affected().eq(&1).then_some(()).ok_or(Error::NotFound)?;
        self.append(
            &mut tx,
            actor,
            "credential.issued",
            &id.to_string(),
            serde_json::json!({"kind":if csrf.is_some(){"session"}else{"api"}}),
        )
        .await?;
        tx.commit().await?;
        Ok(id)
    }
    pub async fn revoke_credential(&self, id: Uuid, actor: &str) -> Result<bool, Error> {
        let mut tx = self.begin().await?;
        self.lock_audit(&mut tx).await?;
        let changed=sqlx::query("UPDATE brigalow.credentials SET revoked=true WHERE org_id=$1 AND id=$2 AND NOT revoked").bind(self.org_id).bind(id).execute(&mut *tx).await?.rows_affected()==1;
        if changed {
            self.append(
                &mut tx,
                actor,
                "credential.revoked",
                &id.to_string(),
                serde_json::Value::Null,
            )
            .await?;
        }
        tx.commit().await?;
        Ok(changed)
    }
    pub async fn create_project_once(
        &self,
        actor: &str,
        name: &str,
        request_id: Uuid,
    ) -> Result<Uuid, Error> {
        let mut tx = self.begin().await?;
        self.lock_audit(&mut tx).await?;
        let inserted =
            sqlx::query("INSERT INTO brigalow.request_ids VALUES ($1,$2) ON CONFLICT DO NOTHING")
                .bind(self.org_id)
                .bind(request_id)
                .execute(&mut *tx)
                .await?
                .rows_affected();
        if inserted == 0 {
            return Err(Error::Conflict);
        }
        let id = Uuid::new_v4();
        sqlx::query("INSERT INTO brigalow.projects VALUES ($1,$2,$3)")
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
            serde_json::json!({"name":name}),
        )
        .await?;
        tx.commit().await?;
        Ok(id)
    }
    pub async fn project_name(&self, id: Uuid) -> Result<Option<String>, Error> {
        let mut tx = self.begin().await?;
        let name =
            sqlx::query_scalar("SELECT name FROM brigalow.projects WHERE org_id=$1 AND id=$2")
                .bind(self.org_id)
                .bind(id)
                .fetch_optional(&mut *tx)
                .await?;
        tx.commit().await?;
        Ok(name)
    }
    pub async fn object_scope(
        &self,
        kind: ObjectKind,
        id: Uuid,
    ) -> Result<Option<(Uuid, Option<Uuid>)>, Error> {
        let query = match kind {
            ObjectKind::Project => {
                "SELECT id,NULL::uuid FROM brigalow.projects WHERE org_id=$1 AND id=$2"
            }
            ObjectKind::Key => {
                "SELECT project_id,NULL::uuid FROM brigalow.signing_keys WHERE org_id=$1 AND id=$2"
            }
            ObjectKind::Policy => {
                "SELECT project_id,id FROM brigalow.policies WHERE org_id=$1 AND id=$2"
            }
            ObjectKind::Request => {
                "SELECT project_id,policy_id FROM brigalow.sign_requests WHERE org_id=$1 AND id=$2"
            }
        };
        let mut tx = self.begin().await?;
        let row = sqlx::query_as(query)
            .bind(self.org_id)
            .bind(id)
            .fetch_optional(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(row)
    }
}
