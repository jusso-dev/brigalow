use crate::*;
use brigalow_core::keys::KeyRecord;
impl Tenant {
    pub async fn key(&self, id: Uuid) -> Result<Option<KeyRecord>, Error> {
        let mut tx = self.begin().await?;
        let record: Option<Option<Json<KeyRecord>>> = sqlx::query_scalar(
            "SELECT record FROM brigalow.signing_keys WHERE org_id=$1 AND id=$2",
        )
        .bind(self.org_id)
        .bind(id)
        .fetch_optional(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(record.flatten().map(|v| v.0))
    }
    pub async fn insert_key(&self, actor: &str, key: &KeyRecord) -> Result<(), Error> {
        let mut tx = self.begin().await?;
        self.lock_audit(&mut tx).await?;
        sqlx::query("INSERT INTO brigalow.signing_keys (org_id,id,project_id,record,revision) VALUES ($1,$2,$3,$4,0)")
            .bind(self.org_id).bind(key.key.id).bind(key.project).bind(Json(key)).execute(&mut *tx).await?;
        self.append(&mut tx,actor,"key.generated",&key.key.id.to_string(),serde_json::json!({"purpose":key.key.purpose,"algorithm":key.key.algorithm,"backend":key.backend,"trust":key.trust,"offline":key.offline})).await?;
        tx.commit().await?;
        Ok(())
    }
    pub async fn update_key(
        &self,
        actor: &str,
        action: &str,
        key: &KeyRecord,
    ) -> Result<(), Error> {
        let mut tx = self.begin().await?;
        self.lock_audit(&mut tx).await?;
        let mut next = key.clone();
        next.revision += 1;
        let changed=sqlx::query("UPDATE brigalow.signing_keys SET record=$3,revision=revision+1 WHERE org_id=$1 AND id=$2 AND revision=$4")
            .bind(self.org_id).bind(key.key.id).bind(Json(&next)).bind(key.revision).execute(&mut *tx).await?;
        if changed.rows_affected() != 1 {
            return Err(Error::Conflict);
        }
        self.append(
            &mut tx,
            actor,
            action,
            &key.key.id.to_string(),
            serde_json::json!({"state":key.state,"trust":key.trust,"revision":next.revision}),
        )
        .await?;
        tx.commit().await?;
        Ok(())
    }
}
