use crate::{Error, Tenant};
use brigalow_core::{
    audit::{Checkpoint, SignedCheckpoint},
    keys::Key,
};
use sqlx::types::Json;
impl Tenant {
    pub async fn checkpoint_head(&self, key: &Key) -> Result<Checkpoint, Error> {
        let mut tx = self.begin().await?;
        self.lock_audit(&mut tx).await?;
        let (seq,hash):(i64,String)=sqlx::query_as("SELECT seq,entry->>'entry_hash' FROM brigalow.audit_entries WHERE org_id=$1 ORDER BY seq DESC LIMIT 1").bind(self.org_id).fetch_optional(&mut *tx).await?.ok_or(Error::NotFound)?;
        let at: i64 =
            sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()))::bigint")
                .fetch_one(&mut *tx)
                .await?;
        tx.commit().await?;
        Ok(Checkpoint {
            version: 1,
            org_id: self.org_id,
            seq: seq as u64,
            entry_hash: hash,
            at,
            key_id: key.id,
            algorithm: key.algorithm,
        })
    }
    pub async fn save_checkpoint(&self, signed: &SignedCheckpoint) -> Result<(), Error> {
        let checkpoint = &signed.checkpoint;
        if checkpoint.org_id != self.org_id
            || checkpoint.message().is_err()
            || signed.signature.len() > 1024
        {
            return Err(Error::Invalid);
        }
        let mut tx = self.begin().await?;
        self.lock_audit(&mut tx).await?;
        let hash: Option<String> = sqlx::query_scalar(
            "SELECT entry->>'entry_hash' FROM brigalow.audit_entries WHERE org_id=$1 AND seq=$2",
        )
        .bind(self.org_id)
        .bind(checkpoint.seq as i64)
        .fetch_optional(&mut *tx)
        .await?;
        if hash.as_deref() != Some(&checkpoint.entry_hash) {
            return Err(Error::Conflict);
        }
        // A checkpoint authenticates this exact prefix, even if new events have arrived.
        let changed=sqlx::query("INSERT INTO brigalow.audit_checkpoints(org_id,seq,record) VALUES($1,$2,$3) ON CONFLICT DO NOTHING").bind(self.org_id).bind(checkpoint.seq as i64).bind(Json(signed)).execute(&mut *tx).await?.rows_affected();
        if changed != 1 {
            return Err(Error::Conflict);
        }
        tx.commit().await?;
        Ok(())
    }
}
