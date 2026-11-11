use crate::{Error, Tenant};
impl Tenant {
    /// Database-clock fixed window anchored at first use; shared across server replicas.
    /// Audit once per exhausted window; an attacker cannot amplify audit writes per rejected call.
    pub async fn take_rate_slot(
        &self,
        credential: &str,
        actor: &str,
        limit: u32,
        seconds: u32,
    ) -> Result<bool, Error> {
        if credential.is_empty()
            || credential.len() > 128
            || limit == 0
            || limit > 100000
            || seconds == 0
            || seconds > 3600
        {
            return Err(Error::Invalid);
        }
        let mut tx = self.begin().await?;
        self.lock_audit(&mut tx).await?;
        let now: i64 =
            sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()))::bigint")
                .fetch_one(&mut *tx)
                .await?;
        sqlx::query("DELETE FROM brigalow.rate_limits WHERE org_id=$1 AND credential IN (SELECT credential FROM brigalow.rate_limits WHERE org_id=$1 AND resets_at<$2 ORDER BY resets_at LIMIT 100)").bind(self.org_id).bind(now-3600).execute(&mut *tx).await?;
        let count:i64=sqlx::query_scalar("INSERT INTO brigalow.rate_limits(org_id,credential,resets_at,count) VALUES($1,$2,$3,1) ON CONFLICT(org_id,credential) DO UPDATE SET count=CASE WHEN brigalow.rate_limits.resets_at<=$4 THEN 1 ELSE least(brigalow.rate_limits.count+1,$5) END,resets_at=CASE WHEN brigalow.rate_limits.resets_at<=$4 THEN $3 ELSE brigalow.rate_limits.resets_at END RETURNING count")
            .bind(self.org_id).bind(credential).bind(now+i64::from(seconds)).bind(now).bind(i64::from(limit)+2).fetch_one(&mut *tx).await?;
        if count == i64::from(limit) + 1 {
            self.append(
                &mut tx,
                actor,
                "credential.rate_limited",
                "request-budget",
                serde_json::json!({"limit":limit,"period_seconds":seconds}),
            )
            .await?;
        }
        tx.commit().await?;
        Ok(count <= i64::from(limit))
    }
}
