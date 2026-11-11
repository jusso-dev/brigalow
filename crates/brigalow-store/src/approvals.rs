use crate::*;
use brigalow_core::{
    approvals::{Decision, Status},
    keys::{KeyRecord, KeyState},
    policy::{Policy, RequestState, SignRequest},
    rbac::Principal,
    windows::ReleaseWindow,
};
impl Tenant {
    pub async fn pending_requests(&self) -> Result<Vec<SignRequest>, Error> {
        let mut tx = self.begin().await?;
        let rows:Vec<Json<SignRequest>>=sqlx::query_scalar("SELECT record FROM brigalow.sign_requests WHERE org_id=$1 AND state='awaiting_approval' ORDER BY id LIMIT 100").bind(self.org_id).fetch_all(&mut *tx).await?;
        tx.commit().await?;
        Ok(rows.into_iter().map(|r| r.0).collect())
    }

    pub(crate) async fn now(tx: &mut Transaction<'_, Postgres>) -> Result<i64, Error> {
        Ok(
            sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()))::bigint")
                .fetch_one(&mut **tx)
                .await?,
        )
    }
    pub async fn window(&self, id: Uuid) -> Result<Option<ReleaseWindow>, Error> {
        let mut tx = self.begin().await?;
        let row: Option<(Json<ReleaseWindow>, i64, bool)> = sqlx::query_as(
            "SELECT record,used,closed FROM brigalow.release_windows WHERE org_id=$1 AND id=$2",
        )
        .bind(self.org_id)
        .bind(id)
        .fetch_optional(&mut *tx)
        .await?;
        tx.commit().await?;
        row.map(|(mut w, used, closed)| {
            w.0.used = used.try_into().map_err(|_| Error::Invalid)?;
            w.0.closed = closed;
            Ok(w.0)
        })
        .transpose()
    }
    pub async fn create_window(&self, actor: &str, window: &ReleaseWindow) -> Result<(), Error> {
        if !window.valid() || window.used != 0 || window.closed {
            return Err(Error::Invalid);
        }
        let mut tx = self.begin().await?;
        self.lock_audit(&mut tx).await?;
        let key:Option<Option<Json<KeyRecord>>>=sqlx::query_scalar("SELECT record FROM brigalow.signing_keys WHERE org_id=$1 AND id=$2 AND project_id=$3 FOR UPDATE").bind(self.org_id).bind(window.key).bind(window.project).fetch_optional(&mut *tx).await?;
        let key = key.flatten().ok_or(Error::NotFound)?.0;
        if !key.offline
            || key.state != KeyState::Active
            || window.ends_at <= Self::now(&mut tx).await?
        {
            return Err(Error::Invalid);
        }
        let overlap:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM brigalow.release_windows WHERE org_id=$1 AND key_id=$2 AND NOT closed AND (record->>'starts_at')::bigint<$4 AND (record->>'ends_at')::bigint>$3)").bind(self.org_id).bind(window.key).bind(window.starts_at).bind(window.ends_at).fetch_one(&mut *tx).await?;
        if overlap {
            return Err(Error::Conflict);
        }
        sqlx::query("INSERT INTO brigalow.release_windows(org_id,id,project_id,key_id,record) VALUES($1,$2,$3,$4,$5)").bind(self.org_id).bind(window.id).bind(window.project).bind(window.key).bind(Json(window)).execute(&mut *tx).await?;
        self.append(
            &mut tx,
            actor,
            "window.opened",
            &window.id.to_string(),
            serde_json::to_value(window).map_err(|_| Error::Invalid)?,
        )
        .await?;
        tx.commit().await?;
        Ok(())
    }
    pub async fn close_window(&self, id: Uuid, actor: &str) -> Result<(), Error> {
        let mut tx = self.begin().await?;
        self.lock_audit(&mut tx).await?;
        let changed=sqlx::query("UPDATE brigalow.release_windows SET closed=true WHERE org_id=$1 AND id=$2 AND NOT closed").bind(self.org_id).bind(id).execute(&mut *tx).await?.rows_affected();
        if changed != 1 {
            return Err(Error::NotFound);
        }
        self.append(
            &mut tx,
            actor,
            "window.closed",
            &id.to_string(),
            serde_json::json!({}),
        )
        .await?;
        tx.commit().await?;
        Ok(())
    }
    pub(crate) async fn claim_window(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        request: &mut SignRequest,
        now: i64,
    ) -> Result<bool, Error> {
        let key = request.key.as_ref().ok_or(Error::Invalid)?;
        if !key.offline {
            return Ok(true);
        }
        let row:Option<(Json<ReleaseWindow>,i64)>=sqlx::query_as("SELECT record,used FROM brigalow.release_windows WHERE org_id=$1 AND key_id=$2 AND project_id=$3 AND NOT closed AND (record->>'starts_at')::bigint<=$4 AND (record->>'ends_at')::bigint>$4 AND (record->>'cap' IS NULL OR used<(record->>'cap')::bigint) ORDER BY id LIMIT 1 FOR UPDATE").bind(self.org_id).bind(key.key.id).bind(key.project).bind(now).fetch_optional(&mut **tx).await?;
        let Some((mut window, used)) = row else {
            return Ok(false);
        };
        window.0.used = used.try_into().map_err(|_| Error::Invalid)?;
        if !window.0.available(now) || window.0.key != key.key.id || window.0.project != key.project
        {
            return Ok(false);
        }
        let changed=sqlx::query("UPDATE brigalow.release_windows SET used=used+1 WHERE org_id=$1 AND id=$2 AND NOT closed AND used=$3").bind(self.org_id).bind(window.0.id).bind(used).execute(&mut **tx).await?.rows_affected();
        if changed != 1 {
            return Err(Error::Conflict);
        }
        request.window = Some(window.0.id);
        self.append(
            tx,
            &request.requester,
            "window.used",
            &window.0.id.to_string(),
            serde_json::json!({"request":request.submission.request_id,"used":used+1}),
        )
        .await?;
        Ok(true)
    }
    pub(crate) async fn persist_request(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        request: &SignRequest,
        actor: &str,
        action: &str,
    ) -> Result<(), Error> {
        sqlx::query(
            "UPDATE brigalow.sign_requests SET record=$3,state=$4 WHERE org_id=$1 AND id=$2",
        )
        .bind(self.org_id)
        .bind(request.submission.request_id)
        .bind(Json(request))
        .bind(request.state.as_str())
        .execute(&mut **tx)
        .await?;
        self.append(
            tx,
            actor,
            action,
            &request.submission.request_id.to_string(),
            serde_json::json!({"state":request.state,"reason":request.failure}),
        )
        .await?;
        Ok(())
    }
    pub async fn decide(
        &self,
        p: &Principal,
        id: Uuid,
        decision: Decision,
        lab: bool,
    ) -> Result<SignRequest, Error> {
        if p.org_id != self.org_id {
            return Err(Error::NotFound);
        }
        let mut tx = self.begin().await?;
        self.lock_audit(&mut tx).await?;
        let row: Option<Option<Json<SignRequest>>> = sqlx::query_scalar(
            "SELECT record FROM brigalow.sign_requests WHERE org_id=$1 AND id=$2 FOR UPDATE",
        )
        .bind(self.org_id)
        .bind(id)
        .fetch_optional(&mut *tx)
        .await?;
        let mut request = row.flatten().ok_or(Error::NotFound)?.0;
        if request.state != RequestState::AwaitingApproval {
            return Err(Error::Conflict);
        }
        let now = Self::now(&mut tx).await?;
        let approval = request.approval.as_mut().ok_or(Error::Invalid)?;
        if approval.status(now) == Status::Expired {
            request.state = RequestState::Expired;
            self.persist_request(&mut tx, &request, "system", "request.expired")
                .await?;
            tx.commit().await?;
            return Err(Error::Conflict);
        }
        let status = approval.decide(p, decision, now).map_err(|e| {
            if e == brigalow_core::approvals::Error::Forbidden {
                Error::Forbidden
            } else {
                Error::Conflict
            }
        })?;
        self.append(
            &mut tx,
            &p.actor,
            "approval.decided",
            &id.to_string(),
            serde_json::json!({"decision":decision}),
        )
        .await?;
        match status {
            Status::Denied => {
                request.state = RequestState::Rejected;
                request.failure = Some("approval_denied".into());
            }
            Status::Approved => {
                let policy:Option<Option<Json<Policy>>>=sqlx::query_scalar("SELECT record FROM brigalow.policies WHERE org_id=$1 AND id=$2 AND project_id=$3").bind(self.org_id).bind(request.submission.policy).bind(request.project).fetch_optional(&mut *tx).await?;
                let policy = policy.flatten().ok_or(Error::NotFound)?.0;
                let key:Option<Option<Json<KeyRecord>>>=sqlx::query_scalar("SELECT record FROM brigalow.signing_keys WHERE org_id=$1 AND id=$2 AND project_id=$3 FOR UPDATE").bind(self.org_id).bind(policy.key).bind(request.project).fetch_optional(&mut *tx).await?;
                let key = key.flatten().ok_or(Error::NotFound)?.0;
                request.failure = policy
                    .authorise(&key, request.principal.as_ref().ok_or(Error::Invalid)?, lab)
                    .err();
                request.key = Some(key);
                let gating = !policy.gates.is_empty();
                request.policy = Some(policy);
                if request.failure.is_none()
                    && !gating
                    && !self.claim_window(&mut tx, &mut request, now).await?
                {
                    request.failure = Some("release_window_required_or_exhausted".into());
                }
                request.state = if request.failure.is_none() {
                    if gating {
                        RequestState::Gating
                    } else {
                        RequestState::Signing
                    }
                } else {
                    RequestState::Rejected
                };
            }
            Status::Pending => {}
            Status::Expired => request.state = RequestState::Expired,
        }
        self.persist_request(
            &mut tx,
            &request,
            &p.actor,
            &format!("request.{}", request.state.as_str()),
        )
        .await?;
        tx.commit().await?;
        Ok(request)
    }
    pub async fn expire_requests(&self) -> Result<(), Error> {
        let mut tx = self.begin().await?;
        self.lock_audit(&mut tx).await?;
        let now = Self::now(&mut tx).await?;
        let rows:Vec<Json<SignRequest>>=sqlx::query_scalar("SELECT record FROM brigalow.sign_requests WHERE org_id=$1 AND state='awaiting_approval' AND (record->'approval'->>'expires_at')::bigint<=$2 ORDER BY id LIMIT 100 FOR UPDATE").bind(self.org_id).bind(now).fetch_all(&mut *tx).await?;
        for row in rows {
            let mut request = row.0;
            request.state = RequestState::Expired;
            self.persist_request(&mut tx, &request, "system", "request.expired")
                .await?;
        }
        tx.commit().await?;
        Ok(())
    }
}
