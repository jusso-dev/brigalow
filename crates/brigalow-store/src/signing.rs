use crate::*;
use brigalow_core::{
    keys::{binding_allowed, KeyRecord},
    policy::{Policy, RequestState, SignRequest, Submission},
    rbac::Principal,
};
impl Tenant {
    pub async fn policy(&self, id: Uuid) -> Result<Option<Policy>, Error> {
        let mut tx = self.begin().await?;
        let row: Option<Option<Json<Policy>>> =
            sqlx::query_scalar("SELECT record FROM brigalow.policies WHERE org_id=$1 AND id=$2")
                .bind(self.org_id)
                .bind(id)
                .fetch_optional(&mut *tx)
                .await?;
        tx.commit().await?;
        Ok(row.flatten().map(|v| v.0))
    }
    pub async fn policy_named(&self, project: Uuid, name: &str) -> Result<Option<Policy>, Error> {
        let mut tx = self.begin().await?;
        let row: Option<Option<Json<Policy>>> = sqlx::query_scalar(
            "SELECT record FROM brigalow.policies WHERE org_id=$1 AND project_id=$2 AND name=$3",
        )
        .bind(self.org_id)
        .bind(project)
        .bind(name)
        .fetch_optional(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(row.flatten().map(|v| v.0))
    }
    pub async fn create_policy(
        &self,
        actor: &str,
        policy: &Policy,
        lab: bool,
    ) -> Result<(), Error> {
        let mut tx = self.begin().await?;
        self.lock_audit(&mut tx).await?;
        let key:Option<Option<Json<KeyRecord>>>=sqlx::query_scalar("SELECT record FROM brigalow.signing_keys WHERE org_id=$1 AND id=$2 AND project_id=$3 FOR UPDATE").bind(self.org_id).bind(policy.key).bind(policy.project).fetch_optional(&mut *tx).await?;
        let key = key.flatten().ok_or(Error::NotFound)?.0;
        if !policy.valid()
            || !binding_allowed(&key, policy.purpose, lab)
            || !policy.algorithms.contains(&key.key.algorithm)
        {
            return Err(Error::Invalid);
        }
        sqlx::query("INSERT INTO brigalow.policies (org_id,id,project_id,key_id,record,name) VALUES ($1,$2,$3,$4,$5,$6)").bind(self.org_id).bind(policy.id).bind(policy.project).bind(policy.key).bind(Json(policy)).bind(&policy.name).execute(&mut *tx).await?;
        self.append(
            &mut tx,
            actor,
            "policy.created",
            &policy.id.to_string(),
            serde_json::json!({"key":policy.key,"purpose":policy.purpose}),
        )
        .await?;
        tx.commit().await?;
        Ok(())
    }
    pub async fn sign_request(&self, id: Uuid) -> Result<Option<SignRequest>, Error> {
        let mut tx = self.begin().await?;
        let row: Option<Option<Json<SignRequest>>> = sqlx::query_scalar(
            "SELECT record FROM brigalow.sign_requests WHERE org_id=$1 AND id=$2",
        )
        .bind(self.org_id)
        .bind(id)
        .fetch_optional(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(row.flatten().map(|v| v.0))
    }
    /// Commit durable intent before any backend call. No automatic retry after a crash.
    pub async fn prepare_sign(
        &self,
        p: &Principal,
        project: Uuid,
        input: Submission,
        lab: bool,
    ) -> Result<SignRequest, Error> {
        if p.org_id != self.org_id {
            return Err(Error::NotFound);
        }
        let mut tx = self.begin().await?;
        self.lock_audit(&mut tx).await?;
        let used =
            sqlx::query("INSERT INTO brigalow.request_ids VALUES ($1,$2) ON CONFLICT DO NOTHING")
                .bind(self.org_id)
                .bind(input.request_id)
                .execute(&mut *tx)
                .await?
                .rows_affected();
        if used != 1 {
            return Err(Error::Conflict);
        }
        let mut request = SignRequest {
            submission: input,
            project,
            requester: p.actor.clone(),
            verified_claims: p.claims.clone(),
            state: RequestState::Rejected,
            policy: None,
            key: None,
            output: None,
            timestamp: None,
            failure: None,
            approval: None,
            principal: Some(p.clone()),
            window: None,
            gate_results: vec![],
            attestation: None,
        };
        let row: Option<Option<Json<Policy>>> = sqlx::query_scalar(
            "SELECT record FROM brigalow.policies WHERE org_id=$1 AND id=$2 AND project_id=$3",
        )
        .bind(self.org_id)
        .bind(request.submission.policy)
        .bind(project)
        .fetch_optional(&mut *tx)
        .await?;
        if let Some(policy) = row.flatten() {
            let policy = policy.0;
            let key:Option<Option<Json<KeyRecord>>>=sqlx::query_scalar("SELECT record FROM brigalow.signing_keys WHERE org_id=$1 AND id=$2 AND project_id=$3 FOR UPDATE").bind(self.org_id).bind(policy.key).bind(project).fetch_optional(&mut *tx).await?;
            if let Some(key) = key.flatten() {
                request.failure = policy.authorise(&key.0, p, lab).err();
                request.key = Some(key.0);
            } else {
                request.failure = Some("key_binding".into());
            }
            let now = Self::now(&mut tx).await?;
            if request.failure.is_none() {
                if let Some(rule) = &policy.approval {
                    request.approval = Some(
                        brigalow_core::approvals::Approval::new(rule.clone(), p.actor.clone(), now)
                            .map_err(|_| Error::Invalid)?,
                    );
                    request.state = RequestState::AwaitingApproval;
                } else if !policy.gates.is_empty() {
                    request.state = RequestState::Gating;
                } else if self.claim_window(&mut tx, &mut request, now).await? {
                    request.state = RequestState::Signing;
                } else {
                    request.failure = Some("release_window_required_or_exhausted".into());
                }
            }
            request.policy = Some(policy);
            sqlx::query("INSERT INTO brigalow.sign_requests (org_id,id,project_id,policy_id,record,state) VALUES ($1,$2,$3,$4,$5,$6)").bind(self.org_id).bind(request.submission.request_id).bind(project).bind(request.submission.policy).bind(Json(&request)).bind(request.state.as_str()).execute(&mut *tx).await?;
        } else {
            request.failure = Some("unknown_policy_or_project".into());
        }
        let id = request.submission.request_id.to_string();
        self.append(&mut tx,&p.actor,"request.submitted",&id,serde_json::json!({"policy":request.submission.policy,"project":project,"digest":request.submission.digest,"artifact_name":request.submission.artifact_name})).await?;
        if matches!(
            request.state,
            RequestState::Signing | RequestState::AwaitingApproval | RequestState::Gating
        ) {
            self.append(
                &mut tx,
                &p.actor,
                "request.authorised",
                &id,
                serde_json::json!({"verified_claims":p.claims}),
            )
            .await?;
            self.append(
                &mut tx,
                &p.actor,
                &format!("request.{}", request.state.as_str()),
                &id,
                serde_json::json!({}),
            )
            .await?;
        } else {
            self.append(
                &mut tx,
                &p.actor,
                "request.rejected",
                &id,
                serde_json::json!({"reason":request.failure}),
            )
            .await?;
        }
        tx.commit().await?;
        Ok(request)
    }
    pub async fn finish_sign(&self, request: &SignRequest) -> Result<(), Error> {
        if !matches!(request.state, RequestState::Signed | RequestState::Failed) {
            return Err(Error::Invalid);
        }
        let mut tx = self.begin().await?;
        self.lock_audit(&mut tx).await?;
        let state = if request.state == RequestState::Signed {
            "signed"
        } else {
            "failed"
        };
        let changed=sqlx::query("UPDATE brigalow.sign_requests SET record=$3,state=$4 WHERE org_id=$1 AND id=$2 AND state='signing'").bind(self.org_id).bind(request.submission.request_id).bind(Json(request)).bind(state).execute(&mut *tx).await?.rows_affected();
        if changed != 1 {
            return Err(Error::Conflict);
        }
        self.append(
            &mut tx,
            &request.requester,
            &format!("request.{state}"),
            &request.submission.request_id.to_string(),
            serde_json::json!({"reason":request.failure}),
        )
        .await?;
        tx.commit().await?;
        Ok(())
    }
}
