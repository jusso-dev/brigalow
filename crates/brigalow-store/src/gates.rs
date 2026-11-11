use crate::*;
use brigalow_core::{
    gates::Result as Outcome,
    keys::KeyRecord,
    policy::{Policy, RequestState, SignRequest},
};
impl Tenant {
    /// A gate response cannot authorise a stale key/window or retry a consumed intent.
    pub async fn finish_gates(
        &self,
        id: Uuid,
        outcomes: Vec<Outcome>,
        lab: bool,
    ) -> Result<SignRequest, Error> {
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
        if request.state != RequestState::Gating {
            return Err(Error::Conflict);
        }
        let expected = &request.policy.as_ref().ok_or(Error::Invalid)?.gates;
        let passed = !expected.is_empty()
            && expected.len() == outcomes.len()
            && expected
                .iter()
                .zip(&outcomes)
                .all(|(name, result)| name == &result.gate && result.passed);
        request.gate_results = outcomes;
        for outcome in &request.gate_results {
            self.append(
                &mut tx,
                "system",
                "gate.result",
                &id.to_string(),
                serde_json::to_value(outcome).map_err(|_| Error::Invalid)?,
            )
            .await?;
        }
        if !passed {
            request.failure = Some("gate_failed".into());
        }
        if request.failure.is_none() {
            let policy: Option<Option<Json<Policy>>> = sqlx::query_scalar(
                "SELECT record FROM brigalow.policies WHERE org_id=$1 AND id=$2 AND project_id=$3",
            )
            .bind(self.org_id)
            .bind(request.submission.policy)
            .bind(request.project)
            .fetch_optional(&mut *tx)
            .await?;
            let policy = policy.flatten().ok_or(Error::NotFound)?.0;
            if serde_json::to_value(&policy).map_err(|_| Error::Invalid)?
                != serde_json::to_value(&request.policy).map_err(|_| Error::Invalid)?
            {
                request.failure = Some("policy_changed".into());
            }
            let key:Option<Option<Json<KeyRecord>>>=sqlx::query_scalar("SELECT record FROM brigalow.signing_keys WHERE org_id=$1 AND id=$2 AND project_id=$3 FOR UPDATE")
                .bind(self.org_id).bind(policy.key).bind(request.project).fetch_optional(&mut *tx).await?;
            let key = key.flatten().ok_or(Error::NotFound)?.0;
            if request.failure.is_none() {
                request.failure = policy
                    .authorise(&key, request.principal.as_ref().ok_or(Error::Invalid)?, lab)
                    .err();
            }
            request.key = Some(key);
            let now = Self::now(&mut tx).await?;
            if request.failure.is_none() && !self.claim_window(&mut tx, &mut request, now).await? {
                request.failure = Some("release_window_required_or_exhausted".into());
            }
        }
        request.state = if request.failure.is_none() {
            RequestState::Signing
        } else {
            RequestState::Rejected
        };
        self.persist_request(
            &mut tx,
            &request,
            "system",
            &format!("request.{}", request.state.as_str()),
        )
        .await?;
        tx.commit().await?;
        Ok(request)
    }
}
