use crate::{
    web::{authenticate, Result, WebError},
    AppState,
};
use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use brigalow_core::{
    keys::Algorithm,
    policy::{Format, Policy, RequestState, SignRequest, Submission, Timestamp},
    rbac::{Action, Scope},
    Purpose,
};
use serde::Deserialize;
use std::collections::BTreeMap;
use uuid::Uuid;
pub const CREATE_POLICY: &str = "/v1/orgs/{org}/projects/{id}/policies";
pub const LOOKUP_POLICY: &str = "/v1/orgs/{org}/projects/{id}/policies/{name}";
pub const SUBMIT: &str = "/v1/orgs/{org}/projects/{id}/sign-requests";
#[derive(Clone, Copy)]
pub enum Route {
    CreatePolicy,
    LookupPolicy,
    Submit,
}
pub const ROUTES: [(Route, &str, &str); 3] = [
    (Route::CreatePolicy, "POST", CREATE_POLICY),
    (Route::LookupPolicy, "GET", LOOKUP_POLICY),
    (Route::Submit, "POST", SUBMIT),
];
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyInput {
    pub name: String,
    pub key: Uuid,
    pub purpose: Purpose,
    pub claims: BTreeMap<String, String>,
    pub algorithms: Vec<Algorithm>,
    pub timestamp: Timestamp,
}
pub async fn create_policy(
    State(state): State<AppState>,
    Path((org, project)): Path<(Uuid, Uuid)>,
    headers: HeaderMap,
    Json(input): Json<PolicyInput>,
) -> Result<(StatusCode, Json<Policy>)> {
    let p = authenticate(&state, &headers, org, None, true).await?;
    let tenant = state.store.tenant(org);
    if tenant.project_name(project).await?.is_none() {
        return Err(WebError(StatusCode::NOT_FOUND));
    }
    if !p.allows(Action::ManageProject) {
        return Err(WebError(StatusCode::FORBIDDEN));
    }
    if input.timestamp == Timestamp::Required && state.tsa.is_none() {
        return Err(WebError(StatusCode::UNPROCESSABLE_ENTITY));
    }
    let policy = Policy {
        id: Uuid::new_v4(),
        name: input.name,
        project,
        key: input.key,
        purpose: input.purpose,
        claims: input.claims,
        algorithms: input.algorithms,
        timestamp: input.timestamp,
    };
    let backend = state
        .keys
        .as_ref()
        .ok_or(WebError(StatusCode::SERVICE_UNAVAILABLE))?;
    tenant
        .create_policy(
            &p.actor,
            &policy,
            state.mode == crate::config::Mode::Lab || backend.backend.is_lab(),
        )
        .await?;
    Ok((StatusCode::CREATED, Json(policy)))
}
pub async fn lookup_policy(
    State(state): State<AppState>,
    Path((org, project, name)): Path<(Uuid, Uuid, String)>,
    headers: HeaderMap,
) -> Result<Json<Policy>> {
    let policy = state.store.tenant(org).policy_named(project, &name).await?;
    let scope = policy.as_ref().map(|p| Scope {
        project,
        policy: p.id,
    });
    let p = authenticate(&state, &headers, org, scope.as_ref(), false).await?;
    let policy = policy.ok_or(WebError(StatusCode::NOT_FOUND))?;
    if !p.permits_scope(project, Some(policy.id)) {
        return Err(WebError(StatusCode::NOT_FOUND));
    }
    if !p.allows(Action::Read) {
        return Err(WebError(StatusCode::FORBIDDEN));
    }
    Ok(Json(policy))
}
pub async fn submit(
    State(state): State<AppState>,
    Path((org, project)): Path<(Uuid, Uuid)>,
    headers: HeaderMap,
    Json(input): Json<Submission>,
) -> Result<(StatusCode, Json<SignRequest>)> {
    if !input.valid() {
        return Err(WebError(StatusCode::BAD_REQUEST));
    }
    let tenant = state.store.tenant(org);
    let scope = Scope {
        project,
        policy: input.policy,
    };
    // Unknown IDs still authenticate against configured authority before returning a uniform 404.
    let existing = tenant.policy(input.policy).await?;
    let p = match authenticate(
        &state,
        &headers,
        org,
        existing.as_ref().map(|_| &scope),
        true,
    )
    .await
    {
        Ok(p) => p,
        Err(error) => {
            if let (Some(identity), Some(token)) = (
                &state.identity,
                headers
                    .get("authorization")
                    .and_then(|v| v.to_str().ok())
                    .and_then(|v| v.strip_prefix("Bearer ")),
            ) {
                if !token.starts_with("brg_") {
                    if let Some((actor, claim)) = identity.rejected_claim(org, token, &scope).await
                    {
                        tenant
                            .record(
                                &actor,
                                "request.rejected",
                                &input.request_id.to_string(),
                                serde_json::json!({"reason":format!("claim:{claim}")}),
                            )
                            .await?;
                    }
                }
            }
            return Err(error);
        }
    };
    if !p.allows(Action::Submit) {
        return Err(WebError(StatusCode::FORBIDDEN));
    }
    let backend = state
        .keys
        .as_ref()
        .ok_or(WebError(StatusCode::SERVICE_UNAVAILABLE))?;
    let mut request = tenant
        .prepare_sign(
            &p,
            project,
            input,
            state.mode == crate::config::Mode::Lab || backend.backend.is_lab(),
        )
        .await?;
    if request.state == RequestState::Rejected {
        return Err(WebError(
            if matches!(
                request.failure.as_deref(),
                Some("unknown_policy_or_project" | "scope")
            ) {
                StatusCode::NOT_FOUND
            } else {
                StatusCode::FORBIDDEN
            },
        ));
    }
    let result = produce(&state, &request).await;
    match result {
        Ok((output, timestamp)) => {
            request.output = Some(output);
            request.timestamp = timestamp;
            request.state = RequestState::Signed;
        }
        Err(_) => {
            request.state = RequestState::Failed;
            request.failure = Some("signing_or_timestamp_failed".into());
        }
    }
    tenant.finish_sign(&request).await?;
    if request.state == RequestState::Failed {
        return Err(WebError(StatusCode::BAD_GATEWAY));
    }
    Ok((StatusCode::CREATED, Json(request)))
}
async fn produce(
    state: &AppState,
    request: &SignRequest,
) -> std::result::Result<(Vec<u8>, Option<Vec<u8>>), brigalow_crypto::Error> {
    use brigalow_crypto::{certificates, cms, Error};
    let service = state.keys.as_ref().ok_or(Error::Unavailable)?;
    let key = request.key.as_ref().ok_or(Error::Unavailable)?;
    let policy = request.policy.as_ref().ok_or(Error::Unavailable)?;
    if key.backend != service.id {
        return Err(Error::Unavailable);
    }
    // Revalidate certificate expiry/path before producing each certificate-bearing signature.
    if !key.chain.is_empty() {
        let roots: Vec<_> = service.anchors.iter().map(|a| a.der.clone()).collect();
        let trust = certificates::validate_chain(
            &key.public_key,
            &key.chain,
            &roots,
            crate::auth::now() as u64,
        )?;
        if policy.purpose == Purpose::Release && !certificates::release_allowed(trust) {
            return Err(Error::Certificate);
        }
    }
    let backend = service.backend.clone();
    let key = key.clone();
    let input = request.submission.clone();
    let (mut output, signature) = tokio::task::spawn_blocking(move || {
        if backend.public_key(&key.key)? != key.public_key {
            return Err(Error::Unavailable);
        }
        match input.format {
            Format::Raw => {
                let s = backend.sign_digest(&key.key, input.digest_alg, &input.digest)?;
                Ok((s.clone(), s))
            }
            Format::Cms => {
                let s = cms::detached(backend.as_ref(), &key.key, &input.digest, &key.chain)?;
                Ok((s.der, s.signature))
            }
        }
    })
    .await
    .map_err(|_| Error::Backend)??;
    let mut token = None;
    if policy.timestamp != Timestamp::Disabled {
        let result = match &state.tsa {
            Some(tsa) => tsa.stamp(&signature, crate::auth::now() as u64).await,
            None => Err(Error::Unavailable),
        };
        match result {
            Ok(t) => token = Some(t),
            Err(e) if policy.timestamp == Timestamp::Required => return Err(e),
            Err(_) => {}
        }
    }
    if request.submission.format == Format::Cms {
        if let Some(token) = &token {
            output = cms::attach_timestamp(&output, token)?;
        }
    }
    Ok((output, token))
}
