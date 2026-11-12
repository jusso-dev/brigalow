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
    policy::{Format, Policy, RemoteEvidence, RequestState, SignRequest, Submission, Timestamp},
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
    #[serde(default)]
    pub approval: Option<brigalow_core::approvals::Rule>,
    #[serde(default)]
    pub gates: Vec<String>,
    #[serde(default)]
    pub attestation: bool,
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
        approval: input.approval,
        gates: input.gates,
        attestation: input.attestation,
    };
    if !state.gates.configured(org, &policy.gates) {
        return Err(WebError(StatusCode::UNPROCESSABLE_ENTITY));
    }
    let backend = state
        .keys
        .as_ref()
        .ok_or(WebError(StatusCode::SERVICE_UNAVAILABLE))?;
    // Rotating keys sign digests only (RSA, raw or CMS). DSSE provenance needs a stable key
    // and message signing, so that combination is refused here and again at signing.
    if backend.backend.rotates()
        && (policy.attestation || policy.algorithms.iter().any(|a| *a != Algorithm::Rsa3072))
    {
        return Err(WebError(StatusCode::UNPROCESSABLE_ENTITY));
    }
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
    let request = tenant
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
    if request.state == RequestState::AwaitingApproval {
        state.notifications.requested(&tenant, &request).await?;
        return Ok((StatusCode::ACCEPTED, Json(request)));
    }
    complete(&state, request).await
}
pub async fn complete(
    state: &AppState,
    mut request: SignRequest,
) -> Result<(StatusCode, Json<SignRequest>)> {
    let tenant = state.store.tenant(
        request
            .principal
            .as_ref()
            .ok_or(WebError(StatusCode::INTERNAL_SERVER_ERROR))?
            .org_id,
    );
    if request.state == RequestState::Gating {
        let outcomes = state.gates.run(&request).await;
        let service = state
            .keys
            .as_ref()
            .ok_or(WebError(StatusCode::SERVICE_UNAVAILABLE))?;
        request = tenant
            .finish_gates(
                request.submission.request_id,
                outcomes,
                state.mode == crate::config::Mode::Lab || service.backend.is_lab(),
            )
            .await?;
        if request.state != RequestState::Signing {
            return Err(WebError(StatusCode::FORBIDDEN));
        }
    }
    let (remote, result) = produce(state, &request).await;
    request.remote = remote;
    match result {
        Ok((output, timestamp, attestation)) => {
            request.attestation = attestation;
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
type Produced = (Vec<u8>, Option<Vec<u8>>, Option<serde_json::Value>);
type Outcome = std::result::Result<Produced, brigalow_crypto::Error>;
async fn produce(state: &AppState, request: &SignRequest) -> (Option<RemoteEvidence>, Outcome) {
    let rotates = state.keys.as_ref().is_some_and(|s| s.backend.rotates());
    if !rotates {
        return (None, produce_pinned(state, request).await);
    }
    let mut evidence = RemoteEvidence::default();
    let result = match remote_sign(state, request, &mut evidence).await {
        Ok((output, signature)) => finish(state, request, output, signature, false).await,
        Err(error) => Err(error),
    };
    // Always recorded for rotating keys: an absent operation ID means none was received,
    // not that the service did not sign (a lost submission is indistinguishable).
    (Some(evidence), result)
}
/// Rotating-key path: one remote operation, accepted only after the returned chain validates
/// to the pinned anchor with the profile EKU and the signature verifies with the leaf key.
async fn remote_sign(
    state: &AppState,
    request: &SignRequest,
    evidence: &mut RemoteEvidence,
) -> std::result::Result<(Vec<u8>, Vec<u8>), brigalow_crypto::Error> {
    use brigalow_crypto::{cms, rotating, Error};
    let service = state.keys.as_ref().ok_or(Error::Unavailable)?;
    let key = request.key.as_ref().ok_or(Error::Unavailable)?;
    let policy = request.policy.as_ref().ok_or(Error::Unavailable)?;
    if key.backend != service.id
        || !key.public_key.is_empty()
        || key.key.algorithm != Algorithm::Rsa3072
        || policy.attestation
    {
        return Err(Error::Unavailable);
    }
    let backend = service.backend.clone();
    if policy.purpose == Purpose::Release {
        // Release needs an external-ca label whose named anchor is still configured with that
        // tier and is the anchor this backend validates every result against.
        let pinned = {
            let backend = backend.clone();
            let key = key.key.clone();
            tokio::task::spawn_blocking(move || backend.rotating(&key))
                .await
                .map_err(|_| Error::Backend)??
                .anchor
        };
        if key.trust != brigalow_core::TrustTier::ExternalCa
            || !service.anchors.iter().any(|a| {
                Some(&a.name) == key.anchor.as_ref()
                    && a.tier == brigalow_core::TrustTier::ExternalCa
                    && a.der == pinned
            })
        {
            return Err(Error::Certificate);
        }
    }
    let key = key.key.clone();
    let input = request.submission.clone();
    let now = crate::auth::now() as u64;
    let (operation_id, result) = tokio::task::spawn_blocking(move || match input.format {
        Format::Raw => {
            let (id, verified) = rotating::sign(backend.as_ref(), &key, &input.digest, now);
            (
                id,
                verified.map(|v| (v.signature.clone(), v.signature, v.chain)),
            )
        }
        Format::Cms => {
            let (id, result) = cms::detached_rotating(backend.as_ref(), &key, &input.digest, now);
            (id, result.map(|(c, chain)| (c.der, c.signature, chain)))
        }
    })
    .await
    .map_err(|_| Error::Backend)?;
    evidence.operation_id = operation_id;
    let (output, signature, chain) = result?;
    use sha2::Digest;
    evidence.certificate_sha256 = Some(
        sha2::Sha256::digest(&chain[0])
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect(),
    );
    evidence.certificate = Some(chain[0].clone());
    Ok((output, signature))
}
async fn produce_pinned(state: &AppState, request: &SignRequest) -> Outcome {
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
    let (output, signature) = tokio::task::spawn_blocking(move || {
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
    finish(state, request, output, signature, policy.attestation).await
}
/// Shared by both paths: timestamp the signature and, for pinned keys, add provenance.
async fn finish(
    state: &AppState,
    request: &SignRequest,
    mut output: Vec<u8>,
    signature: Vec<u8>,
    attestation: bool,
) -> Outcome {
    use brigalow_crypto::{cms, Error};
    let service = state.keys.as_ref().ok_or(Error::Unavailable)?;
    let policy = request.policy.as_ref().ok_or(Error::Unavailable)?;
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
    let attestation = if attestation {
        let backend = service.backend.clone();
        let key = request.key.as_ref().ok_or(Error::Unavailable)?.key.clone();
        let request = request.clone();
        Some(
            tokio::task::spawn_blocking(move || {
                brigalow_crypto::attestation::provenance(backend.as_ref(), &key, &request)
            })
            .await
            .map_err(|_| Error::Backend)??,
        )
    } else {
        None
    };
    Ok((output, token, attestation))
}
