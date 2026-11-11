use crate::{
    web::{self, Result, WebError},
    AppState,
};
use askama::Template;
use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{Html, IntoResponse, Redirect, Response},
    Form, Json,
};
use brigalow_core::{
    approvals::Decision,
    policy::{RequestState, SignRequest},
    rbac::{Action, Principal},
    windows::ReleaseWindow,
};
use serde::Deserialize;
use uuid::Uuid;
#[derive(Clone, Copy)]
pub enum Route {
    Decide,
    CreateWindow,
    Window,
    CloseWindow,
}
pub const ROUTES: [(Route, &str, &str); 4] = [
    (
        Route::Decide,
        "POST",
        "/v1/orgs/{org}/requests/{id}/decisions",
    ),
    (
        Route::CreateWindow,
        "POST",
        "/v1/orgs/{org}/keys/{id}/windows",
    ),
    (Route::Window, "GET", "/v1/orgs/{org}/windows/{id}"),
    (
        Route::CloseWindow,
        "POST",
        "/v1/orgs/{org}/windows/{id}/close",
    ),
];
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DecisionInput {
    pub decision: Decision,
}
async fn decide_as(
    state: &AppState,
    p: &Principal,
    id: Uuid,
    decision: Decision,
) -> Result<(StatusCode, Json<SignRequest>)> {
    let tenant = state.store.tenant(p.org_id);
    let request = tenant
        .sign_request(id)
        .await?
        .ok_or(WebError(StatusCode::NOT_FOUND))?;
    if !p.permits_scope(request.project, Some(request.submission.policy)) {
        return Err(WebError(StatusCode::NOT_FOUND));
    }
    if !p.allows(Action::Approve) {
        return Err(WebError(StatusCode::FORBIDDEN));
    }
    let keys = state
        .keys
        .as_ref()
        .ok_or(WebError(StatusCode::SERVICE_UNAVAILABLE))?;
    let request = tenant
        .decide(
            p,
            id,
            decision,
            state.mode == crate::config::Mode::Lab || keys.backend.is_lab(),
        )
        .await?;
    if request.state == RequestState::Signing {
        crate::signing::complete(state, request).await
    } else {
        Ok((StatusCode::OK, Json(request)))
    }
}
pub async fn decide(
    State(state): State<AppState>,
    Path((org, id)): Path<(Uuid, Uuid)>,
    headers: HeaderMap,
    Json(input): Json<DecisionInput>,
) -> Result<(StatusCode, Json<SignRequest>)> {
    let p = web::authenticate(&state, &headers, org, None, true).await?;
    decide_as(&state, &p, id, input.decision).await
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowInput {
    pub name: String,
    pub starts_at: i64,
    pub ends_at: i64,
    pub cap: Option<u32>,
}
pub async fn create_window(
    State(state): State<AppState>,
    Path((org, id)): Path<(Uuid, Uuid)>,
    headers: HeaderMap,
    Json(input): Json<WindowInput>,
) -> Result<(StatusCode, Json<ReleaseWindow>)> {
    let p = web::authenticate(&state, &headers, org, None, true).await?;
    let tenant = state.store.tenant(org);
    let key = tenant
        .key(id)
        .await?
        .ok_or(WebError(StatusCode::NOT_FOUND))?;
    if !p.allows(Action::ManageKey) {
        return Err(WebError(StatusCode::FORBIDDEN));
    }
    let window = ReleaseWindow {
        id: Uuid::new_v4(),
        key: id,
        project: key.project,
        name: input.name,
        starts_at: input.starts_at,
        ends_at: input.ends_at,
        cap: input.cap,
        used: 0,
        closed: false,
    };
    tenant.create_window(&p.actor, &window).await?;
    Ok((StatusCode::CREATED, Json(window)))
}
pub async fn window(
    State(state): State<AppState>,
    Path((org, id)): Path<(Uuid, Uuid)>,
    headers: HeaderMap,
) -> Result<Json<ReleaseWindow>> {
    let p = web::authenticate(&state, &headers, org, None, false).await?;
    let tenant = state.store.tenant(org);
    let window = tenant
        .window(id)
        .await?
        .ok_or(WebError(StatusCode::NOT_FOUND))?;
    if !p.permits_scope(window.project, None) {
        return Err(WebError(StatusCode::NOT_FOUND));
    }
    if let Some(scope) = &p.scope {
        if tenant.policy_key(scope.policy).await? != Some(window.key) {
            return Err(WebError(StatusCode::NOT_FOUND));
        }
    }
    if !p.allows(Action::Read) {
        return Err(WebError(StatusCode::FORBIDDEN));
    }
    Ok(Json(window))
}
pub async fn close_window(
    State(state): State<AppState>,
    Path((org, id)): Path<(Uuid, Uuid)>,
    headers: HeaderMap,
) -> Result<StatusCode> {
    let p = web::authenticate(&state, &headers, org, None, true).await?;
    let tenant = state.store.tenant(org);
    if tenant.window(id).await?.is_none() {
        return Err(WebError(StatusCode::NOT_FOUND));
    }
    if !p.allows(Action::ManageKey) {
        return Err(WebError(StatusCode::FORBIDDEN));
    }
    tenant.close_window(id, &p.actor).await?;
    Ok(StatusCode::NO_CONTENT)
}
#[derive(Template)]
#[template(path = "request.html")]
struct RequestTemplate<'a> {
    org: Uuid,
    id: Uuid,
    lab: bool,
    artifact: &'a str,
    digest: String,
    status: &'a str,
    policy_name: &'a str,
    key_id: String,
    algorithm: &'a str,
    trust: &'a str,
    claims: Vec<(&'a str, &'a str)>,
    metadata: Vec<(&'a str, &'a str)>,
    decisions: Vec<(&'a str, &'a str)>,
    approval_summary: String,
    can_decide: bool,
    csrf: &'a str,
}
pub async fn page(
    State(state): State<AppState>,
    Path((org, id)): Path<(Uuid, Uuid)>,
    headers: HeaderMap,
) -> Result<Html<String>> {
    let session = web::session(&state, &headers, org).await?;
    let tenant = state.store.tenant(org);
    tenant.expire_requests().await?;
    let request = tenant
        .sign_request(id)
        .await?
        .ok_or(WebError(StatusCode::NOT_FOUND))?;
    if !session
        .principal
        .permits_scope(request.project, Some(request.submission.policy))
    {
        return Err(WebError(StatusCode::NOT_FOUND));
    }
    if !session.principal.allows(Action::Read) {
        return Err(WebError(StatusCode::FORBIDDEN));
    }
    let can_decide = request.state == RequestState::AwaitingApproval
        && request
            .approval
            .as_ref()
            .is_some_and(|a| a.may_decide(&session.principal, crate::auth::now()));
    let approval_summary=match &request.approval {Some(a)=>format!("{} of {} individual approvals required. Any deny rejects while approval is pending. Deadline: {} UTC.",a.rule.required,a.rule.approvers.len(),time::OffsetDateTime::from_unix_timestamp(a.expires_at).map_err(|_|WebError(StatusCode::INTERNAL_SERVER_ERROR))?.format(&time::format_description::well_known::Rfc3339).map_err(|_|WebError(StatusCode::INTERNAL_SERVER_ERROR))?),None=>"No approval required by this policy.".into()};
    let (key_id, algorithm, trust) = match &request.key {
        Some(key) => (
            key.key.id.to_string(),
            match key.key.algorithm {
                brigalow_core::keys::Algorithm::Rsa3072 => "RSA-3072",
                brigalow_core::keys::Algorithm::P256 => "P-256",
                brigalow_core::keys::Algorithm::Ed25519 => "Ed25519",
            },
            match key.trust {
                brigalow_core::TrustTier::Lab => "Lab — test only",
                brigalow_core::TrustTier::Private => "Private anchor",
                brigalow_core::TrustTier::Untrusted => "Untrusted",
                brigalow_core::TrustTier::ExternalCa => "External CA — operator configured",
            },
        ),
        None => ("Unavailable".into(), "Unavailable", "Untrusted"),
    };
    let view = RequestTemplate {
        org,
        id,
        lab: state.mode == crate::config::Mode::Lab,
        artifact: &request.submission.artifact_name,
        digest: request
            .submission
            .digest
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect(),
        status: request.state.as_str(),
        policy_name: request
            .policy
            .as_ref()
            .map(|p| p.name.as_str())
            .unwrap_or("Unavailable"),
        key_id,
        algorithm,
        trust,
        claims: request
            .verified_claims
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect(),
        metadata: request
            .submission
            .metadata
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect(),
        decisions: request
            .approval
            .as_ref()
            .map(|a| {
                a.decisions
                    .iter()
                    .map(|(actor, d)| {
                        (
                            actor.as_str(),
                            if *d == Decision::Approve {
                                "Approved"
                            } else {
                                "Denied"
                            },
                        )
                    })
                    .collect()
            })
            .unwrap_or_default(),
        approval_summary,
        can_decide,
        csrf: session.csrf.as_deref().unwrap_or(""),
    };
    Ok(Html(view.render().map_err(|_| {
        WebError(StatusCode::INTERNAL_SERVER_ERROR)
    })?))
}
#[derive(Template)]
#[template(path = "requests.html")]
struct QueueTemplate {
    org: Uuid,
    lab: bool,
    requests: Vec<(Uuid, String)>,
}
pub async fn queue(
    State(state): State<AppState>,
    Path(org): Path<Uuid>,
    headers: HeaderMap,
) -> Result<Html<String>> {
    let session = web::session(&state, &headers, org).await?;
    if !session.principal.allows(Action::Read) {
        return Err(WebError(StatusCode::FORBIDDEN));
    }
    let tenant = state.store.tenant(org);
    tenant.expire_requests().await?;
    let requests = tenant
        .pending_requests()
        .await?
        .into_iter()
        .filter(|r| {
            session
                .principal
                .permits_scope(r.project, Some(r.submission.policy))
        })
        .map(|r| (r.submission.request_id, r.submission.artifact_name))
        .collect();
    Ok(Html(
        QueueTemplate {
            org,
            lab: state.mode == crate::config::Mode::Lab,
            requests,
        }
        .render()
        .map_err(|_| WebError(StatusCode::INTERNAL_SERVER_ERROR))?,
    ))
}
#[derive(Deserialize)]
pub struct DecisionForm {
    csrf: String,
    decision: Decision,
}
pub async fn form(
    State(state): State<AppState>,
    Path((org, id)): Path<(Uuid, Uuid)>,
    headers: HeaderMap,
    Form(input): Form<DecisionForm>,
) -> Result<Response> {
    web::check_origin(&state, &headers)?;
    let session = web::session(&state, &headers, org).await?;
    web::csrf(&session, Some(&input.csrf))?;
    let _response = decide_as(&state, &session.principal, id, input.decision).await?;
    Ok(Redirect::to(&format!("/orgs/{org}/requests/{id}")).into_response())
}
pub async fn htmx() -> impl IntoResponse {
    (
        [("content-type", "text/javascript; charset=utf-8")],
        include_str!("../static/vendor/htmx-4.0.1.min.js"),
    )
}
