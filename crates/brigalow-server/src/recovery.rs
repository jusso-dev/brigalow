//! Read-only inspection of interrupted signing requests (plan 001, first slice).
//! Never mutates state, never invokes a backend and never releases request IDs or caps.
use crate::{
    web::{authenticate, Result, WebError},
    AppState,
};
use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use brigalow_core::{policy::RequestState, rbac::Action};
use serde::Serialize;
use uuid::Uuid;

pub const INSPECT: &str = "/v1/orgs/{org}/requests/{id}/inspection";
/// Route registry consumed by the router and by cross-tenant tests.
pub const ROUTES: [(&str, &str); 1] = [("GET", INSPECT)];
/// Bound on returned audit summaries; more are reported as truncated, never streamed.
pub const MAX_EVENTS: usize = 64;

#[derive(Serialize)]
pub struct Event {
    pub seq: i64,
    pub at: i64,
    pub action: String,
}
#[derive(Serialize)]
pub struct Inspection {
    pub request_id: Uuid,
    pub project: Uuid,
    pub policy: Uuid,
    pub key: Option<Uuid>,
    pub state: RequestState,
    /// Always true: no persisted row proves whether a native backend call completed.
    pub outcome_unknown: bool,
    /// `signing` has committed authority to call the backend; `gating` has not yet.
    pub backend_invocation_possible: bool,
    pub events: Vec<Event>,
    pub events_truncated: bool,
}

pub async fn inspect(
    State(state): State<AppState>,
    Path((org, id)): Path<(Uuid, Uuid)>,
    headers: HeaderMap,
) -> Result<Json<Inspection>> {
    let p = authenticate(&state, &headers, org, None, false).await?;
    // Permission before lookup, so unauthorised roles learn nothing about existence.
    if !p.allows(Action::Audit) {
        return Err(WebError(StatusCode::FORBIDDEN));
    }
    let (request, events, truncated) = state
        .store
        .tenant(org)
        .inspect_request(id, MAX_EVENTS)
        .await?
        .ok_or(WebError(StatusCode::NOT_FOUND))?;
    if !p.permits_scope(request.project, Some(request.submission.policy)) {
        return Err(WebError(StatusCode::NOT_FOUND));
    }
    if !matches!(request.state, RequestState::Gating | RequestState::Signing) {
        return Err(WebError(StatusCode::CONFLICT));
    }
    Ok(Json(Inspection {
        request_id: request.submission.request_id,
        project: request.project,
        policy: request.submission.policy,
        key: request.key.as_ref().map(|k| k.key.id),
        state: request.state,
        outcome_unknown: true,
        backend_invocation_possible: request.state == RequestState::Signing,
        events: events
            .into_iter()
            .map(|(seq, at, action)| Event { seq, at, action })
            .collect(),
        events_truncated: truncated,
    }))
}
