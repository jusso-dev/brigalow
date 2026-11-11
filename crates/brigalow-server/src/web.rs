use crate::{
    auth::{self, Identity},
    AppState,
};
use askama::Template;
use axum::{
    extract::{Path, Query, Request, State},
    http::{header, HeaderMap, StatusCode},
    middleware::Next,
    response::{Html, IntoResponse, Redirect, Response},
    Form, Json,
};
use brigalow_core::rbac::{Action, Principal, Scope};
use brigalow_store::{identity::Credential, ObjectKind};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use uuid::Uuid;

pub type Result<T> = std::result::Result<T, WebError>;
pub struct WebError(pub StatusCode);
impl IntoResponse for WebError {
    fn into_response(self) -> Response {
        (
            self.0,
            Json(
                serde_json::json!({"error":self.0.canonical_reason().unwrap_or("request failed")}),
            ),
        )
            .into_response()
    }
}
impl From<crate::auth::AuthError> for WebError {
    fn from(_: crate::auth::AuthError) -> Self {
        Self(StatusCode::UNAUTHORIZED)
    }
}
impl From<brigalow_store::Error> for WebError {
    fn from(e: brigalow_store::Error) -> Self {
        Self(match e {
            brigalow_store::Error::Forbidden => StatusCode::FORBIDDEN,
            brigalow_store::Error::Invalid => StatusCode::UNPROCESSABLE_ENTITY,
            brigalow_store::Error::Conflict => StatusCode::CONFLICT,
            brigalow_store::Error::NotFound => StatusCode::NOT_FOUND,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        })
    }
}
#[derive(Clone, Copy, Serialize)]
pub enum RouteKind {
    Project,
    Key,
    Policy,
    Request,
}
impl RouteKind {
    fn object(self) -> ObjectKind {
        match self {
            Self::Project => ObjectKind::Project,
            Self::Key => ObjectKind::Key,
            Self::Policy => ObjectKind::Policy,
            Self::Request => ObjectKind::Request,
        }
    }
}
// Router construction and cross-tenant test generation consume the same route registry.
pub const OBJECT_ROUTES: [(&str, RouteKind); 4] = [
    ("projects", RouteKind::Project),
    ("keys", RouteKind::Key),
    ("policies", RouteKind::Policy),
    ("requests", RouteKind::Request),
];
pub const TENANT_MUTATIONS: [(&str, &str); 3] = [
    ("POST", "/v1/orgs/{org}/projects"),
    ("POST", "/v1/orgs/{org}/tokens"),
    ("DELETE", "/v1/orgs/{org}/tokens/{id}"),
];

pub async fn security(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    let h = response.headers_mut();
    h.insert("content-security-policy","default-src 'none'; connect-src 'self'; style-src 'self'; script-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'".parse().unwrap());
    h.insert("x-content-type-options", "nosniff".parse().unwrap());
    h.insert("referrer-policy", "no-referrer".parse().unwrap());
    h.insert(header::CACHE_CONTROL, "no-store".parse().unwrap());
    response
}
fn cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    let values: Vec<_> = headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|h| h.to_str().ok())
        .flat_map(|v| v.split(';'))
        .filter_map(|v| v.trim().split_once('='))
        .filter(|(k, _)| *k == name)
        .map(|(_, v)| v.to_owned())
        .collect();
    if values.len() == 1 {
        values.into_iter().next()
    } else {
        None
    }
}
fn identity(state: &AppState) -> Result<&Identity> {
    state
        .identity
        .as_deref()
        .ok_or(WebError(StatusCode::SERVICE_UNAVAILABLE))
}
pub(crate) fn csrf(credential: &Credential, value: Option<&str>) -> Result<()> {
    let expected = credential
        .csrf
        .as_deref()
        .ok_or(WebError(StatusCode::FORBIDDEN))?;
    if !value.is_some_and(|v| bool::from(v.as_bytes().ct_eq(expected.as_bytes()))) {
        return Err(WebError(StatusCode::FORBIDDEN));
    }
    Ok(())
}
pub(crate) fn check_origin(state: &AppState, headers: &HeaderMap) -> Result<()> {
    let expected = identity(state)?.config.public_url.trim_end_matches('/');
    if headers.get(header::ORIGIN).and_then(|h| h.to_str().ok()) != Some(expected) {
        return Err(WebError(StatusCode::FORBIDDEN));
    }
    Ok(())
}
pub(crate) async fn session(
    state: &AppState,
    headers: &HeaderMap,
    org: Uuid,
) -> Result<Credential> {
    let value = cookie(headers, "__Host-brigalow").ok_or(WebError(StatusCode::UNAUTHORIZED))?;
    let (given, token) = value
        .split_once('.')
        .ok_or(WebError(StatusCode::UNAUTHORIZED))?;
    if given.parse::<Uuid>().ok() != Some(org) {
        return Err(WebError(StatusCode::NOT_FOUND));
    }
    if token.len() > 128 {
        return Err(WebError(StatusCode::UNAUTHORIZED));
    }
    state
        .store
        .tenant(org)
        .credential(&auth::hash(token), "session")
        .await?
        .ok_or(WebError(StatusCode::UNAUTHORIZED))
}
pub async fn authenticate(
    state: &AppState,
    headers: &HeaderMap,
    org: Uuid,
    scope: Option<&Scope>,
    mutating: bool,
) -> Result<Principal> {
    if let Some(value) = headers.get(header::AUTHORIZATION) {
        let token = value
            .to_str()
            .ok()
            .and_then(|v| v.strip_prefix("Bearer "))
            .ok_or(WebError(StatusCode::UNAUTHORIZED))?;
        if let Some(token) = token.strip_prefix("brg_") {
            let (given, secret) = token
                .split_once('.')
                .ok_or(WebError(StatusCode::UNAUTHORIZED))?;
            if given.parse::<Uuid>().ok() != Some(org) {
                return Err(WebError(StatusCode::NOT_FOUND));
            }
            if secret.len() > 128 {
                return Err(WebError(StatusCode::UNAUTHORIZED));
            }
            let credential = state
                .store
                .tenant(org)
                .credential(&auth::hash(secret), "api")
                .await?
                .ok_or(WebError(StatusCode::UNAUTHORIZED))?;
            return Ok(credential.principal);
        }
        return Ok(identity(state)?.verify_workload(org, token, scope).await?);
    }
    let credential = session(state, headers, org).await?;
    if mutating {
        check_origin(state, headers)?;
        csrf(
            &credential,
            headers.get("x-csrf-token").and_then(|h| h.to_str().ok()),
        )?;
    }
    Ok(credential.principal)
}
pub async fn object(
    state: AppState,
    headers: HeaderMap,
    org: Uuid,
    id: Uuid,
    kind: RouteKind,
) -> Result<Json<serde_json::Value>> {
    let tenant = state.store.tenant(org);
    // Determine scope from server-owned rows, never caller-supplied signing claims.
    let found = tenant.object_scope(kind.object(), id).await?;
    let workload_scope =
        found.and_then(|(project, policy)| policy.map(|policy| Scope { project, policy }));
    let principal = authenticate(&state, &headers, org, workload_scope.as_ref(), false).await?;
    let scope = found.ok_or(WebError(StatusCode::NOT_FOUND))?;
    if !principal.permits_scope(scope.0, scope.1) {
        return Err(WebError(StatusCode::NOT_FOUND));
    }
    if matches!(kind, RouteKind::Key) {
        if let Some(bound) = &principal.scope {
            if tenant.policy_key(bound.policy).await? != Some(id) {
                return Err(WebError(StatusCode::NOT_FOUND));
            }
        }
    }
    if !principal.allows(Action::Read) {
        return Err(WebError(StatusCode::FORBIDDEN));
    }
    if matches!(kind, RouteKind::Key) {
        if let Some(record) = tenant.key(id).await? {
            return Ok(Json(
                serde_json::to_value(record)
                    .map_err(|_| WebError(StatusCode::INTERNAL_SERVER_ERROR))?,
            ));
        }
    }
    if matches!(kind, RouteKind::Policy) {
        if let Some(policy) = tenant.policy(id).await? {
            return Ok(Json(
                serde_json::to_value(policy)
                    .map_err(|_| WebError(StatusCode::INTERNAL_SERVER_ERROR))?,
            ));
        }
    }
    if matches!(kind, RouteKind::Request) {
        tenant.expire_requests().await?;
        if let Some(request) = tenant.sign_request(id).await? {
            return Ok(Json(
                serde_json::to_value(request)
                    .map_err(|_| WebError(StatusCode::INTERNAL_SERVER_ERROR))?,
            ));
        }
    }
    let name = if matches!(kind, RouteKind::Project) {
        tenant.project_name(id).await?
    } else {
        None
    };
    Ok(Json(serde_json::json!({"id":id,"org_id":org,"name":name})))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectInput {
    pub name: String,
    pub request_id: Uuid,
}
pub async fn create_project(
    State(state): State<AppState>,
    Path(org): Path<Uuid>,
    headers: HeaderMap,
    Json(input): Json<ProjectInput>,
) -> Result<(StatusCode, Json<serde_json::Value>)> {
    let p = authenticate(&state, &headers, org, None, true).await?;
    if !p.allows(Action::ManageProject) {
        return Err(WebError(StatusCode::FORBIDDEN));
    }
    if input.name.is_empty() || input.name.chars().count() > 200 {
        return Err(WebError(StatusCode::BAD_REQUEST));
    }
    let id = state
        .store
        .tenant(org)
        .create_project_once(&p.actor, &input.name, input.request_id)
        .await?;
    Ok((StatusCode::CREATED, Json(serde_json::json!({"id":id}))))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TokenInput {
    pub project: Uuid,
    pub policy: Uuid,
    pub expires_at: i64,
}
pub async fn issue_token(
    State(state): State<AppState>,
    Path(org): Path<Uuid>,
    headers: HeaderMap,
    Json(input): Json<TokenInput>,
) -> Result<(StatusCode, Json<serde_json::Value>)> {
    let p = authenticate(&state, &headers, org, None, true).await?;
    if !p.allows(Action::ManageIdentity)
        || p.roles.contains(&brigalow_core::rbac::Role::KeyCustodian)
    {
        return Err(WebError(StatusCode::FORBIDDEN));
    }
    if input.expires_at <= auth::now() || input.expires_at > auth::now() + 86400 * 30 {
        return Err(WebError(StatusCode::BAD_REQUEST));
    }
    let scope = state
        .store
        .tenant(org)
        .object_scope(ObjectKind::Policy, input.policy)
        .await?
        .ok_or(WebError(StatusCode::NOT_FOUND))?;
    if scope.0 != input.project {
        return Err(WebError(StatusCode::NOT_FOUND));
    }
    let secret = auth::random_secret();
    let principal = Principal {
        org_id: org,
        actor: format!("api:{}", Uuid::new_v4()),
        roles: vec![brigalow_core::rbac::Role::Submitter],
        scope: Some(Scope {
            project: input.project,
            policy: input.policy,
        }),
        human: false,
        claims: Default::default(),
    };
    let id = state
        .store
        .tenant(org)
        .issue_credential(
            &auth::hash(&secret),
            &principal,
            None,
            input.expires_at,
            &p.actor,
        )
        .await?;
    Ok((
        StatusCode::CREATED,
        Json(
            serde_json::json!({"id":id,"token":format!("brg_{org}.{secret}"),"expires_at":input.expires_at}),
        ),
    ))
}
pub async fn revoke_token(
    State(state): State<AppState>,
    Path((org, id)): Path<(Uuid, Uuid)>,
    headers: HeaderMap,
) -> Result<StatusCode> {
    let p = authenticate(&state, &headers, org, None, true).await?;
    if !p.allows(Action::ManageIdentity) {
        return Err(WebError(StatusCode::FORBIDDEN));
    }
    if !state
        .store
        .tenant(org)
        .revoke_credential(id, &p.actor)
        .await?
    {
        return Err(WebError(StatusCode::NOT_FOUND));
    }
    Ok(StatusCode::NO_CONTENT)
}
pub async fn login(
    State(state): State<AppState>,
    Path((org, provider)): Path<(Uuid, String)>,
) -> Result<Response> {
    let login = identity(&state)?.login(org, &provider).await?;
    let mut response = Redirect::to(&login.url).into_response();
    response.headers_mut().insert(
        header::SET_COOKIE,
        format!(
            "__Host-brigalow-login={}; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=300",
            login.browser
        )
        .parse()
        .map_err(|_| WebError(StatusCode::INTERNAL_SERVER_ERROR))?,
    );
    Ok(response)
}
#[derive(Deserialize)]
pub struct Callback {
    pub state: String,
    pub code: String,
}
#[derive(Template)]
#[template(path = "complete.html")]
struct CompleteTemplate<'a> {
    org: Uuid,
    provider: &'a str,
    state: &'a str,
    code: &'a str,
}
pub async fn callback(
    Path((org, provider)): Path<(Uuid, String)>,
    Query(query): Query<Callback>,
) -> Result<Html<String>> {
    if query.state.len() > 256
        || query.code.len() > 4096
        || !provider
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err(WebError(StatusCode::BAD_REQUEST));
    }
    Ok(Html(
        CompleteTemplate {
            org,
            provider: &provider,
            state: &query.state,
            code: &query.code,
        }
        .render()
        .map_err(|_| WebError(StatusCode::INTERNAL_SERVER_ERROR))?,
    ))
}
pub async fn complete(
    State(state): State<AppState>,
    Path((org, provider)): Path<(Uuid, String)>,
    headers: HeaderMap,
    Form(query): Form<Callback>,
) -> Result<Response> {
    check_origin(&state, &headers)?;
    let browser =
        cookie(&headers, "__Host-brigalow-login").ok_or(WebError(StatusCode::UNAUTHORIZED))?;
    let (principal, expires) = identity(&state)?
        .complete(org, &provider, &query.state, &query.code, &browser)
        .await?;
    let token = auth::random_secret();
    let csrf = auth::random_secret();
    state
        .store
        .tenant(org)
        .issue_credential(
            &auth::hash(&token),
            &principal,
            Some(&csrf),
            expires,
            &principal.actor,
        )
        .await?;
    let mut response = Redirect::to(&format!("/orgs/{org}")).into_response();
    response.headers_mut().append(
        header::SET_COOKIE,
        format!(
            "__Host-brigalow={org}.{token}; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age={}",
            expires - auth::now()
        )
        .parse()
        .map_err(|_| WebError(StatusCode::INTERNAL_SERVER_ERROR))?,
    );
    response.headers_mut().append(
        header::SET_COOKIE,
        "__Host-brigalow-login=; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=0"
            .parse()
            .unwrap(),
    );
    Ok(response)
}
#[derive(Template)]
#[template(path = "home.html")]
struct HomeTemplate<'a> {
    request_id: Uuid,
    org: Uuid,
    csrf: &'a str,
    lab: bool,
    can_manage: bool,
}
pub async fn home(
    State(state): State<AppState>,
    Path(org): Path<Uuid>,
    headers: HeaderMap,
) -> Result<Html<String>> {
    let credential = session(&state, &headers, org).await?;
    Ok(Html(
        HomeTemplate {
            request_id: Uuid::new_v4(),
            org,
            csrf: credential.csrf.as_deref().unwrap_or(""),
            lab: state.mode == crate::config::Mode::Lab,
            can_manage: credential.principal.allows(Action::ManageProject),
        }
        .render()
        .map_err(|_| WebError(StatusCode::INTERNAL_SERVER_ERROR))?,
    ))
}
#[derive(Deserialize)]
pub struct Logout {
    csrf: String,
}
pub async fn logout(
    State(state): State<AppState>,
    Path(org): Path<Uuid>,
    headers: HeaderMap,
    Form(input): Form<Logout>,
) -> Result<Response> {
    check_origin(&state, &headers)?;
    let credential = session(&state, &headers, org).await?;
    csrf(&credential, Some(&input.csrf))?;
    state
        .store
        .tenant(org)
        .revoke_credential(credential.id, &credential.principal.actor)
        .await?;
    let mut response = StatusCode::NO_CONTENT.into_response();
    response.headers_mut().insert(
        header::SET_COOKIE,
        "__Host-brigalow=; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=0"
            .parse()
            .unwrap(),
    );
    Ok(response)
}
#[derive(Deserialize)]
pub struct ProjectForm {
    csrf: String,
    name: String,
    request_id: Uuid,
}
pub async fn project_form(
    State(state): State<AppState>,
    Path(org): Path<Uuid>,
    headers: HeaderMap,
    Form(input): Form<ProjectForm>,
) -> Result<Response> {
    check_origin(&state, &headers)?;
    let credential = session(&state, &headers, org).await?;
    csrf(&credential, Some(&input.csrf))?;
    if !credential.principal.allows(Action::ManageProject) {
        return Err(WebError(StatusCode::FORBIDDEN));
    }
    if input.name.is_empty() || input.name.chars().count() > 200 {
        return Err(WebError(StatusCode::BAD_REQUEST));
    }
    let id = state
        .store
        .tenant(org)
        .create_project_once(&credential.principal.actor, &input.name, input.request_id)
        .await?;
    Ok(Redirect::to(&format!("/orgs/{org}/projects/{id}")).into_response())
}
#[derive(Template)]
#[template(path = "project.html")]
struct ProjectTemplate<'a> {
    name: &'a str,
    lab: bool,
}
pub async fn project_page(
    State(state): State<AppState>,
    Path((org, id)): Path<(Uuid, Uuid)>,
    headers: HeaderMap,
) -> Result<Html<String>> {
    session(&state, &headers, org).await?;
    let name = state
        .store
        .tenant(org)
        .project_name(id)
        .await?
        .ok_or(WebError(StatusCode::NOT_FOUND))?;
    Ok(Html(
        ProjectTemplate {
            name: &name,
            lab: state.mode == crate::config::Mode::Lab,
        }
        .render()
        .map_err(|_| WebError(StatusCode::INTERNAL_SERVER_ERROR))?,
    ))
}
