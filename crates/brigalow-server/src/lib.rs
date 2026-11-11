pub mod auth;
pub mod config;
pub mod keys;
pub mod signing;
pub mod web;
use axum::{
    extract::{DefaultBodyLimit, Path, State},
    http::{HeaderMap, StatusCode},
    middleware,
    routing::{delete, get, post},
    Json, Router,
};
use brigalow_store::Store;
use config::Mode;
use std::sync::Arc;
use uuid::Uuid;
#[derive(Clone)]
pub struct AppState {
    pub store: Store,
    pub mode: Mode,
    pub identity: Option<Arc<auth::Identity>>,
    pub keys: Option<keys::KeyService>,
    pub tsa: Option<brigalow_crypto::timestamp::Client>,
}
pub fn router(store: Store, mode: Mode) -> Router {
    application(AppState {
        store,
        mode,
        identity: None,
        keys: None,
        tsa: None,
    })
}
pub fn application(state: AppState) -> Router {
    let mut router = Router::new().route("/healthz", get(health));
    for (name, kind) in web::OBJECT_ROUTES {
        router = router.route(
            &format!("/v1/orgs/{{org}}/{name}/{{id}}"),
            get(
                move |State(state): State<AppState>,
                      Path((org, id)): Path<(Uuid, Uuid)>,
                      headers: HeaderMap| async move {
                    web::object(state, headers, org, id, kind).await
                },
            ),
        );
    }
    router = router.route(keys::CREATE, post(keys::generate));
    for (name, operation) in keys::MUTATIONS {
        router = router.route(
            &format!("/v1/orgs/{{org}}/keys/{{id}}/{name}"),
            post(
                move |State(state): State<AppState>,
                      Path((org, id)): Path<(Uuid, Uuid)>,
                      headers: HeaderMap,
                      Json(input): Json<keys::Input>| async move {
                    keys::mutate(state, org, id, headers, input, operation).await
                },
            ),
        );
    }
    for (kind, _, path) in signing::ROUTES {
        let method = match kind {
            signing::Route::CreatePolicy => post(signing::create_policy),
            signing::Route::LookupPolicy => get(signing::lookup_policy),
            signing::Route::Submit => post(signing::submit),
        };
        router = router.route(path, method);
    }
    router
        .route(web::TENANT_MUTATIONS[0].1, post(web::create_project))
        .route(web::TENANT_MUTATIONS[1].1, post(web::issue_token))
        .route(web::TENANT_MUTATIONS[2].1, delete(web::revoke_token))
        .route("/auth/{org}/{provider}/login", get(web::login))
        .route("/auth/{org}/{provider}/callback", get(web::callback))
        .route("/auth/{org}/{provider}/complete", post(web::complete))
        .route("/orgs/{org}", get(web::home))
        .route("/orgs/{org}/projects", post(web::project_form))
        .route("/orgs/{org}/projects/{id}", get(web::project_page))
        .route("/orgs/{org}/logout", post(web::logout))
        .layer(DefaultBodyLimit::max(65536))
        .layer(middleware::from_fn(web::security))
        .with_state(state)
}
async fn health(State(state): State<AppState>) -> (StatusCode, Json<serde_json::Value>) {
    let healthy = state.store.healthy().await;
    (
        if healthy {
            StatusCode::OK
        } else {
            StatusCode::SERVICE_UNAVAILABLE
        },
        Json(
            serde_json::json!({"status":if healthy{"ok"}else{"unavailable"},"mode":state.mode,"signing_available":state.keys.is_some() && state.identity.is_some()}),
        ),
    )
}
