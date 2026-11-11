pub mod config;
use axum::{extract::State, http::StatusCode, routing::get, Json, Router};
use brigalow_store::Store;
use config::Mode;

#[derive(Clone)]
struct AppState {
    store: Store,
    mode: Mode,
}

/// Phase 0 deliberately exposes only health. There is no config/debug or tenant API.
pub fn router(store: Store, mode: Mode) -> Router {
    Router::new()
        .route("/healthz", get(health))
        .with_state(AppState { store, mode })
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
            serde_json::json!({"status":if healthy {"ok"} else {"unavailable"},"mode":state.mode,"signing_available":false}),
        ),
    )
}
