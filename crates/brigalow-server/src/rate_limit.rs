use crate::{
    web::{Result, WebError},
    AppState,
};
use brigalow_core::rbac::Principal;
use serde::Deserialize;
#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RateLimit {
    pub requests: u32,
    pub period_seconds: u32,
}
impl Default for RateLimit {
    fn default() -> Self {
        Self {
            requests: 600,
            period_seconds: 60,
        }
    }
}
impl RateLimit {
    pub fn valid(self) -> bool {
        (1..=100000).contains(&self.requests) && (1..=3600).contains(&self.period_seconds)
    }
}
pub async fn check(state: &AppState, principal: &Principal, credential: &str) -> Result<()> {
    if state
        .store
        .tenant(principal.org_id)
        .take_rate_slot(
            credential,
            &principal.actor,
            state.rate_limit.requests,
            state.rate_limit.period_seconds,
        )
        .await?
    {
        Ok(())
    } else {
        Err(WebError(axum::http::StatusCode::TOO_MANY_REQUESTS))
    }
}
