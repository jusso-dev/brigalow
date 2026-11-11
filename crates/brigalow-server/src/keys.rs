//! Custodian-only lifecycle. All responses contain public metadata only.
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
    keys::{Algorithm, KeyRecord, KeyState},
    rbac::Action,
    Purpose, TrustTier,
};
use brigalow_crypto::{certificates, KeyBackend};
use serde::Deserialize;
use std::sync::Arc;
use uuid::Uuid;
#[derive(Clone)]
pub struct KeyService {
    pub backend: Arc<dyn KeyBackend>,
    pub id: String,
    pub anchors: Vec<Anchor>,
}
#[derive(Clone)]
pub struct Anchor {
    pub name: String,
    pub tier: TrustTier,
    pub der: Vec<u8>,
}
#[derive(Clone, Copy)]
pub enum Operation {
    Csr,
    Import,
    Activate,
    Disable,
    Retire,
}
pub const MUTATIONS: [(&str, Operation); 5] = [
    ("csr", Operation::Csr),
    ("certificate", Operation::Import),
    ("activate", Operation::Activate),
    ("disable", Operation::Disable),
    ("retire", Operation::Retire),
];
pub const CREATE: &str = "/v1/orgs/{org}/projects/{id}/keys";
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Generate {
    pub algorithm: Algorithm,
    pub purpose: Purpose,
    pub offline: bool,
}
#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct Input {
    pub subject: Option<String>,
    pub chain: Option<Vec<Vec<u8>>>,
}
fn service(state: &AppState) -> Result<&KeyService> {
    state
        .keys
        .as_ref()
        .ok_or(WebError(StatusCode::SERVICE_UNAVAILABLE))
}
fn crypto(_: brigalow_crypto::Error) -> WebError {
    WebError(StatusCode::UNPROCESSABLE_ENTITY)
}
pub async fn generate(
    State(state): State<AppState>,
    Path((org, project)): Path<(Uuid, Uuid)>,
    headers: HeaderMap,
    Json(input): Json<Generate>,
) -> Result<(StatusCode, Json<KeyRecord>)> {
    let p = authenticate(&state, &headers, org, None, true).await?;
    let tenant = state.store.tenant(org);
    if tenant.project_name(project).await?.is_none() {
        return Err(WebError(StatusCode::NOT_FOUND));
    }
    if !p.allows(Action::ManageKey) {
        return Err(WebError(StatusCode::FORBIDDEN));
    }
    let service = service(&state)?;
    if state.mode == crate::config::Mode::Lab && input.purpose == Purpose::Release {
        return Err(WebError(StatusCode::UNPROCESSABLE_ENTITY));
    }
    let backend = service.backend.clone();
    let (key, public_key) = tokio::task::spawn_blocking(move || {
        let key = backend.generate(input.algorithm, input.purpose)?;
        match backend.public_key(&key) {
            Ok(public) => Ok((key, public)),
            Err(e) => {
                let _ = backend.disable(&key);
                Err(e)
            }
        }
    })
    .await
    .map_err(|_| WebError(StatusCode::INTERNAL_SERVER_ERROR))?
    .map_err(crypto)?;
    let record = KeyRecord {
        key,
        project,
        backend: service.id.clone(),
        state: KeyState::Generated,
        offline: input.offline,
        trust: if service.backend.is_lab() {
            TrustTier::Lab
        } else {
            TrustTier::Untrusted
        },
        public_key,
        anchor: None,
        chain: vec![],
        revision: 0,
    };
    if let Err(e) = tenant.insert_key(&p.actor, &record).await {
        let _ = service.backend.disable(&record.key);
        return Err(e.into());
    }
    Ok((StatusCode::CREATED, Json(record)))
}
pub async fn mutate(
    state: AppState,
    org: Uuid,
    id: Uuid,
    headers: HeaderMap,
    input: Input,
    operation: Operation,
) -> Result<Json<serde_json::Value>> {
    let p = authenticate(&state, &headers, org, None, true).await?;
    let tenant = state.store.tenant(org);
    let mut record = tenant
        .key(id)
        .await?
        .ok_or(WebError(StatusCode::NOT_FOUND))?;
    if !p.allows(Action::ManageKey) {
        return Err(WebError(StatusCode::FORBIDDEN));
    }
    let service = service(&state)?;
    if record.backend != service.id {
        return Err(WebError(StatusCode::CONFLICT));
    }
    let action = match operation {
        Operation::Csr => {
            if !matches!(record.state, KeyState::Generated | KeyState::Certified) {
                return Err(WebError(StatusCode::CONFLICT));
            }
            let subject = input.subject.ok_or(WebError(StatusCode::BAD_REQUEST))?;
            if subject.len() > 1024 {
                return Err(WebError(StatusCode::BAD_REQUEST));
            }
            let backend = service.backend.clone();
            let key = record.key.clone();
            let csr = tokio::task::spawn_blocking(move || {
                certificates::csr(backend.as_ref(), &key, &subject)
            })
            .await
            .map_err(|_| WebError(StatusCode::INTERNAL_SERVER_ERROR))?
            .map_err(crypto)?;
            tenant
                .record(&p.actor, "key.csr", &id.to_string(), serde_json::json!({}))
                .await?;
            return Ok(Json(serde_json::json!({"csr":csr})));
        }
        Operation::Import => {
            if !matches!(record.state, KeyState::Generated | KeyState::Certified) {
                return Err(WebError(StatusCode::CONFLICT));
            }
            let chain = input.chain.ok_or(WebError(StatusCode::BAD_REQUEST))?;
            let mut trust = certificates::validate_chain(
                &record.public_key,
                &chain,
                &[],
                crate::auth::now() as u64,
            )
            .map_err(crypto)?;
            record.anchor = None;
            for anchor in &service.anchors {
                if certificates::validate_chain(
                    &record.public_key,
                    &chain,
                    std::slice::from_ref(&anchor.der),
                    crate::auth::now() as u64,
                )
                .map_err(crypto)?
                    == TrustTier::Private
                {
                    trust = anchor.tier;
                    record.anchor = Some(anchor.name.clone());
                    break;
                }
            }
            record.trust = if service.backend.is_lab() {
                TrustTier::Lab
            } else {
                trust
            };
            record.chain = chain;
            record.state = KeyState::Certified;
            "key.certificate_imported"
        }
        Operation::Activate => {
            if !record.activate() {
                return Err(WebError(StatusCode::CONFLICT));
            }
            // Resolve the persistent backend object before granting signing authority.
            if service.backend.public_key(&record.key).map_err(crypto)? != record.public_key {
                return Err(WebError(StatusCode::CONFLICT));
            }
            "key.activated"
        }
        Operation::Disable => {
            if record.state == KeyState::Retired {
                return Err(WebError(StatusCode::CONFLICT));
            }
            record.state = KeyState::Disabled;
            "key.disabled"
        }
        Operation::Retire => {
            if record.state != KeyState::Disabled {
                return Err(WebError(StatusCode::CONFLICT));
            }
            record.state = KeyState::Retired;
            "key.retired"
        }
    };
    tenant.update_key(&p.actor, action, &record).await?;
    // DB authority is revoked first. A backend error cannot leave signing enabled in Brigalow.
    if matches!(operation, Operation::Disable | Operation::Retire) {
        service.backend.disable(&record.key).map_err(crypto)?;
    }
    record.revision += 1;
    Ok(Json(serde_json::to_value(record).map_err(|_| {
        WebError(StatusCode::INTERNAL_SERVER_ERROR)
    })?))
}
