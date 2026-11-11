//! Informational approval notifications. Delivery never confers signing authority.
use base64::{engine::general_purpose::STANDARD, Engine};
use brigalow_core::policy::SignRequest;
use hmac::{Hmac, Mac};
use serde::Deserialize;
use sha2::Sha256;
use std::{collections::BTreeMap, path::PathBuf, sync::Arc, time::Duration};
use uuid::Uuid;
use zeroize::Zeroizing;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub org: Uuid,
    pub url: String,
    pub secret_file: PathBuf,
    pub tls_ca_file: Option<PathBuf>,
}
struct Endpoint {
    url: url::Url,
    client: reqwest::Client,
    secret: Zeroizing<String>,
}
#[derive(Clone, Default)]
pub struct Notifications(Arc<BTreeMap<Uuid, Endpoint>>);
impl Notifications {
    pub fn new(configs: &[Config]) -> Result<Self, &'static str> {
        let mut endpoints = BTreeMap::new();
        for config in configs {
            let url = url::Url::parse(&config.url).map_err(|_| "invalid notification URL")?;
            if url.scheme() != "https"
                || url.host_str().is_none()
                || !url.username().is_empty()
                || url.password().is_some()
                || url.fragment().is_some()
                || url.query().is_some()
            {
                return Err(
                    "notification URL must be HTTPS without credentials, query or fragment",
                );
            }
            let secret = Zeroizing::new(
                crate::config::secret_file(&config.secret_file)
                    .map_err(|_| "cannot read notification secret")?,
            );
            if secret.len() < 32 {
                return Err("notification secret requires at least 32 bytes");
            }
            let mut builder = reqwest::Client::builder()
                .https_only(true)
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(Duration::from_secs(3));
            if let Some(path) = &config.tls_ca_file {
                let bytes = std::fs::read(path).map_err(|_| "cannot read notification TLS CA")?;
                builder = builder.add_root_certificate(
                    reqwest::Certificate::from_pem(&bytes)
                        .map_err(|_| "invalid notification TLS CA")?,
                );
            }
            let client = builder
                .build()
                .map_err(|_| "cannot build notification client")?;
            if endpoints
                .insert(
                    config.org,
                    Endpoint {
                        url,
                        client,
                        secret,
                    },
                )
                .is_some()
            {
                return Err("only one notification endpoint per organisation allowed");
            }
        }
        Ok(Self(Arc::new(endpoints)))
    }
    pub async fn requested(
        &self,
        tenant: &brigalow_store::Tenant,
        request: &SignRequest,
    ) -> Result<(), brigalow_store::Error> {
        let org = request
            .principal
            .as_ref()
            .ok_or(brigalow_store::Error::Invalid)?
            .org_id;
        let Some(endpoint) = self.0.get(&org) else {
            return Ok(());
        };
        // Minimal event: no identity claims, artifacts, credentials or output leave this boundary.
        let body = serde_json::to_vec(&serde_json::json!({
            "version":1,"event":"approval.requested","org":org,
            "request":request.submission.request_id,"project":request.project,
            "event_id":Uuid::new_v4(),"at":crate::auth::now()
        }))
        .map_err(|_| brigalow_store::Error::Invalid)?;
        let mut mac = Hmac::<Sha256>::new_from_slice(endpoint.secret.as_bytes())
            .map_err(|_| brigalow_store::Error::Invalid)?;
        mac.update(b"brigalow.notification.v1\n");
        mac.update(&body);
        let tag = STANDARD.encode(mac.finalize().into_bytes());
        // Best effort, one bounded attempt. Never retry the sign submission for delivery failures.
        let delivered = endpoint
            .client
            .post(endpoint.url.clone())
            .header("content-type", "application/json")
            .header("x-brigalow-signature", tag)
            .body(body)
            .send()
            .await
            .is_ok_and(|response| response.status().is_success());
        tenant
            .record(
                "system",
                if delivered {
                    "notification.delivered"
                } else {
                    "notification.failed"
                },
                &request.submission.request_id.to_string(),
                serde_json::json!({"event":"approval.requested"}),
            )
            .await?;
        Ok(())
    }
}
