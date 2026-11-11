//! Operator-pinned, tenant-scoped pre-sign checks. Every failure is a denial.
use base64::{engine::general_purpose::STANDARD, Engine};
use brigalow_core::{gates::Result as Outcome, policy::SignRequest};
use futures_util::StreamExt;
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
    pub name: String,
    pub url: String,
    pub secret_file: PathBuf,
    pub tls_ca_file: Option<PathBuf>,
    pub timeout_ms: u64,
}
struct Endpoint {
    client: reqwest::Client,
    url: url::Url,
    secret: Zeroizing<String>,
}
#[derive(Clone, Default)]
pub struct Gates(Arc<BTreeMap<(Uuid, String), Endpoint>>);
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Reply {
    nonce: Uuid,
    request: Uuid,
    digest: [u8; 32],
    pass: bool,
}
impl Gates {
    pub fn new(configs: &[Config]) -> Result<Self, &'static str> {
        let mut endpoints = BTreeMap::new();
        for config in configs {
            if !(100..=30000).contains(&config.timeout_ms)
                || config.name.is_empty()
                || config.name.len() > 64
                || !config
                    .name
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            {
                return Err("invalid gate name or timeout");
            }
            let url = url::Url::parse(&config.url).map_err(|_| "invalid gate URL")?;
            if url.scheme() != "https"
                || url.host_str().is_none()
                || !url.username().is_empty()
                || url.password().is_some()
                || url.fragment().is_some()
                || url.query().is_some()
            {
                return Err("gate requires HTTPS without URL credentials, query or fragment");
            }
            let secret = Zeroizing::new(
                crate::config::secret_file(&config.secret_file)
                    .map_err(|_| "cannot read gate secret")?,
            );
            if secret.len() < 32 {
                return Err("gate secret requires at least 32 bytes");
            }
            let mut builder = reqwest::Client::builder()
                .https_only(true)
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(Duration::from_millis(config.timeout_ms));
            if let Some(path) = &config.tls_ca_file {
                builder = builder.add_root_certificate(
                    reqwest::Certificate::from_pem(
                        &std::fs::read(path).map_err(|_| "cannot read gate TLS CA")?,
                    )
                    .map_err(|_| "invalid gate TLS CA")?,
                );
            }
            let client = builder.build().map_err(|_| "cannot build gate client")?;
            if endpoints
                .insert(
                    (config.org, config.name.clone()),
                    Endpoint {
                        client,
                        url,
                        secret,
                    },
                )
                .is_some()
            {
                return Err("duplicate gate in organisation");
            }
        }
        Ok(Self(Arc::new(endpoints)))
    }
    pub fn configured(&self, org: Uuid, names: &[String]) -> bool {
        names
            .iter()
            .all(|name| self.0.contains_key(&(org, name.clone())))
    }
    pub async fn run(&self, request: &SignRequest) -> Vec<Outcome> {
        let Some(principal) = &request.principal else {
            return vec![];
        };
        let Some(policy) = &request.policy else {
            return vec![];
        };
        let mut outcomes = vec![];
        for name in &policy.gates {
            let result = match self.0.get(&(principal.org_id, name.clone())) {
                Some(endpoint) => endpoint.check(request).await,
                None => Err("unconfigured"),
            };
            let passed = matches!(result, Ok(true));
            let reason = match result {
                Ok(true) => "pass",
                Ok(false) => "deny",
                Err(reason) => reason,
            };
            outcomes.push(Outcome {
                gate: name.clone(),
                passed,
                reason: reason.into(),
            });
            if !passed {
                break;
            }
        }
        outcomes
    }
}
impl Endpoint {
    async fn check(&self, request: &SignRequest) -> Result<bool, &'static str> {
        let nonce = Uuid::new_v4();
        let org = request.principal.as_ref().ok_or("identity")?.org_id;
        let body=serde_json::to_vec(&serde_json::json!({"version":1,"org":org,
            "request":request.submission.request_id,"project":request.project,"policy":request.submission.policy,
            "digest":request.submission.digest,"digest_alg":"sha256","nonce":nonce,"at":crate::auth::now(),
            "verified_claims":request.verified_claims})).map_err(|_|"encoding")?;
        let mut mac =
            Hmac::<Sha256>::new_from_slice(self.secret.as_bytes()).map_err(|_| "secret")?;
        mac.update(b"brigalow.gate.request.v1\n");
        mac.update(&body);
        let response = self
            .client
            .post(self.url.clone())
            .header("content-type", "application/json")
            .header(
                "x-brigalow-signature",
                STANDARD.encode(mac.finalize().into_bytes()),
            )
            .body(body)
            .send()
            .await
            .map_err(|_| "transport_or_timeout")?;
        if !response.status().is_success() {
            return Err("http_status");
        }
        let tag = response
            .headers()
            .get("x-brigalow-signature")
            .and_then(|v| v.to_str().ok())
            .filter(|s| s.len() == 44)
            .ok_or("signature")?;
        let tag = STANDARD.decode(tag).map_err(|_| "signature")?;
        let mut stream = response.bytes_stream();
        let mut bytes = vec![];
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|_| "transport_or_timeout")?;
            if bytes.len() + chunk.len() > 8192 {
                return Err("size");
            }
            bytes.extend_from_slice(&chunk);
        }
        let mut mac =
            Hmac::<Sha256>::new_from_slice(self.secret.as_bytes()).map_err(|_| "secret")?;
        mac.update(b"brigalow.gate.response.v1\n");
        mac.update(&bytes);
        mac.verify_slice(&tag).map_err(|_| "signature")?;
        let reply: Reply = serde_json::from_slice(&bytes).map_err(|_| "response")?;
        if reply.nonce != nonce
            || reply.request != request.submission.request_id
            || reply.digest != request.submission.digest
        {
            return Err("binding");
        }
        Ok(reply.pass)
    }
}
