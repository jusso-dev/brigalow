pub mod oidc;
pub mod workload;
use crate::config::Mode;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use brigalow_core::rbac::{Principal, Role, Scope};
use rand::RngCore;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, HashMap},
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::Mutex;
use uuid::Uuid;

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HumanConfig {
    pub client_id: String,
    pub authorization_url: String,
    pub token_url: String,
    #[serde(default)]
    pub group_roles: BTreeMap<String, Role>,
}
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkloadRule {
    pub project: Uuid,
    pub policy: Uuid,
    pub claims: BTreeMap<String, String>,
}
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Authority {
    pub org_id: Uuid,
    pub name: String,
    pub issuer: String,
    pub jwks_url: String,
    pub human: Option<HumanConfig>,
    #[serde(default)]
    pub workloads: Vec<WorkloadRule>,
}
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityConfig {
    pub public_url: String,
    pub ca_file: Option<std::path::PathBuf>,
    pub authorities: Vec<Authority>,
}
#[derive(Debug, thiserror::Error)]
#[error("identity verification failed")]
pub struct AuthError;
struct CachedKeys {
    expires: Instant,
    value: serde_json::Value,
}
pub struct Identity {
    pub config: IdentityConfig,
    http: reqwest::Client,
    keys: Mutex<HashMap<(Uuid, String), CachedKeys>>,
    pending: Mutex<HashMap<String, oidc::Pending>>,
}
pub fn hash(value: &str) -> String {
    format!("{:x}", Sha256::digest(value.as_bytes()))
}
pub fn random_secret() -> String {
    let mut value = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut value);
    URL_SAFE_NO_PAD.encode(value)
}
pub fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock before epoch")
        .as_secs() as i64
}
impl Identity {
    pub fn new(config: IdentityConfig, _mode: Mode) -> Result<Arc<Self>, AuthError> {
        fn valid(url: &str) -> bool {
            url::Url::parse(url).is_ok_and(|u| {
                u.scheme() == "https"
                    && u.host_str().is_some()
                    && u.username().is_empty()
                    && u.password().is_none()
                    && u.fragment().is_none()
            })
        }
        if !valid(&config.public_url)
            || config.authorities.len() > 100
            || url::Url::parse(&config.public_url)
                .map_err(|_| AuthError)?
                .path()
                != "/"
        {
            return Err(AuthError);
        }
        let mut names = std::collections::HashSet::new();
        for a in &config.authorities {
            if !valid(&a.issuer)
                || !valid(&a.jwks_url)
                || a.name.is_empty()
                || !a
                    .name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
                || !names.insert((a.org_id, a.name.clone()))
            {
                return Err(AuthError);
            }
            if let Some(h) = &a.human {
                if !valid(&h.authorization_url) || !valid(&h.token_url) || h.client_id.is_empty() {
                    return Err(AuthError);
                }
            }
            for r in &a.workloads {
                if r.claims.is_empty() {
                    return Err(AuthError);
                }
            }
        }
        let mut builder = reqwest::Client::builder()
            .https_only(true)
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(5));
        if let Some(path) = &config.ca_file {
            builder = builder.add_root_certificate(
                reqwest::Certificate::from_pem(&std::fs::read(path).map_err(|_| AuthError)?)
                    .map_err(|_| AuthError)?,
            );
        }
        Ok(Arc::new(Self {
            config,
            http: builder.build().map_err(|_| AuthError)?,
            keys: Mutex::new(HashMap::new()),
            pending: Mutex::new(HashMap::new()),
        }))
    }
    pub fn authority(&self, org: Uuid, name: &str) -> Result<&Authority, AuthError> {
        self.config
            .authorities
            .iter()
            .find(|a| a.org_id == org && a.name == name)
            .ok_or(AuthError)
    }
    pub async fn json_response(
        response: reqwest::Response,
    ) -> Result<serde_json::Value, AuthError> {
        use futures_util::StreamExt;
        if !response.status().is_success() {
            return Err(AuthError);
        }
        let mut stream = response.bytes_stream();
        let mut body = Vec::new();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|_| AuthError)?;
            if body.len() + chunk.len() > 1_048_576 {
                return Err(AuthError);
            }
            body.extend_from_slice(&chunk);
        }
        serde_json::from_slice(&body).map_err(|_| AuthError)
    }
    async fn jwks(&self, a: &Authority) -> Result<serde_json::Value, AuthError> {
        // Fixed issuer set bounds cache cardinality. Unknown kid does not bypass the TTL.
        let mut cache = self.keys.lock().await;
        let key = (a.org_id, a.name.clone());
        if let Some(entry) = cache.get(&key) {
            if entry.expires > Instant::now() {
                return Ok(entry.value.clone());
            }
        }
        let value = Self::json_response(
            self.http
                .get(&a.jwks_url)
                .send()
                .await
                .map_err(|_| AuthError)?,
        )
        .await?;
        let keys = value
            .get("keys")
            .and_then(|v| v.as_array())
            .ok_or(AuthError)?;
        if keys.is_empty() || keys.len() > 32 {
            return Err(AuthError);
        }
        cache.insert(
            key,
            CachedKeys {
                expires: Instant::now() + Duration::from_secs(60),
                value: value.clone(),
            },
        );
        Ok(value)
    }
    pub(crate) async fn verified(
        &self,
        a: &Authority,
        token: &str,
        audience: &str,
    ) -> Result<(serde_json::Value, serde_json::Value), AuthError> {
        use jsonwebtoken::{
            decode, decode_header, jwk::JwkSet, Algorithm, DecodingKey, Validation,
        };
        if token.len() > 16384 {
            return Err(AuthError);
        }
        let header = decode_header(token).map_err(|_| AuthError)?;
        if header.alg != Algorithm::RS256 {
            return Err(AuthError);
        }
        let keys = self.jwks(a).await?;
        let set: JwkSet = serde_json::from_value(keys.clone()).map_err(|_| AuthError)?;
        let kid = header.kid.ok_or(AuthError)?;
        let key = set.find(&kid).ok_or(AuthError)?;
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_issuer(&[&a.issuer]);
        validation.set_audience(&[audience]);
        validation.leeway = 0;
        validation.validate_nbf = true;
        validation.set_required_spec_claims(&["iss", "aud", "sub", "exp"]);
        let claims = decode::<serde_json::Value>(
            token,
            &DecodingKey::from_jwk(key).map_err(|_| AuthError)?,
            &validation,
        )
        .map_err(|_| AuthError)?
        .claims;
        if claims["sub"].as_str().is_none_or(str::is_empty)
            || claims["exp"].as_i64().is_none_or(|t| t <= now())
        {
            return Err(AuthError);
        }
        Ok((claims, keys))
    }
    fn principal(
        a: &Authority,
        claims: &serde_json::Value,
        roles: Vec<Role>,
        scope: Option<Scope>,
        human: bool,
    ) -> Result<Principal, AuthError> {
        let sub = claims["sub"].as_str().ok_or(AuthError)?;
        Ok(Principal {
            org_id: a.org_id,
            actor: serde_json::to_string(&(&a.issuer, sub)).map_err(|_| AuthError)?,
            roles,
            scope,
            human,
            claims: [
                "iss",
                "sub",
                "repository",
                "ref",
                "workflow",
                "environment",
                "sha",
                "job_workflow_ref",
                "run_id",
                "ref_protected",
            ]
            .into_iter()
            .filter_map(|name| {
                claims
                    .get(name)
                    .and_then(|v| match v {
                        serde_json::Value::String(s) => Some(s.clone()),
                        serde_json::Value::Bool(b) => Some(b.to_string()),
                        _ => None,
                    })
                    .map(|v| (name.to_string(), v))
            })
            .collect(),
        })
    }
}
