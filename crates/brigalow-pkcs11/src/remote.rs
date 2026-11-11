//! Digest-only remote client. Errors never include URLs, credentials or response bodies.
use brigalow_core::{
    keys::{Algorithm, KeyRecord},
    policy::{Format, Policy, RequestState, SignRequest, Submission},
};
use serde::{de::DeserializeOwned, Deserialize};
use std::{
    io::Read,
    path::PathBuf,
    time::{Duration, Instant},
};
use uuid::Uuid;
use zeroize::Zeroizing;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    server: String,
    org: Uuid,
    project: Uuid,
    policy: Uuid,
    ca_file: Option<PathBuf>,
}
pub struct Remote {
    config: Config,
    token: Zeroizing<String>,
    client: reqwest::blocking::Client,
    pub key: KeyRecord,
}
fn decode<T: DeserializeOwned>(response: reqwest::blocking::Response) -> Result<T, ()> {
    if !response.status().is_success() {
        return Err(());
    }
    let mut bytes = vec![];
    response
        .take(1048577)
        .read_to_end(&mut bytes)
        .map_err(|_| ())?;
    if bytes.len() > 1048576 {
        return Err(());
    }
    serde_json::from_slice(&bytes).map_err(|_| ())
}
impl Remote {
    pub fn load() -> Result<Self, ()> {
        let config: Config = toml::from_str(
            &std::fs::read_to_string(std::env::var("BRIGALOW_PKCS11_CONFIG").map_err(|_| ())?)
                .map_err(|_| ())?,
        )
        .map_err(|_| ())?;
        let mut url = reqwest::Url::parse(&config.server).map_err(|_| ())?;
        if url.scheme() != "https"
            || url.host_str().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return Err(());
        }
        url.set_path("/");
        let config = Config {
            server: url.to_string().trim_end_matches('/').to_string(),
            ..config
        };
        let token = Zeroizing::new(std::env::var("BRIGALOW_TOKEN").map_err(|_| ())?);
        if token.is_empty() {
            return Err(());
        }
        let mut builder = reqwest::blocking::Client::builder()
            .https_only(true)
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(60));
        if let Some(path) = &config.ca_file {
            builder = builder.add_root_certificate(
                reqwest::Certificate::from_pem(&std::fs::read(path).map_err(|_| ())?)
                    .map_err(|_| ())?,
            );
        }
        let client = builder.build().map_err(|_| ())?;
        let policy: Policy = decode(
            client
                .get(format!(
                    "{}/v1/orgs/{}/policies/{}",
                    config.server, config.org, config.policy
                ))
                .bearer_auth(token.as_str())
                .send()
                .map_err(|_| ())?,
        )?;
        if policy.id != config.policy || policy.project != config.project {
            return Err(());
        }
        let key: KeyRecord = decode(
            client
                .get(format!(
                    "{}/v1/orgs/{}/keys/{}",
                    config.server, config.org, policy.key
                ))
                .bearer_auth(token.as_str())
                .send()
                .map_err(|_| ())?,
        )?;
        if key.key.id != policy.key
            || key.project != policy.project
            || key.key.algorithm != Algorithm::Rsa3072
        {
            return Err(());
        }
        Ok(Self {
            config,
            token,
            client,
            key,
        })
    }
    pub fn sign(&self, digest: [u8; 32]) -> Result<Vec<u8>, ()> {
        let input = Submission {
            request_id: Uuid::new_v4(),
            policy: self.config.policy,
            digest_alg: brigalow_core::keys::DigestAlgorithm::Sha256,
            digest,
            artifact_name: "PKCS11 digest".into(),
            format: Format::Raw,
            metadata: Default::default(),
        };
        let mut result: SignRequest = decode(
            self.client
                .post(format!(
                    "{}/v1/orgs/{}/projects/{}/sign-requests",
                    self.config.server, self.config.org, self.config.project
                ))
                .bearer_auth(self.token.as_str())
                .json(&input)
                .send()
                .map_err(|_| ())?,
        )?;
        let deadline = Instant::now() + Duration::from_secs(300);
        while matches!(
            result.state,
            RequestState::AwaitingApproval | RequestState::Gating | RequestState::Signing
        ) {
            if Instant::now() >= deadline {
                return Err(());
            }
            std::thread::sleep(Duration::from_secs(1));
            result = decode(
                self.client
                    .get(format!(
                        "{}/v1/orgs/{}/requests/{}",
                        self.config.server, self.config.org, input.request_id
                    ))
                    .bearer_auth(self.token.as_str())
                    .send()
                    .map_err(|_| ())?,
            )?;
        }
        if result.state != RequestState::Signed
            || result.submission.request_id != input.request_id
            || result.submission.digest != digest
            || result.submission.policy != input.policy
            || result.project != self.config.project
            || result.submission.format != Format::Raw
            || result
                .key
                .as_ref()
                .is_none_or(|k| k.key.id != self.key.key.id || k.public_key != self.key.public_key)
        {
            return Err(());
        }
        let signature = result.output.ok_or(())?;
        if signature.len() != 384 {
            return Err(());
        }
        Ok(signature)
    }
}
