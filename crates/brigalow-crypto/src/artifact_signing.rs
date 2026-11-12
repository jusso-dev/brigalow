//! Azure Artifact Signing remote backend (data plane `2022-06-15-preview`).
//!
//! Microsoft holds and rotates the key and its 72-hour certificate. This module is transport only:
//! it submits one digest, polls a bounded operation and returns untrusted output. It has no
//! `sign_digest`/`public_key` path; acceptance happens in [`crate::rotating::verify`].
//!
//! Authentication uses an Entra managed-identity token from the fixed Azure IMDS link-local
//! address. That is the only plain-HTTP call in Brigalow and its address is not configurable.
use crate::{
    rotating::{Attempt, Expectation, Remote},
    Algorithm, DigestAlgorithm, Error, Key, KeyBackend, Result,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use brigalow_core::Purpose;
use der::{Decode, Encode};
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    io::Read,
    sync::Mutex,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use uuid::Uuid;
use zeroize::Zeroizing;

pub const API_VERSION: &str = "2022-06-15-preview";
/// Entra token audience for the Artifact Signing data plane.
pub const TOKEN_RESOURCE: &str = "https://codesigning.azure.net";
/// Fixed Azure Instance Metadata Service token endpoint. Plain HTTP to a link-local address that
/// only the local hypervisor answers. Deliberately a constant: never read from configuration.
const IMDS_TOKEN_URL: &str = "http://169.254.169.254/metadata/identity/oauth2/token";
const IMDS_API_VERSION: &str = "2018-02-01";
/// Tokens are refreshed this long before their stated expiry, and refused if already inside it.
pub const TOKEN_REFRESH_MARGIN: u64 = 300;
const MAX_RESPONSE: u64 = 1 << 20;
const MAX_IMDS_RESPONSE: u64 = 65536;
const MAX_TOKEN: usize = 16384;
const MAX_BUNDLE: usize = 262144;
pub const MAX_OPERATION_TIMEOUT: Duration = Duration::from_secs(25);

/// Operator configuration for one Brigalow key reference.
pub struct Binding {
    pub id: Uuid,
    pub org: Uuid,
    pub project: Uuid,
    pub purpose: Purpose,
    pub account: String,
    pub profile: String,
    pub expectation: Expectation,
}
impl Binding {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: Uuid,
        org: Uuid,
        project: Uuid,
        purpose: Purpose,
        account: &str,
        profile: &str,
        anchor: Vec<u8>,
        profile_eku: &str,
    ) -> Result<Self> {
        if id.is_nil()
            || org.is_nil()
            || project.is_nil()
            || !resource_name(account, 3, 24)
            || !resource_name(profile, 5, 100)
        {
            return Err(Error::Backend);
        }
        let expectation = Expectation::new(anchor, profile_eku)?;
        Ok(Self {
            id,
            org,
            project,
            purpose,
            account: account.into(),
            profile: profile.into(),
            expectation,
        })
    }
}
pub struct Settings {
    /// `https://<region>.codesigning.azure.net`, or a literal loopback HTTPS origin in lab mode.
    pub endpoint: String,
    /// Extra TLS root for a loopback lab/test origin only. Azure endpoints use built-in roots.
    pub tls_ca_pem: Option<Vec<u8>>,
    pub lab: bool,
    /// Selects a user-assigned managed identity. An identifier, not a credential.
    pub managed_identity_client_id: Option<Uuid>,
    pub operation_timeout: Duration,
    pub bindings: Vec<Binding>,
}

/// Account/profile names enter URL paths; restrict them to the documented ARM name pattern.
fn resource_name(value: &str, min: usize, max: usize) -> bool {
    (min..=max).contains(&value.len())
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        && !value.starts_with(|c: char| c.is_ascii_digit() || c == '-')
        && !value.ends_with('-')
        && !value.contains("--")
}

/// Validates an operator endpoint. Returns the origin without a trailing slash and whether it is
/// a loopback test origin.
pub fn endpoint(value: &str) -> Result<(String, bool)> {
    let url = reqwest::Url::parse(value).map_err(|_| Error::Backend)?;
    if url.scheme() != "https"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.path() != "/"
    {
        return Err(Error::Backend);
    }
    let loopback = match url.host() {
        Some(url::Host::Ipv4(ip)) if ip.is_loopback() => true,
        Some(url::Host::Ipv6(ip)) if ip.is_loopback() => true,
        Some(url::Host::Domain(host)) => {
            let region = host
                .strip_suffix(".codesigning.azure.net")
                .ok_or(Error::Backend)?;
            if !(2..=32).contains(&region.len())
                || !region
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
                || url.port().is_some()
            {
                return Err(Error::Backend);
            }
            false
        }
        _ => return Err(Error::Backend),
    };
    Ok((url.as_str().trim_end_matches('/').into(), loopback))
}

struct Token {
    value: Zeroizing<String>,
    expires_on: u64,
}
/// Managed-identity token source. Plain HTTP, `Metadata: true`, no proxy, no redirects.
struct Imds {
    url: reqwest::Url,
    client: reqwest::blocking::Client,
    cache: Mutex<Option<Token>>,
}
impl Imds {
    fn with_origin(origin: &str, client_id: Option<Uuid>) -> Result<Self> {
        let mut url = reqwest::Url::parse(origin).map_err(|_| Error::Backend)?;
        {
            let mut query = url.query_pairs_mut();
            query.append_pair("api-version", IMDS_API_VERSION);
            query.append_pair("resource", TOKEN_RESOURCE);
            if let Some(id) = client_id {
                query.append_pair("client_id", &id.to_string());
            }
        }
        let client = reqwest::blocking::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(2))
            .timeout(Duration::from_secs(3))
            .build()
            .map_err(|_| Error::Backend)?;
        Ok(Self {
            url,
            client,
            cache: Mutex::new(None),
        })
    }
    fn azure(client_id: Option<Uuid>) -> Result<Self> {
        Self::with_origin(IMDS_TOKEN_URL, client_id)
    }
    /// Test seam: a loopback plain-HTTP mock. Not reachable from configuration.
    #[cfg(any(test, feature = "integration"))]
    fn test(origin: &str, client_id: Option<Uuid>) -> Result<Self> {
        let url = reqwest::Url::parse(origin).map_err(|_| Error::Backend)?;
        if url.scheme() != "http"
            || !url
                .host_str()
                .and_then(|h| h.trim_matches(['[', ']']).parse::<std::net::IpAddr>().ok())
                .is_some_and(|a| a.is_loopback())
        {
            return Err(Error::Backend);
        }
        Self::with_origin(
            &format!(
                "{}/metadata/identity/oauth2/token",
                origin.trim_end_matches('/')
            ),
            client_id,
        )
    }
    fn token(&self) -> Result<Zeroizing<String>> {
        let mut cache = self.cache.lock().map_err(|_| Error::Backend)?;
        let now = now()?;
        if let Some(token) = cache.as_ref() {
            if token.expires_on > now + TOKEN_REFRESH_MARGIN {
                return Ok(token.value.clone());
            }
        }
        *cache = None;
        let token = self.fetch(now)?;
        let value = token.value.clone();
        *cache = Some(token);
        Ok(value)
    }
    fn invalidate(&self) {
        if let Ok(mut cache) = self.cache.lock() {
            *cache = None;
        }
    }
    fn fetch(&self, now: u64) -> Result<Token> {
        let response = self
            .client
            .get(self.url.clone())
            .header("Metadata", "true")
            .send()
            .map_err(|_| Error::Backend)?;
        if response.status() != reqwest::StatusCode::OK {
            return Err(Error::Backend);
        }
        let mut body = read_json(response, MAX_IMDS_RESPONSE)?;
        let value = match body.get_mut("access_token").map(Value::take) {
            Some(Value::String(s)) => Zeroizing::new(s),
            _ => return Err(Error::Backend),
        };
        if value.is_empty()
            || value.len() > MAX_TOKEN
            || !value.bytes().all(|b| b.is_ascii_graphic())
            || !body["token_type"]
                .as_str()
                .is_some_and(|t| t.eq_ignore_ascii_case("bearer"))
            || body.get("resource").is_some_and(|r| {
                r.as_str().map(|r| r.trim_end_matches('/')) != Some(TOKEN_RESOURCE)
            })
        {
            return Err(Error::Backend);
        }
        let expires_on = match &body["expires_on"] {
            Value::String(s) => s.parse::<u64>().map_err(|_| Error::Backend)?,
            Value::Number(n) => n.as_u64().ok_or(Error::Backend)?,
            _ => return Err(Error::Backend),
        };
        // A token already inside the refresh margin, or implausibly long-lived, is refused.
        if expires_on <= now + TOKEN_REFRESH_MARGIN || expires_on > now + 2 * 86400 {
            return Err(Error::Backend);
        }
        Ok(Token { value, expires_on })
    }
}

fn read_json(response: reqwest::blocking::Response, limit: u64) -> Result<Value> {
    let mut bytes = Zeroizing::new(Vec::new());
    response
        .take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| Error::Backend)?;
    if bytes.len() as u64 > limit {
        return Err(Error::Backend);
    }
    serde_json::from_slice(&bytes).map_err(|_| Error::Backend)
}
fn now() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|v| v.as_secs())
        .map_err(|_| Error::Backend)
}
fn operation_id(value: &Value) -> Option<String> {
    let id = value.as_str()?;
    ((1..=128).contains(&id.len())
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'))
    .then(|| id.to_string())
}

/// `signingCertificate` is base64 of a text bundle (observed via Jsign: base64/MIME DER or PEM).
/// The DER is a PKCS#7 certificates-only SignedData or one or more concatenated X.509 certificates.
pub fn parse_bundle(field: &str) -> Result<Vec<Vec<u8>>> {
    if field.is_empty() || field.len() > MAX_BUNDLE * 2 {
        return Err(Error::Certificate);
    }
    let text = STANDARD.decode(field).map_err(|_| Error::Certificate)?;
    let text = std::str::from_utf8(&text).map_err(|_| Error::Certificate)?;
    let mut certificates = Vec::new();
    if text.contains("-----BEGIN ") {
        let mut rest = text;
        while let Some(start) = rest.find("-----BEGIN ") {
            if !rest[..start].trim().is_empty() {
                return Err(Error::Certificate);
            }
            let block = &rest[start..];
            let label_end = block[11..].find("-----").ok_or(Error::Certificate)? + 11;
            let label = &block[11..label_end];
            let end_marker = format!("-----END {label}-----");
            let end = block.find(&end_marker).ok_or(Error::Certificate)? + end_marker.len();
            let (decoded_label, der) =
                der::pem::decode_vec(&block.as_bytes()[..end]).map_err(|_| Error::Certificate)?;
            match decoded_label {
                "CERTIFICATE" => certificates.push(der),
                "PKCS7" | "CMS" => certificates.extend(der_certificates(&der)?),
                _ => return Err(Error::Certificate),
            }
            rest = &block[end..];
            if certificates.len() > 10 {
                return Err(Error::Certificate);
            }
        }
        if !rest.trim().is_empty() {
            return Err(Error::Certificate);
        }
    } else {
        let compact: String = text.chars().filter(|c| !c.is_ascii_whitespace()).collect();
        let der = STANDARD.decode(compact).map_err(|_| Error::Certificate)?;
        certificates = der_certificates(&der)?;
    }
    if certificates.is_empty()
        || certificates.len() > 10
        || certificates
            .iter()
            .any(|c| x509_cert::Certificate::from_der(c).is_err())
    {
        return Err(Error::Certificate);
    }
    Ok(certificates)
}
fn der_certificates(der: &[u8]) -> Result<Vec<Vec<u8>>> {
    if der.is_empty() || der.len() > MAX_BUNDLE {
        return Err(Error::Certificate);
    }
    if let Ok(info) = cms::content_info::ContentInfo::from_der(der) {
        if info.content_type != crate::cms::oid("1.2.840.113549.1.7.2") {
            return Err(Error::Certificate);
        }
        let data: cms::signed_data::SignedData =
            info.content.decode_as().map_err(|_| Error::Certificate)?;
        return data
            .certificates
            .ok_or(Error::Certificate)?
            .0
            .iter()
            .map(|choice| match choice {
                cms::cert::CertificateChoices::Certificate(c) => {
                    c.to_der().map_err(|_| Error::Certificate)
                }
                _ => Err(Error::Certificate),
            })
            .collect();
    }
    // Concatenated DER certificates; keep the exact received bytes of each.
    let mut certificates = Vec::new();
    let mut reader = der::SliceReader::new(der).map_err(|_| Error::Certificate)?;
    while !der::Reader::is_finished(&reader) {
        let start = u32::from(der::Reader::position(&reader)) as usize;
        x509_cert::Certificate::decode(&mut reader).map_err(|_| Error::Certificate)?;
        let end = u32::from(der::Reader::position(&reader)) as usize;
        certificates.push(der[start..end].to_vec());
        if certificates.len() > 10 {
            return Err(Error::Certificate);
        }
    }
    Ok(certificates)
}

pub struct ArtifactSigning {
    origin: String,
    lab: bool,
    timeout: Duration,
    client: reqwest::blocking::Client,
    imds: Imds,
    bindings: BTreeMap<Uuid, Binding>,
    disabled: Mutex<BTreeSet<Uuid>>,
}
impl ArtifactSigning {
    /// Production constructor. Contacts nothing: tokens are obtained on first use.
    pub fn new(settings: Settings) -> Result<Self> {
        let imds = Imds::azure(settings.managed_identity_client_id)?;
        Self::build(settings, imds, false)
    }
    /// Test seam: loopback mock IMDS (plain HTTP) and an HTTPS loopback signing origin, which
    /// may be labelled non-lab so production-mode policy paths can be exercised.
    #[cfg(any(test, feature = "integration"))]
    pub fn for_tests(settings: Settings, imds_origin: &str) -> Result<Self> {
        let imds = Imds::test(imds_origin, settings.managed_identity_client_id)?;
        Self::build(settings, imds, true)
    }
    fn build(settings: Settings, imds: Imds, test: bool) -> Result<Self> {
        let (origin, loopback) = endpoint(&settings.endpoint)?;
        // Loopback origins and extra TLS roots belong to lab mode or tests, never production.
        if loopback != settings.tls_ca_pem.is_some() || (loopback && !settings.lab && !test) {
            return Err(Error::Backend);
        }
        if settings.operation_timeout.is_zero()
            || settings.operation_timeout > MAX_OPERATION_TIMEOUT
            || settings.bindings.len() > 100
        {
            return Err(Error::Backend);
        }
        let mut builder = reqwest::blocking::Client::builder()
            .https_only(true)
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(3))
            .timeout(Duration::from_secs(10));
        if let Some(pem) = &settings.tls_ca_pem {
            builder = builder.tls_built_in_root_certs(false).add_root_certificate(
                reqwest::Certificate::from_pem(pem).map_err(|_| Error::Backend)?,
            );
        }
        let client = builder.build().map_err(|_| Error::Backend)?;
        let mut bindings = BTreeMap::new();
        let mut targets = BTreeSet::new();
        for binding in settings.bindings {
            if !targets.insert((binding.account.clone(), binding.profile.clone()))
                || bindings.contains_key(&binding.id)
            {
                return Err(Error::Backend);
            }
            bindings.insert(binding.id, binding);
        }
        Ok(Self {
            origin,
            lab: settings.lab,
            timeout: settings.operation_timeout,
            client,
            imds,
            bindings,
            disabled: Mutex::new(BTreeSet::new()),
        })
    }
    fn binding(&self, key: &Key) -> Result<&Binding> {
        let binding = self.bindings.get(&key.id).ok_or(Error::Unavailable)?;
        if key.algorithm != Algorithm::Rsa3072
            || key.purpose != binding.purpose
            || self
                .disabled
                .lock()
                .map_err(|_| Error::Backend)?
                .contains(&key.id)
        {
            return Err(Error::Unavailable);
        }
        Ok(binding)
    }
    fn path(&self, binding: &Binding, suffix: &str) -> String {
        format!(
            "{}/codesigningaccounts/{}/certificateprofiles/{}/sign{suffix}?api-version={API_VERSION}",
            self.origin, binding.account, binding.profile
        )
    }
    fn remaining(deadline: Instant) -> Option<Duration> {
        deadline
            .checked_duration_since(Instant::now())
            .filter(|d| !d.is_zero())
    }
    fn rejected_credential(&self, status: reqwest::StatusCode) {
        if matches!(
            status,
            reqwest::StatusCode::UNAUTHORIZED | reqwest::StatusCode::FORBIDDEN
        ) {
            // Next request obtains a fresh token. This request is not retried.
            self.imds.invalidate();
        }
    }
    fn poll(&self, binding: &Binding, token: &str, id: &str, deadline: Instant) -> Result<Remote> {
        let mut attempt: u64 = 0;
        loop {
            let pause = Duration::from_millis((50 + 10 * attempt).min(1000));
            attempt += 1;
            let remaining = Self::remaining(deadline).ok_or(Error::Backend)?;
            if pause >= remaining {
                return Err(Error::Backend);
            }
            std::thread::sleep(pause);
            let remaining = Self::remaining(deadline).ok_or(Error::Backend)?;
            let response = self
                .client
                .get(self.path(binding, &format!("/{id}")))
                .bearer_auth(token)
                .timeout(remaining.min(Duration::from_secs(10)))
                .send()
                .map_err(|_| Error::Backend)?;
            if response.status() != reqwest::StatusCode::OK {
                self.rejected_credential(response.status());
                return Err(Error::Backend);
            }
            let mut body = read_json(response, MAX_RESPONSE)?;
            for field in ["operationId", "id"] {
                if body.get(field).is_some_and(|v| v.as_str() != Some(id)) {
                    return Err(Error::Backend);
                }
            }
            match body["status"].as_str() {
                Some("InProgress") => continue,
                Some("Succeeded") => {}
                _ => return Err(Error::Backend),
            }
            let signature = match body.get_mut("signature").map(Value::take) {
                Some(Value::String(s)) if !s.is_empty() && s.len() <= 4096 => {
                    STANDARD.decode(s).map_err(|_| Error::Backend)?
                }
                _ => return Err(Error::Backend),
            };
            let certificates = parse_bundle(
                body["signingCertificate"]
                    .as_str()
                    .ok_or(Error::Certificate)?,
            )?;
            return Ok(Remote {
                signature,
                certificates,
            });
        }
    }
}
impl KeyBackend for ArtifactSigning {
    /// Readiness: a managed-identity token is available. No signing request is made.
    fn healthy(&self) -> bool {
        self.imds.token().is_ok()
    }
    fn remote_key(&self, id: Uuid, org: Uuid, project: Uuid) -> Result<Key> {
        let binding = self.bindings.get(&id).ok_or(Error::Unavailable)?;
        if binding.org != org || binding.project != project {
            return Err(Error::Unavailable);
        }
        let key = Key {
            id,
            algorithm: Algorithm::Rsa3072,
            purpose: binding.purpose,
        };
        self.binding(&key)?;
        Ok(key)
    }
    fn rotates(&self) -> bool {
        true
    }
    fn rotating(&self, key: &Key) -> Result<Expectation> {
        Ok(self.binding(key)?.expectation.clone())
    }
    fn sign_rotating(&self, key: &Key, digest: &[u8]) -> Attempt {
        let binding = match self.binding(key) {
            Ok(binding) => binding,
            Err(error) => return Attempt::failed(None, error),
        };
        if crate::check_digest(digest).is_err() {
            return Attempt::failed(None, Error::Algorithm);
        }
        let token = match self.imds.token() {
            Ok(token) => token,
            Err(error) => return Attempt::failed(None, error),
        };
        let deadline = Instant::now() + self.timeout;
        let response = match self
            .client
            .post(self.path(binding, ""))
            .bearer_auth(token.as_str())
            .json(&json!({"signatureAlgorithm":"RS256","digest":STANDARD.encode(digest)}))
            .timeout(self.timeout.min(Duration::from_secs(10)))
            .send()
        {
            Ok(response) => response,
            // Lost submission: the service may have signed. Never resubmitted.
            Err(_) => return Attempt::failed(None, Error::Backend),
        };
        let status = response.status();
        if !matches!(
            status,
            reqwest::StatusCode::ACCEPTED | reqwest::StatusCode::OK
        ) {
            self.rejected_credential(status);
            return Attempt::failed(None, Error::Backend);
        }
        let body = match read_json(response, MAX_RESPONSE) {
            Ok(body) => body,
            Err(error) => return Attempt::failed(None, error),
        };
        let Some(id) = operation_id(&body["operationId"]) else {
            return Attempt::failed(None, Error::Backend);
        };
        let outcome = self.poll(binding, token.as_str(), &id, deadline);
        Attempt {
            operation_id: Some(id),
            outcome,
        }
    }
    fn generate(&self, _algorithm: Algorithm, _purpose: Purpose) -> Result<Key> {
        Err(Error::Unavailable)
    }
    /// No stable public key exists; each result carries its own validated certificate.
    fn public_key(&self, _key: &Key) -> Result<Vec<u8>> {
        Err(Error::Unavailable)
    }
    /// Deliberately absent: every signature must pass through `rotating::sign`.
    fn sign_digest(
        &self,
        _key: &Key,
        _algorithm: DigestAlgorithm,
        _digest: &[u8],
    ) -> Result<Vec<u8>> {
        Err(Error::Unavailable)
    }
    fn sign_message(&self, _key: &Key, _message: &[u8]) -> Result<Vec<u8>> {
        Err(Error::Unavailable)
    }
    fn disable(&self, key: &Key) -> Result<()> {
        if !self.bindings.contains_key(&key.id) {
            return Err(Error::Unavailable);
        }
        self.disabled
            .lock()
            .map_err(|_| Error::Backend)?
            .insert(key.id);
        Ok(())
    }
    fn is_lab(&self) -> bool {
        self.lab
    }
}

#[cfg(test)]
#[path = "artifact_signing_tests.rs"]
mod tests;
