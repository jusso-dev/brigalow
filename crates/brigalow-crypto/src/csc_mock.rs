//! Narrow CSC v2 synchronous mock profile. Literal-loopback HTTPS and lab only.
//! No enrollment, remote key generation, MFA bypass, batch signing or retry.
use crate::{Algorithm, DigestAlgorithm, Error, Key, KeyBackend, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use brigalow_core::Purpose;
use der::{Decode, Encode};
use rsa::pkcs8::DecodePublicKey;
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    io::Read,
    sync::Mutex,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use uuid::Uuid;
use zeroize::Zeroizing;
const RSA: &str = "1.2.840.113549.1.1.1";
const SHA256: &str = "2.16.840.1.101.3.4.2.1";
pub struct Binding {
    pub id: Uuid,
    pub org: Uuid,
    pub project: Uuid,
    pub credential_id: String,
    pub certificate: Vec<u8>,
}
struct Record {
    binding: Binding,
    public: Vec<u8>,
}
pub struct CscMock {
    origin: String,
    token: Zeroizing<String>,
    client: reqwest::blocking::Client,
    records: BTreeMap<Uuid, Record>,
    disabled: Mutex<BTreeSet<Uuid>>,
}
impl CscMock {
    pub fn new(origin: &str, ca_pem: &[u8], token: String, bindings: Vec<Binding>) -> Result<Self> {
        let url = reqwest::Url::parse(origin).map_err(|_| Error::Backend)?;
        if url.scheme() != "https"
            || !url
                .host_str()
                .and_then(|h| h.parse::<std::net::IpAddr>().ok())
                .is_some_and(|a| a.is_loopback())
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
            || url.path() != "/"
            || token.is_empty()
            || token.len() > 4096
            || bindings.is_empty()
            || bindings.len() > 100
        {
            return Err(Error::Backend);
        }
        let client = reqwest::blocking::Client::builder()
            .https_only(true)
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(2))
            .timeout(Duration::from_secs(5))
            .add_root_certificate(
                reqwest::Certificate::from_pem(ca_pem).map_err(|_| Error::Backend)?,
            )
            .build()
            .map_err(|_| Error::Backend)?;
        let mut remote = Self {
            origin: origin.trim_end_matches('/').into(),
            token: Zeroizing::new(token),
            client,
            records: BTreeMap::new(),
            disabled: Mutex::new(BTreeSet::new()),
        };
        let list = remote.call("credentials/list", &json!({"maxResults":100}))?;
        let ids = list["credentialIDs"].as_array().ok_or(Error::Backend)?;
        if ids.len() > 100 || list.get("nextPageToken").is_some() {
            return Err(Error::Backend);
        }
        let mut credentials = BTreeSet::new();
        for binding in bindings {
            if binding.id.is_nil()
                || binding.org.is_nil()
                || binding.project.is_nil()
                || binding.credential_id.is_empty()
                || binding.credential_id.len() > 200
                || !credentials.insert(binding.credential_id.clone())
                || remote.records.contains_key(&binding.id)
                || !ids
                    .iter()
                    .any(|id| id.as_str() == Some(&binding.credential_id))
            {
                return Err(Error::Backend);
            }
            let info = remote.call(
                "credentials/info",
                &json!({"credentialID":binding.credential_id,"certificates":"single"}),
            )?;
            if info["key"]["status"] != "enabled"
                || info["key"]["len"] != 3072
                || !info["key"]["algo"]
                    .as_array()
                    .is_some_and(|a| a.iter().any(|v| v == RSA))
                || info["cert"]["status"] != "valid"
                || info["auth"]["mode"] != "explicit"
                || info["SCAL"] != "2"
                || !info["multisign"].as_u64().is_some_and(|v| v >= 1)
                || !info["auth"]["objects"]
                    .as_array()
                    .is_some_and(|a| a.is_empty())
            {
                return Err(Error::Backend);
            }
            let certs = info["cert"]["certificates"]
                .as_array()
                .ok_or(Error::Backend)?;
            if certs.len() != 1
                || STANDARD
                    .decode(certs[0].as_str().ok_or(Error::Backend)?)
                    .map_err(|_| Error::Backend)?
                    != binding.certificate
                || binding.certificate.len() > 65536
            {
                return Err(Error::Certificate);
            }
            let public = x509_cert::Certificate::from_der(&binding.certificate)
                .map_err(|_| Error::Certificate)?
                .tbs_certificate
                .subject_public_key_info
                .to_der()
                .map_err(|_| Error::Certificate)?;
            if crate::private_ca::validate_public_key(&public)? != Algorithm::Rsa3072 {
                return Err(Error::Algorithm);
            }
            crate::certificates::validate_chain(
                &public,
                std::slice::from_ref(&binding.certificate),
                &[],
                now()?,
            )?;
            remote
                .records
                .insert(binding.id, Record { binding, public });
        }
        Ok(remote)
    }
    fn call(&self, method: &str, body: &Value) -> Result<Value> {
        let response = self
            .client
            .post(format!("{}/csc/v2/{method}", self.origin))
            .bearer_auth(self.token.as_str())
            .json(body)
            .send()
            .map_err(|_| Error::Backend)?;
        // Pending/OOB/MFA authorization is unsupported, never treated as approved.
        if response.status() != reqwest::StatusCode::OK {
            return Err(Error::Backend);
        }
        let mut bytes = Zeroizing::new(Vec::new());
        response
            .take(1048577)
            .read_to_end(&mut bytes)
            .map_err(|_| Error::Backend)?;
        if bytes.len() > 1048576 {
            return Err(Error::Backend);
        }
        serde_json::from_slice(&bytes).map_err(|_| Error::Backend)
    }
    fn record(&self, key: &Key) -> Result<&Record> {
        if key.algorithm != Algorithm::Rsa3072
            || key.purpose != Purpose::Test
            || self
                .disabled
                .lock()
                .map_err(|_| Error::Backend)?
                .contains(&key.id)
        {
            return Err(Error::Unavailable);
        }
        self.records.get(&key.id).ok_or(Error::Unavailable)
    }
}
fn now() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|v| v.as_secs())
        .map_err(|_| Error::Backend)
}
impl KeyBackend for CscMock {
    fn generate(&self, _algorithm: Algorithm, _purpose: Purpose) -> Result<Key> {
        Err(Error::Unavailable)
    }
    fn remote_key(&self, id: Uuid, org: Uuid, project: Uuid) -> Result<Key> {
        let record = self.records.get(&id).ok_or(Error::Unavailable)?;
        if record.binding.org != org || record.binding.project != project {
            return Err(Error::Unavailable);
        }
        let key = Key {
            id,
            algorithm: Algorithm::Rsa3072,
            purpose: Purpose::Test,
        };
        self.record(&key)?;
        Ok(key)
    }
    fn public_key(&self, key: &Key) -> Result<Vec<u8>> {
        Ok(self.record(key)?.public.clone())
    }
    fn sign_digest(
        &self,
        key: &Key,
        _algorithm: DigestAlgorithm,
        digest: &[u8],
    ) -> Result<Vec<u8>> {
        crate::check_digest(digest)?;
        let record = self.record(key)?;
        crate::certificates::validate_chain(
            &record.public,
            std::slice::from_ref(&record.binding.certificate),
            &[],
            now()?,
        )?;
        let hashes = vec![STANDARD.encode(digest)];
        let mut authorised=self.call("credentials/authorize",&json!({"credentialID":record.binding.credential_id,"numSignatures":1,"hashes":hashes,"hashAlgorithmOID":SHA256,"authData":[]}))?;
        let sad = match authorised.get_mut("SAD").map(Value::take) {
            Some(Value::String(s)) => Zeroizing::new(s),
            _ => return Err(Error::Backend),
        };
        if sad.is_empty()
            || sad.len() > 4096
            || !authorised["expiresIn"]
                .as_u64()
                .is_some_and(|v| v > 0 && v <= 3600)
        {
            return Err(Error::Backend);
        }
        let mut body = json!({"credentialID":record.binding.credential_id,"SAD":sad.as_str(),"hashes":hashes,"hashAlgorithmOID":SHA256,"signAlgo":RSA,"operationMode":"S"});
        let result = self.call("signatures/signHash", &body);
        if let Some(Value::String(secret)) = body.get_mut("SAD") {
            use zeroize::Zeroize;
            secret.zeroize();
        }
        let response = result?;
        let signatures = response["signatures"].as_array().ok_or(Error::Backend)?;
        if signatures.len() != 1 {
            return Err(Error::Backend);
        }
        let signature = STANDARD
            .decode(signatures[0].as_str().ok_or(Error::Backend)?)
            .map_err(|_| Error::Backend)?;
        let public =
            rsa::PublicKey::from_public_key_der(&record.public).map_err(|_| Error::Certificate)?;
        public
            .pkcs1v15_verify_prehash::<rsa::sha2::Sha256>(digest, &signature)
            .map_err(|_| Error::Backend)?;
        Ok(signature)
    }
    fn disable(&self, key: &Key) -> Result<()> {
        if key.algorithm != Algorithm::Rsa3072
            || key.purpose != Purpose::Test
            || !self.records.contains_key(&key.id)
        {
            return Err(Error::Unavailable);
        }
        self.disabled
            .lock()
            .map_err(|_| Error::Backend)?
            .insert(key.id);
        Ok(())
    }
    fn is_lab(&self) -> bool {
        true
    }
}
