//! Only non-secret fields and secret file paths may appear in TOML.
use serde::{Deserialize, Serialize};
use sqlx::postgres::{PgConnectOptions, PgSslMode};
use std::{
    fmt,
    io::Read,
    net::SocketAddr,
    path::{Path, PathBuf},
};
use zeroize::Zeroizing;

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    Lab,
    #[default]
    Production,
}

pub struct Secret(Zeroizing<String>);
impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

#[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Backend {
    #[default]
    Disabled,
    Software,
    Pkcs11,
    CscMock,
    ArtifactSigning,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AnchorConfig {
    pub name: String,
    pub tier: brigalow_core::TrustTier,
    pub file: PathBuf,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TsaConfig {
    pub url: String,
    pub tls_ca_file: Option<PathBuf>,
    pub signer_file: PathBuf,
    pub anchors: Vec<PathBuf>,
}
impl TsaConfig {
    pub fn client(&self) -> Result<brigalow_crypto::timestamp::Client, ConfigError> {
        let read = |path: &PathBuf| {
            std::fs::read(path).map_err(|_| ConfigError("cannot read TSA certificate"))
        };
        let signer = read(&self.signer_file)?;
        let anchors = self
            .anchors
            .iter()
            .map(read)
            .collect::<Result<Vec<_>, _>>()?;
        let ca = self.tls_ca_file.as_ref().map(read).transpose()?;
        brigalow_crypto::timestamp::Client::new(&self.url, ca.as_deref(), signer, anchors)
            .map_err(|_| ConfigError("invalid TSA configuration"))
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CscMockConfig {
    pub url: String,
    pub tls_ca_file: PathBuf,
    pub access_token_file: PathBuf,
    pub bindings: Vec<CscBindingConfig>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CscBindingConfig {
    pub id: uuid::Uuid,
    pub org: uuid::Uuid,
    pub project: uuid::Uuid,
    pub credential_id: String,
    pub certificate_file: PathBuf,
}
impl CscMockConfig {
    pub fn backend(&self) -> Result<brigalow_crypto::csc_mock::CscMock, ConfigError> {
        let read = |path: &Path| -> Result<Vec<u8>, ConfigError> {
            let file = std::fs::File::open(path)
                .map_err(|_| ConfigError("cannot read CSC certificate"))?;
            let mut bytes = Vec::new();
            file.take(65537)
                .read_to_end(&mut bytes)
                .map_err(|_| ConfigError("cannot read CSC certificate"))?;
            if bytes.len() > 65536 {
                return Err(ConfigError("CSC certificate too large"));
            }
            Ok(bytes)
        };
        let bindings = self
            .bindings
            .iter()
            .map(|b| {
                Ok(brigalow_crypto::csc_mock::Binding {
                    id: b.id,
                    org: b.org,
                    project: b.project,
                    credential_id: b.credential_id.clone(),
                    certificate: read(&b.certificate_file)?,
                })
            })
            .collect::<Result<Vec<_>, ConfigError>>()?;
        brigalow_crypto::csc_mock::CscMock::new(
            &self.url,
            &read(&self.tls_ca_file)?,
            secret_file(&self.access_token_file)?,
            bindings,
        )
        .map_err(|_| ConfigError("CSC mock startup failed; no fallback allowed"))
    }
}

/// Azure Artifact Signing. Identifiers and paths only: the credential is a managed-identity
/// token from the fixed IMDS address, never configuration.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactSigningConfig {
    /// `https://<region>.codesigning.azure.net`. Lab mode alone may use a loopback HTTPS origin.
    pub endpoint: String,
    /// PEM root for a lab loopback origin only. Azure endpoints use the built-in WebPKI roots.
    pub tls_ca_file: Option<PathBuf>,
    /// Client ID of a user-assigned managed identity (not a secret).
    pub managed_identity_client_id: Option<uuid::Uuid>,
    /// Total deadline for one submit-and-poll operation, 1 to 25 seconds (default 20).
    pub operation_timeout_seconds: Option<u64>,
    /// May be empty on first start (project UUIDs exist only after bootstrap). With no bindings,
    /// no key can be registered or used.
    #[serde(default)]
    pub bindings: Vec<ArtifactSigningBindingConfig>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactSigningBindingConfig {
    pub id: uuid::Uuid,
    pub org: uuid::Uuid,
    pub project: uuid::Uuid,
    pub purpose: brigalow_core::Purpose,
    pub account: String,
    pub profile: String,
    /// Name of a `[[trust_anchors]]` entry: the pinned issuing root every result must chain to.
    pub anchor: String,
    /// Profile-specific EKU (`1.3.6.1.4.1.311.97.` prefix) every returned leaf must carry.
    pub profile_eku: String,
}
pub(crate) fn bounded_file(path: &Path) -> Result<Vec<u8>, ConfigError> {
    let file = std::fs::File::open(path)
        .map_err(|_| ConfigError("cannot read Artifact Signing certificate"))?;
    let mut bytes = Vec::new();
    file.take(65537)
        .read_to_end(&mut bytes)
        .map_err(|_| ConfigError("cannot read Artifact Signing certificate"))?;
    if bytes.is_empty() || bytes.len() > 65536 {
        return Err(ConfigError("Artifact Signing certificate size invalid"));
    }
    Ok(bytes)
}
impl ArtifactSigningConfig {
    pub fn settings(
        &self,
        mode: Mode,
        anchors: &[AnchorConfig],
    ) -> Result<brigalow_crypto::artifact_signing::Settings, ConfigError> {
        use brigalow_crypto::artifact_signing::{Binding, Settings, MAX_OPERATION_TIMEOUT};
        let seconds = self.operation_timeout_seconds.unwrap_or(20);
        if seconds == 0 || seconds > MAX_OPERATION_TIMEOUT.as_secs() {
            return Err(ConfigError(
                "Artifact Signing operation timeout must be 1 to 25 seconds",
            ));
        }
        if self.tls_ca_file.is_some() && mode != Mode::Lab {
            return Err(ConfigError(
                "Artifact Signing test TLS roots require lab mode",
            ));
        }
        let bindings = self
            .bindings
            .iter()
            .map(|b| {
                let anchor = anchors
                    .iter()
                    .find(|a| a.name == b.anchor)
                    .ok_or(ConfigError(
                        "Artifact Signing anchor must name a trust anchor",
                    ))?;
                // Microsoft operates this CA: an outside CA, never Brigalow's private tier.
                if anchor.tier != brigalow_core::TrustTier::ExternalCa {
                    return Err(ConfigError(
                        "Artifact Signing anchor must be an external-ca trust anchor",
                    ));
                }
                Binding::new(
                    b.id,
                    b.org,
                    b.project,
                    b.purpose,
                    &b.account,
                    &b.profile,
                    bounded_file(&anchor.file)?,
                    &b.profile_eku,
                )
                .map_err(|_| ConfigError("invalid Artifact Signing binding"))
            })
            .collect::<Result<Vec<_>, ConfigError>>()?;
        Ok(Settings {
            endpoint: self.endpoint.clone(),
            tls_ca_pem: self.tls_ca_file.as_deref().map(bounded_file).transpose()?,
            lab: mode == Mode::Lab,
            managed_identity_client_id: self.managed_identity_client_id,
            operation_timeout: std::time::Duration::from_secs(seconds),
            bindings,
        })
    }
}

/// Paths and IDs only. Each file holds base64 for exactly 32 random bytes, mode 0600.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoginKeyFile {
    pub id: String,
    pub file: PathBuf,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoginKeysConfig {
    pub active: LoginKeyFile,
    #[serde(default)]
    pub previous: Vec<LoginKeyFile>,
}
impl LoginKeysConfig {
    fn load(&self) -> Result<crate::auth::login_keys::LoginKeys, ConfigError> {
        use base64::{engine::general_purpose::STANDARD, Engine};
        let read = |key: &LoginKeyFile| -> Result<(String, Zeroizing<Vec<u8>>), ConfigError> {
            let encoded = Zeroizing::new(secret_file(&key.file)?);
            let material = Zeroizing::new(
                STANDARD
                    .decode(encoded.trim().as_bytes())
                    .map_err(|_| ConfigError("login state key must be base64 of 32 bytes"))?,
            );
            if material.len() != 32 {
                return Err(ConfigError("login state key must be base64 of 32 bytes"));
            }
            Ok((key.id.clone(), material))
        };
        let active = read(&self.active)?;
        let previous = self
            .previous
            .iter()
            .map(read)
            .collect::<Result<Vec<_>, _>>()?;
        let previous: Vec<(&str, &[u8])> = previous
            .iter()
            .map(|(id, material)| (id.as_str(), material.as_slice()))
            .collect();
        crate::auth::login_keys::LoginKeys::new((&active.0, &active.1), &previous).map_err(|_| {
            ConfigError("invalid login state key ring (IDs must be unique [A-Za-z0-9_-]{1,32}, keys distinct, at most 4 previous)")
        })
    }
}

pub struct Config {
    pub rate_limit: crate::rate_limit::RateLimit,
    pub mode: Mode,
    pub bind: SocketAddr,
    db_host: String,
    db_port: u16,
    db_name: String,
    db_user: String,
    db_ca_file: Option<PathBuf>,
    db_password: Secret,
    pub backend: Backend,
    pub backend_id: String,
    pub hsm_module: Option<PathBuf>,
    pub hsm_token: Option<String>,
    pub trust_anchors: Vec<AnchorConfig>,
    pub tsa: Option<TsaConfig>,
    pub csc_mock: Option<CscMockConfig>,
    pub artifact_signing: Option<ArtifactSigningConfig>,
    pub notifications: Vec<crate::notifications::Config>,
    pub gates: Vec<crate::gates::Config>,
    login_keys: Option<crate::auth::login_keys::LoginKeys>,
    hsm_pin: Option<Secret>,
}
impl fmt::Debug for Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Config")
            .field("mode", &self.mode)
            .field("bind", &self.bind)
            .field("database", &"[REDACTED]")
            .field("db_password", &self.db_password)
            .field("hsm_pin", &self.hsm_pin)
            .field("login_keys", &self.login_keys)
            .finish()
    }
}
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct ConfigError(&'static str);

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileConfig {
    rate_limit: Option<crate::rate_limit::RateLimit>,
    mode: Option<Mode>,
    bind: Option<SocketAddr>,
    db_host: Option<String>,
    db_port: Option<u16>,
    db_name: Option<String>,
    db_user: Option<String>,
    db_ca_file: Option<PathBuf>,
    db_password_file: Option<PathBuf>,
    hsm_pin_file: Option<PathBuf>,
    backend: Option<Backend>,
    backend_id: Option<String>,
    hsm_module: Option<PathBuf>,
    hsm_token: Option<String>,
    trust_anchors: Option<Vec<AnchorConfig>>,
    tsa: Option<TsaConfig>,
    csc_mock: Option<CscMockConfig>,
    artifact_signing: Option<ArtifactSigningConfig>,
    notifications: Option<Vec<crate::notifications::Config>>,
    gates: Option<Vec<crate::gates::Config>>,
    login_keys: Option<LoginKeysConfig>,
}

pub(crate) fn secret_file(path: &Path) -> Result<String, ConfigError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        let file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)
            .map_err(|_| ConfigError("cannot open secret file"))?;
        let metadata = file
            .metadata()
            .map_err(|_| ConfigError("cannot inspect secret file"))?;
        if !metadata.is_file() || metadata.permissions().mode() & 0o7777 != 0o600 {
            return Err(ConfigError(
                "secret file must be a regular file with mode 0600",
            ));
        }
        let mut value = String::new();
        file.take(4097)
            .read_to_string(&mut value)
            .map_err(|_| ConfigError("cannot read secret file"))?;
        if value.len() > 4096 {
            return Err(ConfigError("secret file exceeds 4096 bytes"));
        }
        if value.ends_with('\n') {
            value.pop();
            if value.ends_with('\r') {
                value.pop();
            }
        }
        Ok(value)
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Err(ConfigError(
            "secret files require Unix permission checks; use environment variables",
        ))
    }
}

impl Config {
    /// Moves the pending-login key ring to its single owner (the server identity service).
    pub fn take_login_keys(&mut self) -> Option<crate::auth::login_keys::LoginKeys> {
        self.login_keys.take()
    }
    /// Server startup only: owner tools intentionally do not load a signing backend.
    pub fn require_server(&self, identity_present: bool) -> Result<(), ConfigError> {
        if self.mode == Mode::Production {
            if !matches!(self.backend, Backend::Pkcs11 | Backend::ArtifactSigning) {
                return Err(ConfigError(
                    "production server requires PKCS#11 backend (or artifact_signing)",
                ));
            }
            if !identity_present {
                return Err(ConfigError(
                    "production server requires identity configuration",
                ));
            }
        }
        Ok(())
    }
    pub fn load() -> Result<Self, ConfigError> {
        let lookup = |key: &str| match std::env::var(key) {
            Ok(value) => Ok(Some(value)),
            Err(std::env::VarError::NotPresent) => Ok(None),
            Err(_) => Err(ConfigError("configuration environment must be UTF-8")),
        };
        let text = lookup("BRIGALOW_CONFIG")?
            .map(|path| {
                std::fs::read_to_string(path)
                    .map_err(|_| ConfigError("cannot read configuration file"))
            })
            .transpose()?;
        Self::from_sources(text.as_deref().unwrap_or(""), lookup)
    }

    pub fn from_sources(
        text: &str,
        env: impl Fn(&str) -> Result<Option<String>, ConfigError>,
    ) -> Result<Self, ConfigError> {
        // Never include parser diagnostics: they contain input snippets, including rejected secrets.
        let file: FileConfig = toml::from_str(text).map_err(|_| ConfigError("invalid configuration file (only non-secret settings and secret file paths allowed)"))?;
        let mode = match env("BRIGALOW_MODE")? {
            Some(value) => match value.as_str() {
                "lab" => Mode::Lab,
                "production" => Mode::Production,
                _ => return Err(ConfigError("mode must be lab or production")),
            },
            None => file.mode.unwrap_or_default(),
        };
        let bind = match env("BRIGALOW_BIND")? {
            Some(value) => value
                .parse()
                .map_err(|_| ConfigError("invalid bind address"))?,
            None => file
                .bind
                .unwrap_or_else(|| "127.0.0.1:8080".parse().unwrap()),
        };
        let read_secret = |value_name: &str,
                           path_name: &str,
                           configured: Option<PathBuf>|
         -> Result<Option<Secret>, ConfigError> {
            let value = env(value_name)?;
            let path = env(path_name)?.map(PathBuf::from).or(configured);
            if value.is_some() && path.is_some() {
                return Err(ConfigError("choose one secret source: environment or file"));
            }
            let value = match (value, path) {
                (Some(v), None) => Some(v),
                (None, Some(p)) => Some(secret_file(&p)?),
                _ => None,
            };
            value
                .map(|v| {
                    if v.is_empty() || v.len() > 4096 || v.contains('\0') {
                        return Err(ConfigError(
                            "secret must be non-empty and at most 4096 bytes without NUL",
                        ));
                    }
                    Ok(Secret(Zeroizing::new(v)))
                })
                .transpose()
        };
        let backend = match env("BRIGALOW_BACKEND")?.as_deref() {
            Some("software") => Backend::Software,
            Some("pkcs11") => Backend::Pkcs11,
            Some("csc_mock") => Backend::CscMock,
            Some("artifact_signing") => Backend::ArtifactSigning,
            Some("disabled") => Backend::Disabled,
            None => file.backend.unwrap_or_default(),
            _ => return Err(ConfigError("invalid key backend")),
        };
        if backend == Backend::Software && mode != Mode::Lab {
            return Err(ConfigError("software backend requires lab mode"));
        }
        if (backend == Backend::CscMock || file.csc_mock.is_some()) && mode != Mode::Lab {
            return Err(ConfigError("CSC mock backend requires lab mode"));
        }
        let rate_limit = file.rate_limit.unwrap_or_default();
        if !rate_limit.valid() {
            return Err(ConfigError("invalid rate limit"));
        }
        Ok(Self {
            rate_limit,
            backend,
            backend_id: env("BRIGALOW_BACKEND_ID")?
                .or(file.backend_id)
                .unwrap_or_else(|| "default".into()),
            hsm_module: env("BRIGALOW_HSM_MODULE")?
                .map(PathBuf::from)
                .or(file.hsm_module),
            hsm_token: env("BRIGALOW_HSM_TOKEN")?.or(file.hsm_token),
            trust_anchors: file.trust_anchors.unwrap_or_default(),
            tsa: file.tsa,
            csc_mock: file.csc_mock,
            artifact_signing: file.artifact_signing,
            notifications: file.notifications.unwrap_or_default(),
            gates: file.gates.unwrap_or_default(),
            login_keys: file
                .login_keys
                .as_ref()
                .map(LoginKeysConfig::load)
                .transpose()?,
            mode,
            bind,
            db_host: env("BRIGALOW_DB_HOST")?
                .or(file.db_host)
                .unwrap_or_else(|| "127.0.0.1".into()),
            db_port: match env("BRIGALOW_DB_PORT")? {
                Some(p) => p
                    .parse()
                    .map_err(|_| ConfigError("invalid database port"))?,
                None => file.db_port.unwrap_or(5432),
            },
            db_name: env("BRIGALOW_DB_NAME")?
                .or(file.db_name)
                .unwrap_or_else(|| "brigalow".into()),
            db_user: env("BRIGALOW_DB_USER")?
                .or(file.db_user)
                .unwrap_or_else(|| "brigalow_runtime".into()),
            db_ca_file: env("BRIGALOW_DB_CA_FILE")?
                .map(PathBuf::from)
                .or(file.db_ca_file),
            db_password: read_secret(
                "BRIGALOW_DB_PASSWORD",
                "BRIGALOW_DB_PASSWORD_FILE",
                file.db_password_file,
            )?
            .ok_or(ConfigError(
                "database password required from environment or file",
            ))?,
            hsm_pin: read_secret(
                "BRIGALOW_HSM_PIN",
                "BRIGALOW_HSM_PIN_FILE",
                file.hsm_pin_file,
            )?,
        })
    }

    pub fn key_backend(
        &self,
    ) -> Result<Option<std::sync::Arc<dyn brigalow_crypto::KeyBackend>>, ConfigError> {
        use brigalow_crypto::{pkcs11::Hsm, software::Software};
        let backend: std::sync::Arc<dyn brigalow_crypto::KeyBackend> = match self.backend {
            Backend::Disabled => return Ok(None),
            Backend::CscMock => {
                if self.mode != Mode::Lab {
                    return Err(ConfigError("CSC mock backend requires lab mode"));
                }
                std::sync::Arc::new(
                    self.csc_mock
                        .as_ref()
                        .ok_or(ConfigError("CSC mock configuration required"))?
                        .backend()?,
                )
            }
            Backend::ArtifactSigning => std::sync::Arc::new(
                brigalow_crypto::artifact_signing::ArtifactSigning::new(
                    self.artifact_signing
                        .as_ref()
                        .ok_or(ConfigError("Artifact Signing configuration required"))?
                        .settings(self.mode, &self.trust_anchors)?,
                )
                .map_err(|_| ConfigError("Artifact Signing startup failed; no fallback allowed"))?,
            ),
            Backend::Software => std::sync::Arc::new(
                Software::new(self.mode == Mode::Lab)
                    .map_err(|_| ConfigError("software backend requires lab mode"))?,
            ),
            Backend::Pkcs11 => std::sync::Arc::new(
                Hsm::open(
                    self.hsm_module
                        .as_deref()
                        .ok_or(ConfigError("HSM module required"))?,
                    self.hsm_token
                        .as_deref()
                        .ok_or(ConfigError("HSM token label required"))?,
                    self.hsm_pin
                        .as_ref()
                        .ok_or(ConfigError("HSM PIN required"))?
                        .0
                        .to_string(),
                )
                .map_err(|_| ConfigError("HSM startup failed; no fallback allowed"))?,
            ),
        };
        Ok(Some(backend))
    }

    pub fn database_options(&self) -> PgConnectOptions {
        let options = PgConnectOptions::new()
            .host(&self.db_host)
            .port(self.db_port)
            .database(&self.db_name)
            .username(&self.db_user)
            .password(&self.db_password.0)
            .ssl_mode(PgSslMode::VerifyFull);
        match &self.db_ca_file {
            Some(path) => options.ssl_root_cert(path),
            None => options,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    fn load(text: &str, values: &[(&str, &str)]) -> Result<Config, ConfigError> {
        let values: BTreeMap<_, _> = values.iter().copied().collect();
        Config::from_sources(text, |key| Ok(values.get(key).map(|s| (*s).to_string())))
    }
    #[test]
    fn defaults_production_and_environment_overrides_file() {
        let secret = uuid::Uuid::new_v4().to_string();
        assert_eq!(
            load("", &[("BRIGALOW_DB_PASSWORD", &secret)]).unwrap().mode,
            Mode::Production
        );
        let config = load(
            "mode='production'\nbind='127.0.0.1:1111'",
            &[
                ("BRIGALOW_DB_PASSWORD", &secret),
                ("BRIGALOW_MODE", "lab"),
                ("BRIGALOW_BIND", "127.0.0.1:2222"),
            ],
        )
        .unwrap();
        assert_eq!(config.mode, Mode::Lab);
        assert_eq!(config.bind.port(), 2222);
        assert!(!format!("{config:?}").contains(&secret));
        assert!(load("mode='unknown'", &[]).is_err());
        assert!(load("", &[("BRIGALOW_MODE", "unknown")]).is_err());
        assert!(load("", &[]).is_err());
        assert!(load("", &[("BRIGALOW_DB_PASSWORD", "")]).is_err());
        let error = load(&format!("db_password='{secret}'"), &[]).unwrap_err();
        assert!(!format!("{error:?} {error}").contains(&secret));
    }
    #[test]
    fn at_key_01_startup_guard_and_no_fallback() {
        let secret = uuid::Uuid::new_v4().to_string();
        let error = load("backend='software'", &[("BRIGALOW_DB_PASSWORD", &secret)]).unwrap_err();
        assert!(error
            .to_string()
            .contains("software backend requires lab mode"));
        let config = load(
            "mode='lab'\nbackend='software'",
            &[("BRIGALOW_DB_PASSWORD", &secret)],
        )
        .unwrap();
        assert!(config.key_backend().unwrap().unwrap().is_lab());
        let config = load(
            "mode='lab'\nbackend='pkcs11'\nhsm_module='/nonexistent/module'\nhsm_token='absent'",
            &[
                ("BRIGALOW_DB_PASSWORD", &secret),
                ("BRIGALOW_HSM_PIN", &secret),
            ],
        )
        .unwrap();
        assert!(config.key_backend().is_err());
        assert!(
            load("backend='csc_mock'", &[("BRIGALOW_DB_PASSWORD", &secret)])
                .unwrap_err()
                .to_string()
                .contains("requires lab mode")
        );
        let config = load(
            "mode='lab'\nbackend='csc_mock'",
            &[("BRIGALOW_DB_PASSWORD", &secret)],
        )
        .unwrap();
        assert!(config.key_backend().is_err());
    }
    #[test]
    fn artifact_signing_config_has_no_credentials_and_fails_closed() {
        let secret = uuid::Uuid::new_v4().to_string();
        let env = [("BRIGALOW_DB_PASSWORD", secret.as_str())];
        let base = "mode='production'\nbackend='artifact_signing'\n[[trust_anchors]]\nname='azure'\ntier='external-ca'\nfile='/nonexistent/root.der'\n[artifact_signing]\nendpoint='https://eus.codesigning.azure.net'\n[[artifact_signing.bindings]]\nid='11111111-1111-4111-8111-111111111111'\norg='22222222-2222-4222-8222-222222222222'\nproject='33333333-3333-4333-8333-333333333333'\npurpose='release'\naccount='brigalow'\nprofile='release-profile'\nanchor='azure'\nprofile_eku='1.3.6.1.4.1.311.97.1.2.3'\n";
        let config = load(base, &env).unwrap();
        assert_eq!(config.backend, Backend::ArtifactSigning);
        // Allowed in production mode; the unreadable anchor fails startup with no fallback.
        config.require_server(true).unwrap();
        assert!(config.key_backend().is_err());
        assert!(load(&base.replace("backend='artifact_signing'", ""), &env)
            .unwrap()
            .require_server(true)
            .is_err());
        // Credentials and IMDS addresses are not configuration.
        for extra in [
            "access_token_file='/run/token'\n",
            "client_secret='x'\n",
            "imds_url='http://127.0.0.1'\n",
        ] {
            let text = base.replace(
                "[artifact_signing]\n",
                &format!("[artifact_signing]\n{extra}"),
            );
            assert!(load(&text, &env).is_err(), "{extra}");
        }
        for (from, to) in [
            ("tier='external-ca'", "tier='private'"),
            ("anchor='azure'", "anchor='missing'"),
        ] {
            let config = load(&base.replace(from, to), &env).unwrap();
            assert!(config.key_backend().is_err(), "{to}");
        }
        // Test TLS roots belong to lab mode only.
        let text = base.replace(
            "[artifact_signing]\n",
            "[artifact_signing]\ntls_ca_file='/nonexistent/ca.pem'\n",
        );
        assert!(load(&text, &env)
            .unwrap()
            .key_backend()
            .err()
            .unwrap()
            .to_string()
            .contains("lab mode"));
        for timeout in ["0", "26"] {
            let text = base.replace(
                "[artifact_signing]\n",
                &format!("[artifact_signing]\noperation_timeout_seconds={timeout}\n"),
            );
            assert!(load(&text, &env).unwrap().key_backend().is_err());
        }
    }
    #[test]
    #[cfg(unix)]
    fn login_key_ring_files_are_private_exact_and_redacted() {
        use base64::{engine::general_purpose::STANDARD, Engine};
        use rand::RngCore;
        use std::os::unix::fs::{symlink, PermissionsExt};
        let dir = tempfile::tempdir().unwrap();
        let password = uuid::Uuid::new_v4().to_string();
        let write = |name: &str, bytes: usize, mode: u32| {
            let mut material = vec![0u8; bytes];
            rand::rngs::OsRng.fill_bytes(&mut material);
            let encoded = STANDARD.encode(&material);
            let path = dir.path().join(name);
            std::fs::write(&path, format!("{encoded}\n")).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
            (path, encoded)
        };
        let ring = |active: &std::path::Path, previous: &[(&str, &std::path::Path)]| {
            let mut text = format!(
                "[login_keys]\nactive = {{ id = 'k2', file = '{}' }}\nprevious = [",
                active.display()
            );
            for (id, path) in previous {
                text += &format!("{{ id = '{id}', file = '{}' }},", path.display());
            }
            text + "]\n"
        };
        let (active, active_value) = write("active", 32, 0o600);
        let (old, old_value) = write("old", 32, 0o600);
        let mut config = load(
            &ring(&active, &[("k1", &old)]),
            &[("BRIGALOW_DB_PASSWORD", &password)],
        )
        .unwrap();
        let debug = format!("{config:?}");
        for secret in [&active_value, &old_value, &password] {
            assert!(!debug.contains(secret.as_str()));
        }
        let keys = config.take_login_keys().unwrap();
        assert_eq!(keys.active_id(), "k2");
        assert!(config.take_login_keys().is_none());
        assert!(load("", &[("BRIGALOW_DB_PASSWORD", &password)])
            .unwrap()
            .take_login_keys()
            .is_none());
        let reject = |text: String| {
            let error = load(&text, &[("BRIGALOW_DB_PASSWORD", &password)]).unwrap_err();
            let shown = format!("{error} {error:?}");
            assert!(!shown.contains(&active_value) && !shown.contains(&old_value));
        };
        let (short, _) = write("short", 31, 0o600);
        let (long, _) = write("long", 33, 0o600);
        let (public, _) = write("public", 32, 0o644);
        let link = dir.path().join("link");
        symlink(&active, &link).unwrap();
        let garbage = dir.path().join("garbage");
        std::fs::write(&garbage, "not base64!").unwrap();
        std::fs::set_permissions(&garbage, std::fs::Permissions::from_mode(0o600)).unwrap();
        for path in [
            &short,
            &long,
            &public,
            &link,
            &garbage,
            &dir.path().join("missing"),
        ] {
            reject(ring(path, &[]));
            reject(ring(&active, &[("k1", path)]));
        }
        // Duplicate IDs or reused material are ambiguous; unknown fields are rejected.
        reject(ring(&active, &[("k2", &old)]));
        reject(ring(&active, &[("k1", &active)]));
        reject(ring(&active, &[("bad id", &old)]));
        reject(format!(
            "[login_keys]\nactive = {{ id = 'k2', file = '{}', value = 'x' }}\n",
            active.display()
        ));
        reject(format!(
            "[login_keys]\nactive = {{ id = 'k2', value = '{active_value}' }}\n"
        ));
    }
    #[test]
    #[cfg(unix)]
    fn files_require_0600_and_reject_links_and_ambiguous_sources() {
        use std::{
            io::Write,
            os::unix::fs::{symlink, PermissionsExt},
        };
        let mut file = tempfile::NamedTempFile::new().unwrap();
        let secret = uuid::Uuid::new_v4().to_string();
        writeln!(file, "{secret}").unwrap();
        let path = file.path().to_str().unwrap();
        assert!(load("", &[("BRIGALOW_DB_PASSWORD_FILE", path)]).is_ok());
        assert!(load(
            "",
            &[
                ("BRIGALOW_DB_PASSWORD_FILE", path),
                ("BRIGALOW_DB_PASSWORD", &secret)
            ]
        )
        .is_err());
        let dir = tempfile::tempdir().unwrap();
        let link = dir.path().join("link");
        symlink(file.path(), &link).unwrap();
        assert!(load("", &[("BRIGALOW_DB_PASSWORD_FILE", link.to_str().unwrap())]).is_err());
        let oversized = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(oversized.path(), "x".repeat(4097)).unwrap();
        assert!(load(
            "",
            &[(
                "BRIGALOW_DB_PASSWORD_FILE",
                oversized.path().to_str().unwrap()
            )]
        )
        .is_err());
        let text = format!("db_password_file='{}'", file.path().display());
        assert!(load(&text, &[]).is_ok());
        file.as_file()
            .set_permissions(std::fs::Permissions::from_mode(0o644))
            .unwrap();
        assert!(load("", &[("BRIGALOW_DB_PASSWORD_FILE", path)]).is_err());
    }
}
