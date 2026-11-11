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

pub struct Config {
    pub mode: Mode,
    pub bind: SocketAddr,
    db_host: String,
    db_port: u16,
    db_name: String,
    db_user: String,
    db_ca_file: Option<PathBuf>,
    db_password: Secret,
    // Reserved for the Phase 2 backend; never logged or handed to a software fallback.
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
            .finish()
    }
}
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct ConfigError(&'static str);

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileConfig {
    mode: Option<Mode>,
    bind: Option<SocketAddr>,
    db_host: Option<String>,
    db_port: Option<u16>,
    db_name: Option<String>,
    db_user: Option<String>,
    db_ca_file: Option<PathBuf>,
    db_password_file: Option<PathBuf>,
    hsm_pin_file: Option<PathBuf>,
}

fn secret_file(path: &Path) -> Result<String, ConfigError> {
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
        Ok(Self {
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
