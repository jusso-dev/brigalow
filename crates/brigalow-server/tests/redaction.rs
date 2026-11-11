use std::{
    io::Write,
    process::{Command, Stdio},
    time::{Duration, Instant},
};

#[test]
fn at_ops_01_startup_error_redacts_environment_secrets_and_config() {
    let password = uuid::Uuid::new_v4().to_string();
    let pin = uuid::Uuid::new_v4().to_string();
    let mut config = tempfile::NamedTempFile::new().unwrap();
    // Also exercise untrusted non-secret fields: they must never reach diagnostics.
    writeln!(config, "db_name='{password}'\ndb_user='{pin}'").unwrap();
    let guard = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = guard.local_addr().unwrap().port();
    // Hold a non-Postgres listener open so connection fails with a bounded timeout.
    let stdout = tempfile::NamedTempFile::new().unwrap();
    let stderr = tempfile::NamedTempFile::new().unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_brigalow-server"))
        .env_clear()
        .env("BRIGALOW_CONFIG", config.path())
        .env("BRIGALOW_DB_HOST", "127.0.0.1")
        .env("BRIGALOW_DB_PORT", port.to_string())
        .env("BRIGALOW_DB_PASSWORD", &password)
        .env("BRIGALOW_HSM_PIN", &pin)
        .env("RUST_LOG", "trace")
        .stdout(Stdio::from(stdout.reopen().unwrap()))
        .stderr(Stdio::from(stderr.reopen().unwrap()))
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if Instant::now() > deadline {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!("startup did not fail within deadline");
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    assert!(!status.success());
    let out = std::fs::read_to_string(stdout.path()).unwrap();
    let err = std::fs::read_to_string(stderr.path()).unwrap();
    assert!(err.contains("database startup failed"));
    assert!(err.contains("[REDACTED]"));
    for value in [&password, &pin] {
        assert!(!out.contains(value));
        assert!(!err.contains(value));
    }
}

#[test]
fn at_key_01_production_software_refused_before_database_connection() {
    let output = Command::new(env!("CARGO_BIN_EXE_brigalow-server"))
        .env_clear()
        .env("BRIGALOW_MODE", "production")
        .env("BRIGALOW_BACKEND", "software")
        .output()
        .unwrap();
    assert!(!output.status.success());
    let error = String::from_utf8(output.stderr).unwrap();
    assert!(error.contains("software backend requires lab mode"));
    assert!(!error.contains("database startup failed"));
}
