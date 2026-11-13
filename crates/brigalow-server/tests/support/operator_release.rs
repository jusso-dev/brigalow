//! AT-REL-03: operator release manifest signed through the real production-mode policy path.
//! Disposable SoftHSM token, generated PINs/CA/token only; no vendor HSM qualification claim.
use super::*;
use brigalow_core::{
    keys::KeyRecord,
    policy::{Policy, RequestState, SignRequest},
    windows::ReleaseWindow,
};
use sha2::Digest;
use std::{
    io::{BufRead, Read},
    path::{Path, PathBuf},
    sync::{atomic::Ordering, Mutex},
};

const SOFTHSM: &str = "/usr/lib/softhsm/libsofthsm2.so";
const FIXTURES: [&str; 6] = [
    "brig",
    "brigalow-server",
    "brigalow-ca",
    "brigalow-audit",
    "brigalow-admin",
    "libbrigalow_pkcs11.so",
];

fn command(dir: &Path, program: &str, args: &[&str]) -> Vec<u8> {
    let out = std::process::Command::new(program)
        .current_dir(dir)
        .args(args)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{program} failed (diagnostics withheld)"
    );
    out.stdout
}

struct Run {
    child: ChildGuard,
    stderr: Arc<Mutex<Vec<String>>>,
}
impl Run {
    async fn request_id(&self) -> Uuid {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(120);
        loop {
            if let Some(id) = self.stderr.lock().unwrap().iter().find_map(|line| {
                line.strip_prefix("Brigalow request ID: ")
                    .and_then(|id| id.trim().parse().ok())
            }) {
                return id;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "operator workflow printed no request ID"
            );
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
    }
    async fn finish(mut self) -> (bool, String, String) {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(420);
        let status = loop {
            if let Some(status) = self.child.0.try_wait().unwrap() {
                break status;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "operator workflow hung"
            );
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        };
        let mut stdout = String::new();
        self.child
            .0
            .stdout
            .take()
            .unwrap()
            .read_to_string(&mut stdout)
            .unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        let stderr = self.stderr.lock().unwrap().join("\n");
        (status.success(), stdout, stderr)
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn at_rel_03_tool_operator_release_through_production_policy_path() {
    assert_eq!(
        std::env::consts::OS,
        "linux",
        "run disposable tools container"
    );
    let mut f = fixture().await;
    let org = f.orgs[0];
    let project = f.objects[0][0];
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    let secrets = PathBuf::from(std::env::var("BRIGALOW_TEST_SECRETS").unwrap());

    // Isolated disposable SoftHSM token for this test process only.
    std::fs::create_dir(d.join("tokens")).unwrap();
    std::fs::write(
        d.join("softhsm.conf"),
        format!(
            "directories.tokendir = {}/tokens\nobjectstore.backend = file\nlog.level = ERROR\n",
            d.display()
        ),
    )
    .unwrap();
    let (pin, so_pin) = (auth::random_secret(), auth::random_secret());
    let init = std::process::Command::new("softhsm2-util")
        .env("SOFTHSM2_CONF", d.join("softhsm.conf"))
        .args(["--init-token", "--free", "--label", "brigalow-release-test"])
        .args(["--pin", &pin, "--so-pin", &so_pin])
        .output()
        .unwrap();
    assert!(init.status.success(), "SoftHSM token init failed");
    // SoftHSM reads its configuration once, at C_Initialize inside Hsm::open.
    std::env::set_var("SOFTHSM2_CONF", d.join("softhsm.conf"));
    let hsm = brigalow_crypto::pkcs11::Hsm::open(Path::new(SOFTHSM), "brigalow-release-test", pin);
    std::env::remove_var("SOFTHSM2_CONF");
    let hsm = Arc::new(hsm.unwrap());
    let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let custodian = role_session(&f, "release-custodian", vec![Role::KeyCustodian]).await;
    let approver = role_session(&f, "release-approver", vec![Role::Approver]).await;
    let admin = login(&f, org).await;
    // Production mode: lab software keys can never bind a release policy here.
    let release_keys = brigalow_server::keys::KeyService {
        backend: Arc::new(CountSigning {
            backend: hsm.clone(),
            calls: calls.clone(),
        }),
        id: "release-softhsm".into(),
        anchors: f.keys.anchors.clone(),
    };
    let production = |f: &Fixture| {
        application(AppState {
            rate_limit: Default::default(),
            store: f.store.clone(),
            mode: Mode::Production,
            identity: Some(f.identity.clone()),
            keys: Some(release_keys.clone()),
            tsa: Some(f.tsa.clone()),
            notifications: Default::default(),
            gates: Default::default(),
        })
    };
    f.router = production(&f);

    let result = json_as(
        &f,
        &format!("/v1/orgs/{org}/projects/{project}/keys"),
        &custodian,
        json!({"algorithm":"p256","purpose":"release","offline":true}),
    )
    .await;
    assert_eq!(result.0, 201);
    let key: KeyRecord = serde_json::from_str(&result.2).unwrap();
    let key_id = key.key.id;
    assert_eq!(hsm.protections(&key.key).unwrap(), (true, false));
    let result = json_as(
        &f,
        &format!("/v1/orgs/{org}/keys/{key_id}/csr"),
        &custodian,
        json!({"subject":"CN=Brigalow ephemeral operator release signer"}),
    )
    .await;
    assert_eq!(result.0, 200);
    let csr: Value = serde_json::from_str(&result.2).unwrap();
    std::fs::write(d.join("release.csr"), csr["csr"].as_str().unwrap()).unwrap();
    std::fs::write(d.join("release.ext"),"basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=codeSigning\n").unwrap();
    let ca_cert = secrets.join("ca.crt");
    let ca_key = secrets.join("ca.key");
    command(
        d,
        "openssl",
        &[
            "x509",
            "-req",
            "-in",
            "release.csr",
            "-CA",
            ca_cert.to_str().unwrap(),
            "-CAkey",
            ca_key.to_str().unwrap(),
            "-set_serial",
            "305",
            "-days",
            "1",
            "-extfile",
            "release.ext",
            "-outform",
            "DER",
            "-out",
            "release.der",
        ],
    );
    let chain = vec![
        std::fs::read(d.join("release.der")).unwrap(),
        std::fs::read(secrets.join("ca.der")).unwrap(),
    ];
    for (path, body) in [
        ("certificate", json!({"chain":chain})),
        ("activate", json!({})),
    ] {
        let result = json_as(
            &f,
            &format!("/v1/orgs/{org}/keys/{key_id}/{path}"),
            &custodian,
            body,
        )
        .await;
        assert_eq!(result.0, 200, "key {path}");
    }
    let now = auth::now();
    let result = json_as(
        &f,
        &format!("/v1/orgs/{org}/keys/{key_id}/windows"),
        &custodian,
        json!({"name":"operator release","starts_at":now-5,"ends_at":now+1800,"cap":1}),
    )
    .await;
    assert_eq!(result.0, 201);
    let window: ReleaseWindow = serde_json::from_str(&result.2).unwrap();
    let release_claims = json!({"repository":"acme/release","ref":"refs/heads/main","environment":"release","ref_protected":"true"});
    let result = json_as(
        &f,
        &format!("/v1/orgs/{org}/projects/{project}/policies"),
        &admin,
        json!({"name":"operator-release","key":key_id,"purpose":"release","claims":release_claims,"algorithms":["p256"],"timestamp":"disabled","approval":{"approvers":["release-approver"],"required":1,"ttl_seconds":600}}),
    )
    .await;
    assert_eq!(result.0, 201, "release policy");
    let policy: Policy = serde_json::from_str(&result.2).unwrap();
    // Release signing needs verified CI claims; API credentials carry none. Bind a workload
    // rule for this policy to the fixture's generated-key test IdP and mint a signed token.
    let mut config = f.identity.config.clone();
    config
        .authorities
        .iter_mut()
        .find(|a| a.org_id == org && a.name == "valid")
        .unwrap()
        .workloads
        .push(WorkloadRule {
            project,
            policy: policy.id,
            claims: serde_json::from_value(release_claims.clone()).unwrap(),
            gitlab: None,
        });
    f.identity = Identity::new(config, Mode::Production, f.identity.login_keys()).unwrap();
    f.router = production(&f);
    let mut token_claims = release_claims.clone();
    token_claims["aud"] = json!(format!("brigalow:{org}"));
    let token = mint(&f, token_claims, false, "RS256").await;

    // Independently exported public key, pinned outside any bundle.
    let get = |path: String| {
        let f = &f;
        let cookie = admin.0.clone();
        async move {
            let r = request(f, "GET", &path, Some(&cookie), None, None, Value::Null).await;
            assert_eq!(r.0, 200, "GET {path}");
            r.2
        }
    };
    let exported: KeyRecord =
        serde_json::from_str(&get(format!("/v1/orgs/{org}/keys/{key_id}")).await).unwrap();
    assert_eq!(exported.trust, brigalow_core::TrustTier::Private);
    std::fs::create_dir(d.join("pinned")).unwrap();
    std::fs::write(d.join("pinned/release-public.der"), &exported.public_key).unwrap();
    command(
        &d.join("pinned"),
        "openssl",
        &[
            "pkey",
            "-pubin",
            "-inform",
            "DER",
            "-in",
            "release-public.der",
            "-out",
            "release-public.pem",
        ],
    );
    let pinned = d.join("pinned/release-public.pem");
    let fingerprint: String = sha2::Sha256::digest(&exported.public_key)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let app = f.router.clone();
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let mut proxy = ChildGuard(
        std::process::Command::new("python3")
            .arg(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../deploy/dev/test_proxy.py"
            ))
            .arg(port.to_string())
            .arg(std::env::var("BRIGALOW_TEST_TLS_CERT_FILE").unwrap())
            .arg(std::env::var("BRIGALOW_TEST_TLS_KEY_FILE").unwrap())
            .stdout(std::process::Stdio::piped())
            .spawn()
            .unwrap(),
    );
    let mut port = String::new();
    std::io::BufReader::new(proxy.0.stdout.take().unwrap())
        .read_line(&mut port)
        .unwrap();
    let server_url = format!("https://127.0.0.1:{}", port.trim());

    // Clean generated source checkout and fixture payloads.
    let source = d.join("source");
    std::fs::create_dir_all(source.join("src")).unwrap();
    std::fs::write(source.join("Cargo.toml"), "[package]\nname = \"brigalow-core\"\nversion = \"0.0.1\"\nedition = \"2021\"\nlicense = \"Apache-2.0\"\n").unwrap();
    std::fs::write(source.join("src/lib.rs"), "").unwrap();
    std::fs::write(source.join("LICENSE"), "generated licence fixture\n").unwrap();
    std::fs::write(source.join(".gitignore"), "target/\n").unwrap();
    command(&source, "cargo", &["generate-lockfile", "--offline"]);
    let git = [
        "-c",
        "user.name=Release Test",
        "-c",
        "user.email=release-test@example.invalid",
        "-c",
        "commit.gpgsign=false",
    ];
    command(&source, "git", &["init", "-q"]);
    command(&source, "git", &[&git[..], &["add", "-A"]].concat());
    command(
        &source,
        "git",
        &[&git[..], &["commit", "-q", "-m", "fixture"]].concat(),
    );
    let commit = String::from_utf8(command(&source, "git", &["rev-parse", "HEAD"]))
        .unwrap()
        .trim()
        .to_owned();
    std::fs::create_dir(d.join("bin")).unwrap();
    for name in FIXTURES {
        std::fs::write(d.join("bin").join(name), b"generated packaging fixture").unwrap();
    }
    let published = d.join("published");
    std::fs::create_dir(&published).unwrap();

    let start = |name: &str, timeout: &str| {
        let mut child = ChildGuard(
            std::process::Command::new("python3")
                .arg("/work/scripts/operator_release.py")
                .args(["--binaries", d.join("bin").to_str().unwrap()])
                .args(["--output", published.join(name).to_str().unwrap()])
                .args(["--public-key", pinned.to_str().unwrap()])
                .args(["--expected-key-sha256", &fingerprint])
                .args(["--expected-revision", &commit])
                .args(["--source", source.to_str().unwrap()])
                .args(["--brig", "/work/target/debug/brig"])
                .args(["--server", &server_url])
                .args(["--org", &org.to_string()])
                .args(["--project", &project.to_string()])
                .args(["--policy", "operator-release"])
                .args(["--ca-file", ca_cert.to_str().unwrap()])
                .args(["--timeout", timeout])
                .env("BRIGALOW_TOKEN", &token)
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .spawn()
                .unwrap(),
        );
        let stderr = Arc::new(Mutex::new(vec![]));
        let lines = stderr.clone();
        let pipe = child.0.stderr.take().unwrap();
        std::thread::spawn(move || {
            for line in std::io::BufReader::new(pipe).lines() {
                lines.lock().unwrap().push(line.unwrap_or_default());
            }
        });
        Run { child, stderr }
    };
    let decide = |id: Uuid, decision: &'static str| {
        let f = &f;
        let approver = approver.clone();
        async move {
            let r = json_as(
                f,
                &format!("/v1/orgs/{org}/requests/{id}/decisions"),
                &approver,
                json!({ "decision": decision }),
            )
            .await;
            assert!(r.0.is_success(), "decision {decision} failed: {}", r.0);
            serde_json::from_str::<SignRequest>(&r.2).unwrap()
        }
    };
    // brig prints the request ID before sending it, so wait until the server has stored it.
    let state = |id: Uuid| {
        let f = &f;
        let cookie = admin.0.clone();
        async move {
            let path = format!("/v1/orgs/{org}/requests/{id}");
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
            loop {
                let r = request(f, "GET", &path, Some(&cookie), None, None, Value::Null).await;
                if r.0 == 200 {
                    return serde_json::from_str::<SignRequest>(&r.2).unwrap();
                }
                assert!(
                    r.0 == 404 && std::time::Instant::now() < deadline,
                    "GET {path}: {}",
                    r.0
                );
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
        }
    };
    let staging_clean = || {
        std::fs::read_dir(&published)
            .unwrap()
            .all(|e| !e.unwrap().file_name().to_string_lossy().starts_with('.'))
    };
    // Operator mode requires the expected revision, so a failure here is never a missing flag.
    let verify = |bundle: &Path, mode: &str, key: &Path| {
        let revision: &[&str] = if mode == "operator" {
            &["--expected-revision", &commit]
        } else {
            &[]
        };
        std::process::Command::new("python3")
            .arg("/work/scripts/verify_release.py")
            .arg(bundle)
            .args(["--mode", mode, "--public-key", key.to_str().unwrap()])
            .args(revision)
            .output()
            .unwrap()
            .status
            .success()
    };
    let baseline = calls.load(Ordering::SeqCst);

    // 1. Approved request inside the window: one HSM call, verified, published.
    let run = start("approved", "300");
    let id = run.request_id().await;
    assert_eq!(state(id).await.state, RequestState::AwaitingApproval);
    assert_eq!(calls.load(Ordering::SeqCst), baseline);
    assert_eq!(decide(id, "approve").await.state, RequestState::Signed);
    let (ok, stdout, stderr) = run.finish().await;
    assert!(
        ok,
        "operator workflow failed: {}",
        stderr.replace(&token, "[REDACTED]")
    );
    assert!(stdout.contains("Declared origin: operator") && stdout.contains(&id.to_string()));
    assert_eq!(calls.load(Ordering::SeqCst), baseline + 1);
    let bundle = published.join("approved");
    let mut names: Vec<_> = std::fs::read_dir(&bundle)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    names.sort();
    assert_eq!(
        names,
        [
            "brigalow-linux.tar.gz",
            "manifest.json",
            "manifest.sig",
            "sbom.cdx.json"
        ]
    );
    let manifest: Value =
        serde_json::from_slice(&std::fs::read(bundle.join("manifest.json")).unwrap()).unwrap();
    assert_eq!(
        (
            &manifest["version"],
            &manifest["trust"],
            &manifest["source_commit"]
        ),
        (&json!(2), &json!("operator"), &json!(commit))
    );
    let signed = state(id).await;
    assert_eq!(
        signed.submission.digest,
        <[u8; 32]>::from(sha2::Sha256::digest(
            std::fs::read(bundle.join("manifest.json")).unwrap()
        ))
    );
    // Independent OpenSSL check of the exact manifest bytes with the exported key.
    command(
        &bundle,
        "openssl",
        &[
            "dgst",
            "-sha256",
            "-verify",
            pinned.to_str().unwrap(),
            "-signature",
            "manifest.sig",
            "manifest.json",
        ],
    );
    assert!(verify(&bundle, "operator", &pinned));
    assert!(
        !verify(&bundle, "lab", &pinned),
        "operator bundle passed lab mode"
    );
    command(
        d,
        "openssl",
        &[
            "genpkey",
            "-algorithm",
            "EC",
            "-pkeyopt",
            "ec_paramgen_curve:P-256",
            "-out",
            "other.key",
        ],
    );
    command(
        d,
        "openssl",
        &["pkey", "-in", "other.key", "-pubout", "-out", "other.pem"],
    );
    assert!(!verify(&bundle, "operator", &d.join("other.pem")));
    let tampered = d.join("tampered");
    std::fs::create_dir(&tampered).unwrap();
    for name in &names {
        std::fs::copy(bundle.join(name), tampered.join(name)).unwrap();
    }
    assert!(verify(&tampered, "operator", &pinned));
    std::fs::remove_file(tampered.join("sbom.cdx.json")).unwrap();
    std::fs::write(tampered.join("sbom.cdx.json"), b"{}\n").unwrap();
    assert!(!verify(&tampered, "operator", &pinned));

    // 2. Approver denial while brig waits: non-zero, request ID reported, nothing published.
    let run = start("denied", "300");
    let id = run.request_id().await;
    assert_eq!(state(id).await.state, RequestState::AwaitingApproval);
    assert_eq!(decide(id, "deny").await.state, RequestState::Rejected);
    let (ok, _, stderr) = run.finish().await;
    assert!(!ok);
    assert!(stderr.contains(&format!("Query request {id}")));
    assert!(!published.join("denied").exists());

    // 3. Timeout leaves an uncertain request for the operator to query; never retried.
    let run = start("timed-out", "3");
    let id = run.request_id().await;
    let (ok, _, stderr) = run.finish().await;
    assert!(!ok);
    assert!(
        stderr.contains("outcome uncertain") && stderr.contains(&format!("Query request {id}"))
    );
    assert!(!published.join("timed-out").exists());
    assert_eq!(state(id).await.state, RequestState::AwaitingApproval);
    // The cap-1 window is already consumed, so a late approval cannot sign.
    let late = decide(id, "approve").await;
    assert_eq!(late.state, RequestState::Rejected);
    assert_eq!(
        late.failure.as_deref(),
        Some("release_window_required_or_exhausted")
    );
    assert!(late.output.is_none());

    // 4. Existing output is refused before any submission and left untouched.
    std::fs::create_dir(published.join("approved-copy")).unwrap();
    std::fs::write(published.join("approved-copy/operator-owned"), b"keep").unwrap();
    let (ok, _, stderr) = start("approved-copy", "30").finish().await;
    assert!(!ok && !stderr.contains("Brigalow request ID"));
    assert_eq!(
        std::fs::read(published.join("approved-copy/operator-owned")).unwrap(),
        b"keep"
    );

    assert_eq!(
        calls.load(Ordering::SeqCst),
        baseline + 1,
        "no duplicate HSM call"
    );
    let window: ReleaseWindow =
        serde_json::from_str(&get(format!("/v1/orgs/{org}/windows/{}", window.id)).await).unwrap();
    assert_eq!(window.used, 1);
    assert!(staging_clean(), "staging directories must be removed");
    println!("AT-REL-03: SoftHSM release key, production policy/approval/window path, OpenSSL and pinned-key verification passed");
    server.abort();
    f.store.close().await;
    f.admin.close().await;
}
