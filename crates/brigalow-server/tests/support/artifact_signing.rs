//! AT-AZ-01: Azure Artifact Signing backend against a local HTTPS sign/poll mock and a loopback
//! mock IMDS. Generated keys and CAs only; nothing leaves loopback.
use super::*;
use brigalow_core::{
    keys::KeyRecord,
    policy::{Policy, RequestState, SignRequest},
    Purpose, TrustTier,
};
use brigalow_crypto::{
    artifact_signing::{ArtifactSigning, Binding, Settings},
    KeyBackend,
};
use std::io::BufRead;

struct Mock {
    _child: ChildGuard,
    dir: tempfile::TempDir,
    sign: String,
    imds: String,
}
impl Mock {
    fn start() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let mut child = ChildGuard(
            std::process::Command::new("python3")
                .arg(concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/../../deploy/dev/test_artifact_signing.py"
                ))
                .arg(dir.path())
                .stdout(std::process::Stdio::piped())
                .spawn()
                .unwrap(),
        );
        let mut ports = String::new();
        std::io::BufReader::new(child.0.stdout.take().unwrap())
            .read_line(&mut ports)
            .unwrap();
        let ports: Vec<&str> = ports.split_whitespace().collect();
        assert_eq!(ports.len(), 2, "mock failed to start");
        Self {
            sign: format!("https://127.0.0.1:{}", ports[0]),
            imds: format!("http://127.0.0.1:{}", ports[1]),
            _child: child,
            dir,
        }
    }
    fn path(&self, name: &str) -> std::path::PathBuf {
        self.dir.path().join(name)
    }
    fn set(&self, name: &str, value: &str) {
        std::fs::write(self.path(name), value).unwrap();
    }
    fn events(&self) -> Vec<Value> {
        std::fs::read_to_string(self.path("events"))
            .unwrap()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect()
    }
    fn count(&self, server: &str, method: &str) -> usize {
        self.events()
            .iter()
            .filter(|e| e["server"] == server && e["method"] == method)
            .count()
    }
    fn der(&self, name: &str) -> Vec<u8> {
        std::fs::read(self.path(&format!("{name}.der"))).unwrap()
    }
    fn backend(&self, bindings: Vec<Binding>, lab: bool) -> ArtifactSigning {
        ArtifactSigning::for_tests(
            Settings {
                endpoint: self.sign.clone(),
                tls_ca_pem: Some(std::fs::read(self.path("tls-ca.pem")).unwrap()),
                lab,
                managed_identity_client_id: Some(Uuid::nil()),
                operation_timeout: std::time::Duration::from_secs(4),
                bindings,
            },
            &self.imds,
        )
        .unwrap()
    }
}
/// Submit one request; returns its ID and the HTTP result.
async fn submit_one(
    f: &Fixture,
    path: &str,
    session: &(String, String),
    input: Value,
) -> (Uuid, (StatusCode, HeaderMap, String)) {
    let id = serde_json::from_value(input["request_id"].clone()).unwrap();
    (id, json_as(f, path, session, input).await)
}
async fn audit_entry(
    f: &Fixture,
    org: Uuid,
    subject: Uuid,
    action: &str,
) -> brigalow_core::audit::Entry {
    let (mut after, mut found) = (0, None);
    loop {
        let page = f.store.tenant(org).audit_page(after, 1000).await.unwrap();
        let Some(last) = page.last() else { break };
        after = last.seq as i64;
        found = page
            .into_iter()
            .rfind(|e| e.subject == subject.to_string() && e.action == action)
            .or(found);
    }
    found.unwrap()
}
const PROFILE_EKU: &str = "1.3.6.1.4.1.311.97.4242.1.1";

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn at_az_01_artifact_signing_rotating_chain_verified_fail_closed() {
    let mut f = fixture().await;
    let org = f.orgs[0];
    let project = f.objects[0][0];
    let mock = Arc::new(tokio::task::spawn_blocking(Mock::start).await.unwrap());
    let (test_id, release_id, untrusted_id) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
    let binding = |id, purpose, profile: &str, anchor: Vec<u8>| {
        Binding::new(
            id,
            org,
            project,
            purpose,
            "brigalowtest",
            profile,
            anchor,
            PROFILE_EKU,
        )
        .unwrap()
    };
    let (root, wrong_root) = (mock.der("root"), mock.der("wrong-root"));
    // The "untrusted" binding pins a root that is not a configured external-ca anchor.
    let bindings = || {
        vec![
            binding(test_id, Purpose::Test, "test-profile", root.clone()),
            binding(
                release_id,
                Purpose::Release,
                "release-profile",
                root.clone(),
            ),
            binding(
                untrusted_id,
                Purpose::Release,
                "untrusted-profile",
                wrong_root.clone(),
            ),
        ]
    };
    // Production constructor refuses the loopback mock; configuration refuses production test
    // roots and non-Azure hosts before any network call.
    let settings = Settings {
        endpoint: mock.sign.clone(),
        tls_ca_pem: Some(std::fs::read(mock.path("tls-ca.pem")).unwrap()),
        lab: false,
        managed_identity_client_id: None,
        operation_timeout: std::time::Duration::from_secs(5),
        bindings: bindings(),
    };
    assert!(
        tokio::task::spawn_blocking(move || ArtifactSigning::new(settings).is_err())
            .await
            .unwrap()
    );
    let anchor_file = mock.path("root.der");
    let config = |mode: &str, endpoint: &str, tls: bool| {
        format!(
            "mode='{mode}'\nbackend='artifact_signing'\n[[trust_anchors]]\nname='azure-root'\ntier='external-ca'\nfile='{}'\n[artifact_signing]\nendpoint='{endpoint}'\n{}[[artifact_signing.bindings]]\nid='{test_id}'\norg='{org}'\nproject='{project}'\npurpose='test'\naccount='brigalowtest'\nprofile='test-profile'\nanchor='azure-root'\nprofile_eku='{PROFILE_EKU}'\n",
            anchor_file.display(),
            if tls { format!("tls_ca_file='{}'\n", mock.path("tls-ca.pem").display()) } else { String::new() }
        )
    };
    let before = mock.events().len();
    let cases = [
        (
            config("production", "https://eus.codesigning.azure.net", false),
            true,
        ),
        (config("lab", &mock.sign, true), true),
        (config("production", &mock.sign, true), false),
        (config("production", &mock.sign, false), false),
        (
            config(
                "production",
                "https://eus.codesigning.azure.net.evil.test",
                false,
            ),
            false,
        ),
        (
            config("production", "http://eus.codesigning.azure.net", false),
            false,
        ),
        (
            config("production", "https://eus.codesigning.azure.net", false)
                .replace("tier='external-ca'", "tier='private'"),
            false,
        ),
        (
            config("production", "https://eus.codesigning.azure.net", false)
                .replace(PROFILE_EKU, "1.3.6.1.5.5.7.3.3"),
            false,
        ),
        (
            config("production", "https://eus.codesigning.azure.net", false)
                .replace("anchor='azure-root'", "anchor='missing'"),
            false,
        ),
        (
            config("production", "https://eus.codesigning.azure.net", false) + "token='x'\n",
            false,
        ),
    ];
    tokio::task::spawn_blocking(move || {
        for (text, ok) in cases {
            let result = brigalow_server::config::Config::from_sources(&text, |key| {
                Ok((key == "BRIGALOW_DB_PASSWORD").then(auth::random_secret))
            })
            .and_then(|c| {
                c.require_server(true)?;
                c.key_backend().map(|_| ())
            });
            assert_eq!(result.is_ok(), ok, "{text}");
        }
    })
    .await
    .unwrap();
    assert_eq!(
        mock.events().len(),
        before,
        "configuration contacted a service"
    );

    // The test seam constructs a non-lab instance against the loopback mock so production-mode
    // policy paths run; the client builder is blocking, so build it off the async runtime.
    let backend: Arc<dyn brigalow_crypto::KeyBackend> = Arc::new(
        tokio::task::spawn_blocking({
            let (mock, bindings) = (mock.clone(), bindings());
            move || mock.backend(bindings, false)
        })
        .await
        .unwrap(),
    );
    f.keys = brigalow_server::keys::KeyService {
        backend,
        id: "artifact-signing".into(),
        anchors: vec![brigalow_server::keys::Anchor {
            name: "azure-root".into(),
            tier: TrustTier::ExternalCa,
            der: root.clone(),
        }],
    };
    f.router = application(AppState {
        rate_limit: Default::default(),
        gates: Default::default(),
        notifications: Default::default(),
        tsa: Some(f.tsa.clone()),
        keys: Some(f.keys.clone()),
        store: f.store.clone(),
        mode: Mode::Production,
        identity: Some(f.identity.clone()),
    });
    let custodian = role_session(&f, "azure-custodian", vec![Role::KeyCustodian]).await;
    let admin = role_session(&f, "azure-admin", vec![Role::OrgAdmin]).await;
    let submitter = role_session(&f, "azure-submitter", vec![Role::Submitter]).await;
    let create = format!("/v1/orgs/{org}/projects/{project}/keys");
    let register = |id: Uuid, purpose: &str| json!({"remote_key":id,"algorithm":"rsa3072","purpose":purpose,"offline":false});

    // Registration: no generation, wrong purpose/algorithm or foreign scope; all 404/422.
    assert_eq!(
        json_as(
            &f,
            &create,
            &custodian,
            json!({"algorithm":"rsa3072","purpose":"test","offline":false})
        )
        .await
        .0,
        422
    );
    assert_eq!(
        json_as(&f, &create, &custodian, register(test_id, "release"))
            .await
            .0,
        404
    );
    assert_eq!(
        json_as(
            &f,
            &create,
            &custodian,
            json!({"remote_key":test_id,"algorithm":"p256","purpose":"test","offline":false})
        )
        .await
        .0,
        404
    );
    let other = f
        .store
        .tenant(org)
        .create_project("fixture", "other")
        .await
        .unwrap();
    assert_eq!(
        json_as(
            &f,
            &format!("/v1/orgs/{org}/projects/{other}/keys"),
            &custodian,
            register(test_id, "test")
        )
        .await
        .0,
        404
    );
    let result = json_as(&f, &create, &custodian, register(test_id, "test")).await;
    assert_eq!(result.0, 201, "{}", result.2);
    let key: KeyRecord = serde_json::from_str(&result.2).unwrap();
    assert_eq!(key.trust, TrustTier::ExternalCa);
    assert_eq!(key.anchor.as_deref(), Some("azure-root"));
    assert!(key.public_key.is_empty() && key.chain.is_empty());
    assert_eq!(
        json_as(&f, &create, &custodian, register(test_id, "test"))
            .await
            .0,
        409
    );
    // A binding whose pinned root is not a configured external-ca anchor stays untrusted
    // and can never activate for release.
    let result = json_as(&f, &create, &custodian, register(untrusted_id, "release")).await;
    assert_eq!(result.0, 201);
    let untrusted: KeyRecord = serde_json::from_str(&result.2).unwrap();
    assert_eq!(untrusted.trust, TrustTier::Untrusted);
    let mutate = |id: Uuid, op: &str| format!("/v1/orgs/{org}/keys/{id}/{op}");
    assert_eq!(
        json_as(&f, &mutate(untrusted_id, "activate"), &custodian, json!({}))
            .await
            .0,
        409
    );
    // No CSR or chain import for a rotating key.
    assert_eq!(
        json_as(
            &f,
            &mutate(test_id, "csr"),
            &custodian,
            json!({"subject":"CN=x"})
        )
        .await
        .0,
        422
    );
    assert_eq!(
        json_as(
            &f,
            &mutate(test_id, "certificate"),
            &custodian,
            json!({"chain":[mock.der("day0")]})
        )
        .await
        .0,
        422
    );
    assert_eq!(
        json_as(&f, &mutate(test_id, "activate"), &custodian, json!({}))
            .await
            .0,
        200
    );
    assert_eq!(
        mock.count("sign", "POST"),
        0,
        "registration signed something"
    );

    // Policy creation rejects unsupported combinations.
    let policies = format!("/v1/orgs/{org}/projects/{project}/policies");
    let policy_input = json!({"name":"azure","key":test_id,"purpose":"test","claims":{},"algorithms":["rsa3072"],"timestamp":"disabled"});
    for (field, value) in [
        ("algorithms", json!(["rsa3072", "p256"])),
        ("attestation", json!(true)),
    ] {
        let mut bad = policy_input.clone();
        bad[field] = value;
        bad["name"] = json!(format!("bad-{field}"));
        assert_eq!(json_as(&f, &policies, &admin, bad).await.0, 422, "{field}");
    }
    let result = json_as(&f, &policies, &admin, policy_input).await;
    assert_eq!(result.0, 201);
    let policy: Policy = serde_json::from_str(&result.2).unwrap();

    use sha2::{Digest, Sha256};
    let d = mock.dir.path();
    let artifact = b"Artifact Signing fixture stays on the build host";
    std::fs::write(d.join("artifact.bin"), artifact).unwrap();
    let digest = Sha256::digest(artifact).to_vec();
    std::fs::write(d.join("digest"), &digest).unwrap();
    let submit = format!("/v1/orgs/{org}/projects/{project}/sign-requests");
    let submission = |policy: Uuid, format: &str| json!({"request_id":Uuid::new_v4(),"policy":policy,"digest_alg":"sha256","digest":digest,"artifact_name":"azure-fixture","format":format});
    macro_rules! sign {
        ($format:expr) => {
            submit_one(&f, &submit, &submitter, submission(policy.id, $format)).await
        };
    }
    let openssl = |args: &[&str]| {
        let out = std::process::Command::new("openssl")
            .current_dir(d)
            .args(args)
            .output()
            .unwrap();
        out.status.success()
    };
    let leaf_public = |request: &SignRequest, name: &str| {
        let leaf = request
            .remote
            .as_ref()
            .unwrap()
            .certificate
            .clone()
            .unwrap();
        std::fs::write(d.join(format!("{name}.der")), &leaf).unwrap();
        assert!(openssl(&[
            "x509",
            "-inform",
            "DER",
            "-in",
            &format!("{name}.der"),
            "-pubkey",
            "-noout",
            "-out",
            &format!("{name}-public.pem")
        ]));
        leaf
    };
    let raw_verifies = |signature: &[u8], public: &str| {
        std::fs::write(d.join("signature"), signature).unwrap();
        openssl(&[
            "pkeyutl",
            "-verify",
            "-pubin",
            "-inkey",
            public,
            "-sigfile",
            "signature",
            "-in",
            "digest",
            "-pkeyopt",
            "digest:sha256",
        ])
    };
    let polls_before = mock.count("sign", "GET");

    // Success: raw, verified independently by OpenSSL against the recorded leaf.
    let (id, result) = sign!("raw");
    assert_eq!(result.0, 201, "{}", result.2);
    let signed: SignRequest = serde_json::from_str(&result.2).unwrap();
    assert_eq!(signed.state, RequestState::Signed);
    let leaf0 = leaf_public(&signed, "leaf0");
    assert_eq!(leaf0, mock.der("day0"));
    assert!(raw_verifies(
        signed.output.as_ref().unwrap(),
        "leaf0-public.pem"
    ));
    let operation = signed
        .remote
        .as_ref()
        .unwrap()
        .operation_id
        .clone()
        .unwrap();
    let entry = audit_entry(&f, org, id, "request.signed").await;
    assert_eq!(entry.details["remote"]["operation_id"], json!(operation));
    let fingerprint: String = Sha256::digest(&leaf0)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    assert_eq!(
        entry.details["remote"]["certificate_sha256"],
        json!(fingerprint)
    );
    assert!(
        mock.count("sign", "GET") > polls_before,
        "result was not polled"
    );
    // Exactly one IMDS call with Metadata header and client_id; never an Authorization header.
    let imds: Vec<Value> = mock
        .events()
        .into_iter()
        .filter(|e| e["server"] == "imds")
        .collect();
    assert_eq!(imds.len(), 1);
    assert_eq!(imds[0]["metadata"], "true");
    assert_eq!(imds[0]["authorization"], false);
    assert_eq!(imds[0]["client_id"], json!(Uuid::nil().to_string()));

    // Success: detached CMS built from the returned chain; OpenSSL verifies to the pinned root.
    let (_, result) = sign!("cms");
    assert_eq!(result.0, 201, "{}", result.2);
    let signed: SignRequest = serde_json::from_str(&result.2).unwrap();
    std::fs::write(d.join("artifact.cms"), signed.output.as_ref().unwrap()).unwrap();
    assert!(openssl(&[
        "cms",
        "-verify",
        "-binary",
        "-inform",
        "DER",
        "-in",
        "artifact.cms",
        "-content",
        "artifact.bin",
        "-CAfile",
        "root.pem",
        "-purpose",
        "any",
        "-out",
        "verified"
    ]));
    assert!(!openssl(&[
        "cms",
        "-verify",
        "-binary",
        "-inform",
        "DER",
        "-in",
        "artifact.cms",
        "-content",
        "digest",
        "-CAfile",
        "root.pem",
        "-purpose",
        "any",
        "-out",
        "verified"
    ]));
    assert!(!openssl(&[
        "cms",
        "-verify",
        "-binary",
        "-inform",
        "DER",
        "-in",
        "artifact.cms",
        "-content",
        "artifact.bin",
        "-CAfile",
        "wrong-root.pem",
        "-purpose",
        "any",
        "-out",
        "verified"
    ]));
    // Cached token: still one IMDS call.
    assert_eq!(mock.count("imds", "GET"), 1);

    // Daily rotation: the next day's key and leaf are accepted and recorded.
    mock.set("day", "day1");
    let (_, result) = sign!("raw");
    assert_eq!(result.0, 201, "{}", result.2);
    let rotated: SignRequest = serde_json::from_str(&result.2).unwrap();
    let leaf1 = leaf_public(&rotated, "leaf1");
    assert_eq!(leaf1, mock.der("day1"));
    assert_ne!(leaf1, leaf0);
    assert!(raw_verifies(
        rotated.output.as_ref().unwrap(),
        "leaf1-public.pem"
    ));
    assert!(!raw_verifies(
        rotated.output.as_ref().unwrap(),
        "leaf0-public.pem"
    ));
    // Alternative bundle encodings observed in clients are accepted.
    for mode in ["pem", "der-concat"] {
        mock.set("mode", mode);
        assert_eq!(sign!("raw").1 .0, 201, "{mode}");
    }

    // Every failure: 502, no output in HTTP or persistence, failed request, exactly one POST
    // (no automatic retry), operation ID audited whenever one was received.
    for (mode, has_operation) in [
        ("wrong-anchor", true),
        ("other-profile", true),
        ("no-codesigning", true),
        ("expired", true),
        ("corrupt-signature", true),
        ("wrong-digest", true),
        ("malformed", true),
        ("timeout", true),
        ("failed", true),
        ("wrong-operation", true),
        ("poll-redirect", true),
        ("poll-drop", true),
        ("unauthorized", false),
        ("forbidden", false),
        ("redirect", false),
        ("drop", false),
    ] {
        mock.set("mode", mode);
        let posts = mock.count("sign", "POST");
        let (id, result) = sign!("raw");
        assert_eq!(result.0, 502, "{mode}: {}", result.2);
        assert!(!result.2.contains("output"), "{mode}");
        assert_eq!(mock.count("sign", "POST"), posts + 1, "{mode}: retried");
        let failed = f.store.tenant(org).sign_request(id).await.unwrap().unwrap();
        assert_eq!(failed.state, RequestState::Failed, "{mode}");
        assert!(
            failed.output.is_none() && failed.timestamp.is_none(),
            "{mode}"
        );
        let remote = failed.remote.unwrap();
        assert!(remote.certificate.is_none(), "{mode}");
        assert_eq!(remote.operation_id.is_some(), has_operation, "{mode}");
        let entry = audit_entry(&f, org, id, "request.failed").await;
        assert_eq!(
            entry.details["remote"]["operation_id"],
            json!(remote.operation_id),
            "{mode}"
        );
    }
    // A 401 discards the cached token; the next request fetches a new one.
    mock.set("mode", "unauthorized");
    assert_eq!(sign!("raw").1 .0, 502);
    mock.set("mode", "pass");
    let fetched = mock.count("imds", "GET");
    assert_eq!(sign!("raw").1 .0, 201);
    assert_eq!(mock.count("imds", "GET"), fetched + 1);

    // Token expiry: server-side revocation fails the in-flight request (no retry); the cache is
    // dropped and the next request succeeds with a fresh token.
    mock.set("revoke", "1");
    let posts = mock.count("sign", "POST");
    assert_eq!(sign!("raw").1 .0, 502);
    assert_eq!(mock.count("sign", "POST"), posts + 1);
    assert_eq!(sign!("raw").1 .0, 201);
    // A token inside the refresh margin is refused rather than used; IMDS redirects and errors
    // fail closed without contacting the signing service.
    for mode in ["short", "redirect", "error"] {
        mock.set("revoke", "1");
        mock.set("mode", "unauthorized");
        assert_eq!(sign!("raw").1 .0, 502);
        mock.set("mode", "pass");
        mock.set("imds_mode", mode);
        let posts = mock.count("sign", "POST");
        assert_eq!(sign!("raw").1 .0, 502, "imds {mode}");
        assert_eq!(
            mock.count("sign", "POST"),
            posts,
            "imds {mode}: signed without a token"
        );
    }
    mock.set("imds_mode", "pass");
    assert!(!mock.events().iter().any(|e| e["path"] == "/redirected"));

    // Release: allowed in production mode with an external-ca anchor; approval path unchanged.
    let result = json_as(&f, &create, &custodian, register(release_id, "release")).await;
    assert_eq!(result.0, 201);
    assert_eq!(
        json_as(&f, &mutate(release_id, "activate"), &custodian, json!({}))
            .await
            .0,
        200
    );
    let release_claims = json!({"repository":"acme/app","ref":"refs/heads/main","environment":"release","ref_protected":"true"});
    let result = json_as(&f, &policies, &admin, json!({"name":"azure-release","key":release_id,"purpose":"release","claims":release_claims,"algorithms":["rsa3072"],"timestamp":"disabled"})).await;
    assert_eq!(result.0, 201, "{}", result.2);
    // In lab mode the same release registration is refused.
    let lab = application(AppState {
        rate_limit: Default::default(),
        gates: Default::default(),
        notifications: Default::default(),
        tsa: None,
        keys: Some(f.keys.clone()),
        store: f.store.clone(),
        mode: Mode::Lab,
        identity: Some(f.identity.clone()),
    });
    let r = request_at(
        &lab,
        "POST",
        &create,
        Some(&custodian.0),
        None,
        Some(&custodian.1),
        register(release_id, "release"),
    )
    .await;
    assert_eq!(r.0, 422);
    // A lab-labelled instance never reports production readiness labels.
    let lab_backend = tokio::task::spawn_blocking({
        let (mock, bindings) = (mock.clone(), bindings());
        move || mock.backend(bindings, true).is_lab()
    })
    .await
    .unwrap();
    assert!(lab_backend);

    // Disable stops Brigalow authority with no remote call.
    assert_eq!(
        json_as(&f, &mutate(test_id, "disable"), &custodian, json!({}))
            .await
            .0,
        200
    );
    let posts = mock.count("sign", "POST");
    assert_eq!(sign!("raw").1 .0, 403);
    assert_eq!(mock.count("sign", "POST"), posts);

    // Digest-only transport and no credential in any public observation.
    for event in mock.events() {
        if event["server"] == "sign" && event["method"] == "POST" {
            assert!(event["size"].as_u64().unwrap() < 256);
            assert_eq!(event["fields"], json!(["digest", "signatureAlgorithm"]));
            assert_eq!(event["algorithm"], "RS256");
        }
    }
    f.store.close().await;
    f.admin.close().await;
}
