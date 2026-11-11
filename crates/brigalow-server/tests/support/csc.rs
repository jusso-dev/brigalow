use super::*;
use brigalow_core::{
    keys::KeyRecord,
    policy::{Policy, RequestState, SignRequest},
};
use std::io::BufRead;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn at_pub_01_tool_csc_digest_only_fail_closed() {
    assert_eq!(
        std::env::consts::OS,
        "linux",
        "run disposable tools container"
    );
    let mut f = fixture().await;
    let org = f.orgs[0];
    let project = f.objects[0][0];
    let id = Uuid::new_v4();
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    let mut mock = ChildGuard(
        std::process::Command::new("python3")
            .arg(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../deploy/dev/test_csc.py"
            ))
            .arg(d)
            .stdout(std::process::Stdio::piped())
            .spawn()
            .unwrap(),
    );
    let mut port = String::new();
    std::io::BufReader::new(mock.0.stdout.take().unwrap())
        .read_line(&mut port)
        .unwrap();
    assert!(!port.trim().is_empty(), "mock failed to start");
    let url = format!("https://127.0.0.1:{}", port.trim());
    let text=format!("mode='lab'\nbackend='csc_mock'\n[csc_mock]\nurl='{url}'\ntls_ca_file='{}'\naccess_token_file='{}'\n[[csc_mock.bindings]]\nid='{id}'\norg='{org}'\nproject='{project}'\ncredential_id='mock-key'\ncertificate_file='{}'\n",
        std::env::var("BRIGALOW_TEST_DB_CA_FILE").unwrap(), d.join("token").display(),d.join("leaf.der").display());
    let load = |text: &str| {
        brigalow_server::config::Config::from_sources(text, |key| {
            Ok((key == "BRIGALOW_DB_PASSWORD").then(auth::random_secret))
        })
    };
    assert!(load(&text.replace("mode='lab'", "mode='production'")).is_err());
    // Startup refuses unpinned certificates and non-loopback addresses before sending credentials.
    for bad in [
        text.replace(&url, "https://example.invalid"),
        text.replace("leaf.der", "missing.der"),
    ] {
        let config = load(&bad).unwrap();
        assert!(
            tokio::task::spawn_blocking(move || config.key_backend().is_err())
                .await
                .unwrap()
        );
    }
    let wrong_pin = text.replace(
        &d.join("leaf.der").display().to_string(),
        &std::path::Path::new(&std::env::var("BRIGALOW_TEST_SECRETS").unwrap())
            .join("ca.der")
            .display()
            .to_string(),
    );
    let config = load(&wrong_pin).unwrap();
    assert!(
        tokio::task::spawn_blocking(move || config.key_backend().is_err())
            .await
            .unwrap()
    );
    let config = load(&text).unwrap();
    let backend = tokio::task::spawn_blocking(move || config.key_backend().unwrap().unwrap())
        .await
        .unwrap();
    f.keys = brigalow_server::keys::KeyService {
        backend,
        id: "csc-mock".into(),
        anchors: vec![],
    };
    f.router = application(AppState {
        rate_limit: Default::default(),
        gates: Default::default(),
        notifications: Default::default(),
        tsa: Some(f.tsa.clone()),
        keys: Some(f.keys.clone()),
        store: f.store.clone(),
        mode: Mode::Lab,
        identity: Some(f.identity.clone()),
    });
    let custodian = role_session(&f, "remote-custodian", vec![Role::KeyCustodian]).await;
    let admin = role_session(&f, "remote-admin", vec![Role::OrgAdmin]).await;
    let submitter = role_session(&f, "remote-submitter", vec![Role::Submitter]).await;
    let create = format!("/v1/orgs/{org}/projects/{project}/keys");
    let input = json!({"remote_key":id,"algorithm":"rsa3072","purpose":"test","offline":false});
    let other_project = f
        .store
        .tenant(org)
        .create_project("fixture", "other")
        .await
        .unwrap();
    assert_eq!(
        json_as(
            &f,
            &format!("/v1/orgs/{org}/projects/{other_project}/keys"),
            &custodian,
            input.clone()
        )
        .await
        .0,
        404
    );
    // Legitimate custodian in the other tenant cannot attach this body-supplied reference.
    f.orgs.swap(0, 1);
    let foreign = role_session(&f, "foreign-custodian", vec![Role::KeyCustodian]).await;
    f.orgs.swap(0, 1);
    assert_eq!(
        json_as(
            &f,
            &format!("/v1/orgs/{}/projects/{}/keys", f.orgs[1], f.objects[1][0]),
            &foreign,
            input.clone()
        )
        .await
        .0,
        404
    );
    let result = json_as(&f, &create, &custodian, input.clone()).await;
    assert_eq!(result.0, 201);
    let key: KeyRecord = serde_json::from_str(&result.2).unwrap();
    assert_eq!(key.trust, brigalow_core::TrustTier::Lab);
    assert_eq!(key.key.id, id);
    assert!(f
        .store
        .tenant(org)
        .audit_page(0, 100)
        .await
        .unwrap()
        .iter()
        .any(|e| e.action == "key.remote_registered" && e.subject == id.to_string()));
    assert_eq!(json_as(&f, &create, &custodian, input).await.0, 409);
    assert_eq!(
        json_as(
            &f,
            &format!("/v1/orgs/{org}/keys/{id}/activate"),
            &custodian,
            json!({})
        )
        .await
        .0,
        200
    );
    let policies = format!("/v1/orgs/{org}/projects/{project}/policies");
    let policy_input = json!({"name":"remote","key":id,"purpose":"test","claims":{},"algorithms":["rsa3072"],"timestamp":"disabled"});
    let result = json_as(&f, &policies, &admin, policy_input.clone()).await;
    assert_eq!(result.0, 201);
    let policy: Policy = serde_json::from_str(&result.2).unwrap();
    let mut deny_input = policy_input;
    deny_input["name"] = json!("denied");
    deny_input["claims"] = json!({"repository":"required"});
    let result = json_as(&f, &policies, &admin, deny_input).await;
    assert_eq!(result.0, 201);
    let denied: Policy = serde_json::from_str(&result.2).unwrap();
    let submit = format!("/v1/orgs/{org}/projects/{project}/sign-requests");
    use sha2::{Digest, Sha256};
    let artifact = b"CSC mock artifact remains on build host";
    let digest = Sha256::digest(artifact).to_vec();
    let submission = |policy| json!({"request_id":Uuid::new_v4(),"policy":policy,"digest_alg":"sha256","digest":digest,"artifact_name":"remote-fixture","format":"raw"});
    let events = || std::fs::read_to_string(d.join("events")).unwrap();
    let before = events();
    let result = json_as(&f, &submit, &submitter, submission(denied.id)).await;
    assert_eq!(result.0, 403);
    assert_eq!(events(), before, "policy denial contacted remote signer");
    let result = json_as(&f, &submit, &submitter, submission(policy.id)).await;
    assert_eq!(result.0, 201);
    let signed: SignRequest = serde_json::from_str(&result.2).unwrap();
    assert_eq!(signed.state, RequestState::Signed);
    std::fs::write(d.join("artifact"), artifact).unwrap();
    std::fs::write(d.join("signature"), signed.output.unwrap()).unwrap();
    assert!(std::process::Command::new("openssl")
        .current_dir(d)
        .args([
            "dgst",
            "-sha256",
            "-verify",
            "public.pem",
            "-signature",
            "signature",
            "artifact"
        ])
        .output()
        .unwrap()
        .status
        .success());
    for mode in [
        "denied",
        "expired",
        "expired-remote",
        "wrong-signature",
        "multiple",
        "redirect",
        "oversize",
    ] {
        std::fs::write(d.join("mode"), mode).unwrap();
        let input = submission(policy.id);
        let request_id = serde_json::from_value(input["request_id"].clone()).unwrap();
        let result = json_as(&f, &submit, &submitter, input).await;
        assert_eq!(result.0, 502, "{mode}");
        assert!(!result.2.contains("output"));
        let failed = f
            .store
            .tenant(org)
            .sign_request(request_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(failed.state, RequestState::Failed, "{mode}");
        assert!(failed.output.is_none());
    }
    let logs = events();
    assert!(!logs.contains("redirect-target"));
    assert!(!logs.contains(&std::fs::read_to_string(d.join("token")).unwrap()));
    use base64::Engine;
    for line in logs.lines() {
        let event: Value = serde_json::from_str(line).unwrap();
        assert!(event["size"].as_u64().unwrap() < 1024);
        for hash in event["hashes"].as_array().unwrap() {
            assert_eq!(
                base64::engine::general_purpose::STANDARD
                    .decode(hash.as_str().unwrap())
                    .unwrap(),
                digest
            );
        }
    }
    assert!(
        logs.contains("credentials/list")
            && logs.contains("credentials/info")
            && logs.contains("credentials/authorize")
            && logs.contains("signatures/signHash")
    );
    std::fs::write(d.join("mode"), "pass").unwrap();
    assert_eq!(
        json_as(
            &f,
            &format!("/v1/orgs/{org}/keys/{id}/disable"),
            &custodian,
            json!({})
        )
        .await
        .0,
        200
    );
    let before = events();
    assert_eq!(
        json_as(&f, &submit, &submitter, submission(policy.id))
            .await
            .0,
        403
    );
    assert_eq!(events(), before);
    f.store.close().await;
    f.admin.close().await;
}
