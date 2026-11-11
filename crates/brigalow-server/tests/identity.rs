#![cfg(feature = "integration")]
use axum::{
    body::Body,
    http::{HeaderMap, Request, StatusCode},
    Router,
};
use brigalow_core::rbac::{Role, Scope};
use brigalow_server::{
    application,
    auth::{self, Authority, HumanConfig, Identity, IdentityConfig, WorkloadRule},
    config::Mode,
    web::{OBJECT_ROUTES, TENANT_MUTATIONS},
    AppState,
};
use brigalow_store::Store;
use http_body_util::BodyExt;
use serde_json::{json, Value};
use sqlx::{
    postgres::{PgConnectOptions, PgSslMode},
    ConnectOptions, PgPool,
};
use std::{collections::BTreeMap, sync::Arc};
use tower::ServiceExt;
use uuid::Uuid;
struct Fixture {
    router: Router,
    store: Store,
    admin: PgPool,
    identity: Arc<Identity>,
    http: reqwest::Client,
    issuer: String,
    orgs: [Uuid; 2],
    objects: [[Uuid; 4]; 2],
}
async fn fixture() -> Fixture {
    let base = PgConnectOptions::new()
        .host("127.0.0.1")
        .port(
            std::env::var("BRIGALOW_TEST_DB_PORT")
                .expect("run scripts/e2e.sh")
                .parse()
                .unwrap(),
        )
        .database("brigalow")
        .ssl_mode(PgSslMode::VerifyFull)
        .ssl_root_cert(std::env::var("BRIGALOW_TEST_DB_CA_FILE").unwrap())
        .disable_statement_logging();
    let read = |name: &str| std::fs::read_to_string(std::env::var(name).unwrap()).unwrap();
    let admin = PgPool::connect_with(
        base.clone()
            .username("postgres")
            .password(&read("BRIGALOW_TEST_ADMIN_PASSWORD_FILE")),
    )
    .await
    .unwrap();
    let store = Store::connect(
        base.username("brigalow_runtime")
            .password(&read("BRIGALOW_TEST_APP_PASSWORD_FILE")),
    )
    .await
    .unwrap();
    let orgs = [Uuid::new_v4(), Uuid::new_v4()];
    let mut objects = [[Uuid::nil(); 4]; 2];
    for (i, org) in orgs.iter().enumerate() {
        sqlx::query("INSERT INTO brigalow.organisations VALUES ($1,'identity-test')")
            .bind(org)
            .execute(&admin)
            .await
            .unwrap();
        objects[i][0] = store
            .tenant(*org)
            .create_project("fixture", "project")
            .await
            .unwrap();
        for id in objects[i].iter_mut().skip(1) {
            *id = Uuid::new_v4();
        }
        sqlx::query("INSERT INTO brigalow.signing_keys (org_id,id,project_id) VALUES ($1,$2,$3)")
            .bind(org)
            .bind(objects[i][1])
            .bind(objects[i][0])
            .execute(&admin)
            .await
            .unwrap();
        sqlx::query("INSERT INTO brigalow.policies VALUES ($1,$2,$3,$4)")
            .bind(org)
            .bind(objects[i][2])
            .bind(objects[i][0])
            .bind(objects[i][1])
            .execute(&admin)
            .await
            .unwrap();
        sqlx::query("INSERT INTO brigalow.sign_requests VALUES ($1,$2,$3,$4)")
            .bind(org)
            .bind(objects[i][3])
            .bind(objects[i][0])
            .bind(objects[i][2])
            .execute(&admin)
            .await
            .unwrap();
    }
    let issuer = std::env::var("BRIGALOW_TEST_IDP_URL").unwrap();
    let mut authorities = Vec::new();
    for (i, org) in orgs.iter().enumerate() {
        for client in ["valid", "wrong-audience", "expired", "wrong-nonce"] {
            authorities.push(Authority {
                org_id: *org,
                name: client.into(),
                issuer: issuer.clone(),
                jwks_url: format!("{issuer}/jwks"),
                human: Some(HumanConfig {
                    client_id: client.into(),
                    authorization_url: format!("{issuer}/authorize"),
                    token_url: format!("{issuer}/token"),
                    group_roles: BTreeMap::from([("admins".into(), Role::OrgAdmin)]),
                }),
                workloads: if client == "valid" {
                    vec![WorkloadRule {
                        project: objects[i][0],
                        policy: objects[i][2],
                        claims: BTreeMap::from([
                            ("repository".into(), "acme/app".into()),
                            ("ref".into(), "refs/heads/main".into()),
                            ("environment".into(), "release".into()),
                            ("workflow".into(), "build".into()),
                        ]),
                    }]
                } else {
                    vec![]
                },
            });
        }
    }
    let identity = Identity::new(
        IdentityConfig {
            public_url: "https://brigalow.test".into(),
            ca_file: Some(std::env::var("BRIGALOW_TEST_DB_CA_FILE").unwrap().into()),
            authorities,
        },
        Mode::Lab,
    )
    .unwrap();
    let http = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .add_root_certificate(
            reqwest::Certificate::from_pem(
                &std::fs::read(std::env::var("BRIGALOW_TEST_DB_CA_FILE").unwrap()).unwrap(),
            )
            .unwrap(),
        )
        .build()
        .unwrap();
    let router = application(AppState {
        keys: Some(brigalow_server::keys::KeyService {
            backend: Arc::new(brigalow_crypto::software::Software::new(true).unwrap()),
            id: "test".into(),
            anchors: vec![],
        }),
        store: store.clone(),
        mode: Mode::Lab,
        identity: Some(identity.clone()),
    });
    Fixture {
        router,
        store,
        admin,
        identity,
        http,
        issuer,
        orgs,
        objects,
    }
}
async fn request(
    f: &Fixture,
    method: &str,
    path: &str,
    cookie: Option<&str>,
    bearer: Option<&str>,
    csrf: Option<&str>,
    body: Value,
) -> (StatusCode, HeaderMap, String) {
    let mut builder = Request::builder()
        .method(method)
        .uri(path)
        .header("origin", "https://brigalow.test")
        .header("content-type", "application/json");
    if let Some(c) = cookie {
        builder = builder.header("cookie", c);
    }
    if let Some(b) = bearer {
        builder = builder.header("authorization", format!("Bearer {b}"));
    }
    if let Some(c) = csrf {
        builder = builder.header("x-csrf-token", c);
    }
    let response = f
        .router
        .clone()
        .oneshot(builder.body(Body::from(body.to_string())).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    (status, headers, String::from_utf8(bytes.to_vec()).unwrap())
}
async fn begin(f: &Fixture, org: Uuid, provider: &str) -> (String, String, String) {
    let (status, h, _) = request(
        f,
        "GET",
        &format!("/auth/{org}/{provider}/login"),
        None,
        None,
        None,
        Value::Null,
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    let cookie = h["set-cookie"]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_owned();
    let response = f
        .http
        .get(h["location"].to_str().unwrap())
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 302);
    let url = url::Url::parse(response.headers()["location"].to_str().unwrap()).unwrap();
    let params: BTreeMap<_, _> = url.query_pairs().into_owned().collect();
    (cookie, params["state"].clone(), params["code"].clone())
}
async fn complete(
    f: &Fixture,
    org: Uuid,
    provider: &str,
    cookie: &str,
    state: &str,
    code: &str,
) -> (StatusCode, HeaderMap) {
    let form = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("state", state)
        .append_pair("code", code)
        .finish();
    let response = f
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/auth/{org}/{provider}/complete"))
                .header("cookie", cookie)
                .header("origin", "https://brigalow.test")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(form))
                .unwrap(),
        )
        .await
        .unwrap();
    (response.status(), response.headers().clone())
}
async fn login(f: &Fixture, org: Uuid) -> (String, String) {
    let (binding, state, code) = begin(f, org, "valid").await;
    let (status, h) = complete(f, org, "valid", &binding, &state, &code).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    let cookie = h
        .get_all("set-cookie")
        .iter()
        .map(|h| h.to_str().unwrap())
        .find(|v| v.starts_with("__Host-brigalow="))
        .unwrap();
    for attribute in ["Secure", "HttpOnly", "SameSite=Strict", "Path=/"] {
        assert!(cookie.contains(attribute));
    }
    let cookie = cookie.split(';').next().unwrap().to_owned();
    let (status, _, body) = request(
        f,
        "GET",
        &format!("/orgs/{org}"),
        Some(&cookie),
        None,
        None,
        Value::Null,
    )
    .await;
    assert_eq!(status, 200);
    let csrf = body
        .split("name=\"csrf\" value=\"")
        .nth(1)
        .unwrap()
        .split('"')
        .next()
        .unwrap()
        .to_owned();
    (cookie, csrf)
}
#[tokio::test]
async fn at_id_01_pkce_nonce_groups_and_one_use_browser_bound_login() {
    let f = fixture().await;
    let org = f.orgs[0];
    let (binding, state, code) = begin(&f, org, "valid").await;
    assert_eq!(
        complete(
            &f,
            org,
            "valid",
            "__Host-brigalow-login=wrong",
            &state,
            &code
        )
        .await
        .0,
        401
    );
    assert_eq!(
        complete(&f, org, "valid", &binding, &state, &code).await.0,
        303
    );
    assert_eq!(
        complete(&f, org, "valid", &binding, &state, &code).await.0,
        401
    );
    for provider in ["wrong-audience", "expired", "wrong-nonce"] {
        let (binding, state, code) = begin(&f, org, provider).await;
        assert_eq!(
            complete(&f, org, provider, &binding, &state, &code).await.0,
            401
        );
    }
    let attempt = f.identity.login(org, "valid").await.unwrap();
    let response = f.http.get(attempt.url).send().await.unwrap();
    let url = url::Url::parse(response.headers()["location"].to_str().unwrap()).unwrap();
    let query: BTreeMap<_, _> = url.query_pairs().into_owned().collect();
    let response = f
        .http
        .post(format!("{}/token", f.issuer))
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", query["code"].as_str()),
            ("client_id", "valid"),
            (
                "redirect_uri",
                &format!("https://brigalow.test/auth/{org}/valid/callback"),
            ),
            ("code_verifier", "wrong"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 400);
    // Group mapping confers administration; it does not confer submitter/approver authority.
    let (cookie, csrf) = login(&f, org).await;
    assert_eq!(
        request(
            &f,
            "POST",
            &format!("/v1/orgs/{org}/projects"),
            Some(&cookie),
            None,
            Some(&csrf),
            json!({"name":"group-mapped","request_id":Uuid::new_v4()})
        )
        .await
        .0,
        201
    );
}
async fn mint(f: &Fixture, claims: Value, bad: bool, alg: &str) -> String {
    let result: Value = f
        .http
        .post(format!("{}/mint", f.issuer))
        .json(&json!({"claims":claims,"bad":bad,"alg":alg}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    result["token"].as_str().unwrap().into()
}
#[tokio::test]
async fn at_id_02_workload_claims_and_at_id_03_expiry_rechecked() {
    let f = fixture().await;
    let org = f.orgs[0];
    let scope = Scope {
        project: f.objects[0][0],
        policy: f.objects[0][2],
    };
    let claims = json!({"aud":format!("brigalow:{org}"),"repository":"acme/app","ref":"refs/heads/main","environment":"release","workflow":"build"});
    let valid = mint(&f, claims.clone(), false, "RS256").await;
    assert!(f.identity.workload(org, &valid, &scope).await.is_ok());
    assert_eq!(
        request(
            &f,
            "GET",
            &format!("/v1/orgs/{org}/policies/{}", scope.policy),
            None,
            Some(&valid),
            None,
            Value::Null
        )
        .await
        .0,
        200
    );
    for (field, value) in [
        ("iss", json!("https://unknown.invalid")),
        ("aud", json!("wrong")),
        ("exp", json!(auth::now() - 1)),
        ("nbf", json!(auth::now() + 300)),
        ("repository", json!("other/app")),
        ("ref", json!("refs/heads/feature")),
        ("environment", json!("test")),
        ("workflow", json!("other")),
    ] {
        let mut invalid = claims.clone();
        invalid[field] = value;
        let token = mint(&f, invalid, false, "RS256").await;
        assert!(
            f.identity.workload(org, &token, &scope).await.is_err(),
            "accepted invalid {field}"
        );
    }
    for (bad, alg) in [(true, "RS256"), (false, "none")] {
        let token = mint(&f, claims.clone(), bad, alg).await;
        assert!(f.identity.workload(org, &token, &scope).await.is_err());
    }
    let mut short = claims;
    short["exp"] = json!(auth::now() + 2);
    let token = mint(&f, short, false, "RS256").await;
    assert!(f.identity.workload(org, &token, &scope).await.is_ok());
    tokio::time::sleep(std::time::Duration::from_secs(3)).await;
    assert!(f.identity.workload(org, &token, &scope).await.is_err());
}
#[tokio::test]
async fn at_ten_01_routes_at_web_01_csrf_xss_and_at_id_03_replay() {
    let f = fixture().await;
    let a = f.orgs[0];
    let b = f.orgs[1];
    let (cookie, csrf) = login(&f, a).await;
    for (i, (name, _)) in OBJECT_ROUTES.iter().enumerate() {
        assert_eq!(
            request(
                &f,
                "GET",
                &format!("/v1/orgs/{a}/{name}/{}", f.objects[0][i]),
                Some(&cookie),
                None,
                None,
                Value::Null
            )
            .await
            .0,
            200
        );
        for org in [a, b] {
            assert_eq!(
                request(
                    &f,
                    "GET",
                    &format!("/v1/orgs/{org}/{name}/{}", f.objects[1][i]),
                    Some(&cookie),
                    None,
                    None,
                    Value::Null
                )
                .await
                .0,
                404
            );
        }
    }
    for (method, path) in TENANT_MUTATIONS {
        let path = path
            .replace("{org}", &b.to_string())
            .replace("{id}", &Uuid::new_v4().to_string());
        let body = if path.ends_with("projects") {
            json!({"name":"foreign","request_id":Uuid::new_v4()})
        } else if method == "POST" {
            json!({"project":f.objects[1][0],"policy":f.objects[1][2],"expires_at":auth::now()+60})
        } else {
            Value::Null
        };
        assert_eq!(
            request(&f, method, &path, Some(&cookie), None, Some(&csrf), body)
                .await
                .0,
            404
        );
    }
    let path = format!("/v1/orgs/{a}/projects");
    let data = json!({"name":"<script>alert(1)</script>","request_id":Uuid::new_v4()});
    assert_eq!(
        request(&f, "POST", &path, Some(&cookie), None, None, data.clone())
            .await
            .0,
        403
    );
    assert_eq!(
        request(
            &f,
            "POST",
            &path,
            Some(&cookie),
            None,
            Some("wrong"),
            data.clone()
        )
        .await
        .0,
        403
    );
    let (status, _, body) = request(
        &f,
        "POST",
        &path,
        Some(&cookie),
        None,
        Some(&csrf),
        data.clone(),
    )
    .await;
    assert_eq!(status, 201);
    assert_eq!(
        request(&f, "POST", &path, Some(&cookie), None, Some(&csrf), data)
            .await
            .0,
        409
    );
    let id: Value = serde_json::from_str(&body).unwrap();
    let (status, h, body) = request(
        &f,
        "GET",
        &format!("/orgs/{a}/projects/{}", id["id"].as_str().unwrap()),
        Some(&cookie),
        None,
        None,
        Value::Null,
    )
    .await;
    assert_eq!(status, 200);
    assert!(!body.contains("<script>"));
    assert!(body.contains("&lt;script&gt;") || body.contains("&#60;script&#62;"));
    assert!(!h["content-security-policy"]
        .to_str()
        .unwrap()
        .contains("unsafe-inline"));
    assert_eq!(h["x-content-type-options"], "nosniff");
    // Every current ordinary form rejects a missing or incorrect CSRF token.
    for suffix in ["projects", "logout"] {
        let response = f
            .router
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/orgs/{a}/{suffix}"))
                    .header("cookie", &cookie)
                    .header("origin", "https://brigalow.test")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from(format!(
                        "csrf=wrong&name=test&request_id={}",
                        Uuid::new_v4()
                    )))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), 403);
    }
    // API tokens are scoped, expiring, revocable, and hashed at rest.
    let token_path = format!("/v1/orgs/{a}/tokens");
    let input =
        json!({"project":f.objects[0][0],"policy":f.objects[0][2],"expires_at":auth::now()+60});
    assert_eq!(
        request(
            &f,
            "POST",
            &token_path,
            Some(&cookie),
            None,
            None,
            input.clone()
        )
        .await
        .0,
        403
    );
    let (status, _, body) = request(
        &f,
        "POST",
        &token_path,
        Some(&cookie),
        None,
        Some(&csrf),
        input,
    )
    .await;
    assert_eq!(status, 201);
    let value: Value = serde_json::from_str(&body).unwrap();
    let token = value["token"].as_str().unwrap();
    let token_id = value["id"].as_str().unwrap();
    let stored: String = sqlx::query_scalar(
        "SELECT secret_hash FROM brigalow.credentials WHERE org_id=$1 AND id=$2",
    )
    .bind(a)
    .bind(token_id.parse::<Uuid>().unwrap())
    .fetch_one(&f.admin)
    .await
    .unwrap();
    assert_eq!(stored, auth::hash(token.split_once('.').unwrap().1));
    assert!(!stored.contains(token));
    assert_eq!(
        request(
            &f,
            "GET",
            &format!("/v1/orgs/{a}/policies/{}", f.objects[0][2]),
            None,
            Some(token),
            None,
            Value::Null
        )
        .await
        .0,
        200
    );
    assert_eq!(
        request(
            &f,
            "GET",
            &format!("/v1/orgs/{b}/policies/{}", f.objects[1][2]),
            None,
            Some(token),
            None,
            Value::Null
        )
        .await
        .0,
        404
    );
    assert_eq!(
        request(
            &f,
            "POST",
            &path,
            None,
            Some(token),
            None,
            json!({"name":"escalation","request_id":Uuid::new_v4()})
        )
        .await
        .0,
        403
    );
    let other_key = Uuid::new_v4();
    sqlx::query("INSERT INTO brigalow.signing_keys (org_id,id,project_id) VALUES ($1,$2,$3)")
        .bind(a)
        .bind(other_key)
        .bind(f.objects[0][0])
        .execute(&f.admin)
        .await
        .unwrap();
    assert_eq!(
        request(
            &f,
            "GET",
            &format!("/v1/orgs/{a}/keys/{other_key}"),
            None,
            Some(token),
            None,
            Value::Null
        )
        .await
        .0,
        404
    );
    assert_eq!(
        request(
            &f,
            "GET",
            &format!("/v1/orgs/{a}/keys/{}", f.objects[0][1]),
            None,
            Some(token),
            None,
            Value::Null
        )
        .await
        .0,
        200
    );
    sqlx::query("UPDATE brigalow.credentials SET expires_at=clock_timestamp()-interval '1 second' WHERE org_id=$1 AND id=$2").bind(a).bind(token_id.parse::<Uuid>().unwrap()).execute(&f.admin).await.unwrap();
    assert_eq!(
        request(
            &f,
            "GET",
            &format!("/v1/orgs/{a}/policies/{}", f.objects[0][2]),
            None,
            Some(token),
            None,
            Value::Null
        )
        .await
        .0,
        401
    );
    sqlx::query("UPDATE brigalow.credentials SET expires_at=clock_timestamp()+interval '1 minute' WHERE org_id=$1 AND id=$2").bind(a).bind(token_id.parse::<Uuid>().unwrap()).execute(&f.admin).await.unwrap();
    assert_eq!(
        request(
            &f,
            "DELETE",
            &format!("{token_path}/{token_id}"),
            Some(&cookie),
            None,
            Some(&csrf),
            Value::Null
        )
        .await
        .0,
        204
    );
    assert_eq!(
        request(
            &f,
            "GET",
            &format!("/v1/orgs/{a}/policies/{}", f.objects[0][2]),
            None,
            Some(token),
            None,
            Value::Null
        )
        .await
        .0,
        401
    );
    let principal = brigalow_core::rbac::Principal {
        org_id: a,
        actor: "test".into(),
        roles: vec![Role::Submitter],
        scope: Some(Scope {
            project: f.objects[0][0],
            policy: f.objects[0][2],
        }),
        human: false,
    };
    assert!(f
        .store
        .tenant(a)
        .issue_credential(
            &auth::hash(&auth::random_secret()),
            &principal,
            None,
            auth::now() - 1,
            "test"
        )
        .await
        .is_err());
}

#[tokio::test]
async fn key_lifecycle_custody_tenancy_and_csrf() {
    use brigalow_core::{keys::KeyRecord, rbac::Principal};
    use brigalow_server::keys::{CREATE, MUTATIONS};
    let f = fixture().await;
    let org = f.orgs[0];
    let project = f.objects[0][0];
    let secret = auth::random_secret();
    let csrf = auth::random_secret();
    let p = Principal {
        org_id: org,
        actor: "custodian".into(),
        roles: vec![Role::KeyCustodian],
        scope: None,
        human: true,
    };
    f.store
        .tenant(org)
        .issue_credential(
            &auth::hash(&secret),
            &p,
            Some(&csrf),
            auth::now() + 300,
            "fixture",
        )
        .await
        .unwrap();
    let cookie = format!("__Host-brigalow={org}.{secret}");
    let path = CREATE
        .replace("{org}", &org.to_string())
        .replace("{id}", &project.to_string());
    let body = json!({"algorithm":"p256","purpose":"test","offline":true});
    assert_eq!(
        request(&f, "POST", &path, Some(&cookie), None, None, body.clone())
            .await
            .0,
        StatusCode::FORBIDDEN
    );
    let other_path = CREATE
        .replace("{org}", &org.to_string())
        .replace("{id}", &f.objects[1][0].to_string());
    assert_eq!(
        request(
            &f,
            "POST",
            &other_path,
            Some(&cookie),
            None,
            Some(&csrf),
            body.clone()
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );
    let (status, _, response) = request(
        &f,
        "POST",
        &path,
        Some(&cookie),
        None,
        Some(&csrf),
        body.clone(),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let key: KeyRecord = serde_json::from_str(&response).unwrap();
    let id = key.key.id;
    assert_eq!(key.trust, brigalow_core::TrustTier::Lab);
    assert!(key.offline);
    let response: Value = serde_json::from_str(&response).unwrap();
    let fields: std::collections::BTreeSet<_> = response
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(
        fields,
        std::collections::BTreeSet::from([
            "key",
            "project",
            "backend",
            "state",
            "offline",
            "trust",
            "public_key",
            "chain",
            "revision",
            "anchor"
        ])
    );
    // Every registered lifecycle route rejects cross-tenant IDs and missing CSRF.
    for (name, _) in MUTATIONS {
        let route = format!("/v1/orgs/{org}/keys/{}/{name}", f.objects[1][1]);
        assert_eq!(
            request(
                &f,
                "POST",
                &route,
                Some(&cookie),
                None,
                Some(&csrf),
                json!({})
            )
            .await
            .0,
            StatusCode::NOT_FOUND
        );
        let route = format!("/v1/orgs/{org}/keys/{id}/{name}");
        assert_eq!(
            request(&f, "POST", &route, Some(&cookie), None, None, json!({}))
                .await
                .0,
            StatusCode::FORBIDDEN
        );
        assert!(!name.contains("export"));
    }
    let (admin, admin_csrf) = login(&f, org).await;
    assert_eq!(
        request(
            &f,
            "POST",
            &path,
            Some(&admin),
            None,
            Some(&admin_csrf),
            body
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    for (algorithm, purpose) in [("rsa2048", "test"), ("p256", "release")] {
        assert_eq!(
            request(
                &f,
                "POST",
                &path,
                Some(&cookie),
                None,
                Some(&csrf),
                json!({"algorithm":algorithm,"purpose":purpose,"offline":false})
            )
            .await
            .0,
            StatusCode::UNPROCESSABLE_ENTITY
        );
    }
    let keypath = format!("/v1/orgs/{org}/keys/{id}");
    assert_eq!(
        request(
            &f,
            "POST",
            &format!("{keypath}/csr"),
            Some(&cookie),
            None,
            Some(&csrf),
            json!({"subject":"CN=Test"})
        )
        .await
        .0,
        StatusCode::OK
    );
    assert_eq!(
        request(
            &f,
            "POST",
            &format!("{keypath}/certificate"),
            Some(&cookie),
            None,
            Some(&csrf),
            json!({"chain":[[0,1,2]]})
        )
        .await
        .0,
        StatusCode::UNPROCESSABLE_ENTITY
    );
    for action in ["activate", "disable", "retire"] {
        assert_eq!(
            request(
                &f,
                "POST",
                &format!("{keypath}/{action}"),
                Some(&cookie),
                None,
                Some(&csrf),
                json!({})
            )
            .await
            .0,
            StatusCode::OK
        );
    }
    assert_eq!(
        request(
            &f,
            "POST",
            &format!("{keypath}/activate"),
            Some(&cookie),
            None,
            Some(&csrf),
            json!({})
        )
        .await
        .0,
        StatusCode::CONFLICT
    );
    let events = f.store.tenant(org).audit_page(0, 1000).await.unwrap();
    for action in [
        "key.generated",
        "key.csr",
        "key.activated",
        "key.disabled",
        "key.retired",
    ] {
        assert!(events.iter().any(|e| e.action == action));
    }
    // A stale writer cannot overwrite a revocation.
    assert!(f
        .store
        .tenant(org)
        .update_key("stale", "key.activated", &key)
        .await
        .is_err());
    f.store.close().await;
    f.admin.close().await;
}
