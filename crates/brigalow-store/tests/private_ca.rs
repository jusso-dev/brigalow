#![cfg(feature = "integration")]
use brigalow_store::{private_ca::CaStore, Store, MIGRATOR};
use sqlx::{
    postgres::{PgConnectOptions, PgSslMode},
    ConnectOptions, PgPool,
};
use uuid::Uuid;
fn options(user: &str, secret: &str) -> PgConnectOptions {
    PgConnectOptions::new()
        .host("127.0.0.1")
        .port(
            std::env::var("BRIGALOW_TEST_DB_PORT")
                .unwrap()
                .parse()
                .unwrap(),
        )
        .database("brigalow")
        .username(user)
        .password(secret)
        .ssl_mode(PgSslMode::VerifyFull)
        .ssl_root_cert(std::env::var("BRIGALOW_TEST_DB_CA_FILE").unwrap())
        .disable_statement_logging()
}
#[tokio::test]
async fn ca_ledger_separates_roles_reserves_once_and_rejects_stale_crls() {
    let admin_secret =
        std::fs::read_to_string(std::env::var("BRIGALOW_TEST_ADMIN_PASSWORD_FILE").unwrap())
            .unwrap();
    let secret =
        std::fs::read_to_string(std::env::var("BRIGALOW_TEST_APP_PASSWORD_FILE").unwrap()).unwrap();
    let admin = PgPool::connect_with(options("postgres", &admin_secret))
        .await
        .unwrap();
    MIGRATOR.run(&admin).await.unwrap();
    let user = format!("ca_test_{}", Uuid::new_v4().simple());
    let sql: String = sqlx::query_scalar(
        "SELECT format('CREATE ROLE %I LOGIN IN ROLE brigalow_ca PASSWORD %L',$1::text,$2::text)",
    )
    .bind(&user)
    .bind(&secret)
    .fetch_one(&admin)
    .await
    .unwrap();
    sqlx::query(&sql)
        .execute(&admin)
        .await
        .map_err(|_| "cannot create ephemeral CA login")
        .unwrap();
    let a = Uuid::new_v4();
    let b = Uuid::new_v4();
    for org in [a, b] {
        sqlx::query("INSERT INTO brigalow.organisations VALUES($1,'CA test')")
            .bind(org)
            .execute(&admin)
            .await
            .unwrap();
    }
    assert!(CaStore::connect(options("brigalow_runtime", &secret), a)
        .await
        .is_err());
    assert!(Store::connect(options(&user, &secret)).await.is_err());
    assert!(CaStore::connect(options("postgres", &admin_secret), a)
        .await
        .is_err());
    let ca = CaStore::connect(options(&user, &secret), a).await.unwrap();
    let other = CaStore::connect(options(&user, &secret), b).await.unwrap();
    let app = PgPool::connect_with(options("brigalow_runtime", &secret))
        .await
        .unwrap();
    for table in ["ca_profiles", "ca_leaves", "ca_crls"] {
        assert!(sqlx::query(&format!("SELECT * FROM brigalow.{table}"))
            .fetch_all(&app)
            .await
            .is_err());
    }
    let issuer = Uuid::new_v4();
    let profile = Uuid::new_v4();
    let record = serde_json::json!({"id":profile,"oid":"1.3.6.1.4.1.32473.1"});
    let mut tasks = vec![];
    for _ in 0..10 {
        let ca = ca.clone();
        let record = record.clone();
        tasks.push(tokio::spawn(async move {
            ca.reserve(issuer, profile, record, vec![1; 64]).await
        }));
    }
    let mut successes = vec![];
    for t in tasks {
        if let Ok(leaf) = t.await.unwrap() {
            successes.push(leaf);
        }
    }
    assert_eq!(successes.len(), 1);
    let leaf = &successes[0];
    assert!(other.leaf(profile, leaf.day).await.unwrap().is_none());
    assert!(ca
        .reserve(
            issuer,
            profile,
            serde_json::json!({"changed":true}),
            vec![1; 64]
        )
        .await
        .is_err());
    ca.finish(leaf, vec![vec![1; 100]]).await.unwrap();
    assert!(ca.finish(leaf, vec![vec![2; 100]]).await.is_err());
    let stale = ca.reserve_crl(issuer).await.unwrap();
    ca.revoke(profile, leaf.day).await.unwrap();
    assert!(ca.finish_crl(issuer, &stale, vec![1]).await.is_err());
    let fresh = ca.reserve_crl(issuer).await.unwrap();
    assert_eq!(fresh.revoked.len(), 1);
    ca.finish_crl(issuer, &fresh, vec![2]).await.unwrap();
    let interrupted = ca
        .reserve(issuer, Uuid::new_v4(), serde_json::json!({}), vec![3; 64])
        .await
        .unwrap();
    ca.revoke(interrupted.profile, interrupted.day)
        .await
        .unwrap();
    assert!(ca.finish(&interrupted, vec![vec![1; 100]]).await.is_err());
    let pool = PgPool::connect_with(options(&user, &secret)).await.unwrap();
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM brigalow.ca_leaves")
            .fetch_one(&pool)
            .await
            .unwrap(),
        0
    );
    assert!(sqlx::query("DELETE FROM brigalow.ca_leaves")
        .execute(&pool)
        .await
        .is_err());
    assert!(sqlx::query("UPDATE brigalow.ca_profiles SET record='{}'")
        .execute(&pool)
        .await
        .is_err());
    assert!(sqlx::query("UPDATE brigalow.audit_entries SET entry='{}'")
        .execute(&pool)
        .await
        .is_err());
    assert!(sqlx::query(
        "INSERT INTO brigalow.signing_keys(org_id,id,project_id) VALUES($1,$2,$3)"
    )
    .bind(a)
    .bind(Uuid::new_v4())
    .bind(Uuid::new_v4())
    .execute(&pool)
    .await
    .is_err());
    ca.close().await;
    other.close().await;
    pool.close().await;
    app.close().await;
    admin.close().await;
}
