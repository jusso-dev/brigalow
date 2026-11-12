#![cfg(feature = "integration")]
use brigalow_store::{admin::Admin, schema_current, Error, Store};
use sqlx::{
    postgres::{PgConnectOptions, PgSslMode},
    ConnectOptions, PgPool,
};
use uuid::Uuid;
fn options(owner: bool) -> PgConnectOptions {
    let password = std::fs::read_to_string(
        std::env::var(if owner {
            "BRIGALOW_TEST_ADMIN_PASSWORD_FILE"
        } else {
            "BRIGALOW_TEST_APP_PASSWORD_FILE"
        })
        .unwrap(),
    )
    .unwrap();
    PgConnectOptions::new()
        .host("127.0.0.1")
        .port(
            std::env::var("BRIGALOW_TEST_DB_PORT")
                .unwrap()
                .parse()
                .unwrap(),
        )
        .ssl_mode(PgSslMode::VerifyFull)
        .ssl_root_cert(std::env::var("BRIGALOW_TEST_DB_CA_FILE").unwrap())
        .database("brigalow")
        .username(if owner {
            "postgres"
        } else {
            "brigalow_runtime"
        })
        .password(&password)
        .disable_statement_logging()
}
#[tokio::test]
async fn at_ops_04_owner_bootstrap_and_schema_readiness() {
    let admin = Admin::connect(options(true)).await.unwrap();
    admin.migrate().await.unwrap();
    admin.migrate().await.unwrap();
    let org = Uuid::new_v4();
    assert!(admin.create_org(org, "bootstrap test").await.unwrap());
    assert!(!admin.create_org(org, "bootstrap test").await.unwrap());
    assert!(matches!(
        admin.create_org(org, "rename forbidden").await,
        Err(Error::Conflict)
    ));
    let owner = PgPool::connect_with(options(true)).await.unwrap();
    // Tests run independently of foundations.rs; create the restricted login once if needed.
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM pg_roles WHERE rolname='brigalow_runtime')",
    )
    .fetch_one(&owner)
    .await
    .unwrap();
    if !exists {
        let password =
            std::fs::read_to_string(std::env::var("BRIGALOW_TEST_APP_PASSWORD_FILE").unwrap())
                .unwrap();
        let sql: String = sqlx::query_scalar("SELECT format('CREATE ROLE brigalow_runtime LOGIN IN ROLE brigalow_app PASSWORD %L', $1::text)").bind(password).fetch_one(&owner).await.unwrap();
        sqlx::query(sqlx::AssertSqlSafe(sql))
            .execute(&owner)
            .await
            .map_err(|_| "test role creation failed")
            .unwrap();
    }
    assert!(matches!(
        Admin::connect(options(false)).await,
        Err(Error::UnsafeRole)
    ));
    let runtime = Store::connect(options(false)).await.unwrap();
    let events = runtime.tenant(org).audit_page(0, 10).await.unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].action, "organisation.created");
    let mut tx = owner.begin().await.unwrap();
    assert!(schema_current(&mut tx).await.unwrap());
    sqlx::query("DELETE FROM public._sqlx_migrations WHERE version=9")
        .execute(&mut *tx)
        .await
        .unwrap();
    assert!(!schema_current(&mut tx).await.unwrap());
    tx.rollback().await.unwrap();
    let mut tx = owner.begin().await.unwrap();
    sqlx::query("UPDATE public._sqlx_migrations SET checksum='bad'::bytea WHERE version=9")
        .execute(&mut *tx)
        .await
        .unwrap();
    assert!(!schema_current(&mut tx).await.unwrap());
    tx.rollback().await.unwrap();
    let pool = PgPool::connect_with(options(false)).await.unwrap();
    assert!(sqlx::query("DELETE FROM public._sqlx_migrations")
        .execute(&pool)
        .await
        .is_err());
    pool.close().await;
    runtime.close().await;
    admin.close().await;
    owner.close().await;
}
