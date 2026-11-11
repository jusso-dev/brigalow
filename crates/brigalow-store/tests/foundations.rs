#![cfg(feature = "integration")]
use brigalow_core::audit::Verifier;
use brigalow_store::{ObjectKind, Store, MIGRATOR};
use sqlx::{postgres::PgConnectOptions, ConnectOptions, PgPool};
use uuid::Uuid;

fn options(user: &str, variable: &str) -> PgConnectOptions {
    let secret =
        std::fs::read_to_string(std::env::var(variable).expect("run scripts/e2e.sh")).unwrap();
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
        .password(&secret)
        .disable_statement_logging()
}

#[tokio::test]
async fn at_ten_01_store_isolation_and_atomic_audit() {
    let admin_options = options("postgres", "BRIGALOW_TEST_ADMIN_PASSWORD_FILE");
    let admin = PgPool::connect_with(admin_options.clone()).await.unwrap();
    MIGRATOR.run(&admin).await.unwrap();
    let password =
        std::fs::read_to_string(std::env::var("BRIGALOW_TEST_APP_PASSWORD_FILE").unwrap()).unwrap();
    let sql: String = sqlx::query_scalar("SELECT format('CREATE ROLE brigalow_runtime LOGIN IN ROLE brigalow_app PASSWORD %L', $1::text)")
        .bind(&password).fetch_one(&admin).await.unwrap();
    sqlx::query(&sql)
        .execute(&admin)
        .await
        .map_err(|_| "cannot provision test login")
        .unwrap();
    let app_options = options("brigalow_runtime", "BRIGALOW_TEST_APP_PASSWORD_FILE");
    let store = Store::connect(app_options.clone()).await.unwrap();
    assert!(matches!(
        Store::connect(admin_options).await,
        Err(brigalow_store::Error::UnsafeRole)
    ));
    let a = Uuid::new_v4();
    let b = Uuid::new_v4();
    let mut fixture = Vec::new();
    for org in [a, b] {
        sqlx::query("INSERT INTO brigalow.organisations VALUES ($1,'test')")
            .bind(org)
            .execute(&admin)
            .await
            .unwrap();
        let tenant = store.tenant(org);
        let project = tenant.create_project("test", "project").await.unwrap();
        let key = Uuid::new_v4();
        let policy = Uuid::new_v4();
        let request = Uuid::new_v4();
        sqlx::query("INSERT INTO brigalow.signing_keys VALUES ($1,$2,$3)")
            .bind(org)
            .bind(key)
            .bind(project)
            .execute(&admin)
            .await
            .unwrap();
        sqlx::query("INSERT INTO brigalow.policies VALUES ($1,$2,$3,$4)")
            .bind(org)
            .bind(policy)
            .bind(project)
            .bind(key)
            .execute(&admin)
            .await
            .unwrap();
        sqlx::query("INSERT INTO brigalow.sign_requests VALUES ($1,$2,$3,$4)")
            .bind(org)
            .bind(request)
            .bind(project)
            .bind(policy)
            .execute(&admin)
            .await
            .unwrap();
        fixture.push([project, key, policy, request]);
    }
    // All object lookup kinds, both directions; repeat across pool reuse.
    for _ in 0..12 {
        for (index, org) in [a, b].into_iter().enumerate() {
            for (kind, id) in ObjectKind::ALL.into_iter().zip(fixture[index]) {
                assert_eq!(store.tenant(org).find(kind, id).await.unwrap(), Some(id));
                assert_eq!(
                    store
                        .tenant(if org == a { b } else { a })
                        .find(kind, id)
                        .await
                        .unwrap(),
                    None
                );
            }
        }
    }
    let app = PgPool::connect_with(app_options).await.unwrap();
    // RLS denies access without context, including when a query omits org_id.
    for table in [
        "organisations",
        "projects",
        "signing_keys",
        "policies",
        "sign_requests",
        "audit_entries",
    ] {
        let count: i64 = sqlx::query_scalar(&format!("SELECT count(*) FROM brigalow.{table}"))
            .fetch_one(&app)
            .await
            .unwrap();
        assert_eq!(count, 0);
    }
    let mut tx = app.begin().await.unwrap();
    sqlx::query("SELECT set_config('brigalow.org_id',$1,true)")
        .bind(a.to_string())
        .execute(&mut *tx)
        .await
        .unwrap();
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM brigalow.projects")
        .fetch_one(&mut *tx)
        .await
        .unwrap();
    assert_eq!(count, 1);
    assert!(
        sqlx::query("INSERT INTO brigalow.projects VALUES ($1,$2,'foreign')")
            .bind(b)
            .bind(Uuid::new_v4())
            .execute(&mut *tx)
            .await
            .is_err()
    );
    tx.rollback().await.unwrap();
    // Composite foreign keys prevent cross-tenant references, even for owner writes.
    assert!(
        sqlx::query("INSERT INTO brigalow.signing_keys VALUES ($1,$2,$3)")
            .bind(a)
            .bind(Uuid::new_v4())
            .bind(fixture[1][0])
            .execute(&admin)
            .await
            .is_err()
    );
    let grants: Vec<String> = sqlx::query_scalar("SELECT privilege_type FROM information_schema.role_table_grants WHERE grantee='brigalow_app' AND table_schema='brigalow' AND table_name='audit_entries' ORDER BY privilege_type").fetch_all(&admin).await.unwrap();
    assert_eq!(grants, vec!["INSERT", "SELECT"]);
    for sql in [
        "UPDATE brigalow.audit_entries SET seq=seq",
        "DELETE FROM brigalow.audit_entries",
        "TRUNCATE brigalow.audit_entries",
    ] {
        assert!(sqlx::query(sql).execute(&app).await.is_err());
    }
    let tenant = store.tenant(a);
    let before = tenant.audit_page(0, 1000).await.unwrap().len();
    assert!(tenant.create_project("test", "").await.is_err());
    assert_eq!(tenant.audit_page(0, 1000).await.unwrap().len(), before);
    assert!(tenant
        .record("test", "invalid", "test", serde_json::json!({"float":1.5}))
        .await
        .is_err());
    assert_eq!(tenant.audit_page(0, 1000).await.unwrap().len(), before);
    // Force audit insertion failure after the project INSERT: both must roll back.
    sqlx::query("REVOKE INSERT ON brigalow.audit_entries FROM brigalow_app")
        .execute(&admin)
        .await
        .unwrap();
    assert!(tenant
        .create_project("test", "must-rollback")
        .await
        .is_err());
    sqlx::query("GRANT INSERT ON brigalow.audit_entries TO brigalow_app")
        .execute(&admin)
        .await
        .unwrap();
    let count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM brigalow.projects WHERE name='must-rollback'")
            .fetch_one(&admin)
            .await
            .unwrap();
    assert_eq!(count, 0);
    // Concurrent first entries and later appends cannot fork either chain.
    let fresh = Uuid::new_v4();
    sqlx::query("INSERT INTO brigalow.organisations VALUES ($1,'concurrent')")
        .bind(fresh)
        .execute(&admin)
        .await
        .unwrap();
    let mut tasks = Vec::new();
    for i in 0..20 {
        let tenant = store.tenant(fresh);
        tasks.push(tokio::spawn(async move {
            tenant
                .create_project("test", &format!("project-{i}"))
                .await
                .unwrap()
        }));
    }
    for task in tasks {
        task.await.unwrap();
    }
    let mut verifier = Verifier::default();
    for entry in store.tenant(fresh).audit_page(0, 1000).await.unwrap() {
        verifier.push(&entry).unwrap();
    }
    assert_eq!(verifier.finish().unwrap(), 20);
    assert_eq!(store.tenant(b).audit_page(0, 1000).await.unwrap().len(), 1);
    assert!(store
        .tenant(Uuid::new_v4())
        .create_project("test", "missing")
        .await
        .is_err());
    store.close().await;
    app.close().await;
    admin.close().await;
}
