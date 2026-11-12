use sqlx::{
    migrate::{Migration, MigrationType, Migrator},
    SqlSafeStr,
};
use std::sync::LazyLock;

// Embedded SQL retains SQLx's checksum, transaction, locking and applied-version checks.
pub static MIGRATOR: LazyLock<Migrator> = LazyLock::new(|| {
    Migrator::with_migrations(vec![
        Migration::new(
            9,
            "schema readiness".into(),
            MigrationType::Simple,
            include_str!("../migrations/0009_schema_readiness.sql").into_sql_str(),
            false,
        ),
        Migration::new(
            1,
            "foundations".into(),
            MigrationType::Simple,
            include_str!("../migrations/0001_foundations.sql").into_sql_str(),
            false,
        ),
        Migration::new(
            2,
            "identity".into(),
            MigrationType::Simple,
            include_str!("../migrations/0002_identity.sql").into_sql_str(),
            false,
        ),
        Migration::new(
            3,
            "keys".into(),
            MigrationType::Simple,
            include_str!("../migrations/0003_keys.sql").into_sql_str(),
            false,
        ),
        Migration::new(
            4,
            "signing".into(),
            MigrationType::Simple,
            include_str!("../migrations/0004_signing.sql").into_sql_str(),
            false,
        ),
        Migration::new(
            5,
            "approvals windows".into(),
            MigrationType::Simple,
            include_str!("../migrations/0005_approvals_windows.sql").into_sql_str(),
            false,
        ),
        Migration::new(
            6,
            "private ca".into(),
            MigrationType::Simple,
            include_str!("../migrations/0006_private_ca.sql").into_sql_str(),
            false,
        ),
        Migration::new(
            7,
            "rate limits".into(),
            MigrationType::Simple,
            include_str!("../migrations/0007_rate_limits.sql").into_sql_str(),
            false,
        ),
        Migration::new(
            8,
            "audit checkpoints".into(),
            MigrationType::Simple,
            include_str!("../migrations/0008_audit_checkpoints.sql").into_sql_str(),
            false,
        ),
        Migration::new(
            10,
            "pending logins".into(),
            MigrationType::Simple,
            include_str!("../migrations/0010_pending_logins.sql").into_sql_str(),
            false,
        ),
    ])
});

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn embedded_migrations_match_sqlx_directory_resolution() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("migrations");
        let from_disk = Migrator::new(path.as_path()).await.unwrap();
        let embedded: Vec<_> = MIGRATOR.iter().collect();
        let disk: Vec<_> = from_disk.iter().collect();
        assert_eq!(
            embedded.len(),
            disk.len(),
            "new migrations must be embedded"
        );
        for (a, b) in embedded.into_iter().zip(disk) {
            assert_eq!(a.version, b.version);
            assert_eq!(a.description, b.description);
            assert_eq!(a.migration_type, b.migration_type);
            assert_eq!(a.sql.as_str(), b.sql.as_str());
            assert_eq!(a.checksum, b.checksum);
            assert_eq!(a.no_tx, b.no_tx);
        }
    }
}
