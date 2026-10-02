use super::*;

#[test]
fn only_typed_query_and_pool_failures_are_unavailable() {
    use diesel::ConnectionError;
    assert!(
        signing_query(Error::DatabaseError(
            DatabaseErrorKind::ClosedConnection,
            Box::new("fixture".to_owned())
        ))
        .is::<nazo_key_management::SigningKeyRepositoryUnavailable>()
    );
    assert!(
        migration_query(Error::DatabaseError(
            DatabaseErrorKind::SerializationFailure,
            Box::new("fixture".to_owned())
        ))
        .context("outer context")
        .is::<nazo_persistence::MigrationUnavailable>()
    );
    for kind in [
        DatabaseErrorKind::UniqueViolation,
        DatabaseErrorKind::ForeignKeyViolation,
        DatabaseErrorKind::Unknown,
    ] {
        let error = signing_query(Error::DatabaseError(
            kind,
            Box::new("connection closed timeout serialization".to_owned()),
        ));
        assert!(!error.is::<nazo_key_management::SigningKeyRepositoryUnavailable>());
    }
    let closed: anyhow::Error = PoolError::Closed.into();
    assert!(
        signing_checkout(closed.context("checkout"))
            .is::<nazo_key_management::SigningKeyRepositoryUnavailable>()
    );
    let opaque: anyhow::Error = PoolError::Backend(BackendError::ConnectionError(
        ConnectionError::BadConnection("temporarily unavailable".to_owned()),
    ))
    .into();
    assert!(!signing_checkout(opaque).is::<nazo_key_management::SigningKeyRepositoryUnavailable>());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn actual_migration_harness_preserves_wrapped_query_type() {
    use diesel_async::{
        AsyncConnection, AsyncMigrationHarness, AsyncPgConnection, SimpleAsyncConnection,
    };
    use diesel_migrations::{FileBasedMigrations, MigrationHarness};
    let url = std::env::var("NAZO_TEST_DATABASE_URL")
        .or_else(|_| std::env::var("DATABASE_URL"))
        .ok();
    let Some(url) = url else {
        assert!(
            std::env::var_os("CI").is_none(),
            "CI typed migration regression requires PostgreSQL"
        );
        return;
    };
    for code in ["40001", "42501", "23505"] {
        let tag = uuid::Uuid::now_v7().simple().to_string();
        let directory = std::env::temp_dir().join(format!("migration-type-{tag}"));
        let migration = directory.join("20261002000400_fixture_error");
        std::fs::create_dir_all(&migration).unwrap();
        std::fs::write(
            migration.join("up.sql"),
            format!("DO $$ BEGIN RAISE EXCEPTION 'fixture' USING ERRCODE='{code}'; END $$;"),
        )
        .unwrap();
        std::fs::write(migration.join("down.sql"), "SELECT 1;").unwrap();
        let schema = format!("migration_type_{tag}");
        let mut connection = AsyncPgConnection::establish(&url).await.unwrap();
        connection
            .batch_execute(&format!(
                "CREATE SCHEMA {schema}; SET search_path TO {schema}"
            ))
            .await
            .unwrap();
        let mut harness = AsyncMigrationHarness::new(connection);
        let error = harness
            .run_pending_migrations(FileBasedMigrations::from_path(&directory).unwrap())
            .unwrap_err();
        assert!(
            error.downcast_ref::<Error>().is_none(),
            "pinned harness boxes a private wrapper"
        );
        let classified = migration_harness(error).context("outer migration context");
        assert!(
            !classified.is::<nazo_persistence::MigrationUnavailable>(),
            "opaque migration wrappers are not guessed from their text"
        );
        assert!(
            classified.chain().count() >= 2,
            "boxed harness source remains attached to outer context"
        );
        let mut connection = harness.into_inner();
        connection
            .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
            .await
            .unwrap();
        std::fs::remove_dir_all(directory).unwrap();
    }
}

#[test]
fn unlock_failure_preserves_primary_error_category() {
    let primary = migration_query(Error::DatabaseError(
        DatabaseErrorKind::UniqueViolation,
        Box::new("fixture".to_owned()),
    ));
    let cleanup = migration_query(Error::DatabaseError(
        DatabaseErrorKind::ClosedConnection,
        Box::new("fixture".to_owned()),
    ));
    let combined = migration_outcome(Err(primary), Err(cleanup)).unwrap_err();
    assert!(!combined.is::<nazo_persistence::MigrationUnavailable>());
    assert!(combined.is::<Error>());
    let primary = migration_query(Error::DatabaseError(
        DatabaseErrorKind::ClosedConnection,
        Box::new("fixture".to_owned()),
    ));
    let cleanup = anyhow::anyhow!("unlock permanent fixture");
    assert!(
        migration_outcome(Err(primary), Err(cleanup))
            .unwrap_err()
            .is::<nazo_persistence::MigrationUnavailable>()
    );
    assert!(
        migration_outcome(
            Ok(true),
            Err(migration_query(Error::DatabaseError(
                DatabaseErrorKind::ClosedConnection,
                Box::new("fixture".to_owned())
            )))
        )
        .unwrap_err()
        .is::<nazo_persistence::MigrationUnavailable>()
    );
}

#[test]
fn direct_boxed_public_migration_errors_keep_typed_retry_and_original_cause() {
    for (kind, retryable) in [
        (DatabaseErrorKind::ClosedConnection, true),
        (DatabaseErrorKind::SerializationFailure, true),
        (DatabaseErrorKind::UniqueViolation, false),
        (DatabaseErrorKind::Unknown, false),
    ] {
        let error = migration_harness(Box::new(Error::DatabaseError(
            kind,
            Box::new("fixture".to_owned()),
        )))
        .context("outer context");
        assert_eq!(
            error.is::<nazo_persistence::MigrationUnavailable>(),
            retryable
        );
        assert!(
            error
                .chain()
                .any(|cause| cause.downcast_ref::<Error>().is_some())
        );
    }
}
