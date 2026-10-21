#[path = "support/database.rs"]
mod database;

#[tokio::test]
async fn migration_revision_distinguishes_empty_applied_and_noop() {
    let base = std::env::var("NAZO_TEST_DATABASE_URL").or_else(|_| std::env::var("DATABASE_URL"));
    let base = match base {
        Ok(base) => base,
        Err(_) if std::env::var_os("CI").is_none() => return,
        Err(error) => panic!("real PostgreSQL fixture required: {error}"),
    };
    let database = database::OwnedDatabase::new(&base).await;
    let before = nazo_postgres::migration_schema_revision(&database.url)
        .await
        .unwrap();
    assert!(
        nazo_postgres::run_pending_migrations(&database.url)
            .await
            .unwrap()
    );
    let after = nazo_postgres::migration_schema_revision(&database.url)
        .await
        .unwrap();
    assert_ne!(before, after);
    assert!(
        !nazo_postgres::run_pending_migrations(&database.url)
            .await
            .unwrap()
    );
    assert_eq!(
        nazo_postgres::migration_schema_revision(&database.url)
            .await
            .unwrap(),
        after
    );
}
