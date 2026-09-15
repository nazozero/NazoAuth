use diesel::sql_query;
use diesel_async::RunQueryDsl;
use nazo_postgres::{create_pool, db_pool_metrics, get_conn, health_check};

fn function_source<'a>(source: &'a str, name: &str, next_name: Option<&str>) -> &'a str {
    let start = source
        .find(&format!("pub async fn {name}"))
        .unwrap_or_else(|| panic!("{name} must remain a public async function"));
    let source = &source[start..];
    next_name
        .and_then(|next| source.find(&format!("pub async fn {next}")))
        .map_or(source, |end| &source[..end])
}

#[test]
fn pool_admin_operations_keep_async_rustls_and_isolate_the_migration_harness() {
    let source = include_str!("../src/pool.rs");
    let migrations = function_source(
        source,
        "run_pending_migrations",
        Some("configure_runtime_role"),
    );
    let runtime_role = function_source(source, "configure_runtime_role", None);
    // The public wrapper delegates to the private inner function where the
    // shared async TLS connection is actually established.
    let inner_start = source
        .find("async fn run_pending_migrations_inner")
        .expect("run_pending_migrations_inner must remain");
    let migrations_inner = &source[inner_start..];

    for (name, operation) in [
        ("configure_runtime_role", runtime_role),
        ("run_pending_migrations_inner", migrations_inner),
    ] {
        assert!(
            operation.contains("establish_connection(database_url).await?"),
            "{name} must use the shared async PostgreSQL TLS connection path"
        );
        for synchronous_connection in ["diesel::PgConnection", "diesel::pg::PgConnection"] {
            assert!(
                !operation.contains(synchronous_connection),
                "{name} must not reintroduce the synchronous libpq connection path"
            );
        }
    }

    assert!(source.contains("MakeRustlsConnect::with_native_certs"));
    assert!(source.contains("AsyncPgConnection::try_from_client_and_connection"));
    assert!(migrations.contains("tokio::task::spawn_blocking"));
    assert!(migrations.contains("tokio::runtime::Builder::new_multi_thread"));
    assert!(migrations.contains(".worker_threads(1)"));
    assert!(migrations.contains("runtime.block_on(run_pending_migrations_inner(&database_url))"));
    assert!(migrations_inner.contains("AsyncMigrationHarness::new(connection)"));
    assert!(migrations_inner.contains("SET SESSION lock_timeout"));
    assert!(migrations_inner.contains("SET SESSION statement_timeout"));
    assert!(migrations_inner.contains("pg_try_advisory_lock"));
    assert!(migrations_inner.contains("pg_advisory_unlock"));
    assert!(migrations_inner.contains("!applied.is_empty()"));
    // Security-state reclamation is owned by the runtime maintenance worker,
    // never by the migration path.
    assert!(!source.contains("nazo_oauth_cleanup_expired_security_state"));
    assert!(!source.contains("nazo_openid4vp_cleanup_expired_transactions"));
}

#[tokio::test(flavor = "current_thread")]
async fn migrations_run_from_a_current_thread_runtime() {
    let database_url = std::env::var("NAZO_TEST_DATABASE_URL")
        .or_else(|_| std::env::var("DATABASE_URL"))
        .ok();
    if database_url.is_none() && std::env::var_os("CI").is_some() {
        panic!("CI migration runtime tests require NAZO_TEST_DATABASE_URL or DATABASE_URL");
    }
    let Some(database_url) = database_url else {
        return;
    };

    nazo_postgres::run_pending_migrations(&database_url)
        .await
        .expect("the isolated migration harness should run from a current-thread Tokio runtime");
}

#[tokio::test(flavor = "current_thread")]
async fn pool_admin_operation_errors_remain_typed_across_runtime_boundaries() {
    let invalid_url = "postgres://127.0.0.1:not-a-port/database";

    let migration_error = nazo_postgres::run_pending_migrations(invalid_url)
        .await
        .expect_err("an invalid URL must fail migration connection setup");
    assert!(
        migration_error
            .downcast_ref::<diesel::ConnectionError>()
            .is_some(),
        "the migration operation error must not be replaced by a task-join error"
    );

    let role_error = nazo_postgres::configure_runtime_role(invalid_url, "nazo_runtime")
        .await
        .expect_err("an invalid URL must fail runtime-role connection setup");
    assert!(
        role_error
            .downcast_ref::<diesel::ConnectionError>()
            .is_some(),
        "the runtime-role operation error must not be replaced by a task-join error"
    );
}

#[tokio::test]
async fn pool_health_and_connection_round_trip_record_acquisition_metrics() {
    let database_url = std::env::var("NAZO_TEST_DATABASE_URL")
        .or_else(|_| std::env::var("DATABASE_URL"))
        .ok();
    if database_url.is_none() && std::env::var_os("CI").is_some() {
        panic!("CI pool health tests require NAZO_TEST_DATABASE_URL or DATABASE_URL");
    }
    let Some(database_url) = database_url else {
        return;
    };

    let before = db_pool_metrics();
    let pool = create_pool(database_url, 1).expect("the test pool should be configured");
    health_check(&pool)
        .await
        .expect("the pool health check should execute a database round trip");
    let mut connection = get_conn(&pool)
        .await
        .expect("the pool should acquire an asynchronous connection");
    sql_query("SELECT 1")
        .execute(&mut connection)
        .await
        .expect("an acquired connection should execute a query");
    drop(connection);

    let after = db_pool_metrics();
    assert!(after.acquire_count >= before.acquire_count + 2);
    assert!(after.wait_nanos_total >= before.wait_nanos_total);
    assert!(after.wait_nanos_max >= before.wait_nanos_max);
}

#[tokio::test]
async fn failed_pool_acquisition_still_records_the_attempt_metrics() {
    let before = db_pool_metrics();
    // Port 1 refuses immediately; pool construction is lazy so only the
    // acquisition attempt inside `get_conn` can fail.
    let pool = create_pool("postgres://127.0.0.1:1/nazo-unreachable", 1)
        .expect("pool construction does not open a connection");

    let result = get_conn(&pool).await;

    assert!(
        result.is_err(),
        "a refused backend must fail the acquisition"
    );
    let after = db_pool_metrics();
    assert!(
        after.acquire_count > before.acquire_count,
        "failed acquisitions are still counted attempts"
    );
    assert!(after.wait_nanos_total >= before.wait_nanos_total);
}

#[tokio::test]
async fn concurrent_acquisitions_count_each_attempt_once() {
    let database_url = std::env::var("NAZO_TEST_DATABASE_URL")
        .or_else(|_| std::env::var("DATABASE_URL"))
        .ok();
    if database_url.is_none() && std::env::var_os("CI").is_some() {
        panic!("CI pool metrics tests require NAZO_TEST_DATABASE_URL or DATABASE_URL");
    }
    let Some(database_url) = database_url else {
        return;
    };

    let before = db_pool_metrics();
    let pool = create_pool(database_url, 4).expect("the test pool should be configured");
    let attempts = 8usize;
    let mut tasks = tokio::task::JoinSet::new();
    for _ in 0..attempts {
        let pool = pool.clone();
        tasks.spawn(async move { get_conn(&pool).await.is_ok() });
    }
    let mut succeeded = 0usize;
    while let Some(result) = tasks.join_next().await {
        if result.expect("acquisition task must not panic") {
            succeeded += 1;
        }
    }
    assert_eq!(succeeded, attempts, "every concurrent acquisition succeeds");

    let after = db_pool_metrics();
    assert!(
        after.acquire_count >= before.acquire_count + attempts as u64,
        "each concurrent attempt is counted exactly once"
    );
}
