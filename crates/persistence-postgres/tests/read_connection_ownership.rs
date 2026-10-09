use diesel::{QueryableByName, sql_query, sql_types};
use diesel_async::{AsyncConnection, AsyncPgConnection, RunQueryDsl, SimpleAsyncConnection};
use futures_util::{FutureExt, future::BoxFuture};
use nazo_identity::{TenantId, UserId, ports::RepositoryError};
use nazo_postgres::{
    DbPool, OAuthClientRepository, UserRepository, create_pool, get_conn, run_pending_migrations,
};
use std::time::Duration;
use uuid::Uuid;

#[derive(QueryableByName)]
struct CountRow {
    #[diesel(sql_type = sql_types::BigInt)]
    count: i64,
}

async fn wait_for_state(observer: &mut AsyncPgConnection, name: &str, state: &str) {
    loop {
        let row = sql_query("SELECT count(*)::bigint AS count FROM pg_stat_activity WHERE application_name = $1 AND CASE WHEN $2 = 'blocked' THEN wait_event_type = 'Lock' ELSE state = $2 END")
            .bind::<sql_types::Text, _>(name)
            .bind::<sql_types::Text, _>(state)
            .get_result::<CountRow>(observer).await.expect("independent backend observation");
        if row.count == 1 {
            return;
        }
        tokio::task::yield_now().await;
    }
}

async fn assert_read_releases_connection(
    pool: &DbPool,
    blocker: &mut AsyncPgConnection,
    observer: &mut AsyncPgConnection,
    application: &str,
    table: &str,
    mut read: BoxFuture<'_, Result<bool, RepositoryError>>,
    case: &str,
) {
    assert!(matches!(table, "oauth_clients" | "users"));
    blocker
        .batch_execute(&format!(
            "BEGIN; LOCK TABLE {table} IN ACCESS EXCLUSIVE MODE"
        ))
        .await
        .unwrap();
    tokio::select! {
        result = &mut read => panic!("{case}: read completed before database barrier released: {result:?}"),
        observed = tokio::time::timeout(Duration::from_secs(5), wait_for_state(observer, application, "blocked")) => observed.expect("read must reach real PostgreSQL lock barrier"),
    }
    blocker.batch_execute("COMMIT").await.unwrap();
    // Deliberately stop polling the HTTP-side future. The independent backend
    // confirms PostgreSQL has finished the read; no sleep simulates SQL success.
    tokio::time::timeout(
        Duration::from_secs(5),
        wait_for_state(observer, application, "idle"),
    )
    .await
    .expect("PostgreSQL must finish the read after barrier release");
    let returned = tokio::time::timeout(Duration::from_secs(1), get_conn(pool)).await;
    assert!(
        returned.is_ok(),
        "{case}: completed database read still holds the sole pool connection until its caller is polled"
    );
    drop(returned.unwrap().expect("pool connection remains usable"));
    assert!(read.await.expect("read result remains available"));
    println!("{case}: real query completed and pool slot returned before caller resumed");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn completed_reads_return_connections_before_request_resumes() {
    let url = std::env::var("NAZO_TEST_DATABASE_URL")
        .or_else(|_| std::env::var("DATABASE_URL"))
        .expect("read ownership regression requires an isolated PostgreSQL fixture");
    run_pending_migrations(&url).await.unwrap();
    let application = format!("read-owner-{}", Uuid::now_v7());
    let separator = if url.contains('?') { '&' } else { '?' };
    let pool = create_pool(format!("{url}{separator}application_name={application}"), 1).unwrap();
    drop(get_conn(&pool).await.unwrap());
    let mut blocker = AsyncPgConnection::establish(&url).await.unwrap();
    let mut observer = AsyncPgConnection::establish(&url).await.unwrap();
    let clients = OAuthClientRepository::new(pool.clone());
    let users = UserRepository::new(pool.clone());
    let tenant = TenantId::new(Uuid::now_v7()).unwrap();
    let user = UserId::new(Uuid::now_v7()).unwrap();
    let missing_id = Uuid::now_v7();
    type ReadCase<'a> = (
        &'a str,
        &'a str,
        BoxFuture<'a, Result<bool, RepositoryError>>,
    );
    let cases: Vec<ReadCase<'_>> = vec![
        (
            "client lookup",
            "oauth_clients",
            clients
                .by_client_id(tenant.as_uuid(), "missing-client")
                .map(|r| r.map(|v| v.is_none()))
                .boxed(),
        ),
        (
            "client identity",
            "oauth_clients",
            clients
                .by_id(tenant.as_uuid(), missing_id)
                .map(|r| r.map(|v| v.is_none()))
                .boxed(),
        ),
        (
            "client authentication snapshot",
            "oauth_clients",
            clients
                .authentication_snapshot(tenant.as_uuid(), "missing-client")
                .map(|r| r.map(|v| v.is_none()))
                .boxed(),
        ),
        (
            "client secret match",
            "oauth_clients",
            clients
                .client_secret_digest_matches(tenant.as_uuid(), missing_id, "missing-digest")
                .map(|r| r.map(|v| !v))
                .boxed(),
        ),
        (
            "public account",
            "users",
            users
                .public_account_by_id(tenant, user)
                .map(|r| r.map(|v| v.is_none()))
                .boxed(),
        ),
        (
            "principal",
            "users",
            users
                .principal_by_tenant_id(tenant, user)
                .map(|r| r.map(|v| v.is_none()))
                .boxed(),
        ),
        (
            "subject claims",
            "users",
            users
                .active_subject_claims_by_tenant_id(tenant, user, "missing-subject")
                .map(|r| r.map(|v| v.is_none()))
                .boxed(),
        ),
    ];
    for (case, table, read) in cases {
        assert_read_releases_connection(
            &pool,
            &mut blocker,
            &mut observer,
            &application,
            table,
            read,
            case,
        )
        .await;
    }
}

#[derive(QueryableByName)]
struct BackendRow {
    #[diesel(sql_type = sql_types::Integer)]
    pid: i32,
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cancelling_a_blocked_read_retires_its_backend_before_reuse() {
    let url = std::env::var("NAZO_TEST_DATABASE_URL")
        .or_else(|_| std::env::var("DATABASE_URL"))
        .expect("read cancellation regression requires isolated PostgreSQL");
    run_pending_migrations(&url).await.unwrap();
    let application = format!("read-cancel-{}", Uuid::now_v7());
    let separator = if url.contains('?') { '&' } else { '?' };
    let pool = create_pool(format!("{url}{separator}application_name={application}"), 1).unwrap();
    let old_pid = {
        let mut connection = get_conn(&pool).await.unwrap();
        // Exercise PostgreSQL's default disconnect detection even when the
        // surrounding fixture enables more frequent connection checks.
        connection
            .batch_execute("SET client_connection_check_interval = 0")
            .await
            .unwrap();
        sql_query("SELECT pg_backend_pid() AS pid")
            .get_result::<BackendRow>(&mut connection)
            .await
            .unwrap()
            .pid
    };
    let mut blocker = AsyncPgConnection::establish(&url).await.unwrap();
    let mut observer = AsyncPgConnection::establish(&url).await.unwrap();
    blocker
        .batch_execute("BEGIN; LOCK TABLE oauth_clients IN ACCESS EXCLUSIVE MODE")
        .await
        .unwrap();
    let clients = OAuthClientRepository::new(pool.clone());
    let mut read = clients
        .by_client_id(Uuid::now_v7(), "missing-client")
        .boxed();
    tokio::select! {
        result = &mut read => panic!("read must remain blocked: {result:?}"),
        observed = tokio::time::timeout(Duration::from_secs(5), wait_for_state(&mut observer, &application, "blocked")) => observed.expect("real read must reach lock barrier"),
    }
    drop(read);
    // First prove the cancelled owner discarded the connection, rather than
    // letting the query complete and returning it normally after barrier release.
    tokio::time::timeout(Duration::from_secs(5), async {
        while pool.status().size != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("cancelled owner must discard its pool connection while still blocked");
    // With PostgreSQL's default connection checks, a backend waiting on our
    // lock need not notice socket closure until it resumes. Release only the
    // test-owned barrier, then observe retirement before any new checkout.
    blocker.batch_execute("ROLLBACK").await.unwrap();
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let count =
                sql_query("SELECT count(*)::bigint AS count FROM pg_stat_activity WHERE pid = $1")
                    .bind::<sql_types::Integer, _>(old_pid)
                    .get_result::<CountRow>(&mut observer)
                    .await
                    .unwrap()
                    .count;
            if count == 0 {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("cancelled read backend must disappear");
    let mut replacement = tokio::time::timeout(Duration::from_secs(5), get_conn(&pool))
        .await
        .unwrap()
        .unwrap();
    let new_pid = sql_query("SELECT pg_backend_pid() AS pid")
        .get_result::<BackendRow>(&mut replacement)
        .await
        .unwrap()
        .pid;
    assert_ne!(old_pid, new_pid);
    println!(
        "cancelled read backend {old_pid} independently disappeared; replacement {new_pid} executes SQL"
    );
}
