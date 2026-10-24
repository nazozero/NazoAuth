use super::*;
use diesel::{QueryableByName, sql_query, sql_types::Integer};
use diesel_async::{AnsiTransactionManager, RunQueryDsl, TransactionManager};

#[derive(QueryableByName)]
struct BackendPid {
    #[diesel(sql_type = Integer)]
    pid: i32,
}

fn database_pool() -> Option<DbPool> {
    let url = std::env::var("NAZO_TEST_DATABASE_URL")
        .or_else(|_| std::env::var("DATABASE_URL"))
        .ok();
    assert!(
        url.is_some() || std::env::var_os("CI").is_none(),
        "CI requires PostgreSQL"
    );
    url.map(|url| create_pool(url, 1).unwrap())
}

async fn backend_pid(connection: &mut AsyncPgConnection) -> i32 {
    sql_query("SELECT pg_backend_pid() AS pid")
        .get_result::<BackendPid>(connection)
        .await
        .unwrap()
        .pid
}

#[tokio::test]
async fn completed_transactions_reuse_connections_after_commit_and_rollback() {
    let Some(pool) = database_pool() else { return };
    let mut guard = DiscardOnDrop(Some(get_conn(&pool).await.unwrap()));
    let original = backend_pid(guard.connection()).await;
    guard
        .connection()
        .batch_execute("CREATE TEMP TABLE guard_probe (value integer UNIQUE)")
        .await
        .unwrap();
    guard.return_to_pool();
    for outcome in ["commit", "business_error", "sql_error"] {
        let mut guard = DiscardOnDrop(Some(get_conn(&pool).await.unwrap()));
        assert_eq!(backend_pid(guard.connection()).await, original);
        let result = guard
            .connection()
            .transaction::<(), diesel::result::Error, _>(async |connection| {
                sql_query("INSERT INTO guard_probe VALUES (1)")
                    .execute(connection)
                    .await?;
                match outcome {
                    "business_error" => Err(diesel::result::Error::NotFound),
                    "sql_error" => sql_query("INSERT INTO guard_probe VALUES (1)")
                        .execute(connection)
                        .await
                        .map(|_| ()),
                    _ => Ok(()),
                }
            })
            .await;
        assert_eq!(result.is_ok(), outcome == "commit");
        guard.return_to_pool();
        assert_eq!(pool.status().size, 1);
        let mut connection = get_conn(&pool).await.unwrap();
        assert_eq!(backend_pid(&mut connection).await, original);
        sql_query("TRUNCATE guard_probe")
            .execute(&mut connection)
            .await
            .unwrap();
    }
}

#[tokio::test]
async fn completed_guard_discards_an_open_transaction() {
    let Some(pool) = database_pool() else { return };
    let mut guard = DiscardOnDrop(Some(get_conn(&pool).await.unwrap()));
    AnsiTransactionManager::begin_transaction(&mut **guard.connection())
        .await
        .unwrap();
    guard.return_to_pool();
    assert_eq!(pool.status().size, 0);
}

#[tokio::test]
async fn failed_rollback_discards_the_connection() {
    let Some(pool) = database_pool() else { return };
    let observer_pool = database_pool().unwrap();
    let mut observer = get_conn(&observer_pool).await.unwrap();
    let mut guard = DiscardOnDrop(Some(get_conn(&pool).await.unwrap()));
    let pid = backend_pid(guard.connection()).await;
    let result = guard
        .connection()
        .transaction::<(), diesel::result::Error, _>(async |connection| {
            sql_query("SELECT pg_terminate_backend($1)")
                .bind::<Integer, _>(pid)
                .execute(&mut observer)
                .await
                .unwrap();
            assert!(sql_query("SELECT 1").execute(connection).await.is_err());
            Err(diesel::result::Error::NotFound)
        })
        .await;
    assert!(result.is_err());
    guard.return_to_pool();
    assert_eq!(pool.status().size, 0);
    assert_ne!(backend_pid(&mut get_conn(&pool).await.unwrap()).await, pid);
}
