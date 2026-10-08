//! Real PostgreSQL late-commit faults in the final cleanup category.
//! Only a newly created child of the isolated audit fixture is modified.
use std::time::{Duration, Instant};

use diesel::{
    QueryableByName, sql_query,
    sql_types::{BigInt, Integer, Text},
};
use diesel_async::{AsyncConnection, AsyncPgConnection, RunQueryDsl, SimpleAsyncConnection};
use nazo_persistence::SecurityStateMaintenancePort;
use nazo_postgres::{
    DbPool, SecurityStateMaintenanceRepository, create_pool, get_conn, run_pending_migrations,
};
use uuid::Uuid;

#[derive(QueryableByName)]
struct Number {
    #[diesel(sql_type = Integer)]
    value: i32,
}

#[derive(QueryableByName)]
struct Count {
    #[diesel(sql_type = BigInt)]
    value: i64,
}

async fn pool_pid(pool: &DbPool) -> i32 {
    let mut connection = get_conn(pool).await.unwrap();
    sql_query("SELECT pg_backend_pid() AS value")
        .get_result::<Number>(&mut connection)
        .await
        .unwrap()
        .value
}

async fn wait_backend(observer: &mut AsyncPgConnection, pid: i32, waiting: bool) {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let count = sql_query(
            "SELECT COUNT(*)::bigint AS value FROM pg_stat_activity \
             WHERE pid = $1 AND ($2 = 'gone' OR wait_event = 'advisory')",
        )
        .bind::<Integer, _>(pid)
        .bind::<Text, _>(if waiting { "wait" } else { "gone" })
        .get_result::<Count>(observer)
        .await
        .unwrap()
        .value;
        if (waiting && count == 1) || (!waiting && count == 0) {
            return;
        }
        assert!(Instant::now() < deadline, "backend state did not converge");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

async fn nonce_count(observer: &mut AsyncPgConnection, digit: &str) -> i64 {
    sql_query(
        "SELECT COUNT(*)::bigint AS value FROM openid4vci_nonces \
         WHERE nonce_hash = repeat($1, 64)",
    )
    .bind::<Text, _>(digit)
    .get_result::<Count>(observer)
    .await
    .unwrap()
    .value
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cleanup_counts_wait_for_commit_and_uncertain_connections_are_discarded() {
    let Ok(base) = std::env::var("NAZO_AUDIT_TEST_DATABASE_URL") else {
        assert!(
            std::env::var_os("CI").is_none(),
            "CI requires the isolated audit database"
        );
        return;
    };
    let base_url = url::Url::parse(&base).unwrap();
    assert!(
        base_url.path().contains("audit_test"),
        "never run cleanup fault injection against an application database"
    );
    let mut admin = AsyncPgConnection::establish(&base).await.unwrap();
    for fault in ["raise", "cancel", "disconnect"] {
        let name = format!("audit_test_cleanup_{}", Uuid::now_v7().simple());
        admin
            .batch_execute(&format!("CREATE DATABASE {name}"))
            .await
            .unwrap();
        let mut url = base_url.clone();
        url.set_path(&format!("/{name}"));
        run_pending_migrations(url.as_str()).await.unwrap();
        let mut observer = AsyncPgConnection::establish(url.as_str()).await.unwrap();
        observer
            .batch_execute(
                r#"
                INSERT INTO openid4vci_nonces (nonce_hash, created_at, expires_at)
                VALUES (repeat('a',64), now()-interval '2 hours', now()-interval '1 hour'),
                       (repeat('b',64), now()-interval '2 hours', now()+interval '1 hour');
                CREATE TABLE cleanup_commit_fault (mode text NOT NULL);
                INSERT INTO cleanup_commit_fault VALUES ('off');
                CREATE FUNCTION cleanup_deferred_fault() RETURNS trigger LANGUAGE plpgsql AS $$
                DECLARE mode text;
                BEGIN
                    SELECT f.mode INTO mode FROM cleanup_commit_fault AS f;
                    IF mode = 'raise' THEN
                        RAISE EXCEPTION 'cleanup late commit failure' USING ERRCODE = '23514';
                    ELSIF mode = 'gate' THEN
                        PERFORM pg_advisory_xact_lock(23020261009);
                    END IF;
                    RETURN NULL;
                END $$;
                CREATE CONSTRAINT TRIGGER cleanup_late
                    AFTER DELETE ON openid4vci_nonces DEFERRABLE INITIALLY DEFERRED
                    FOR EACH ROW EXECUTE FUNCTION cleanup_deferred_fault();
                "#,
            )
            .await
            .unwrap();
        let pool = create_pool(url.to_string(), 1).unwrap();
        let maintenance = SecurityStateMaintenanceRepository::new(pool.clone());
        let pid = pool_pid(&pool).await;
        sql_query("UPDATE cleanup_commit_fault SET mode = $1")
            .bind::<Text, _>(if fault == "raise" { "raise" } else { "gate" })
            .execute(&mut observer)
            .await
            .unwrap();
        if fault == "raise" {
            let result = maintenance.cleanup_batch().await;
            assert!(result.is_err(), "a result row is not a committed cleanup count");
            assert!(
                result
                    .err()
                    .unwrap()
                    .to_string()
                    .contains("cleanup late commit failure")
            );
        } else {
            observer
                .batch_execute("SELECT pg_advisory_lock(23020261009)")
                .await
                .unwrap();
            let task_repository = maintenance.clone();
            let task = tokio::spawn(async move { task_repository.cleanup_batch().await });
            wait_backend(&mut observer, pid, true).await;
            assert!(!task.is_finished(), "cleanup cannot succeed before final commit");
            if fault == "cancel" {
                task.abort();
                assert!(task.await.unwrap_err().is_cancelled());
            } else {
                observer
                    .batch_execute(&format!("SELECT pg_terminate_backend({pid})"))
                    .await
                    .unwrap();
                assert!(task.await.unwrap().is_err());
            }
            observer
                .batch_execute("SELECT pg_advisory_unlock(23020261009)")
                .await
                .unwrap();
        }
        // Observe physical retirement before any pool checkout can recycle it.
        wait_backend(&mut observer, pid, false).await;
        assert_eq!(nonce_count(&mut observer, "b").await, 1);
        if fault != "cancel" {
            assert_eq!(nonce_count(&mut observer, "a").await, 1);
        }
        let replacement = pool_pid(&pool).await;
        assert_ne!(pid, replacement);
        observer
            .batch_execute("UPDATE cleanup_commit_fault SET mode = 'off'")
            .await
            .unwrap();
        let result = maintenance.cleanup_batch().await.unwrap();
        if fault == "cancel" {
            // Cancellation is not rollback. The old operation may have committed.
            assert!(result.credential_nonces <= 1);
        } else {
            assert_eq!(result.credential_nonces, 1);
        }
        assert_eq!(nonce_count(&mut observer, "a").await, 0);
        assert_eq!(nonce_count(&mut observer, "b").await, 1);
        assert_eq!(pool_pid(&pool).await, replacement);
        println!("{fault}: no premature cleanup success, backend retired, recovery committed");
        drop(maintenance);
        drop(pool);
        drop(observer);
        admin
            .batch_execute(&format!("DROP DATABASE {name} WITH (FORCE)"))
            .await
            .unwrap();
    }
}
