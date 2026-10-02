//! Counter writes require a confirmed idle transaction after rejection.

use super::{RecoveryRootError, RecoveryRootRepository};
use chrono::Utc;
use diesel_async::{AsyncConnection, AsyncPgConnection, TransactionManager as _};
use uuid::Uuid;

#[path = "../../support/query_counter.rs"]
mod query_counter;

#[tokio::test]
async fn failed_attempt_counter_refuses_open_and_broken_transaction_states() {
    let url = std::env::var("NAZO_TEST_DATABASE_URL")
        .or_else(|_| std::env::var("DATABASE_URL"))
        .ok();
    let Some(url) = url else {
        assert!(
            std::env::var_os("CI").is_none(),
            "CI recovery tests require a test database"
        );
        return;
    };
    let mut connection = AsyncPgConnection::establish(&url)
        .await
        .expect("fixture connection");
    let counter = query_counter::QueryCounter::new();
    connection.set_instrumentation(counter.clone());
    type TransactionManager = <AsyncPgConnection as AsyncConnection>::TransactionManager;

    TransactionManager::begin_transaction(&mut connection)
        .await
        .unwrap();
    let before = counter.snapshot();
    let error = RecoveryRootRepository::record_failed_attempt(
        &mut connection,
        "deployment-uncertain",
        Uuid::now_v7(),
        Utc::now(),
    )
    .await
    .expect_err("an open transaction is not a confirmed rollback");
    assert!(matches!(error, RecoveryRootError::Transport(_)));
    assert_eq!(counter.since(before), query_counter::QuerySnapshot::default());
    TransactionManager::rollback_transaction(&mut connection)
        .await
        .unwrap();

    // Diesel's transaction helper can retain the original rejection when
    // rollback reports BrokenTransactionManager. This state must not write.
    TransactionManager::transaction_manager_status_mut(&mut connection).set_in_error();
    let before = counter.snapshot();
    let error = RecoveryRootRepository::record_failed_attempt(
        &mut connection,
        "deployment-uncertain",
        Uuid::now_v7(),
        Utc::now(),
    )
    .await
    .expect_err("an unknown rollback must not reuse the connection");
    assert!(matches!(error, RecoveryRootError::Transport(_)));
    assert_eq!(counter.since(before), query_counter::QuerySnapshot::default());
}
