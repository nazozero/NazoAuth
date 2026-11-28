use super::*;
use nazo_auth::{CibaPingNotification, CibaStatus};
use std::sync::Arc;
use tokio::sync::Barrier;

fn request(now: i64) -> CibaRequestState {
    CibaRequestState {
        client_id: "client".to_owned(),
        user_id: uuid::Uuid::from_u128(1),
        scopes: vec!["openid".to_owned()],
        audiences: vec!["resource".to_owned()],
        acr: None,
        authentication_context: None,
        binding_message: Some("confirm this device".to_owned()),
        issued_at: now,
        status: CibaStatus::Pending,
        interval_seconds: 5,
        expires_at: now + 60,
        retention_expires_at: now + 180,
        last_poll_at: None,
        ping_notification: None,
    }
}

fn pending_ping(now: i64) -> CibaRequestState {
    let mut state = request(now);
    state.ping_notification = Some(CibaPingNotification {
        auth_req_id: None,
        endpoint: "https://client.example/ping".to_owned(),
        client_notification_token: Some("notification-secret".to_owned()),
        status: CibaPingNotificationStatus::Pending,
        attempts: 0,
        next_attempt_at: Some(now),
    });
    state
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cas_has_one_winner_and_retains_original_deadline() {
    let store = crate::test_support::test_state();
    let state = request(Timestamp::now().as_second());
    assert_eq!(
        CibaStateStorePort::create(&store, "request", &state)
            .await
            .unwrap(),
        CibaAtomicResult::Applied
    );
    let snapshot = CibaStateStorePort::load(&store, "request")
        .await
        .unwrap()
        .unwrap();
    let barrier = Arc::new(Barrier::new(16));
    let mut tasks = Vec::new();
    for interval in 6..22 {
        let store = store.clone();
        let version = snapshot.version().clone();
        let mut state = state.clone();
        state.interval_seconds = interval;
        let barrier = barrier.clone();
        tasks.push(tokio::spawn(async move {
            barrier.wait().await;
            CibaStateStorePort::replace(&store, "request", &version, &state)
                .await
                .unwrap()
        }));
    }
    let mut winners = 0;
    for task in tasks {
        winners += usize::from(task.await.unwrap() == CibaAtomicResult::Applied);
    }
    assert_eq!(winners, 1);
    let current = CibaStateStorePort::load(&store, "request")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        current.version().retention_expires_at(),
        state.retention_expires_at
    );
    let mut extended = current.state().clone();
    extended.retention_expires_at += 1;
    assert_eq!(
        CibaStateStorePort::replace(&store, "request", current.version(), &extended)
            .await
            .unwrap_err(),
        CibaStatePortError::CorruptData
    );
    assert_eq!(
        CibaStateStorePort::load(&store, "request")
            .await
            .unwrap()
            .unwrap()
            .state(),
        current.state()
    );
}

#[tokio::test]
async fn external_deadline_and_tenant_mismatch_do_not_mutate_state() {
    let store = crate::test_support::test_state();
    let now = Timestamp::now().as_second();
    let state = request(now);
    assert_eq!(
        store
            .create_with_authorization_deadline("expired", &state, Some(now))
            .await
            .unwrap(),
        CibaAtomicResult::DeadlineElapsed
    );
    assert!(
        CibaStateStorePort::load(&store, "expired")
            .await
            .unwrap()
            .is_none()
    );
    CibaStateStorePort::create(&store, "request", &state)
        .await
        .unwrap();
    let current = CibaStateStorePort::load(&store, "request")
        .await
        .unwrap()
        .unwrap();
    let mut replacement = state.clone();
    replacement.last_poll_at = Some(now);
    assert_eq!(
        store
            .replace_with_authorization_deadline(
                "request",
                current.version(),
                &replacement,
                Some(now)
            )
            .await
            .unwrap(),
        CibaAtomicResult::DeadlineElapsed
    );
    assert_eq!(
        store
            .delete_with_authorization_deadline("request", current.version(), Some(now))
            .await
            .unwrap(),
        CibaAtomicResult::DeadlineElapsed
    );
    assert_eq!(
        CibaStateStorePort::load(&store, "request")
            .await
            .unwrap()
            .unwrap()
            .state(),
        &state
    );
    let mut other = store.clone();
    other.tenant_id = nazo_identity::TenantId::new(uuid::Uuid::from_u128(2)).unwrap();
    assert!(
        CibaStateStorePort::load(&other, "request")
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        CibaStateStorePort::delete(&other, "request", current.version())
            .await
            .unwrap(),
        CibaAtomicResult::Conflict
    );
}

#[tokio::test]
async fn ping_claims_are_bounded_fenced_and_expire_independently() {
    let store = crate::test_support::test_state();
    let now = Timestamp::now().as_second();
    for id in ["a", "b", "c"] {
        CibaStateStorePort::create(&store, id, &pending_ping(now))
            .await
            .unwrap();
    }
    let first = store.claim_due(now, now + 5, 1).await.unwrap();
    assert_eq!(first.scanned, 1);
    assert_eq!(first.deliveries.len(), 1);
    let rest = store.claim_due(now, now + 5, 8).await.unwrap();
    assert_eq!(rest.scanned, 2);
    assert_eq!(rest.deliveries.len(), 2);
    assert_eq!(store.claim_due(now, now + 5, 8).await.unwrap().scanned, 0);
    let reclaimed = store.claim_due(now + 5, now + 10, 8).await.unwrap();
    assert_eq!(reclaimed.deliveries.len(), 3);
    assert_eq!(
        store
            .finish(&first.deliveries[0], CibaPingFinishOutcome::Delivered)
            .await
            .unwrap(),
        CibaPingFinishResult::Conflict
    );
    let delivered = &reclaimed.deliveries[0];
    assert_eq!(
        store
            .finish(delivered, CibaPingFinishOutcome::Delivered)
            .await
            .unwrap(),
        CibaPingFinishResult::Applied
    );
    let done = CibaStateStorePort::load(&store, &delivered.auth_req_id)
        .await
        .unwrap()
        .unwrap();
    let ping = done.state().ping_notification.as_ref().unwrap();
    assert_eq!(ping.status, CibaPingNotificationStatus::Delivered);
    assert!(ping.client_notification_token.is_none());
    assert_eq!(done.version().retention_expires_at(), now + 180);
    let retry = &reclaimed.deliveries[1];
    assert_eq!(
        store
            .finish(retry, CibaPingFinishOutcome::RetryAt(now + 11))
            .await
            .unwrap(),
        CibaPingFinishResult::Applied
    );
    assert_eq!(
        store
            .claim_due(now + 10, now + 15, 8)
            .await
            .unwrap()
            .deliveries
            .len(),
        1
    );
    let expired = store.claim_due(now + 61, now + 65, 8).await.unwrap();
    assert!(expired.deliveries.is_empty());
    assert_eq!(expired.scanned, 2);
    assert_eq!(
        store
            .claim_due(now + 61, now + 65, 8)
            .await
            .unwrap()
            .scanned,
        0
    );
    for item in &reclaimed.deliveries[1..] {
        let current = CibaStateStorePort::load(&store, &item.auth_req_id)
            .await
            .unwrap()
            .unwrap();
        let ping = current.state().ping_notification.as_ref().unwrap();
        assert_eq!(ping.status, CibaPingNotificationStatus::Failed);
        assert!(ping.client_notification_token.is_none());
    }
}
