use super::*;
use jiff::Timestamp;
use nazo_auth::DeviceAuthorizationPayload;
use std::{sync::Arc, time::Duration};
use tokio::sync::Barrier;

fn pending() -> DeviceAuthorizationState {
    let now = Timestamp::now();
    DeviceAuthorizationState::Pending {
        payload: DeviceAuthorizationPayload {
            client_id: "client".to_owned(),
            client_name: "Example device".to_owned(),
            scopes: vec!["openid".to_owned()],
            resource_indicators: vec!["resource".to_owned()],
            authorization_details: serde_json::json!([]),
            interval_seconds: 5,
            issued_at: now,
            expires_at: now
                .checked_add(jiff::SignedDuration::from_secs(60))
                .unwrap(),
        },
        last_poll_at: None,
        slow_down_count: 0,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn creation_collision_never_publishes_half_a_pair() {
    let store = crate::test_support::test_state();
    let state = pending();
    let barrier = Arc::new(Barrier::new(16));
    let mut tasks = Vec::new();
    for index in 0..16 {
        let store = store.clone();
        let state = state.clone();
        let barrier = barrier.clone();
        tasks.push(tokio::spawn(async move {
            let code = format!("device-{index}");
            barrier.wait().await;
            let outcome = DeviceStateStorePort::create(&store, &code, "USER", &state, 60)
                .await
                .unwrap();
            (code, outcome)
        }));
    }
    let mut winner = None;
    for task in tasks {
        let (code, outcome) = task.await.unwrap();
        if outcome == DeviceCreateResult::Applied {
            assert!(winner.replace(code).is_none());
        } else {
            assert_eq!(outcome, DeviceCreateResult::UserCodeCollision);
            assert!(store.load_by_device_code(&code).await.unwrap().is_none());
        }
    }
    let winner = winner.unwrap();
    assert_eq!(
        store.resolve_user_code("USER").await.unwrap().unwrap(),
        blake3::hash(winner.as_bytes()).to_hex().as_str()
    );
    assert_eq!(
        DeviceStateStorePort::create(&store, &winner, "OTHER", &state, 60)
            .await
            .unwrap(),
        DeviceCreateResult::DeviceCodeCollision
    );
    assert!(store.resolve_user_code("OTHER").await.unwrap().is_none());
}

#[tokio::test]
async fn decision_checks_both_versions_and_removes_only_matching_mapping() {
    let store = crate::test_support::test_state();
    DeviceStateStorePort::create(&store, "device", "USER", &pending(), 60)
        .await
        .unwrap();
    DeviceStateStorePort::create(&store, "other", "OTHER", &pending(), 60)
        .await
        .unwrap();
    let hash = store.resolve_user_code("USER").await.unwrap().unwrap();
    let snapshot = store.load_by_device_hash(&hash).await.unwrap().unwrap();
    let consumed = DeviceAuthorizationState::Consumed {
        consumed_at: Timestamp::now(),
    };
    assert_eq!(
        store
            .claim_decision(&hash, "OTHER", snapshot.version(), &consumed)
            .await
            .unwrap(),
        DeviceAtomicResult::Conflict
    );
    assert_eq!(
        store
            .complete_decision(&hash, "OTHER", snapshot.version(), &consumed)
            .await
            .unwrap(),
        DeviceAtomicResult::Conflict
    );
    assert_eq!(
        store
            .complete_decision(&hash, "USER", snapshot.version(), &consumed)
            .await
            .unwrap(),
        DeviceAtomicResult::Applied
    );
    assert!(store.resolve_user_code("USER").await.unwrap().is_none());
    assert!(store.resolve_user_code("OTHER").await.unwrap().is_some());
    assert_eq!(
        store
            .load_by_device_hash(&hash)
            .await
            .unwrap()
            .unwrap()
            .state(),
        &consumed
    );
    assert_eq!(
        store
            .replace_by_device_code("device", snapshot.version(), &pending())
            .await
            .unwrap(),
        DeviceAtomicResult::Conflict
    );
    let mut other = store.clone();
    other.tenant_id = nazo_identity::TenantId::new(uuid::Uuid::from_u128(2)).unwrap();
    assert!(other.load_by_device_code("device").await.unwrap().is_none());
    assert!(other.resolve_user_code("OTHER").await.unwrap().is_none());
}

#[tokio::test]
async fn repeated_cas_cannot_extend_original_expiry() {
    let store = crate::test_support::test_state();
    DeviceStateStorePort::create(&store, "device", "USER", &pending(), 1)
        .await
        .unwrap();
    for _ in 0..3 {
        tokio::time::sleep(Duration::from_millis(200)).await;
        let current = store.load_by_device_code("device").await.unwrap().unwrap();
        let state = DeviceAuthorizationState::Consumed {
            consumed_at: Timestamp::now(),
        };
        assert_eq!(
            store
                .replace_by_device_code("device", current.version(), &state)
                .await
                .unwrap(),
            DeviceAtomicResult::Applied
        );
    }
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(store.load_by_device_code("device").await.unwrap().is_none());
    assert!(store.resolve_user_code("USER").await.unwrap().is_none());
}
