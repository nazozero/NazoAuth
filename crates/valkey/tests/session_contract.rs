use std::time::Duration;

use fred::interfaces::{ClientLike, KeysInterface};
use fred::prelude::{Builder, Config};
use nazo_identity::{UserId, session::SessionRecord};
use nazo_valkey::{SessionRotationResult, SessionStore, ValkeyConnection};

async fn setup() -> Option<(SessionStore, fred::prelude::Client)> {
    let url = std::env::var("VALKEY_URL").ok()?;
    let connection = ValkeyConnection::connect(&url, Duration::from_secs(1))
        .await
        .expect("an explicitly configured Valkey must be available");
    let inspector = Builder::from_config(Config::from_url(&url).unwrap())
        .build()
        .unwrap();
    inspector
        .init()
        .await
        .expect("an explicitly configured Valkey must be available");
    Some((SessionStore::new(&connection), inspector))
}

fn payload() -> SessionRecord {
    SessionRecord::new(
        UserId::new(uuid::Uuid::from_u128(1)).unwrap(),
        1_000,
        vec!["password".to_owned()],
        true,
        Some("oidc-sid".to_owned()),
    )
}

#[tokio::test]
async fn session_store_preserves_exact_key_payload_and_ttl() {
    let Some((store, inspector)) = setup().await else {
        return;
    };
    let sid = uuid::Uuid::now_v7().to_string();
    let key = format!("oauth:session:{sid}");
    let value = payload();

    store.store(&sid, &value, 30).await.unwrap();

    assert_eq!(
        inspector.get::<String, _>(&key).await.unwrap(),
        r#"{"user_id":"00000000-0000-0000-0000-000000000001","auth_time":1000,"amr":["password"],"pending_mfa":true,"oidc_sid":"oidc-sid"}"#
    );
    assert!((1..=30).contains(&inspector.ttl::<i64, _>(&key).await.unwrap()));
    assert_eq!(store.load(&sid).await.unwrap().unwrap().value(), &value);
}

#[tokio::test]
async fn concurrent_session_rotation_has_exactly_one_winner_and_no_partial_state() {
    let Some((store, inspector)) = setup().await else {
        return;
    };
    let old_sid = format!("old-{}", uuid::Uuid::now_v7());
    let first_sid = format!("first-{}", uuid::Uuid::now_v7());
    let second_sid = format!("second-{}", uuid::Uuid::now_v7());
    let old = payload();
    let mut replacement = old.clone();
    replacement.set_pending_mfa(false);
    replacement.add_amr("mfa");
    store.store(&old_sid, &old, 30).await.unwrap();
    let stored = store.load(&old_sid).await.unwrap().unwrap();

    let (first, second) = tokio::join!(
        store.rotate(&old_sid, &stored, &first_sid, &replacement, 30),
        store.rotate(&old_sid, &stored, &second_sid, &replacement, 30)
    );
    let results = [first.unwrap(), second.unwrap()];
    assert_eq!(
        results
            .iter()
            .filter(|r| **r == SessionRotationResult::Applied)
            .count(),
        1
    );
    assert_eq!(
        results
            .iter()
            .filter(|r| **r == SessionRotationResult::Conflict)
            .count(),
        1
    );
    assert!(store.load(&old_sid).await.unwrap().is_none());
    let first_exists = inspector
        .exists::<i64, _>(format!("oauth:session:{first_sid}"))
        .await
        .unwrap();
    let second_exists = inspector
        .exists::<i64, _>(format!("oauth:session:{second_sid}"))
        .await
        .unwrap();
    assert_eq!(first_exists + second_exists, 1);
}
