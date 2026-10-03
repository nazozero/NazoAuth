use std::{sync::Arc, time::Duration};

use chrono::{Duration as ChronoDuration, Utc};
use fred::interfaces::{ClientLike, KeysInterface};
use fred::prelude::{Builder, Config};
use nazo_identity::{
    UserId,
    ports::{
        DeliveryConsume, DeliveryPublish, DeliveryRecord, DeliveryStage, DeliveryStageResult,
        DeliveryStorePort,
    },
};
use nazo_valkey::DeliveryStore;
use serde_json::json;
use tokio::sync::Barrier;
use uuid::Uuid;

async fn setup() -> Option<(Arc<dyn DeliveryStorePort>, fred::prelude::Client)> {
    let url = match std::env::var("VALKEY_URL") {
        Ok(url) => url,
        Err(_) if std::env::var_os("CI").is_some() => {
            panic!("CI delivery tests require VALKEY_URL")
        }
        Err(_) => return None,
    };
    let connection = nazo_valkey::test_support::scoped_connect(&url, Duration::from_secs(1))
        .await
        .expect("configured Valkey must be available");
    let inspector = Builder::from_config(Config::from_url(&url).unwrap())
        .build()
        .unwrap();
    inspector
        .init()
        .await
        .expect("configured Valkey must be available");
    Some((Arc::new(DeliveryStore::new(&connection)), inspector))
}

fn key(user: UserId, token: &str) -> String {
    nazo_valkey::test_support::state_storage_key(format!(
        "oauth:client_delivery:{}:{token}",
        user.as_uuid()
    ))
}

fn candidate(user: UserId, secret: &str, seconds: i64) -> DeliveryStage {
    let expiry = Utc::now() + ChronoDuration::seconds(seconds);
    DeliveryStage {
        attempt_id: Uuid::now_v7(),
        expires_at: expiry,
        secret_binding: Some(format!("binding-{secret}")),
        value: json!({"delivery_state":"staged", "request_id":Uuid::now_v7(),
            "user_id":user.as_uuid(), "client_id":"client-a", "client_secret":secret,
            "expires_at":expiry}),
    }
}

async fn stage(
    store: &dyn DeliveryStorePort,
    user: UserId,
    token: &str,
    value: DeliveryStage,
) -> DeliveryRecord {
    match store.stage(user, token, value).await.unwrap() {
        DeliveryStageResult::Created(record) => record,
        _ => panic!("fresh owned attempt must stage"),
    }
}

async fn committed(store: &dyn DeliveryStorePort, user: UserId, token: &str) -> DeliveryRecord {
    let staged = stage(store, user, token, candidate(user, "secret", 30)).await;
    assert_eq!(
        store
            .publish(user, token, &staged, Uuid::now_v7())
            .await
            .unwrap(),
        DeliveryPublish::Published
    );
    store.load(user, token).await.unwrap().unwrap()
}

#[tokio::test]
async fn client_delivery_preserves_payload_and_exact_original_deadline() {
    let Some((store, inspector)) = setup().await else {
        return;
    };
    let user = UserId::new(Uuid::now_v7()).unwrap();
    let token = Uuid::now_v7().to_string();
    let staged = stage(store.as_ref(), user, &token, candidate(user, "secret", 30)).await;
    let deadline: i64 = inspector
        .custom(fred::cmd!("PEXPIRETIME"), vec![key(user, &token)])
        .await
        .unwrap();
    assert_eq!(deadline, staged.expires_at.timestamp_millis());
    let client = Uuid::now_v7();
    assert_eq!(
        store.publish(user, &token, &staged, client).await.unwrap(),
        DeliveryPublish::Published
    );
    let after: i64 = inspector
        .custom(fred::cmd!("PEXPIRETIME"), vec![key(user, &token)])
        .await
        .unwrap();
    assert_eq!(
        after, deadline,
        "publishing must not extend the disclosure deadline"
    );
    let record = store.load(user, &token).await.unwrap().unwrap();
    assert_eq!(record.attempt_id, staged.attempt_id);
    assert_eq!(record.secret_binding, staged.secret_binding);
    assert_eq!(record.value["client_secret"], staged.value["client_secret"]);
    assert_eq!(record.value["approved_client_id"], json!(client));
    assert!(record.value.get("secret_binding").is_none());
    assert!(
        !store.retire(user, &token, &staged).await.unwrap(),
        "stale stage cleanup cannot remove a committed winner"
    );
    assert!(store.load(user, &token).await.unwrap().is_some());
}

#[tokio::test]
async fn concurrent_stagers_cannot_overwrite_the_winners_secret_or_attempt() {
    let Some((store, _)) = setup().await else {
        return;
    };
    let user = UserId::new(Uuid::now_v7()).unwrap();
    let token = Uuid::now_v7().to_string();
    let gate = Arc::new(Barrier::new(33));
    let mut workers = Vec::new();
    for n in 0..32 {
        let store = store.clone();
        let token = token.clone();
        let gate = gate.clone();
        workers.push(tokio::spawn(async move {
            let candidate = candidate(user, &format!("secret-{n}"), 30);
            gate.wait().await;
            store.stage(user, &token, candidate).await.unwrap()
        }));
    }
    gate.wait().await;
    let mut winner = None;
    let mut existing = 0;
    for worker in workers {
        match worker.await.unwrap() {
            DeliveryStageResult::Created(record) => {
                assert!(winner.is_none());
                winner = Some(record);
            }
            DeliveryStageResult::Existing => existing += 1,
            DeliveryStageResult::Expired => panic!("fresh stages cannot expire"),
        }
    }
    assert_eq!(existing, 31);
    let winner = winner.unwrap();
    let actual = store.load(user, &token).await.unwrap().unwrap();
    assert_eq!(actual.opaque_version, winner.opaque_version);
    assert_eq!(actual.value["client_secret"], winner.value["client_secret"]);
}

#[tokio::test]
async fn exact_publish_cannot_recreate_missing_or_replace_another_attempt() {
    let Some((store, _)) = setup().await else {
        return;
    };
    let user = UserId::new(Uuid::now_v7()).unwrap();
    let token = Uuid::now_v7().to_string();
    let old = stage(store.as_ref(), user, &token, candidate(user, "old", 30)).await;
    assert!(store.retire(user, &token, &old).await.unwrap());
    assert_eq!(
        store
            .publish(user, &token, &old, Uuid::now_v7())
            .await
            .unwrap(),
        DeliveryPublish::MissingOrChanged
    );
    assert!(store.load(user, &token).await.unwrap().is_none());
    let new = stage(store.as_ref(), user, &token, candidate(user, "new", 30)).await;
    assert_eq!(
        store
            .publish(user, &token, &old, Uuid::now_v7())
            .await
            .unwrap(),
        DeliveryPublish::MissingOrChanged
    );
    assert!(!store.retire(user, &token, &old).await.unwrap());
    assert_eq!(
        store
            .load(user, &token)
            .await
            .unwrap()
            .unwrap()
            .opaque_version,
        new.opaque_version
    );
}

#[tokio::test]
async fn recovery_consume_before_original_publisher_resumes_cannot_disclose_twice() {
    let Some((store, _)) = setup().await else {
        return;
    };
    let user = UserId::new(Uuid::now_v7()).unwrap();
    let token = Uuid::now_v7().to_string();
    let original = stage(
        store.as_ref(),
        user,
        &token,
        candidate(user, "original-secret", 30),
    )
    .await;
    let entered = Arc::new(Barrier::new(2));
    let release = Arc::new(Barrier::new(2));
    let publisher = {
        let store = store.clone();
        let token = token.clone();
        let expected = original.clone();
        let entered = entered.clone();
        let release = release.clone();
        tokio::spawn(async move {
            entered.wait().await;
            release.wait().await;
            store
                .publish(user, &token, &expected, Uuid::now_v7())
                .await
                .unwrap()
        })
    };
    entered.wait().await;
    assert_eq!(
        store
            .publish(user, &token, &original, Uuid::now_v7())
            .await
            .unwrap(),
        DeliveryPublish::Published
    );
    let snapshot = store.load(user, &token).await.unwrap().unwrap();
    let gate = Arc::new(Barrier::new(33));
    let mut consumers = Vec::new();
    for _ in 0..32 {
        let store = store.clone();
        let token = token.clone();
        let expected = snapshot.clone();
        let gate = gate.clone();
        consumers.push(tokio::spawn(async move {
            gate.wait().await;
            store.consume(user, &token, &expected).await.unwrap()
        }));
    }
    gate.wait().await;
    let mut disclosures = 0;
    for consumer in consumers {
        if let DeliveryConsume::Consumed(value) = consumer.await.unwrap() {
            assert_eq!(value["client_secret"], "original-secret");
            disclosures += 1;
        }
    }
    assert_eq!(disclosures, 1);
    release.wait().await;
    assert_eq!(publisher.await.unwrap(), DeliveryPublish::MissingOrChanged);
    assert!(store.load(user, &token).await.unwrap().is_none());
    assert_eq!(
        store
            .publish(user, &token, &original, Uuid::now_v7())
            .await
            .unwrap(),
        DeliveryPublish::MissingOrChanged
    );
}

#[tokio::test]
async fn expired_attempts_cannot_stage_publish_or_extend_the_deadline() {
    let Some((store, inspector)) = setup().await else {
        return;
    };
    let user = UserId::new(Uuid::now_v7()).unwrap();
    let token = Uuid::now_v7().to_string();
    assert!(matches!(
        store
            .stage(user, &token, candidate(user, "expired", -1))
            .await
            .unwrap(),
        DeliveryStageResult::Expired
    ));
    assert!(store.load(user, &token).await.unwrap().is_none());
    let staged = stage(store.as_ref(), user, &token, candidate(user, "live", 30)).await;
    let _: i64 = inspector
        .pexpire(&key(user, &token), 1, None)
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(10)).await;
    assert_eq!(
        store
            .publish(user, &token, &staged, Uuid::now_v7())
            .await
            .unwrap(),
        DeliveryPublish::MissingOrChanged
    );
    assert!(store.load(user, &token).await.unwrap().is_none());
}

#[tokio::test]
async fn committed_snapshot_rejects_republication_and_has_one_exact_consumer() {
    let Some((store, _)) = setup().await else {
        return;
    };
    let user = UserId::new(Uuid::now_v7()).unwrap();
    let token = Uuid::now_v7().to_string();
    let record = committed(store.as_ref(), user, &token).await;
    assert_eq!(
        store
            .publish(user, &token, &record, Uuid::now_v7())
            .await
            .unwrap(),
        DeliveryPublish::MissingOrChanged
    );
    let (a, b) = tokio::join!(
        store.consume(user, &token, &record),
        store.consume(user, &token, &record)
    );
    assert_eq!(
        [a.unwrap(), b.unwrap()]
            .into_iter()
            .filter(|r| matches!(r, DeliveryConsume::Consumed(_)))
            .count(),
        1
    );
    assert!(store.load(user, &token).await.unwrap().is_none());
}
