use std::time::Duration;

use fred::interfaces::{ClientLike, KeysInterface};
use fred::prelude::{Builder, Config};
use nazo_valkey::{
    AuthenticationStore, LoginFailureDimension, RateDimension, RateLimitStore, TokenStateStore,
    ValkeyConnection,
};
use serde_json::json;

async fn setup() -> Option<(ValkeyConnection, fred::prelude::Client)> {
    let url = std::env::var("VALKEY_URL").ok()?;
    let connection = ValkeyConnection::connect(&url, Duration::from_secs(1))
        .await
        .unwrap();
    let inspector = Builder::from_config(Config::from_url(&url).unwrap())
        .build()
        .unwrap();
    inspector
        .init()
        .await
        .expect("explicit Valkey must be available");
    Some((connection, inspector))
}

#[tokio::test]
async fn authentication_short_state_preserves_exact_keys_and_one_time_semantics() {
    let Some((connection, inspector)) = setup().await else {
        return;
    };
    let store = AuthenticationStore::new(&connection);
    let suffix = uuid::Uuid::now_v7().to_string();
    let email = format!("{suffix}@example.com");
    let ceremony = format!("ceremony-{suffix}");
    assert!(store.reserve_email_send(&email, 30).await.unwrap());
    assert!(!store.reserve_email_send(&email, 30).await.unwrap());
    assert_eq!(
        inspector
            .get::<String, _>(format!("oauth:email_verify:send:{email}"))
            .await
            .unwrap(),
        "1"
    );
    store.store_email_code(&email, "123456", 30).await.unwrap();
    assert_eq!(
        store.load_email_code(&email).await.unwrap().as_deref(),
        Some("123456")
    );
    let payload = json!({"challenge":"opaque", "user_id": suffix});
    store
        .store_passkey_registration(&ceremony, &payload, 30)
        .await
        .unwrap();
    assert_eq!(
        store.take_passkey_registration(&ceremony).await.unwrap(),
        Some(payload)
    );
    assert!(
        store
            .take_passkey_registration(&ceremony)
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn concurrent_rate_counters_are_atomic_and_preserve_first_window_ttl() {
    let Some((connection, inspector)) = setup().await else {
        return;
    };
    let store = RateLimitStore::new(&connection);
    let subject = format!("subject-{}", uuid::Uuid::now_v7());
    let futures = (0..20).map(|_| store.increment(RateDimension::Token, &subject, 30));
    let results = futures_util::future::join_all(futures).await;
    let mut counts = results.into_iter().collect::<Result<Vec<_>, _>>().unwrap();
    counts.sort_unstable();
    assert_eq!(counts, (1..=20).collect::<Vec<_>>());
    let key = format!(
        "oauth:rate:token:{}",
        blake3::hash(subject.as_bytes()).to_hex()
    );
    assert!((1..=30).contains(&inspector.ttl::<i64, _>(&key).await.unwrap()));
    assert_eq!(
        store
            .login_failure_count(LoginFailureDimension::Email, &subject)
            .await
            .unwrap(),
        0
    );
}

#[tokio::test]
async fn token_state_preserves_subject_and_native_sso_key_contracts() {
    let Some((connection, inspector)) = setup().await else {
        return;
    };
    let store = TokenStateStore::new(&connection);
    let tenant = uuid::Uuid::from_u128(1);
    let user = uuid::Uuid::from_u128(2);
    let jti = format!("jti-{}", uuid::Uuid::now_v7());
    let secret = format!("secret-{}", uuid::Uuid::now_v7());
    store
        .store_access_token_subject(tenant, &jti, user, 30)
        .await
        .unwrap();
    assert_eq!(
        store.load_access_token_subject(tenant, &jti).await.unwrap(),
        Some(user)
    );
    let subject_key = format!(
        "oauth:access_token:subject:{tenant}:{}",
        blake3::hash(jti.as_bytes()).to_hex()
    );
    assert_eq!(
        inspector.get::<String, _>(&subject_key).await.unwrap(),
        user.to_string()
    );
    let payload = json!({"tenant_id":tenant,"user_id":user,"sid":"sid"});
    store.store_native_sso(&secret, &payload, 30).await.unwrap();
    assert_eq!(store.load_native_sso(&secret).await.unwrap(), Some(payload));
}
