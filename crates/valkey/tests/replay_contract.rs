use std::time::Duration;

use fred::interfaces::{ClientLike, KeysInterface};
use fred::prelude::{Builder, Config};
use nazo_valkey::{ErrorKind, ReplayStore, ValkeyConnection};

fn explicit_valkey_url() -> Option<String> {
    std::env::var("VALKEY_URL").ok()
}

async fn inspection_client(url: &str) -> fred::prelude::Client {
    let client = Builder::from_config(Config::from_url(url).expect("VALKEY_URL should parse"))
        .build()
        .expect("inspection client should build");
    client
        .init()
        .await
        .expect("an explicitly configured Valkey must be available");
    client
}

#[tokio::test]
async fn fapi_http_signature_replay_preserves_exact_key_value_and_ttl_contract() {
    let Some(url) = explicit_valkey_url() else {
        return;
    };
    let connection = ValkeyConnection::connect(&url, Duration::from_secs(1))
        .await
        .expect("an explicitly configured Valkey must be available");
    let store = ReplayStore::new(&connection);
    let inspector = inspection_client(&url).await;
    let fingerprint = [0xa5; 32];
    let key = format!(
        "fapi_http_signature_replay:{}",
        blake3::Hash::from_bytes(fingerprint).to_hex()
    );
    let _: i64 = inspector.del(&key).await.unwrap();

    assert!(
        store
            .consume_fapi_http_signature(&fingerprint, 10)
            .await
            .unwrap()
    );
    assert_eq!(inspector.get::<String, _>(&key).await.unwrap(), "1");
    let ttl = inspector.ttl::<i64, _>(&key).await.unwrap();
    assert!(ttl > 0 && ttl <= 15, "expected max-age + 5s TTL, got {ttl}");
    assert!(
        !store
            .consume_fapi_http_signature(&fingerprint, 10)
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn replay_store_distinguishes_unavailable_dependency() {
    let error = ValkeyConnection::connect("redis://127.0.0.1:1/0", Duration::from_millis(50))
        .await
        .expect_err("closed local port must not connect");

    assert!(matches!(
        error.kind(),
        ErrorKind::Unavailable | ErrorKind::Timeout
    ));
}

#[tokio::test]
async fn replay_ttl_overflow_fails_before_storage() {
    let Some(url) = explicit_valkey_url() else {
        return;
    };
    let connection = ValkeyConnection::connect(&url, Duration::from_secs(1))
        .await
        .expect("an explicitly configured Valkey must be available");
    let store = ReplayStore::new(&connection);

    let error = store
        .consume_fapi_http_signature(&[0x5a; 32], i64::MAX)
        .await
        .expect_err("max-age + future skew overflow must fail closed");
    assert_eq!(error.kind(), ErrorKind::UnexpectedResult);
}

#[tokio::test]
async fn connection_rejects_cluster_topology_before_connecting() {
    let error =
        ValkeyConnection::connect("redis-cluster://127.0.0.1:16384/0", Duration::from_secs(1))
            .await
            .expect_err("multi-key scripts require an explicitly standalone topology");

    assert_eq!(error.kind(), ErrorKind::UnexpectedResult);
}

#[tokio::test]
async fn protocol_replay_keys_preserve_hashing_prefix_and_one_time_semantics() {
    let Some(url) = explicit_valkey_url() else {
        return;
    };
    let connection = ValkeyConnection::connect(&url, Duration::from_secs(1))
        .await
        .expect("an explicitly configured Valkey must be available");
    let store = ReplayStore::new(&connection);
    let inspector = inspection_client(&url).await;
    let jkt = "thumbprint";
    let client_id = "client-a";
    let jti = "opaque-jti";
    let digest = blake3::hash(jti.as_bytes()).to_hex();
    let client_digest = blake3::hash(client_id.as_bytes()).to_hex();
    let keys = [
        format!("oauth:dpop:jti:{jkt}:{digest}"),
        format!("oauth:client_assertion:jti:{client_digest}:{digest}"),
        format!("oauth:jar:jti:{client_digest}:{digest}"),
        format!("oauth:jwt_bearer:jti:{client_digest}:{digest}"),
    ];
    let _: i64 = inspector.del(keys.to_vec()).await.unwrap();

    assert!(store.consume_dpop(jkt, jti, 30).await.unwrap());
    assert!(
        store
            .consume_private_key_jwt(client_id, jti, 30)
            .await
            .unwrap()
    );
    assert!(store.consume_jar(client_id, jti, 30).await.unwrap());
    assert!(store.consume_jwt_bearer(client_id, jti, 30).await.unwrap());
    for key in &keys {
        assert_eq!(inspector.get::<String, _>(key).await.unwrap(), "1");
        assert!((1..=30).contains(&inspector.ttl::<i64, _>(key).await.unwrap()));
    }
    assert!(!store.consume_dpop(jkt, jti, 30).await.unwrap());
    assert!(
        !store
            .consume_private_key_jwt(client_id, jti, 30)
            .await
            .unwrap()
    );
    assert!(!store.consume_jar(client_id, jti, 30).await.unwrap());
    assert!(!store.consume_jwt_bearer(client_id, jti, 30).await.unwrap());
}

#[tokio::test]
async fn dpop_nonce_preserves_exact_key_and_is_consumed_once() {
    let Some(url) = explicit_valkey_url() else {
        return;
    };
    let connection = ValkeyConnection::connect(&url, Duration::from_secs(1))
        .await
        .expect("an explicitly configured Valkey must be available");
    let store = ReplayStore::new(&connection);
    let inspector = inspection_client(&url).await;
    let nonce = "opaque-nonce";
    let key = format!(
        "oauth:dpop:nonce:{}",
        blake3::hash(nonce.as_bytes()).to_hex()
    );
    let _: i64 = inspector.del(&key).await.unwrap();

    store.issue_dpop_nonce(nonce, 30).await.unwrap();
    assert_eq!(inspector.get::<String, _>(&key).await.unwrap(), "1");
    assert!(store.consume_dpop_nonce(nonce).await.unwrap());
    assert!(!store.consume_dpop_nonce(nonce).await.unwrap());
}
