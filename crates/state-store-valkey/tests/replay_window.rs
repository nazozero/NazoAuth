//! Real state-store replay window contract: the single NX marker must keep
//! one winner under concurrency and its TTL must cover the configured
//! retention period instead of the proof acceptance age.

use std::time::Duration;

use fred::interfaces::{ClientLike, KeysInterface};
use fred::prelude::{Builder, Config};
use futures_util::future::join_all;
use nazo_auth::DpopStateStorePort;
use nazo_valkey::{ReplayStore, test_support};

fn explicit_valkey_url() -> Option<String> {
    std::env::var("VALKEY_URL").ok()
}

#[tokio::test]
async fn replay_nx_allows_only_one_concurrent_acceptance() {
    let Some(url) = explicit_valkey_url() else {
        return;
    };
    let connection = nazo_valkey::test_support::scoped_connect(&url, Duration::from_secs(1))
        .await
        .expect("an explicitly configured Valkey must be available");
    let store = ReplayStore::new(&connection);
    let inspector = Builder::from_config(Config::from_url(&url).expect("VALKEY_URL should parse"))
        .build()
        .expect("inspection client should build");
    inspector
        .init()
        .await
        .expect("an explicitly configured Valkey must be available");

    let jkt = "replay-window-jkt";
    let jti = uuid::Uuid::now_v7().to_string();
    let retention_seconds = nazo_auth::DPOP_REPLAY_TTL_SECONDS;
    let inspected_key = test_support::state_storage_key(format!(
        "oauth:dpop:jti:{jkt}:{}",
        blake3::hash(jti.as_bytes()).to_hex()
    ));
    let _: i64 = inspector.del(&inspected_key).await.expect("cleanup");

    let attempts = join_all((0..32).map(|_| {
        let store = &store;
        let jti = &jti;
        async move { store.consume_replay(jkt, jti, retention_seconds).await }
    }))
    .await;

    let winners = attempts
        .iter()
        .filter(|result| matches!(result, Ok(true)))
        .count();
    assert_eq!(
        winners, 1,
        "exactly one concurrent consumer may win the NX marker"
    );
    assert_eq!(
        attempts
            .iter()
            .filter(|result| matches!(result, Ok(false)))
            .count(),
        31
    );

    let pttl = inspector
        .pttl::<i64, _>(&inspected_key)
        .await
        .expect("marker key must be inspectable");
    assert!(
        pttl > 0 && pttl <= (retention_seconds * 1000) as i64,
        "marker PTTL {pttl} must cover the configured {retention_seconds}s retention"
    );

    let _: i64 = inspector.del(&inspected_key).await.expect("cleanup");
}
