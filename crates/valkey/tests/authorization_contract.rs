use std::{collections::HashMap, time::Duration};

use chrono::{TimeZone, Utc};
use fred::interfaces::{ClientLike, KeysInterface};
use fred::prelude::{Builder, Config};
use nazo_auth::{AuthorizationCodeState, CodePayload, PushedAuthorizationRequest};
use nazo_valkey::{AuthorizationCodeBegin, AuthorizationStore, ValkeyConnection};
use serde_json::json;

async fn setup() -> Option<(AuthorizationStore, fred::prelude::Client)> {
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
        .expect("explicit Valkey must be available");
    Some((AuthorizationStore::new(&connection), inspector))
}

fn code_payload(code_id: &str) -> CodePayload {
    CodePayload {
        code_id: code_id.to_owned(),
        user_id: uuid::Uuid::from_u128(1),
        client_id: "client-a".to_owned(),
        redirect_uri: "https://client.example/cb".to_owned(),
        redirect_uri_was_supplied: true,
        scopes: vec!["openid".to_owned()],
        resource_indicators: vec![],
        authorization_details: json!([]),
        nonce: None,
        auth_time: 1_000,
        amr: vec!["password".to_owned()],
        oidc_sid: Some("sid".to_owned()),
        acr: None,
        userinfo_claims: vec![],
        userinfo_claim_requests: vec![],
        id_token_claims: vec![],
        id_token_claim_requests: vec![],
        code_challenge: None,
        code_challenge_method: None,
        dpop_jkt: None,
        mtls_x5t_s256: None,
        issued_at: Utc.timestamp_opt(1_000, 0).unwrap(),
        expires_at: Utc.timestamp_opt(1_030, 0).unwrap(),
    }
}

#[tokio::test]
async fn par_preserves_exact_hashed_key_json_ttl_and_one_time_take() {
    let Some((store, inspector)) = setup().await else {
        return;
    };
    let request_uri = format!("urn:ietf:params:oauth:request_uri:{}", uuid::Uuid::now_v7());
    let key = format!(
        "oauth:par:{}",
        blake3::hash(request_uri.as_bytes()).to_hex()
    );
    let payload = PushedAuthorizationRequest {
        client_id: "client-a".to_owned(),
        params: HashMap::from([("scope".to_owned(), "openid".to_owned())]),
        dpop_jkt: None,
        mtls_x5t_s256: None,
        issued_at: Utc.timestamp_opt(1_000, 0).unwrap(),
        expires_at: Utc.timestamp_opt(1_030, 0).unwrap(),
    };

    store.store_par(&request_uri, &payload, 30).await.unwrap();
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&inspector.get::<String, _>(&key).await.unwrap())
            .unwrap(),
        serde_json::to_value(&payload).unwrap()
    );
    assert!((1..=30).contains(&inspector.ttl::<i64, _>(&key).await.unwrap()));
    assert!(store.take_par(&request_uri).await.unwrap().is_some());
    assert!(store.take_par(&request_uri).await.unwrap().is_none());
}

#[tokio::test]
async fn concurrent_authorization_code_begin_has_one_consuming_winner() {
    let Some((store, _)) = setup().await else {
        return;
    };
    let code_hash = uuid::Uuid::now_v7().to_string();
    let pending = AuthorizationCodeState::Pending {
        payload: code_payload(&code_hash),
    };
    store
        .store_authorization_code_hash(&code_hash, &pending, 30)
        .await
        .unwrap();

    let (first, second) = tokio::join!(
        store.begin_authorization_code(&code_hash, Utc.timestamp_opt(1_001, 0).unwrap()),
        store.begin_authorization_code(&code_hash, Utc.timestamp_opt(1_001, 0).unwrap())
    );
    let results = [first.unwrap(), second.unwrap()];
    assert_eq!(
        results
            .iter()
            .filter(|r| matches!(r, AuthorizationCodeBegin::Consuming(_)))
            .count(),
        1
    );
    assert_eq!(
        results
            .iter()
            .filter(|r| matches!(r, AuthorizationCodeBegin::Busy))
            .count(),
        1
    );
}
