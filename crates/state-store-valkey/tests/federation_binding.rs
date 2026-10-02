use std::time::Duration;

use fred::interfaces::{ClientLike, KeysInterface, LuaInterface};
use fred::prelude::{Builder, Config, Expiration};
use nazo_identity::ports::{FederationStatePort, RepositoryError};
use nazo_identity::{OidcFederationState, SocialFederationState};
use nazo_valkey::{AuthenticationStore, ValkeyConnection};
use serde_json::{Value, json};

async fn setup() -> Option<(AuthenticationStore, fred::prelude::Client)> {
    let url = std::env::var("VALKEY_URL").ok()?;
    let connection: ValkeyConnection =
        nazo_valkey::test_support::scoped_connect(&url, Duration::from_secs(2))
            .await
            .expect("explicit isolated Valkey should connect");
    let inspector = Builder::from_config(Config::from_url(&url).unwrap())
        .build()
        .unwrap();
    inspector.init().await.unwrap();
    Some((AuthenticationStore::new(&connection), inspector))
}

async fn snapshot(inspector: &fred::prelude::Client, key: &str) -> Value {
    let raw = inspector
        .eval::<String, _, _, _>(
            "return cjson.encode({raw=redis.call('GET',KEYS[1]),deadline=redis.call('PEXPIRETIME',KEYS[1])})",
            vec![key.to_owned()],
            Vec::<String>::new(),
        )
        .await
        .unwrap();
    serde_json::from_str(&raw).unwrap()
}

#[tokio::test]
async fn nonowner_legacy_and_corrupt_state_keep_exact_raw_value_and_expiry() {
    let Some((store, inspector)) = setup().await else {
        return;
    };
    let cases = [
        "{not-json".to_owned(),
        "null".to_owned(),
        "[]".to_owned(),
        "7".to_owned(),
        json!({"nonce":"nonce","pkce_verifier":"verifier","provider_id":"provider","created_at":1}).to_string(),
        json!({"browser_binding_hash":null}).to_string(),
        json!({"browser_binding_hash":7}).to_string(),
        json!({"browser_binding_hash":"another-browser"}).to_string(),
    ];
    for social in [false, true] {
        for raw in &cases {
            let state = format!("binding-{}", uuid::Uuid::now_v7());
            let key = if social {
                nazo_valkey::test_support::social_federation_storage_key(&state)
            } else {
                nazo_valkey::test_support::oidc_federation_storage_key(&state)
            };
            inspector
                .set::<(), _, _>(&key, raw.as_str(), Some(Expiration::PX(300_000)), None, false)
                .await
                .unwrap();
            let before = snapshot(&inspector, &key).await;
            if social {
                assert!(FederationStatePort::take_social(&store, &state, "owner-browser")
                    .await.unwrap().is_none());
            } else {
                assert!(FederationStatePort::take_oidc(&store, &state, "owner-browser")
                    .await.unwrap().is_none());
            }
            assert_eq!(snapshot(&inspector, &key).await, before);
            inspector.del::<i64, _>(&key).await.unwrap();
        }
    }
}

#[tokio::test]
async fn matching_owner_typed_corruption_is_consumed_then_rejected() {
    let Some((store, inspector)) = setup().await else {
        return;
    };
    for social in [false, true] {
        let state = format!("typed-corrupt-{}", uuid::Uuid::now_v7());
        let key = if social {
            nazo_valkey::test_support::social_federation_storage_key(&state)
        } else {
            nazo_valkey::test_support::oidc_federation_storage_key(&state)
        };
        // The hash matches, but required typed fields are absent.
        let raw = json!({"browser_binding_hash":"owner-browser"}).to_string();
        inspector
            .set::<(), _, _>(&key, raw, Some(Expiration::EX(300)), None, false)
            .await
            .unwrap();
        let error = if social {
            FederationStatePort::take_social(&store, &state, "owner-browser")
                .await.unwrap_err()
        } else {
            FederationStatePort::take_oidc(&store, &state, "owner-browser")
                .await.unwrap_err()
        };
        assert!(matches!(error, RepositoryError::Consistency(_)));
        assert!(inspector.get::<Option<String>, _>(&key).await.unwrap().is_none());
    }
}

#[tokio::test]
async fn correct_and_wrong_browser_concurrency_has_exactly_one_owner_winner() {
    let Some((store, _inspector)) = setup().await else {
        return;
    };
    let oidc_state = format!("oidc-{}", uuid::Uuid::now_v7());
    let oidc = OidcFederationState {
        browser_binding_hash: Some("owner-browser".to_owned()),
        provider_id: Some("oidc-provider".to_owned()),
        nonce: "original-nonce".to_owned(),
        pkce_verifier: "original-verifier".to_owned(),
        created_at: 1_700_000_000,
    };
    FederationStatePort::store_oidc(&store, &oidc_state, &oidc, 300).await.unwrap();
    let (a, b, wrong) = tokio::join!(
        FederationStatePort::take_oidc(&store, &oidc_state, "owner-browser"),
        FederationStatePort::take_oidc(&store, &oidc_state, "owner-browser"),
        FederationStatePort::take_oidc(&store, &oidc_state, "wrong-browser"),
    );
    assert!(wrong.unwrap().is_none());
    let winners: Vec<_> = [a.unwrap(), b.unwrap()].into_iter().flatten().collect();
    assert_eq!(winners.len(), 1);
    assert_eq!(winners[0].nonce, oidc.nonce);
    assert_eq!(winners[0].pkce_verifier, oidc.pkce_verifier);
    assert_eq!(winners[0].provider_id, oidc.provider_id);

    let social_state = format!("social-{}", uuid::Uuid::now_v7());
    let social = SocialFederationState {
        browser_binding_hash: Some("owner-browser".to_owned()),
        provider_id: "social-provider".to_owned(),
        pkce_verifier: "social-verifier".to_owned(),
        created_at: 1_700_000_000,
    };
    FederationStatePort::store_social(&store, &social_state, &social, 300).await.unwrap();
    let (a, wrong, b) = tokio::join!(
        FederationStatePort::take_social(&store, &social_state, "owner-browser"),
        FederationStatePort::take_social(&store, &social_state, "wrong-browser"),
        FederationStatePort::take_social(&store, &social_state, "owner-browser"),
    );
    assert!(wrong.unwrap().is_none());
    let winners: Vec<_> = [a.unwrap(), b.unwrap()].into_iter().flatten().collect();
    assert_eq!(winners.len(), 1);
    assert_eq!(winners[0].pkce_verifier, social.pkce_verifier);
    assert_eq!(winners[0].provider_id, social.provider_id);
}

#[test]
fn each_federation_take_uses_the_single_eval_matching_path() {
    let source = include_str!("../src/authentication.rs");
    let helper = source.split("async fn take_federation_value(").nth(1).unwrap()
        .split("async fn take_value(").next().unwrap();
    assert_eq!(helper.matches("command::eval_string(").count(), 1);
    for forbidden in ["command::get(", "command::take(", "command::delete("] {
        assert!(!helper.contains(forbidden));
    }
    for name in ["oidc", "social"] {
        let signature = format!("pub async fn take_{name}_federation(");
        let body = source.split(signature.as_str()).nth(1).unwrap().split("\n    pub ").next().unwrap();
        assert_eq!(body.matches("self.take_federation_value(").count(), 1);
        assert!(!body.contains("self.take_value("));
    }
}
