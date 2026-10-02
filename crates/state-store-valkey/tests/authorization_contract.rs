use std::{collections::HashMap, sync::Arc, time::Duration};

use chrono::{TimeZone, Utc};
use fred::interfaces::{ClientLike, KeysInterface, LuaInterface};
use fred::prelude::{Builder, Config, Expiration};
use nazo_auth::{
    AuthorizationCodeState, AuthorizationPortError, AuthorizationStateStorePort, CodePayload,
    ConsentPayload, ConsumedAuthorizationCode, DecisionMaterialDiscardError,
    DecisionMaterialDiscardOutcome, PushedAuthorizationRequest,
};
use nazo_identity::TenantId;
use nazo_valkey::{
    AuthorizationCodeBegin, AuthorizationPreparationWrite, AuthorizationStateAdapter,
    AuthorizationStore, AuthorizationTransition, ValkeyConnection,
};
use serde_json::json;

async fn setup() -> Option<(AuthorizationStore, fred::prelude::Client)> {
    let url = std::env::var("VALKEY_URL").ok()?;
    let connection = nazo_valkey::test_support::scoped_connect(&url, Duration::from_secs(1))
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

fn consent_payload(request_id: &str, user_id: uuid::Uuid) -> ConsentPayload {
    ConsentPayload {
        request_id: request_id.to_owned(),
        user_id,
        client_id: "client-a".to_owned(),
        client_name: "Client A".to_owned(),
        redirect_uri: "https://client.example/cb".to_owned(),
        redirect_uri_was_supplied: true,
        scopes: vec!["openid".to_owned()],
        resource_indicators: Vec::new(),
        authorization_details: json!([]),
        state: Some("state".to_owned()),
        response_mode: None,
        nonce: Some("nonce".to_owned()),
        auth_time: 1_000,
        amr: vec!["password".to_owned()],
        oidc_sid: Some("sid".to_owned()),
        acr: None,
        userinfo_claims: Vec::new(),
        userinfo_claim_requests: Vec::new(),
        id_token_claims: Vec::new(),
        id_token_claim_requests: Vec::new(),
        code_challenge: None,
        code_challenge_method: None,
        dpop_jkt: None,
        mtls_x5t_s256: None,
        pushed_request_uri: None,
        pushed_request_digest: None,
        signed_authorization_response_required: None,
        session_management_allowed: None,
        authorization_code_ttl_seconds: None,
        issued_at: Utc.timestamp_opt(1_000, 0).unwrap(),
        expires_at: Utc.timestamp_opt(1_030, 0).unwrap(),
    }
}

fn par_payload() -> PushedAuthorizationRequest {
    PushedAuthorizationRequest {
        client_id: "client-a".to_owned(),
        params: HashMap::from([("scope".to_owned(), "openid".to_owned())]),
        dpop_jkt: None,
        mtls_x5t_s256: None,
        issued_at: Utc.timestamp_opt(1_000, 0).unwrap(),
        expires_at: Utc.timestamp_opt(1_030, 0).unwrap(),
    }
}

#[tokio::test]
async fn decision_cleanup_uses_raw_versions_and_supports_consent_without_par() {
    let Some((store, inspector)) = setup().await else {
        return;
    };
    let connection = nazo_valkey::test_support::scoped_connection(inspector.clone());
    let adapter: Arc<dyn AuthorizationStateStorePort> =
        Arc::new(AuthorizationStateAdapter::new(&connection));
    for include_par in [false, true] {
        let request_id = uuid::Uuid::now_v7().to_string();
        let request_uri = format!("urn:ietf:params:oauth:request_uri:{}", uuid::Uuid::now_v7());
        let consent = consent_payload(&request_id, uuid::Uuid::from_u128(1));
        let par = par_payload();
        // Deliberately use different wire formatting from normal store writes.
        // Only the observed bytes, never reserialized payloads, may be removed.
        for (key, raw) in [
            (
                nazo_valkey::test_support::consent_storage_key(&request_id),
                serde_json::to_string_pretty(&consent).unwrap(),
            ),
            (
                nazo_valkey::test_support::par_storage_key(&request_uri),
                serde_json::to_string_pretty(&par).unwrap(),
            ),
        ] {
            inspector
                .set::<(), _, _>(key, raw, Some(Expiration::EX(30)), None, false)
                .await
                .unwrap();
        }
        let consent = adapter.load_consent(&request_id).await.unwrap().unwrap();
        let par = adapter.load_par(&request_uri).await.unwrap().unwrap();
        let pushed_request = include_par.then_some((request_uri.as_str(), par.version.as_str()));
        assert_eq!(
            adapter
                .discard_decision_material(&request_id, &consent.version, pushed_request)
                .await,
            Ok(DecisionMaterialDiscardOutcome::Discarded)
        );
        assert!(adapter.load_consent(&request_id).await.unwrap().is_none());
        assert_eq!(
            adapter.load_par(&request_uri).await.unwrap().is_none(),
            include_par
        );
        assert_eq!(
            adapter
                .discard_decision_material(&request_id, &consent.version, pushed_request)
                .await,
            Ok(DecisionMaterialDiscardOutcome::ConsentMissingOrChanged)
        );
        if !include_par {
            assert_eq!(
                adapter
                    .load_par(&request_uri)
                    .await
                    .unwrap()
                    .unwrap()
                    .version,
                par.version
            );
            assert!(
                store
                    .compare_and_delete_par(&request_uri, &par.version)
                    .await
                    .unwrap()
            );
        }
    }
}

#[tokio::test]
async fn decision_cleanup_preserves_replacements_and_original_partial_cleanup_order() {
    let Some((store, inspector)) = setup().await else {
        return;
    };
    for change_consent in [false, true] {
        for remove_instead in [false, true] {
            let request_id = uuid::Uuid::now_v7().to_string();
            let request_uri = format!("urn:ietf:params:oauth:request_uri:{}", uuid::Uuid::now_v7());
            let consent = consent_payload(&request_id, uuid::Uuid::from_u128(1));
            let par = par_payload();
            assert_eq!(
                store
                    .store_consent(&request_id, &consent, 30)
                    .await
                    .unwrap(),
                AuthorizationPreparationWrite::Stored
            );
            assert_eq!(
                store.store_par(&request_uri, &par, 30).await.unwrap(),
                AuthorizationPreparationWrite::Stored
            );
            let consent_snapshot = store
                .load_consent_snapshot(&request_id)
                .await
                .unwrap()
                .unwrap();
            let par_snapshot = store.load_par(&request_uri).await.unwrap().unwrap();
            let (changed_key, replacement) = if change_consent {
                (
                    nazo_valkey::test_support::consent_storage_key(&request_id),
                    serde_json::to_string_pretty(&consent).unwrap(),
                )
            } else {
                (
                    nazo_valkey::test_support::par_storage_key(&request_uri),
                    serde_json::to_string_pretty(&par).unwrap(),
                )
            };
            if remove_instead {
                inspector.del::<i64, _>(&changed_key).await.unwrap();
            } else {
                inspector
                    .set::<(), _, _>(
                        &changed_key,
                        &replacement,
                        Some(Expiration::EX(30)),
                        None,
                        false,
                    )
                    .await
                    .unwrap();
            }
            let outcome = store
                .discard_decision_material(
                    &request_id,
                    &consent_snapshot.version,
                    Some((&request_uri, &par_snapshot.version)),
                )
                .await
                .unwrap();
            assert_eq!(
                outcome,
                if change_consent {
                    DecisionMaterialDiscardOutcome::ConsentMissingOrChanged
                } else {
                    DecisionMaterialDiscardOutcome::ParMissingOrChanged
                }
            );
            if change_consent {
                assert_eq!(
                    store.load_par(&request_uri).await.unwrap().unwrap().version,
                    par_snapshot.version
                );
            } else {
                assert!(
                    store
                        .load_consent_snapshot(&request_id)
                        .await
                        .unwrap()
                        .is_none()
                );
            }
            let current: Option<String> = inspector.get(&changed_key).await.unwrap();
            assert_eq!(current, (!remove_instead).then_some(replacement));
            if !remove_instead {
                assert!((1..=30).contains(&inspector.ttl::<i64, _>(&changed_key).await.unwrap()));
            }
            inspector
                .del::<i64, _>(vec![
                    nazo_valkey::test_support::consent_storage_key(&request_id),
                    nazo_valkey::test_support::par_storage_key(&request_uri),
                ])
                .await
                .unwrap();
        }
    }
}

#[tokio::test]
async fn decision_cleanup_wrong_type_is_an_error_at_the_confirmed_stage() {
    let Some((store, inspector)) = setup().await else {
        return;
    };
    let connection = nazo_valkey::test_support::scoped_connection(inspector.clone());
    let adapter = AuthorizationStateAdapter::new(&connection);
    for corrupt_consent in [false, true] {
        let request_id = uuid::Uuid::now_v7().to_string();
        let request_uri = format!("urn:ietf:params:oauth:request_uri:{}", uuid::Uuid::now_v7());
        adapter
            .store_consent(
                &request_id,
                &consent_payload(&request_id, uuid::Uuid::from_u128(1)),
                30,
            )
            .await
            .unwrap();
        adapter
            .store_par(&request_uri, &par_payload(), 30)
            .await
            .unwrap();
        let consent = adapter.load_consent(&request_id).await.unwrap().unwrap();
        let par = adapter.load_par(&request_uri).await.unwrap().unwrap();
        let key = if corrupt_consent {
            nazo_valkey::test_support::consent_storage_key(&request_id)
        } else {
            nazo_valkey::test_support::par_storage_key(&request_uri)
        };
        inspector
            .eval::<i64, _, _, _>(
                "redis.call('DEL', KEYS[1]); \
                 redis.call('LPUSH', KEYS[1], 'wrong-type'); \
                 return redis.call('EXPIRE', KEYS[1], 30)",
                vec![key.clone()],
                Vec::<String>::new(),
            )
            .await
            .unwrap();
        let error = adapter
            .discard_decision_material(
                &request_id,
                &consent.version,
                Some((&request_uri, &par.version)),
            )
            .await
            .unwrap_err();
        assert_eq!(
            error,
            if corrupt_consent {
                DecisionMaterialDiscardError::ConsentOrUnknown(AuthorizationPortError::Unexpected)
            } else {
                DecisionMaterialDiscardError::PushedRequest(AuthorizationPortError::Unexpected)
            }
        );
        assert_eq!(inspector.exists::<i64, _>(&key).await.unwrap(), 1);
        if corrupt_consent {
            assert_eq!(
                store.load_par(&request_uri).await.unwrap().unwrap().version,
                par.version
            );
        } else {
            assert!(
                store
                    .load_consent_snapshot(&request_id)
                    .await
                    .unwrap()
                    .is_none()
            );
        }
        inspector
            .del::<i64, _>(vec![
                nazo_valkey::test_support::consent_storage_key(&request_id),
                nazo_valkey::test_support::par_storage_key(&request_uri),
            ])
            .await
            .unwrap();
    }
}

#[tokio::test]
async fn decision_cleanup_keeps_tenant_deployment_and_epoch_boundaries() {
    let Some((_, inspector)) = setup().await else {
        return;
    };
    let deployment = format!("cleanup-{}", uuid::Uuid::now_v7());
    let other_deployment = format!("cleanup-other-{}", uuid::Uuid::now_v7());
    let epoch = uuid::Uuid::now_v7();
    let tenant = TenantId::new(uuid::Uuid::from_u128(0x700)).unwrap();
    let other_tenant = TenantId::new(uuid::Uuid::from_u128(0x701)).unwrap();
    let request_id = uuid::Uuid::now_v7().to_string();
    let request_uri = format!("urn:ietf:params:oauth:request_uri:{}", uuid::Uuid::now_v7());
    let consent = consent_payload(&request_id, uuid::Uuid::from_u128(1));
    let par = par_payload();
    let mut adapters = Vec::new();
    for (deployment, epoch, tenant) in [
        (deployment.as_str(), epoch, tenant),
        (deployment.as_str(), epoch, other_tenant),
        (other_deployment.as_str(), epoch, tenant),
        (deployment.as_str(), uuid::Uuid::now_v7(), tenant),
    ] {
        let connection =
            ValkeyConnection::from_existing_client(inspector.clone(), deployment, epoch, tenant)
                .unwrap();
        let adapter: Arc<dyn AuthorizationStateStorePort> =
            Arc::new(AuthorizationStateAdapter::new(&connection));
        adapter
            .store_consent(&request_id, &consent, 30)
            .await
            .unwrap();
        adapter.store_par(&request_uri, &par, 30).await.unwrap();
        adapters.push(adapter);
    }
    let consent = adapters[0]
        .load_consent(&request_id)
        .await
        .unwrap()
        .unwrap();
    let par = adapters[0].load_par(&request_uri).await.unwrap().unwrap();
    // All namespaces intentionally contain the same logical identities and bytes.
    for (index, adapter) in adapters.iter().enumerate() {
        assert_eq!(
            adapter
                .load_consent(&request_id)
                .await
                .unwrap()
                .unwrap()
                .version,
            consent.version
        );
        assert_eq!(
            adapter
                .load_par(&request_uri)
                .await
                .unwrap()
                .unwrap()
                .version,
            par.version
        );
        assert_eq!(
            adapter
                .discard_decision_material(
                    &request_id,
                    &consent.version,
                    Some((&request_uri, &par.version)),
                )
                .await,
            Ok(DecisionMaterialDiscardOutcome::Discarded)
        );
        assert!(adapter.load_consent(&request_id).await.unwrap().is_none());
        assert!(adapter.load_par(&request_uri).await.unwrap().is_none());
        for other in &adapters[index + 1..] {
            assert_eq!(
                other
                    .load_consent(&request_id)
                    .await
                    .unwrap()
                    .unwrap()
                    .version,
                consent.version
            );
            assert_eq!(
                other.load_par(&request_uri).await.unwrap().unwrap().version,
                par.version
            );
        }
    }
}

#[tokio::test]
async fn par_preserves_exact_hashed_key_json_ttl_and_conditional_cleanup() {
    let Some((store, inspector)) = setup().await else {
        return;
    };
    let request_uri = format!("urn:ietf:params:oauth:request_uri:{}", uuid::Uuid::now_v7());
    let key = nazo_valkey::test_support::par_storage_key(&request_uri);
    let payload = PushedAuthorizationRequest {
        client_id: "client-a".to_owned(),
        params: HashMap::from([("scope".to_owned(), "openid".to_owned())]),
        dpop_jkt: None,
        mtls_x5t_s256: None,
        issued_at: Utc.timestamp_opt(1_000, 0).unwrap(),
        expires_at: Utc.timestamp_opt(1_030, 0).unwrap(),
    };

    assert_eq!(
        store.store_par(&request_uri, &payload, 30).await.unwrap(),
        AuthorizationPreparationWrite::Stored
    );
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&inspector.get::<String, _>(&key).await.unwrap())
            .unwrap(),
        serde_json::to_value(&payload).unwrap()
    );
    assert!((1..=30).contains(&inspector.ttl::<i64, _>(&key).await.unwrap()));
    let snapshot = store.load_par(&request_uri).await.unwrap().unwrap();
    assert!(
        store
            .compare_and_delete_par(&request_uri, &snapshot.version)
            .await
            .unwrap()
    );
    assert!(
        !store
            .compare_and_delete_par(&request_uri, &snapshot.version)
            .await
            .unwrap()
    );
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

#[tokio::test]
async fn concurrent_reauthentication_nonce_consumption_has_exactly_one_winner() {
    let Some((store, _)) = setup().await else {
        return;
    };
    let nonce = uuid::Uuid::now_v7().to_string();
    store.store_reauth_nonce(&nonce, 1_000, 30).await.unwrap();

    let (first, second) = tokio::join!(
        store.take_reauth_nonce(&nonce),
        store.take_reauth_nonce(&nonce),
    );
    let results = [first.unwrap(), second.unwrap()];
    assert_eq!(
        results
            .into_iter()
            .filter(|started_at| *started_at == Some(1_000))
            .count(),
        1
    );
    assert_eq!(results.into_iter().filter(Option::is_none).count(), 1);
}

#[tokio::test]
async fn consent_rejects_replacement_and_retry_after_preview_without_refreshing_ttl() {
    let Some((store, inspector)) = setup().await else {
        return;
    };
    let request_id = uuid::Uuid::now_v7().to_string();
    let key = nazo_valkey::test_support::state_storage_key(format!("oauth:consent:{request_id}"));
    let observed = consent_payload(&request_id, uuid::Uuid::from_u128(1));
    let mut replacement = consent_payload(&request_id, uuid::Uuid::from_u128(2));
    replacement.expires_at = Utc.timestamp_opt(1_300, 0).unwrap();
    assert_eq!(
        store
            .store_consent(&request_id, &observed, 30)
            .await
            .unwrap(),
        AuthorizationPreparationWrite::Stored
    );
    let snapshot = store
        .load_consent_snapshot(&request_id)
        .await
        .unwrap()
        .unwrap();
    let original_ttl = inspector.pttl::<i64, _>(&key).await.unwrap();
    assert!((1..=30_000).contains(&original_ttl));

    for payload in [&replacement, &observed] {
        assert_eq!(
            store
                .store_consent(&request_id, payload, 300)
                .await
                .unwrap(),
            AuthorizationPreparationWrite::Conflict
        );
        assert_eq!(
            inspector.get::<String, _>(&key).await.unwrap(),
            snapshot.version
        );
        assert!((1..=original_ttl).contains(&inspector.pttl::<i64, _>(&key).await.unwrap()));
    }
    let unchanged = store.load_consent(&request_id).await.unwrap().unwrap();
    assert_eq!(unchanged.user_id, observed.user_id);
    assert_eq!(unchanged.expires_at, observed.expires_at);

    let replacement_id = uuid::Uuid::now_v7().to_string();
    replacement.request_id = replacement_id.clone();
    assert_eq!(
        store
            .store_consent(&replacement_id, &replacement, 30)
            .await
            .unwrap(),
        AuthorizationPreparationWrite::Stored
    );
    assert_eq!(
        store
            .load_consent(&replacement_id)
            .await
            .unwrap()
            .unwrap()
            .user_id,
        replacement.user_id
    );
    assert!(
        store
            .compare_and_delete_consent(&request_id, &snapshot.version)
            .await
            .unwrap()
    );
    assert!(store.load_consent(&replacement_id).await.unwrap().is_some());
    store.delete_consent(&replacement_id).await.unwrap();
}

#[tokio::test]
async fn concurrent_consent_cleanup_has_exactly_one_winner() {
    let Some((store, _)) = setup().await else {
        return;
    };
    let request_id = uuid::Uuid::now_v7().to_string();
    let observed = consent_payload(&request_id, uuid::Uuid::from_u128(1));
    assert_eq!(
        store
            .store_consent(&request_id, &observed, 30)
            .await
            .unwrap(),
        AuthorizationPreparationWrite::Stored
    );

    let snapshot = store
        .load_consent_snapshot(&request_id)
        .await
        .unwrap()
        .unwrap();
    let (first, second) = tokio::join!(
        store.compare_and_delete_consent(&request_id, &snapshot.version),
        store.compare_and_delete_consent(&request_id, &snapshot.version),
    );
    assert_eq!(
        [first.unwrap(), second.unwrap()]
            .into_iter()
            .filter(|deleted| *deleted)
            .count(),
        1
    );
}

#[tokio::test]
async fn par_rejects_replacement_and_retry_after_preview_without_refreshing_ttl() {
    let Some((store, inspector)) = setup().await else {
        return;
    };
    let request_uri = format!("urn:ietf:params:oauth:request_uri:{}", uuid::Uuid::now_v7());
    let key = nazo_valkey::test_support::par_storage_key(&request_uri);
    let observed = PushedAuthorizationRequest {
        client_id: "client-a".to_owned(),
        params: HashMap::from([("scope".to_owned(), "openid".to_owned())]),
        dpop_jkt: None,
        mtls_x5t_s256: None,
        issued_at: Utc.timestamp_opt(1_000, 0).unwrap(),
        expires_at: Utc.timestamp_opt(1_030, 0).unwrap(),
    };
    let mut replacement = observed.clone();
    replacement.client_id = "client-b".to_owned();
    replacement.expires_at = Utc.timestamp_opt(1_300, 0).unwrap();
    assert_eq!(
        store.store_par(&request_uri, &observed, 30).await.unwrap(),
        AuthorizationPreparationWrite::Stored
    );
    let snapshot = store.load_par(&request_uri).await.unwrap().unwrap();
    let original_ttl = inspector.pttl::<i64, _>(&key).await.unwrap();
    assert!((1..=30_000).contains(&original_ttl));

    for payload in [&replacement, &observed] {
        assert_eq!(
            store.store_par(&request_uri, payload, 300).await.unwrap(),
            AuthorizationPreparationWrite::Conflict
        );
        assert_eq!(
            inspector.get::<String, _>(&key).await.unwrap(),
            snapshot.version
        );
        assert!((1..=original_ttl).contains(&inspector.pttl::<i64, _>(&key).await.unwrap()));
    }
    let unchanged = store.load_par(&request_uri).await.unwrap().unwrap().payload;
    assert_eq!(unchanged.client_id, observed.client_id);
    assert_eq!(unchanged.expires_at, observed.expires_at);

    let replacement_uri = format!("urn:ietf:params:oauth:request_uri:{}", uuid::Uuid::now_v7());
    assert_eq!(
        store
            .store_par(&replacement_uri, &replacement, 30)
            .await
            .unwrap(),
        AuthorizationPreparationWrite::Stored
    );
    let replacement_snapshot = store.load_par(&replacement_uri).await.unwrap().unwrap();
    assert_eq!(
        replacement_snapshot.payload.client_id,
        replacement.client_id
    );
    assert!(
        store
            .compare_and_delete_par(&request_uri, &snapshot.version)
            .await
            .unwrap()
    );
    assert!(store.load_par(&replacement_uri).await.unwrap().is_some());
    assert!(
        store
            .compare_and_delete_par(&replacement_uri, &replacement_snapshot.version)
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn par_snapshot_cleanup_accepts_legacy_wire_with_reordered_multi_parameter_json() {
    let Some((store, inspector)) = setup().await else {
        return;
    };
    let request_uri = format!("urn:ietf:params:oauth:request_uri:{}", uuid::Uuid::now_v7());
    let observed = PushedAuthorizationRequest {
        client_id: "client-a".to_owned(),
        params: HashMap::from([
            (
                "redirect_uri".to_owned(),
                "https://client.example/cb".to_owned(),
            ),
            ("scope".to_owned(), "openid profile".to_owned()),
        ]),
        dpop_jkt: None,
        mtls_x5t_s256: None,
        issued_at: Utc.timestamp_opt(1_000, 0).unwrap(),
        expires_at: Utc.timestamp_opt(1_030, 0).unwrap(),
    };
    let key = nazo_valkey::test_support::par_storage_key(&request_uri);
    let reordered = format!(
        r#"{{"expires_at":{},"params":{{"scope":{},"redirect_uri":{}}},"client_id":{},"issued_at":{}}}"#,
        serde_json::to_string(&observed.expires_at).unwrap(),
        serde_json::to_string(&observed.params["scope"]).unwrap(),
        serde_json::to_string(&observed.params["redirect_uri"]).unwrap(),
        serde_json::to_string(&observed.client_id).unwrap(),
        serde_json::to_string(&observed.issued_at).unwrap(),
    );
    inspector
        .set::<(), _, _>(&key, reordered.clone(), None, None, false)
        .await
        .unwrap();
    let snapshot = store.load_par(&request_uri).await.unwrap().unwrap();
    assert_eq!(snapshot.version, reordered);
    assert_eq!(snapshot.payload.params, observed.params);

    assert!(
        store
            .compare_and_delete_par(&request_uri, &snapshot.version)
            .await
            .unwrap()
    );
    assert!(!inspector.exists::<bool, _>(&key).await.unwrap());
}

#[tokio::test]
async fn consent_snapshot_accepts_old_wire_but_rejects_rewritten_or_changed_state() {
    let Some((store, inspector)) = setup().await else {
        return;
    };
    let request_id = uuid::Uuid::now_v7().to_string();
    let key = nazo_valkey::test_support::state_storage_key(format!("oauth:consent:{request_id}"));
    let mut observed = consent_payload(&request_id, uuid::Uuid::from_u128(1));
    observed.authorization_details = json!([{
        "type": "payment_initiation",
        "actions": ["transfer"],
        "instructedAmount": {"amount": "123.50", "currency": "EUR"}
    }]);
    let canonical = serde_json::to_string(&observed).unwrap();
    let reordered = canonical.replace(
        r#""instructedAmount":{"amount":"123.50","currency":"EUR"}"#,
        r#""instructedAmount":{"currency":"EUR","amount":"123.50"}"#,
    );
    assert_ne!(canonical, reordered);
    inspector
        .set::<(), _, _>(&key, reordered.clone(), None, None, false)
        .await
        .unwrap();
    let snapshot = store
        .load_consent_snapshot(&request_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(snapshot.version, reordered);
    assert_eq!(
        snapshot.payload.authorization_details,
        observed.authorization_details
    );
    assert!(
        store
            .compare_and_delete_consent(&request_id, &snapshot.version)
            .await
            .unwrap()
    );

    inspector
        .set::<(), _, _>(&key, &reordered, None, None, false)
        .await
        .unwrap();
    let snapshot = store
        .load_consent_snapshot(&request_id)
        .await
        .unwrap()
        .unwrap();
    inspector
        .set::<(), _, _>(&key, canonical, None, None, false)
        .await
        .unwrap();
    assert!(
        !store
            .compare_and_delete_consent(&request_id, &snapshot.version)
            .await
            .unwrap()
    );
    assert!(inspector.exists::<bool, _>(&key).await.unwrap());

    let array = consent_payload(&request_id, uuid::Uuid::from_u128(1));
    // Deliberately bypass immutable preparation writes to inject legacy/corrupt wire state.
    inspector
        .set::<(), _, _>(
            &key,
            serde_json::to_string(&array).unwrap(),
            None,
            None,
            false,
        )
        .await
        .unwrap();
    let snapshot = store
        .load_consent_snapshot(&request_id)
        .await
        .unwrap()
        .unwrap();
    let object_replacement = serde_json::to_string(&array).unwrap().replace(
        r#""authorization_details":[]"#,
        r#""authorization_details":{}"#,
    );
    inspector
        .set::<(), _, _>(&key, object_replacement, None, None, false)
        .await
        .unwrap();
    assert!(
        !store
            .compare_and_delete_consent(&request_id, &snapshot.version)
            .await
            .unwrap()
    );
    assert!(inspector.exists::<bool, _>(&key).await.unwrap());
    store.delete_consent(&request_id).await.unwrap();
}

#[tokio::test]
async fn malformed_snapshot_and_corrupt_replacement_fail_closed_without_deleting() {
    let Some((store, inspector)) = setup().await else {
        return;
    };
    let request_id = uuid::Uuid::now_v7().to_string();
    let key = nazo_valkey::test_support::state_storage_key(format!("oauth:consent:{request_id}"));
    let expected = consent_payload(&request_id, uuid::Uuid::from_u128(1));
    inspector
        .set::<(), _, _>(&key, "{", None, None, false)
        .await
        .unwrap();

    let error = store.load_consent_snapshot(&request_id).await.unwrap_err();
    assert_eq!(error.kind(), nazo_valkey::ErrorKind::CorruptData);
    assert!(inspector.exists::<bool, _>(&key).await.unwrap());

    assert_eq!(
        store
            .store_consent(&request_id, &expected, 30)
            .await
            .unwrap(),
        AuthorizationPreparationWrite::Conflict
    );
    assert_eq!(inspector.get::<String, _>(&key).await.unwrap(), "{");
    // Reset this fault-injection fixture through the raw test inspector only.
    inspector
        .set::<(), _, _>(
            &key,
            serde_json::to_string(&expected).unwrap(),
            None,
            None,
            false,
        )
        .await
        .unwrap();
    let snapshot = store
        .load_consent_snapshot(&request_id)
        .await
        .unwrap()
        .unwrap();
    inspector
        .set::<(), _, _>(&key, "{", None, None, false)
        .await
        .unwrap();
    assert!(
        !store
            .compare_and_delete_consent(&request_id, &snapshot.version)
            .await
            .unwrap()
    );
    assert_eq!(inspector.get::<String, _>(&key).await.unwrap(), "{");
    store.delete_consent(&request_id).await.unwrap();
}

#[tokio::test]
async fn concurrent_preparation_writes_have_one_initial_winner() {
    let Some((store, _)) = setup().await else {
        return;
    };
    let request_id = uuid::Uuid::now_v7().to_string();
    let consent_a = consent_payload(&request_id, uuid::Uuid::from_u128(1));
    let consent_b = consent_payload(&request_id, uuid::Uuid::from_u128(2));
    let (first, second) = tokio::join!(
        store.store_consent(&request_id, &consent_a, 30),
        store.store_consent(&request_id, &consent_b, 30),
    );
    let first = first.unwrap();
    let second = second.unwrap();
    assert_eq!(
        [first, second]
            .into_iter()
            .filter(|outcome| *outcome == AuthorizationPreparationWrite::Stored)
            .count(),
        1
    );
    let expected_user = if first == AuthorizationPreparationWrite::Stored {
        consent_a.user_id
    } else {
        consent_b.user_id
    };
    assert_eq!(
        store
            .load_consent(&request_id)
            .await
            .unwrap()
            .unwrap()
            .user_id,
        expected_user
    );
    store.delete_consent(&request_id).await.unwrap();

    let request_uri = format!("urn:ietf:params:oauth:request_uri:{}", uuid::Uuid::now_v7());
    let par_a = PushedAuthorizationRequest {
        client_id: "client-a".to_owned(),
        params: HashMap::from([("scope".to_owned(), "openid".to_owned())]),
        dpop_jkt: None,
        mtls_x5t_s256: None,
        issued_at: Utc.timestamp_opt(1_000, 0).unwrap(),
        expires_at: Utc.timestamp_opt(1_030, 0).unwrap(),
    };
    let mut par_b = par_a.clone();
    par_b.client_id = "client-b".to_owned();
    let (first, second) = tokio::join!(
        store.store_par(&request_uri, &par_a, 30),
        store.store_par(&request_uri, &par_b, 30),
    );
    let first = first.unwrap();
    let second = second.unwrap();
    assert_eq!(
        [first, second]
            .into_iter()
            .filter(|outcome| *outcome == AuthorizationPreparationWrite::Stored)
            .count(),
        1
    );
    let expected_client = if first == AuthorizationPreparationWrite::Stored {
        par_a.client_id
    } else {
        par_b.client_id
    };
    let snapshot = store.load_par(&request_uri).await.unwrap().unwrap();
    assert_eq!(snapshot.payload.client_id, expected_client);
    assert!(
        store
            .compare_and_delete_par(&request_uri, &snapshot.version)
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn preparation_conflicts_and_cleanup_are_tenant_scoped() {
    let Some((_, inspector)) = setup().await else {
        return;
    };
    let connection_a = nazo_valkey::test_support::tenant_scoped_connection(
        inspector.clone(),
        TenantId::new(uuid::Uuid::from_u128(0x701)).unwrap(),
    );
    let connection_b = nazo_valkey::test_support::tenant_scoped_connection(
        inspector,
        TenantId::new(uuid::Uuid::from_u128(0x702)).unwrap(),
    );
    let store_a = AuthorizationStateAdapter::new(&connection_a);
    let store_b = AuthorizationStateAdapter::new(&connection_b);
    let request_id = uuid::Uuid::now_v7().to_string();
    let consent_a = consent_payload(&request_id, uuid::Uuid::from_u128(1));
    let consent_b = consent_payload(&request_id, uuid::Uuid::from_u128(2));
    store_a
        .store_consent(&request_id, &consent_a, 30)
        .await
        .unwrap();
    store_b
        .store_consent(&request_id, &consent_b, 30)
        .await
        .unwrap();
    for store in [&store_a, &store_b] {
        assert!(matches!(
            store.store_consent(&request_id, &consent_a, 300).await,
            Err(AuthorizationPortError::Conflict)
        ));
    }
    let snapshot_a = store_a.load_consent(&request_id).await.unwrap().unwrap();
    let snapshot_b = store_b.load_consent(&request_id).await.unwrap().unwrap();
    assert_eq!(snapshot_a.payload.user_id, consent_a.user_id);
    assert_eq!(snapshot_b.payload.user_id, consent_b.user_id);
    assert!(
        store_a
            .compare_and_delete_consent(&request_id, &snapshot_a.version)
            .await
            .unwrap()
    );
    assert!(store_a.load_consent(&request_id).await.unwrap().is_none());
    assert_eq!(
        store_b
            .load_consent(&request_id)
            .await
            .unwrap()
            .unwrap()
            .version,
        snapshot_b.version
    );
    assert!(
        store_b
            .compare_and_delete_consent(&request_id, &snapshot_b.version)
            .await
            .unwrap()
    );

    let request_uri = format!("urn:ietf:params:oauth:request_uri:{}", uuid::Uuid::now_v7());
    let par_a = PushedAuthorizationRequest {
        client_id: "client-a".to_owned(),
        params: HashMap::from([("scope".to_owned(), "openid".to_owned())]),
        dpop_jkt: None,
        mtls_x5t_s256: None,
        issued_at: Utc.timestamp_opt(1_000, 0).unwrap(),
        expires_at: Utc.timestamp_opt(1_030, 0).unwrap(),
    };
    let mut par_b = par_a.clone();
    par_b.client_id = "client-b".to_owned();
    store_a.store_par(&request_uri, &par_a, 30).await.unwrap();
    store_b.store_par(&request_uri, &par_b, 30).await.unwrap();
    for store in [&store_a, &store_b] {
        assert!(matches!(
            store.store_par(&request_uri, &par_a, 300).await,
            Err(AuthorizationPortError::Conflict)
        ));
    }
    let snapshot_a = store_a.load_par(&request_uri).await.unwrap().unwrap();
    let snapshot_b = store_b.load_par(&request_uri).await.unwrap().unwrap();
    assert_eq!(snapshot_a.payload.client_id, par_a.client_id);
    assert_eq!(snapshot_b.payload.client_id, par_b.client_id);
    assert!(
        store_a
            .compare_and_delete_par(&request_uri, &snapshot_a.version)
            .await
            .unwrap()
    );
    assert!(store_a.load_par(&request_uri).await.unwrap().is_none());
    assert_eq!(
        store_b
            .load_par(&request_uri)
            .await
            .unwrap()
            .unwrap()
            .version,
        snapshot_b.version
    );
    assert!(
        store_b
            .compare_and_delete_par(&request_uri, &snapshot_b.version)
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn authorization_code_transitions_keep_begin_ttl_and_terminal_replay_semantics() {
    let Some((store, inspector)) = setup().await else {
        return;
    };
    let code = uuid::Uuid::now_v7().to_string();
    let code_hash = blake3::hash(code.as_bytes()).to_hex().to_string();
    let key = nazo_valkey::test_support::authorization_code_storage_key(&code);
    let pending = AuthorizationCodeState::Pending {
        payload: code_payload(&code_hash),
    };
    store
        .store_authorization_code_hash(&code_hash, &pending, 30)
        .await
        .unwrap();
    let consumed = AuthorizationCodeState::Consumed {
        marker: ConsumedAuthorizationCode {
            client_id: uuid::Uuid::from_u128(3),
            redemption_binding: Some("request-binding".to_owned()),
            access_token_jti: "issued-jti".to_owned(),
            access_token_expires_at: 2_000,
            refresh_token_family_id: None,
        },
    };
    assert_eq!(
        store
            .mark_authorization_code(&code_hash, &consumed, 60)
            .await
            .unwrap(),
        AuthorizationTransition::Pending
    );
    let original_ttl = inspector.pttl::<i64, _>(&key).await.unwrap();
    assert!((1..=30_000).contains(&original_ttl));
    assert!(matches!(
        store
            .begin_authorization_code(&code_hash, Utc.timestamp_opt(1_001, 0).unwrap())
            .await
            .unwrap(),
        AuthorizationCodeBegin::Consuming(_)
    ));
    assert!((1..=original_ttl).contains(&inspector.pttl::<i64, _>(&key).await.unwrap()));
    assert!(matches!(
        store
            .load_authorization_code_hash(&code_hash)
            .await
            .unwrap()
            .unwrap(),
        AuthorizationCodeState::Consuming { .. }
    ));
    assert!(matches!(
        store
            .begin_authorization_code(&code_hash, Utc.timestamp_opt(1_002, 0).unwrap())
            .await
            .unwrap(),
        AuthorizationCodeBegin::Busy
    ));
    assert_eq!(
        store
            .mark_authorization_code(&code_hash, &consumed, 60)
            .await
            .unwrap(),
        AuthorizationTransition::Applied
    );
    assert!((31..=60).contains(&inspector.ttl::<i64, _>(&key).await.unwrap()));
    let replay = store
        .begin_authorization_code(&code_hash, Utc.timestamp_opt(1_003, 0).unwrap())
        .await
        .unwrap();
    match replay {
        AuthorizationCodeBegin::Consumed(AuthorizationCodeState::Consumed { marker }) => {
            assert_eq!(marker.access_token_jti, "issued-jti");
            assert_eq!(
                marker.redemption_binding.as_deref(),
                Some("request-binding")
            );
        }
        unexpected => panic!("expected terminal consumed marker, got {unexpected:?}"),
    }
    let failed = AuthorizationCodeState::Failed {
        failed_at: Utc.timestamp_opt(1_004, 0).unwrap(),
        error: "test failure".to_owned(),
    };
    assert_eq!(
        store
            .mark_authorization_code(&code_hash, &failed, 120)
            .await
            .unwrap(),
        AuthorizationTransition::Consumed
    );
    assert_eq!(
        serde_json::to_value(
            store
                .load_authorization_code_hash(&code_hash)
                .await
                .unwrap()
                .unwrap()
        )
        .unwrap(),
        serde_json::to_value(consumed).unwrap()
    );
    store
        .delete_authorization_code_hash(&code_hash)
        .await
        .unwrap();
}

#[tokio::test]
async fn invalid_preparation_ttl_remains_an_unexpected_dependency_error() {
    let Some((_, inspector)) = setup().await else {
        return;
    };
    let connection = nazo_valkey::test_support::scoped_connection(inspector);
    let store = AuthorizationStateAdapter::new(&connection);
    let request_id = uuid::Uuid::now_v7().to_string();
    let consent = consent_payload(&request_id, uuid::Uuid::from_u128(1));
    assert_eq!(
        store.store_consent(&request_id, &consent, 0).await,
        Err(AuthorizationPortError::Unexpected)
    );
    assert!(store.load_consent(&request_id).await.unwrap().is_none());

    let request_uri = format!("urn:ietf:params:oauth:request_uri:{}", uuid::Uuid::now_v7());
    let par = PushedAuthorizationRequest {
        client_id: "client-a".to_owned(),
        params: HashMap::from([("scope".to_owned(), "openid".to_owned())]),
        dpop_jkt: None,
        mtls_x5t_s256: None,
        issued_at: Utc.timestamp_opt(1_000, 0).unwrap(),
        expires_at: Utc.timestamp_opt(1_030, 0).unwrap(),
    };
    assert_eq!(
        store.store_par(&request_uri, &par, 0).await,
        Err(AuthorizationPortError::Unexpected)
    );
    assert!(store.load_par(&request_uri).await.unwrap().is_none());
}

#[tokio::test]
async fn authorization_code_begin_and_busy_retry_preserve_the_original_ttl() {
    let Some((store, inspector)) = setup().await else {
        return;
    };
    let code = uuid::Uuid::now_v7().to_string();
    let code_hash = blake3::hash(code.as_bytes()).to_hex().to_string();
    let key = nazo_valkey::test_support::authorization_code_storage_key(&code);
    let pending = AuthorizationCodeState::Pending {
        payload: code_payload(&code_hash),
    };
    store
        .store_authorization_code_hash(&code_hash, &pending, 2)
        .await
        .unwrap();
    let original_ttl = inspector.pttl::<i64, _>(&key).await.unwrap();
    assert!((1..=2_000).contains(&original_ttl));
    assert!(matches!(
        store
            .begin_authorization_code(&code_hash, Utc::now())
            .await
            .unwrap(),
        AuthorizationCodeBegin::Consuming(_)
    ));
    assert!(matches!(
        store
            .begin_authorization_code(&code_hash, Utc::now())
            .await
            .unwrap(),
        AuthorizationCodeBegin::Busy
    ));
    let remaining = inspector.pttl::<i64, _>(&key).await.unwrap();
    assert!(remaining > 0 && remaining <= original_ttl);
    tokio::time::sleep(Duration::from_millis(2_100)).await;
    assert!(
        store
            .load_authorization_code_hash(&code_hash)
            .await
            .unwrap()
            .is_none()
    );
    assert!(matches!(
        store
            .begin_authorization_code(&code_hash, Utc::now())
            .await
            .unwrap(),
        AuthorizationCodeBegin::Missing
    ));
}
