use std::collections::HashMap;

use super::*;

fn code() -> CodePayload {
    CodePayload {
        redemption_contract_version: nazo_auth::AUTHORIZATION_CODE_REDEMPTION_VERSION,
        code_id: "code-id".into(),
        user_id: uuid::Uuid::from_u128(1),
        client_id: "client".into(),
        redirect_uri: "https://client.example/cb".into(),
        redirect_uri_was_supplied: true,
        scopes: vec!["openid".into()],
        resource_indicators: vec![],
        authorization_details: serde_json::json!([{"type":"payment_initiation","amount":9007199254740993_u64,"ratio":1.23456789,"nested":[1,2,3]}]),
        nonce: None,
        auth_time: Timestamp::now().as_second(),
        amr: vec!["password".into()],
        oidc_sid: None,
        acr: None,
        userinfo_claim_requests: vec![].into(),
        id_token_claim_requests: vec![].into(),
        pkce: None.into(),
        dpop_jkt: None,
        mtls_x5t_s256: None,
        expires_at: Timestamp::now()
            .checked_add(std::time::Duration::from_secs(60))
            .unwrap(),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn authorization_code_has_one_consumer_and_preserves_payload_and_expiry() {
    let state = crate::test_support::test_state();
    let payload = code();
    AuthorizationStateStorePort::store_authorization_code(
        &state,
        "hash",
        &AuthorizationCodeState::Pending {
            payload: payload.clone(),
        },
        60,
    )
    .await
    .unwrap();
    let original: StoredCode = state
        .read_json(&state.key("code", &[b"hash"]))
        .unwrap()
        .unwrap();
    let mut tasks = Vec::new();
    for _ in 0..32 {
        let state = state.clone();
        tasks.push(tokio::spawn(async move {
            state
                .begin_authorization_code("hash", Timestamp::now())
                .await
                .unwrap()
        }));
    }
    let mut winners = 0;
    for task in tasks {
        match task.await.unwrap() {
            AuthorizationCodeBeginResult::Consuming(value) => {
                winners += 1;
                assert_eq!(value.authorization_details, payload.authorization_details);
            }
            AuthorizationCodeBeginResult::Busy => {}
            other => panic!("unexpected result {other:?}"),
        }
    }
    assert_eq!(winners, 1);
    let changed: StoredCode = state
        .read_json(&state.key("code", &[b"hash"]))
        .unwrap()
        .unwrap();
    assert_eq!(changed.expires_at_ms, original.expires_at_ms);
    assert_eq!(
        state
            .mark_authorization_code("hash", &AuthorizationCodeState::Consumed, 60)
            .await
            .unwrap(),
        AuthorizationCodeTransitionResult::Applied
    );
    assert!(matches!(
        state
            .begin_authorization_code("hash", Timestamp::now())
            .await
            .unwrap(),
        AuthorizationCodeBeginResult::Consumed(_)
    ));
    assert_eq!(
        state
            .mark_authorization_code("hash", &AuthorizationCodeState::Consumed, 60)
            .await
            .unwrap(),
        AuthorizationCodeTransitionResult::Consumed
    );
}

#[tokio::test]
async fn preparation_is_immutable_and_cas_uses_observed_bytes() {
    let state = crate::test_support::test_state();
    let payload = PushedAuthorizationRequest {
        client_id: "client".into(),
        params: HashMap::from([("scope".into(), "openid".into())]),
        dpop_jkt: None,
        mtls_x5t_s256: None,
        issued_at: Timestamp::now(),
        expires_at: Timestamp::now()
            .checked_add(std::time::Duration::from_secs(30))
            .unwrap(),
    };
    state.store_par("request", &payload, 30).await.unwrap();
    assert_eq!(
        state.store_par("request", &payload, 60).await,
        Err(AuthorizationPortError::Conflict)
    );
    let observed = state.load_par("request").await.unwrap().unwrap();
    assert!(
        !state
            .compare_and_delete_par("request", "wrong")
            .await
            .unwrap()
    );
    assert!(
        state
            .compare_and_delete_par("request", &observed.version)
            .await
            .unwrap()
    );
    assert!(state.load_par("request").await.unwrap().is_none());
}

#[tokio::test]
async fn original_code_deadline_is_checked_even_without_physical_expiry() {
    let state = crate::test_support::test_state();
    let key = state.key("code", &[b"expired"]);
    let code = AuthorizationCodeState::Pending { payload: code() };
    let raw = encode(&CodeRef {
        expires_at_ms: now_ms() - 1,
        state: &code,
    })
    .unwrap();
    state.volatile.with(|store| {
        store.set(&key, raw, None, SetCondition::Always);
    });
    assert!(
        state
            .load_authorization_code("expired")
            .await
            .unwrap()
            .is_none()
    );
    assert!(matches!(
        state
            .begin_authorization_code("expired", Timestamp::now())
            .await
            .unwrap(),
        AuthorizationCodeBeginResult::Missing
    ));
}

#[tokio::test]
async fn reauth_is_one_use_and_tenant_keys_do_not_overlap() {
    let state = crate::test_support::test_state();
    let mut other = state.clone();
    other.tenant_id = nazo_identity::TenantId::new(uuid::Uuid::from_u128(2)).unwrap();
    state
        .store_reauth_nonce("nonce", 1_234_567, 30)
        .await
        .unwrap();
    assert_eq!(other.take_reauth_nonce("nonce").await.unwrap(), None);
    assert_eq!(
        state.take_reauth_nonce("nonce").await.unwrap(),
        Some(1_234_567)
    );
    assert_eq!(state.take_reauth_nonce("nonce").await.unwrap(), None);
}
