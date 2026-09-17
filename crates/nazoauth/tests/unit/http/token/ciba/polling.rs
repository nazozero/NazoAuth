use super::*;

#[actix_web::test]
async fn token_ciba_rejects_a_missing_auth_req_id_before_state_access() {
    let state = ciba_test_state();
    let key = client_signing_fixture(jsonwebtoken::Algorithm::PS256);
    let client = ciba_private_key_jwt_client("missing-auth-req-id-kid", &key);
    let form = TokenForm {
        grant_type: CIBA_GRANT_TYPE.to_owned(),
        ..ciba_token_form("ignored".to_owned())
    };
    let form = TokenForm {
        auth_req_id: None,
        ..form
    };
    let request = actix_web::test::TestRequest::post()
        .uri("/token")
        .to_http_request();

    let response =
        call_ciba_token_with_form_for_test(&state, &client, form, request, None, "private_key_jwt")
            .await;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(oauth_error_code(response).await, "invalid_request");
}

#[actix_web::test]
async fn ciba_poll_storage_error_presenter_preserves_503_and_no_store() {
    let response = nazo_http_actix::oauth_endpoint_error_response(
        nazo_oauth_server::contracts::oauth_error::OAuthEndpointError::token(
            http::StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "CIBA state unavailable.",
            false,
        ),
    );

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        response
            .headers()
            .get(header::CACHE_CONTROL)
            .and_then(|value| value.to_str().ok()),
        Some("no-store")
    );
    assert_eq!(
        Some(oauth_error_code(response).await.as_str()),
        Some("server_error")
    );
}

#[actix_web::test]
async fn ciba_poll_error_presenter_preserves_invalid_grant_and_contention_headers() {
    for (description, expected_status, expected_error) in [
        (
            "CIBA auth_req_id is expired or consumed.",
            StatusCode::BAD_REQUEST,
            "invalid_grant",
        ),
        (
            "CIBA auth_req_id was not issued to this client.",
            StatusCode::BAD_REQUEST,
            "invalid_grant",
        ),
        (
            "CIBA state is busy.",
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
        ),
    ] {
        let response = nazo_http_actix::oauth_endpoint_error_response(
            nazo_oauth_server::contracts::oauth_error::OAuthEndpointError::token(
                http::StatusCode::from_u16(expected_status.as_u16()).expect("valid status"),
                expected_error,
                description,
                false,
            ),
        );
        assert_eq!(response.status(), expected_status);
        assert_eq!(
            response
                .headers()
                .get(header::CACHE_CONTROL)
                .and_then(|value| value.to_str().ok()),
            Some("no-store")
        );
        assert_eq!(
            Some(oauth_error_code(response).await.as_str()),
            Some(expected_error)
        );
    }
}

#[actix_web::test]
async fn ciba_token_poll_maps_pending_slow_down_and_denied_states() {
    let Some(mut state) = live_ciba_replay_state().await else {
        return;
    };
    configure_ciba_test_mtls_proxy(&mut state);
    let key = client_signing_fixture(jsonwebtoken::Algorithm::PS256);
    let mut client = ciba_private_key_jwt_client("poll-status-kid", &key);
    client.require_mtls_bound_tokens = true;
    persist_ciba_test_client(&state, &client).await;

    let pending_id = format!("pending-status-{}", Uuid::now_v7());
    store_ciba_state(&state, &client, &pending_id, CibaStatus::Pending).await;
    let pending = call_ciba_token_with_mtls_for_test(&state, &client, pending_id.clone()).await;
    assert_eq!(pending.status(), StatusCode::BAD_REQUEST);
    assert_eq!(oauth_error_code(pending).await, "authorization_pending");

    let slow_down = call_ciba_token_with_mtls_for_test(&state, &client, pending_id).await;
    assert_eq!(slow_down.status(), StatusCode::BAD_REQUEST);
    assert_eq!(oauth_error_code(slow_down).await, "slow_down");

    let denied_id = format!("denied-status-{}", Uuid::now_v7());
    store_ciba_state(&state, &client, &denied_id, CibaStatus::Denied).await;
    let denied = call_ciba_token_with_mtls_for_test(&state, &client, denied_id).await;
    assert_eq!(denied.status(), StatusCode::BAD_REQUEST);
    assert_eq!(oauth_error_code(denied).await, "access_denied");
}

#[actix_web::test]
async fn ciba_token_poll_fails_closed_for_approved_state_without_authentication_context() {
    let Some(mut state) = live_ciba_replay_state().await else {
        return;
    };
    configure_ciba_test_mtls_proxy(&mut state);
    let key = client_signing_fixture(jsonwebtoken::Algorithm::PS256);
    let mut client = ciba_private_key_jwt_client("missing-context-kid", &key);
    client.security_policy.allow_cross_device_flows = true;
    client.require_mtls_bound_tokens = true;
    persist_ciba_test_client(&state, &client).await;
    let auth_req_id = format!("approved-without-context-{}", Uuid::now_v7());
    let now = Utc::now().timestamp();
    CibaStore::new(&state.valkey_connection())
        .create(
            &auth_req_id,
            &CibaRequestState {
                client_id: client.client_id.clone(),
                user_id: Uuid::now_v7(),
                scopes: vec!["openid".to_owned()],
                audiences: vec!["resource://default".to_owned()],
                acr: None,
                authentication_context: None,
                binding_message: None,
                issued_at: now,
                status: CibaStatus::Approved,
                interval_seconds: 5,
                expires_at: now + 600,
                retention_expires_at: now + 720,
                last_poll_at: None,
                ping_notification: None,
            },
        )
        .await
        .expect("malformed approved CIBA fixture should reach the core validation boundary");

    let response = call_ciba_token_with_mtls_for_test(&state, &client, auth_req_id.clone()).await;

    assert_eq!(
        (response.status(), oauth_error_code(response).await),
        (StatusCode::SERVICE_UNAVAILABLE, "server_error".to_owned())
    );
    let store = CibaStore::new(&state.valkey_connection());
    assert!(
        nazo_valkey::CibaStore::load(&store, &auth_req_id)
            .await
            .expect("malformed state should remain inspectable")
            .is_some(),
        "a malformed approved state must not be redeemed"
    );
}

#[actix_web::test]
async fn ciba_token_poll_maps_an_expired_state_before_user_lookup() {
    let Some(mut state) = live_ciba_replay_state().await else {
        return;
    };
    configure_ciba_test_mtls_proxy(&mut state);
    let key = client_signing_fixture(jsonwebtoken::Algorithm::PS256);
    let mut client = ciba_private_key_jwt_client("expired-status-kid", &key);
    client.require_mtls_bound_tokens = true;
    persist_ciba_test_client(&state, &client).await;
    let auth_req_id = format!("expired-status-{}", Uuid::now_v7());
    let now = Utc::now().timestamp();
    CibaStore::new(&state.valkey_connection())
        .create(
            &auth_req_id,
            &CibaRequestState {
                client_id: client.client_id.clone(),
                user_id: Uuid::now_v7(),
                scopes: vec!["openid".to_owned()],
                audiences: vec!["resource://default".to_owned()],
                acr: None,
                authentication_context: None,
                binding_message: None,
                issued_at: now - 120,
                status: CibaStatus::Pending,
                interval_seconds: 5,
                expires_at: now - 1,
                retention_expires_at: now + 600,
                last_poll_at: None,
                ping_notification: None,
            },
        )
        .await
        .expect("expired CIBA state should be stored");

    let response = call_ciba_token_with_mtls_for_test(&state, &client, auth_req_id).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(oauth_error_code(response).await, "expired_token");
}
