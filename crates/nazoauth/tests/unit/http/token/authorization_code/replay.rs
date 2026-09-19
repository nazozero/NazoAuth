use super::*;

#[actix_web::test]
async fn begin_authorization_code_consumption_tracks_single_consumer_and_terminal_states() {
    let Some(fixture) = LiveAuthorizationCodeFixture::new().await else {
        return;
    };
    let client = live_client("live-consume-client");
    let code = format!("code-{}", Uuid::now_v7());
    fixture
        .store_code_state(
            &code,
            &AuthorizationCodeState::Pending {
                payload: payload_for_client(&client),
            },
        )
        .await;

    match begin_authorization_code_consumption(&fixture.state, &blake3_hex(&code))
        .await
        .expect("pending authorization code should start consuming")
    {
        AuthorizationCodeConsumption::Consuming(payload) => {
            assert_eq!(payload.client_id, client.client_id);
        }
        _ => panic!("pending authorization code must move into consuming state"),
    }

    assert!(matches!(
        begin_authorization_code_consumption(&fixture.state, &blake3_hex(&code))
            .await
            .expect("second consumer should observe busy state"),
        AuthorizationCodeConsumption::Busy
    ));

    let failed_code = format!("code-{}", Uuid::now_v7());
    fixture
        .store_code_state(
            &failed_code,
            &AuthorizationCodeState::Failed {
                failed_at: Utc::now(),
                error: "pkce_failed".to_owned(),
            },
        )
        .await;
    assert!(matches!(
        begin_authorization_code_consumption(&fixture.state, &blake3_hex(&failed_code))
            .await
            .expect("failed code should remain terminal"),
        AuthorizationCodeConsumption::Failed
    ));

    let malformed_code = format!("code-{}", Uuid::now_v7());
    fixture.store_raw_code_state(&malformed_code, "{").await;
    assert!(matches!(
        begin_authorization_code_consumption(&fixture.state, &blake3_hex(&malformed_code))
            .await
            .expect("malformed stored state should map to malformed consumption"),
        AuthorizationCodeConsumption::Malformed
    ));
}

#[actix_web::test]
async fn token_authorization_code_replay_revokes_previous_tokens_and_rejects_reuse() {
    let Some(fixture) = LiveAuthorizationCodeFixture::new().await else {
        return;
    };
    let client = live_client(&format!("client-replay-{}", Uuid::now_v7()));
    fixture.insert_client(&client).await;
    let family_id = Uuid::now_v7();
    fixture.insert_refresh_token(&client, family_id).await;

    let code = format!("code-{}", Uuid::now_v7());
    let marker = ConsumedAuthorizationCode {
        client_id: client.id,
        redemption_binding: Some(authorization_code_grant_key(
            &blake3_hex(&code),
            &form_for_code(&code),
            None,
            None,
            None,
        )),
        access_token_jti: format!("access-jti-{}", Uuid::now_v7()),
        access_token_expires_at: Utc::now().timestamp() + 300,
        refresh_token_family_id: Some(family_id),
    };
    fixture
        .store_code_state(
            &code,
            &AuthorizationCodeState::Consumed {
                marker: marker.clone(),
            },
        )
        .await;
    let req = actix_web::test::TestRequest::post()
        .uri("/token")
        .to_http_request();
    let response =
        token_authorization_code(&fixture.state, &req, &client, &form_for_code(&code), None).await;
    let (status, body) = token_json_body(response).await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_grant");
    assert_eq!(
        fixture
            .access_token_revocation_count(&client, &marker.access_token_jti)
            .await,
        1
    );
    assert!(
        fixture
            .refresh_token_revoked_at(&client, family_id)
            .await
            .is_some(),
        "authorization code replay must revoke the refresh token family"
    );

    let missing_client_code = format!("code-{}", Uuid::now_v7());
    fixture
        .store_code_state(
            &missing_client_code,
            &AuthorizationCodeState::Consumed {
                marker: ConsumedAuthorizationCode {
                    client_id: Uuid::now_v7(),
                    redemption_binding: None,
                    access_token_jti: "access-jti-2".to_owned(),
                    access_token_expires_at: Utc::now().timestamp() + 300,
                    refresh_token_family_id: None,
                },
            },
        )
        .await;
    let missing_client_response = token_authorization_code(
        &fixture.state,
        &req,
        &client,
        &form_for_code(&missing_client_code),
        None,
    )
    .await;
    assert_eq!(missing_client_response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        oauth_error_code(missing_client_response).await,
        "invalid_grant"
    );
    assert_eq!(
        fixture
            .access_token_revocation_count(&client, "access-jti-2")
            .await,
        0,
        "a marker bound to another client must not revoke the authenticated client's tokens"
    );
}

#[actix_web::test]
async fn token_authorization_code_replay_fails_closed_when_token_revocation_errors() {
    let Some(fixture) = LiveAuthorizationCodeFixture::new().await else {
        return;
    };
    let client = live_client(&format!("client-replay-db-error-{}", Uuid::now_v7()));
    let state = Data::new(TestInfrastructure {
        diesel_db: create_pool(
            "postgres://nazo_auth_code_test_invalid:nazo_auth_code_test_invalid@127.0.0.1:1/nazo"
                .to_owned(),
            1,
        )
        .expect("pool construction should not connect"),
        valkey: fixture.state.valkey.clone(),
        settings: fixture.state.settings.clone(),
        keyset: fixture.state.keyset.clone(),
    });
    let code = format!("code-{}", Uuid::now_v7());
    fixture
        .store_code_state(
            &code,
            &AuthorizationCodeState::Consumed {
                marker: ConsumedAuthorizationCode {
                    client_id: client.id,
                    redemption_binding: Some(authorization_code_grant_key(
                        &blake3_hex(&code),
                        &form_for_code(&code),
                        None,
                        None,
                        None,
                    )),
                    access_token_jti: format!("access-jti-{}", Uuid::now_v7()),
                    access_token_expires_at: Utc::now().timestamp() + 300,
                    refresh_token_family_id: Some(Uuid::now_v7()),
                },
            },
        )
        .await;
    let req = actix_web::test::TestRequest::post()
        .uri("/token")
        .to_http_request();

    let response =
        token_authorization_code(&state, &req, &client, &form_for_code(&code), None).await;

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(oauth_error_code(response).await, "server_error");
}

#[actix_web::test]
async fn token_authorization_code_reports_busy_failed_and_missing_states() {
    let Some(fixture) = LiveAuthorizationCodeFixture::new().await else {
        return;
    };
    let client = live_client("client-terminal");
    let req = actix_web::test::TestRequest::post()
        .uri("/token")
        .to_http_request();

    let consuming_code = format!("code-{}", Uuid::now_v7());
    fixture
        .store_code_state(
            &consuming_code,
            &AuthorizationCodeState::Consuming {
                payload: payload_for_client(&client),
                consuming_at: Utc::now(),
            },
        )
        .await;
    let consuming_response = token_authorization_code(
        &fixture.state,
        &req,
        &client,
        &form_for_code(&consuming_code),
        None,
    )
    .await;
    assert_eq!(consuming_response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(oauth_error_code(consuming_response).await, "invalid_grant");

    let expired_code = format!("code-{}", Uuid::now_v7());
    let mut expired_payload = payload_for_client(&client);
    expired_payload.expires_at = Utc::now() - Duration::seconds(1);
    fixture
        .store_code_state(
            &expired_code,
            &AuthorizationCodeState::Pending {
                payload: expired_payload,
            },
        )
        .await;
    let expired_response = token_authorization_code(
        &fixture.state,
        &req,
        &client,
        &form_for_code(&expired_code),
        None,
    )
    .await;
    assert_eq!(expired_response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(oauth_error_code(expired_response).await, "invalid_grant");
    assert!(matches!(
        fixture.code_state(&expired_code).await,
        AuthorizationCodeState::Pending { .. }
    ));

    let failed_code = format!("code-{}", Uuid::now_v7());
    fixture
        .store_code_state(
            &failed_code,
            &AuthorizationCodeState::Failed {
                failed_at: Utc::now(),
                error: "pkce_failed".to_owned(),
            },
        )
        .await;
    let failed_response = token_authorization_code(
        &fixture.state,
        &req,
        &client,
        &form_for_code(&failed_code),
        None,
    )
    .await;
    assert_eq!(failed_response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(oauth_error_code(failed_response).await, "invalid_grant");

    let missing_response = token_authorization_code(
        &fixture.state,
        &req,
        &client,
        &form_for_code("missing-code"),
        None,
    )
    .await;
    assert_eq!(missing_response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(oauth_error_code(missing_response).await, "invalid_grant");

    let malformed_code = format!("code-{}", Uuid::now_v7());
    fixture
        .store_raw_code_state(&malformed_code, r#"{"status":"unknown"}"#)
        .await;
    let malformed_response = token_authorization_code(
        &fixture.state,
        &req,
        &client,
        &form_for_code(&malformed_code),
        None,
    )
    .await;
    assert_eq!(malformed_response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(oauth_error_code(malformed_response).await, "server_error");
}
