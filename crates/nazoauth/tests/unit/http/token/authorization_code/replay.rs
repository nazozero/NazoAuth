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
        redemption_binding: Some(legacy_authorization_code_redemption_key(
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
    // A cached marker alone is no longer authority to revoke. Retain the
    // historical exact-request receipt to exercise the bounded legacy path.
    fixture
        .insert_single_use_issuance(
            &client,
            marker.redemption_binding.as_deref().unwrap(),
            &marker.access_token_jti,
            Some(family_id),
        )
        .await;
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
                    redemption_binding: Some(legacy_authorization_code_redemption_key(
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

/// After the short-lived code entry is gone, an exact replay must still be
/// detected through the committed single-use issuance row and revoke the
/// tokens the original redemption produced.
#[actix_web::test]
async fn token_authorization_code_replay_reads_back_committed_issuance_evidence() {
    let Some(fixture) = LiveAuthorizationCodeFixture::new().await else {
        return;
    };
    let client = live_client(&format!("client-ledger-replay-{}", Uuid::now_v7()));
    fixture.insert_client(&client).await;
    let family_id = Uuid::now_v7();
    fixture.insert_refresh_token(&client, family_id).await;

    let code = format!("code-{}", Uuid::now_v7());
    let access_token_jti = format!("access-jti-{}", Uuid::now_v7());
    let grant_key = legacy_authorization_code_redemption_key(
        &blake3_hex(&code),
        &form_for_code(&code),
        None,
        None,
        None,
    );
    fixture
        .insert_single_use_issuance(&client, &grant_key, &access_token_jti, Some(family_id))
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
            .access_token_revocation_count(&client, &access_token_jti)
            .await,
        1,
        "ledger-backed replay must revoke the access token the redemption issued"
    );
    assert!(
        fixture
            .refresh_token_revoked_at(&client, family_id)
            .await
            .is_some(),
        "ledger-backed replay must revoke the refresh token family"
    );

    // A replay carrying different proofs must not resolve the fence: the
    // grant key binds the redemption to its exact request, so a divergent
    // request is rejected as unknown rather than revoking another grant.
    let mut divergent = form_for_code(&code);
    divergent.scope = Some("openid email".to_owned());
    let divergent_response =
        token_authorization_code(&fixture.state, &req, &client, &divergent, None).await;
    assert_eq!(divergent_response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(oauth_error_code(divergent_response).await, "invalid_grant");
}

#[actix_web::test]
async fn committed_code_cleanup_success_failure_and_lost_ack_preserve_replay_revocation() {
    use fred::interfaces::KeysInterface as _;
    let mut settings = LiveAuthorizationCodeFixture::settings();
    settings.protocol.auth_code_ttl_seconds = 2;
    let Some(fixture) = LiveAuthorizationCodeFixture::new_with_settings_and_keyset(
        settings,
        crate::test_support::test_key_manager_with_algorithm(jsonwebtoken::Algorithm::RS256),
    )
    .await
    else {
        return;
    };
    let user = fixture.insert_user().await;
    let client = live_client(&format!("client-ttl-replay-{}", Uuid::now_v7()));
    fixture.insert_client(&client).await;
    let req = actix_web::test::TestRequest::post()
        .uri("/token")
        .to_http_request();
    for (fault, expire) in [
        (CodeCleanupFault::None, false),
        (CodeCleanupFault::BeforeDelete, false),
        (CodeCleanupFault::BeforeDelete, true),
        (CodeCleanupFault::AfterDelete, false),
    ] {
        let store = Arc::new(CodeCleanupStore {
            live: nazo_valkey::TokenIssuanceStateAdapter::new(&fixture.state.valkey_connection()),
            fault,
            delete_calls: std::sync::atomic::AtomicUsize::new(0),
        });
        let service = ServerTokenService::from_port(
            Arc::new(crate::test_support::token_issuance_repository(
                fixture.state.diesel_db.clone(),
            )),
            store.clone(),
            fixture.state.keyset.clone(),
        );
        let code = format!("code-{}", Uuid::now_v7());
        let mut payload = payload_for_client(&client);
        payload.user_id = user.id;
        payload.scopes = vec!["accounts".to_owned()];
        payload.expires_at = Utc::now() + Duration::minutes(5);
        fixture
            .store_code_state(&code, &AuthorizationCodeState::Pending { payload })
            .await;
        let key = authorization_code_key(&code);
        let initial_ttl = fixture.state.valkey.pttl::<i64, _>(&key).await.unwrap();
        let response = token_authorization_code_using_service(
            &fixture.state,
            &req,
            &client,
            &form_for_code(&code),
            None,
            &service,
        )
        .await;
        let (status, body) = token_json_body(response).await;
        assert_eq!(status, StatusCode::OK);
        let encoded = body["access_token"]
            .as_str()
            .unwrap()
            .split('.')
            .nth(1)
            .unwrap();
        let claims: Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(encoded).unwrap()).unwrap();
        let jti = claims["jti"].as_str().unwrap();
        assert_eq!(
            std::sync::atomic::AtomicUsize::load(
                &store.delete_calls,
                std::sync::atomic::Ordering::SeqCst
            ),
            1
        );
        let remaining = fixture.state.valkey.pttl::<i64, _>(&key).await.unwrap();
        if matches!(fault, CodeCleanupFault::BeforeDelete) {
            assert!(matches!(
                fixture.code_state(&code).await,
                AuthorizationCodeState::Consuming { .. }
            ));
            assert!(
                remaining > 0 && remaining <= initial_ttl,
                "failed cleanup must not refresh TTL"
            );
        } else {
            assert_eq!(
                remaining, -2,
                "confirmed commit releases the entire code payload"
            );
        }
        assert_eq!(
            fixture.access_token_revocation_count(&client, jti).await,
            0,
            "cleanup failure must not revoke committed tokens"
        );
        if expire {
            tokio::time::sleep(StdDuration::from_millis(2_100)).await;
            assert!(
                valkey_get(&fixture.state.valkey, key)
                    .await
                    .unwrap()
                    .is_none()
            );
        }
        let mut divergent = form_for_code(&code);
        divergent.scope = Some("different-proof".to_owned());
        let response =
            token_authorization_code(&fixture.state, &req, &client, &divergent, None).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            fixture.access_token_revocation_count(&client, jti).await,
            1,
            "scope representation does not change the original holder identity"
        );
        let response =
            token_authorization_code(&fixture.state, &req, &client, &form_for_code(&code), None)
                .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(oauth_error_code(response).await, "invalid_grant");
        assert_eq!(
            fixture.access_token_revocation_count(&client, jti).await,
            1,
            "a matching holder replay synchronously revokes through the durable receipt"
        );
    }
}

#[derive(Clone, Copy)]
enum CodeCleanupFault {
    None,
    BeforeDelete,
    AfterDelete,
}

/// Delegate state transitions to live Valkey, faulting only committed cleanup.
struct CodeCleanupStore {
    live: nazo_valkey::TokenIssuanceStateAdapter,
    fault: CodeCleanupFault,
    delete_calls: std::sync::atomic::AtomicUsize,
}
impl nazo_auth::TokenStateStorePort for CodeCleanupStore {
    fn load_authorization_code<'a>(
        &'a self,
        hash: &'a str,
    ) -> nazo_auth::TokenFuture<'a, Option<AuthorizationCodeState>> {
        self.live.load_authorization_code(hash)
    }
    fn begin_authorization_code<'a>(
        &'a self,
        hash: &'a str,
        now: DateTime<Utc>,
    ) -> nazo_auth::TokenFuture<'a, nazo_auth::AuthorizationCodeBeginResult> {
        self.live.begin_authorization_code(hash, now)
    }
    fn mark_authorization_code<'a>(
        &'a self,
        hash: &'a str,
        replacement: &'a AuthorizationCodeState,
        ttl: u64,
    ) -> nazo_auth::TokenFuture<'a, nazo_auth::AuthorizationCodeTransitionResult> {
        self.live.mark_authorization_code(hash, replacement, ttl)
    }
    fn delete_authorization_code<'a>(&'a self, hash: &'a str) -> nazo_auth::TokenFuture<'a, ()> {
        Box::pin(async move {
            self.delete_calls
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if matches!(self.fault, CodeCleanupFault::BeforeDelete) {
                return Err(nazo_auth::TokenPortError::Unavailable);
            }
            self.live.delete_authorization_code(hash).await?;
            if matches!(self.fault, CodeCleanupFault::AfterDelete) {
                return Err(nazo_auth::TokenPortError::Unavailable);
            }
            Ok(())
        })
    }
    fn increment_token_management_rate<'a>(
        &'a self,
        subject: &'a str,
        window: u64,
    ) -> nazo_auth::TokenFuture<'a, u64> {
        self.live.increment_token_management_rate(subject, window)
    }
    fn store_native_sso<'a>(
        &'a self,
        secret: &'a str,
        value: &'a Value,
        ttl: u64,
    ) -> nazo_auth::TokenFuture<'a, ()> {
        self.live.store_native_sso(secret, value, ttl)
    }
    fn load_native_sso<'a>(&'a self, secret: &'a str) -> nazo_auth::TokenFuture<'a, Option<Value>> {
        self.live.load_native_sso(secret)
    }
}
