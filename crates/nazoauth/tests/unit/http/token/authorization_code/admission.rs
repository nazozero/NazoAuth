use super::*;

fn unavailable_valkey_client() -> fred::prelude::Client {
    let mut builder = ValkeyBuilder::from_config(
        ValkeyConfig::from_url("redis://127.0.0.1:1").expect("unavailable Valkey URL should parse"),
    );
    builder.with_performance_config(|performance: &mut PerformanceConfig| {
        performance.default_command_timeout = StdDuration::from_millis(200);
    });
    builder.with_connection_config(|connection: &mut ConnectionConfig| {
        connection.connection_timeout = StdDuration::from_millis(200);
        connection.internal_command_timeout = StdDuration::from_millis(200);
        connection.max_command_attempts = 1;
    });
    builder
        .build()
        .expect("unavailable valkey client construction should not connect")
}

fn test_state() -> TestInfrastructure {
    TestInfrastructure {
        diesel_db: create_pool(
            "postgres://nazo_auth_code_test_invalid:nazo_auth_code_test_invalid@127.0.0.1:1/nazo"
                .to_owned(),
            1,
        )
        .expect("pool construction should not connect"),
        valkey: unavailable_valkey_client(),
        settings: Arc::new(
            Settings::from_config(&ConfigSource::default()).expect("default settings should load"),
        ),
        keyset: crate::test_support::test_key_manager(),
    }
}

async fn load_pending_authorization_code_payload(
    state: &TestInfrastructure,
    code_hash: &str,
) -> Result<Option<Box<CodePayload>>, HttpResponse> {
    load_pending_authorization_code_payload_with_service(&test_token_service(state), code_hash)
        .await
        .map_err(nazo_http_actix::oauth_endpoint_error_response)
}

#[actix_web::test]
async fn pending_authorization_code_validation_covers_non_consuming_policy_boundaries() {
    let state = test_state();
    let config = crate::http::token::issue::token_issuance_config(state.settings.as_ref());
    let authorization = crate::http::token::issue::test_support::test_authorization_service(&state);
    let mut modules = state.active_module_snapshot();
    let client = pkce_policy_client();
    let mut payload = payload_for_client(&client);
    let mut form = form_for_code("pure-validation");

    {
        let issuance = TokenIssuanceContext {
            config: &config,
            modules: &modules,
            authorization: &authorization,
            security_audit: crate::http::authorization::test_support::test_security_audit(),
            remote_client_documents: crate::test_support::test_remote_client_documents(),
        };
        payload.expires_at = Utc::now() - Duration::seconds(1);
        let expired =
            validate_pending_authorization_code_request(&issuance, &client, &form, &payload)
                .map_err(nazo_http_actix::oauth_endpoint_error_response)
                .expect_err(
                    "expired pending authorization codes must be rejected before consumption",
                );
        assert_eq!(expired.status(), StatusCode::BAD_REQUEST);
        assert_eq!(oauth_error_code(expired).await, "invalid_grant");

        payload.expires_at = Utc::now() + Duration::seconds(60);
        payload.code_challenge = None;
        payload.code_challenge_method = None;
        for verifier in ["", "wrong-verifier", VALID_CODE_VERIFIER] {
            form.code_verifier = Some(verifier.to_owned());
            let downgrade =
                validate_pending_authorization_code_request(&issuance, &client, &form, &payload)
                    .map_err(nazo_http_actix::oauth_endpoint_error_response)
                    .expect_err("a verifier must never be accepted without an original challenge");
            assert_eq!(downgrade.status(), StatusCode::BAD_REQUEST);
            assert_eq!(oauth_error_code(downgrade).await, "invalid_grant");
        }
        form.code_verifier = None;
        let no_pkce = validate_pending_authorization_code_request(
            &issuance, &client, &form, &payload,
        )
        .map_err(nazo_http_actix::oauth_endpoint_error_response)
        .expect("confidential openid clients may redeem codes without PKCE when policy allows it");
        assert_eq!(no_pkce, vec!["resource://default".to_owned()]);

        payload.resource_indicators = vec!["resource://authorized".to_owned()];
        form.audiences = vec!["resource://outside".to_owned()];
        let outside_resource =
            validate_pending_authorization_code_request(&issuance, &client, &form, &payload)
                .map_err(nazo_http_actix::oauth_endpoint_error_response)
                .expect_err("a token resource outside the authorization must be rejected");
        assert_eq!(outside_resource.status(), StatusCode::BAD_REQUEST);
        assert_eq!(oauth_error_code(outside_resource).await, "invalid_target");

        payload.resource_indicators.clear();
        form.audiences.clear();
        payload.code_challenge = Some(pkce_s256(VALID_CODE_VERIFIER));
        payload.code_challenge_method = Some("S256".to_owned());
        form.code_verifier = Some(VALID_CODE_VERIFIER.to_owned());
        payload.scopes = vec![nazo_oauth_server::token::native_sso::DEVICE_SSO_SCOPE.to_owned()];
        let native_sso_disabled =
            validate_pending_authorization_code_request(&issuance, &client, &form, &payload)
                .map_err(nazo_http_actix::oauth_endpoint_error_response)
                .expect_err("Native SSO must be rejected when its runtime module is disabled");
        assert_eq!(native_sso_disabled.status(), StatusCode::BAD_REQUEST);
        assert_eq!(oauth_error_code(native_sso_disabled).await, "invalid_scope");
    }

    modules
        .accepting
        .insert(nazo_runtime_modules::ModuleId::NativeSso);
    let issuance = TokenIssuanceContext {
        config: &config,
        modules: &modules,
        authorization: &authorization,
        security_audit: crate::http::authorization::test_support::test_security_audit(),
        remote_client_documents: crate::test_support::test_remote_client_documents(),
    };
    let native_sso_without_openid =
        validate_pending_authorization_code_request(&issuance, &client, &form, &payload)
            .map_err(nazo_http_actix::oauth_endpoint_error_response)
            .expect_err("Native SSO must require the openid scope");
    assert_eq!(native_sso_without_openid.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        oauth_error_code(native_sso_without_openid).await,
        "invalid_scope"
    );
}

#[actix_web::test]
async fn authorization_code_grant_requires_code_before_state_lookup() {
    let state = test_state();
    let client = pkce_policy_client();
    let req = actix_web::test::TestRequest::post()
        .uri("/token")
        .to_http_request();
    let form = TokenForm {
        grant_type: "authorization_code".to_owned(),
        code: None,
        device_code: None,
        auth_req_id: None,
        redirect_uri: Some("https://client.example/callback".to_owned()),
        code_verifier: Some("verifier".to_owned()),
        refresh_token: None,
        device_secret: None,
        scope: None,
        client_id: Some("client-1".to_owned()),
        client_secret: None,
        client_assertion_type: None,
        client_assertion: None,
        assertion: None,
        requested_token_type: None,
        subject_token: None,
        subject_token_type: None,
        actor_token: None,
        actor_token_type: None,
        audiences: Vec::new(),
        has_audience_param: false,
    };

    let response = token_authorization_code(&state, &req, &client, &form, None).await;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(oauth_error_code(response).await, "invalid_request");
}

#[actix_web::test]
async fn authorization_code_helpers_fail_closed_when_valkey_is_unavailable() {
    let state = test_state();
    let code_hash = blake3_hex("code-unavailable");
    let client = pkce_policy_client();
    let req = actix_web::test::TestRequest::post()
        .uri("/token")
        .to_http_request();

    let pending = load_pending_authorization_code_payload(&state, &code_hash)
        .await
        .expect_err("unavailable Valkey must not be treated as an absent authorization code");
    assert_eq!(pending.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(oauth_error_code(pending).await, "server_error");

    let consuming = match begin_authorization_code_consumption(&state, &code_hash).await {
        Ok(_) => panic!("unavailable Valkey must not start authorization code consumption"),
        Err(response) => response,
    };
    assert_eq!(consuming.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(oauth_error_code(consuming).await, "server_error");

    let endpoint = token_authorization_code(
        &state,
        &req,
        &client,
        &form_for_code("code-unavailable"),
        None,
    )
    .await;
    assert_eq!(endpoint.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(oauth_error_code(endpoint).await, "server_error");
}

#[actix_web::test]
async fn load_pending_authorization_code_payload_reads_pending_missing_and_malformed_states() {
    let Some(fixture) = LiveAuthorizationCodeFixture::new().await else {
        return;
    };
    let client = live_client("live-load-client");
    let pending_code = format!("code-{}", Uuid::now_v7());
    fixture
        .store_code_state(
            &pending_code,
            &AuthorizationCodeState::Pending {
                payload: payload_for_client(&client),
            },
        )
        .await;

    let pending =
        load_pending_authorization_code_payload(&fixture.state, &blake3_hex(&pending_code))
            .await
            .expect("pending state should load");
    assert_eq!(
        pending.expect("pending payload should exist").client_id,
        client.client_id
    );

    let missing =
        load_pending_authorization_code_payload(&fixture.state, &blake3_hex("missing-code"))
            .await
            .expect("missing state should not error");
    assert!(missing.is_none());

    let malformed_code = format!("code-{}", Uuid::now_v7());
    fixture
        .store_raw_code_state(&malformed_code, "{not-json")
        .await;
    let malformed =
        load_pending_authorization_code_payload(&fixture.state, &blake3_hex(&malformed_code))
            .await
            .expect_err("malformed authorization code state must fail closed");
    assert_eq!(malformed.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(oauth_error_code(malformed).await, "server_error");
}

#[actix_web::test]
async fn token_authorization_code_rejects_client_binding_mismatch_without_consuming_code() {
    let Some(fixture) = LiveAuthorizationCodeFixture::new().await else {
        return;
    };
    let client = live_client("client-bound");
    let mut payload = payload_for_client(&client);
    payload.client_id = "different-client".to_owned();
    let code = format!("code-{}", Uuid::now_v7());
    fixture
        .store_code_state(&code, &AuthorizationCodeState::Pending { payload })
        .await;
    let req = actix_web::test::TestRequest::post()
        .uri("/token")
        .to_http_request();
    let form = form_for_code(&code);

    let response = token_authorization_code(&fixture.state, &req, &client, &form, None).await;
    let (status, body) = token_json_body(response).await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_grant");
    assert!(matches!(
        fixture.code_state(&code).await,
        AuthorizationCodeState::Pending { .. }
    ));
}

#[actix_web::test]
async fn token_authorization_code_preserves_pending_state_for_redirect_pkce_and_audience_errors() {
    let Some(fixture) = LiveAuthorizationCodeFixture::new().await else {
        return;
    };
    let req = actix_web::test::TestRequest::post()
        .uri("/token")
        .to_http_request();
    let client = live_client("client-failure-cases");

    let no_challenge_code = format!("code-{}", Uuid::now_v7());
    let mut no_challenge_payload = payload_for_client(&client);
    no_challenge_payload.code_challenge = None;
    no_challenge_payload.code_challenge_method = None;
    fixture
        .store_code_state(
            &no_challenge_code,
            &AuthorizationCodeState::Pending {
                payload: no_challenge_payload,
            },
        )
        .await;
    for verifier in ["", "wrong-verifier", VALID_CODE_VERIFIER] {
        let mut form = form_for_code(&no_challenge_code);
        form.code_verifier = Some(verifier.to_owned());
        let response = token_authorization_code(&fixture.state, &req, &client, &form, None).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(oauth_error_code(response).await, "invalid_grant");
        assert!(matches!(
            fixture.code_state(&no_challenge_code).await,
            AuthorizationCodeState::Pending { .. }
        ));
    }

    let redirect_code = format!("code-{}", Uuid::now_v7());
    fixture
        .store_code_state(
            &redirect_code,
            &AuthorizationCodeState::Pending {
                payload: payload_for_client(&client),
            },
        )
        .await;
    let mut redirect_form = form_for_code(&redirect_code);
    redirect_form.redirect_uri = Some("https://attacker.example/callback".to_owned());
    let redirect_response =
        token_authorization_code(&fixture.state, &req, &client, &redirect_form, None).await;
    assert_eq!(oauth_error_code(redirect_response).await, "invalid_grant");
    assert!(matches!(
        fixture.code_state(&redirect_code).await,
        AuthorizationCodeState::Pending { .. }
    ));

    let missing_verifier_code = format!("code-{}", Uuid::now_v7());
    fixture
        .store_code_state(
            &missing_verifier_code,
            &AuthorizationCodeState::Pending {
                payload: payload_for_client(&client),
            },
        )
        .await;
    let mut missing_verifier_form = form_for_code(&missing_verifier_code);
    missing_verifier_form.code_verifier = None;
    let missing_verifier_response =
        token_authorization_code(&fixture.state, &req, &client, &missing_verifier_form, None).await;
    assert_eq!(
        oauth_error_code(missing_verifier_response).await,
        "invalid_grant"
    );
    assert!(matches!(
        fixture.code_state(&missing_verifier_code).await,
        AuthorizationCodeState::Pending { .. }
    ));

    let pkce_failed_code = format!("code-{}", Uuid::now_v7());
    fixture
        .store_code_state(
            &pkce_failed_code,
            &AuthorizationCodeState::Pending {
                payload: payload_for_client(&client),
            },
        )
        .await;
    let mut pkce_failed_form = form_for_code(&pkce_failed_code);
    pkce_failed_form.code_verifier = Some("wrong-verifier".to_owned());
    let pkce_failed_response =
        token_authorization_code(&fixture.state, &req, &client, &pkce_failed_form, None).await;
    assert_eq!(
        oauth_error_code(pkce_failed_response).await,
        "invalid_grant"
    );
    assert!(matches!(
        fixture.code_state(&pkce_failed_code).await,
        AuthorizationCodeState::Pending { .. }
    ));

    let pkce_state_code = format!("code-{}", Uuid::now_v7());
    let mut pkce_state_payload = payload_for_client(&client);
    pkce_state_payload.code_challenge_method = None;
    fixture
        .store_code_state(
            &pkce_state_code,
            &AuthorizationCodeState::Pending {
                payload: pkce_state_payload,
            },
        )
        .await;
    let pkce_state_response = token_authorization_code(
        &fixture.state,
        &req,
        &client,
        &form_for_code(&pkce_state_code),
        None,
    )
    .await;
    assert_eq!(
        pkce_state_response.status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(oauth_error_code(pkce_state_response).await, "server_error");
    assert!(matches!(
        fixture.code_state(&pkce_state_code).await,
        AuthorizationCodeState::Pending { .. }
    ));

    let audience_code = format!("code-{}", Uuid::now_v7());
    fixture
        .store_code_state(
            &audience_code,
            &AuthorizationCodeState::Pending {
                payload: payload_for_client(&client),
            },
        )
        .await;
    let mut audience_form = form_for_code(&audience_code);
    audience_form.audiences = vec!["resource://other".to_owned()];
    let audience_response =
        token_authorization_code(&fixture.state, &req, &client, &audience_form, None).await;
    assert_eq!(audience_response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(oauth_error_code(audience_response).await, "invalid_target");
    assert!(matches!(
        fixture.code_state(&audience_code).await,
        AuthorizationCodeState::Pending { .. }
    ));
}
