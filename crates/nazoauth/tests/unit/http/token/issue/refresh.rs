use super::*;

async fn issue_native_sso_token_response(
    state: &TestInfrastructure,
    client: &ClientRow,
    issue: TokenIssue,
) -> HttpResponse {
    let mut modules = state.active_module_snapshot();
    modules
        .accepting
        .insert(nazo_runtime_modules::ModuleId::NativeSso);
    issue_token_response_with_modules(state, client, issue, modules).await
}

#[actix_web::test]
async fn native_sso_issue_fails_closed_when_the_runtime_module_is_disabled() {
    let state = issue_state_with_valid_signing_key();
    let client = client_with_grants(&["authorization_code", "refresh_token"]);
    let mut issue = token_issue_without_openid();
    issue.user_id = Some(Uuid::now_v7());
    issue.scopes = vec!["openid".to_owned(), "offline_access".to_owned()];
    issue.native_sso = Some(NativeSsoTokenBinding {
        device_secret: "device-secret".to_owned(),
        ds_hash: "device-hash".to_owned(),
        sid: "sid-1".to_owned(),
    });

    let response = issue_token_response(&state, &client, issue).await;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(oauth_error_code(response).await, "invalid_scope");
}

#[actix_web::test]
async fn native_sso_issue_requires_openid_before_token_signing() {
    let state = issue_state_with_valid_signing_key();
    let client = client_with_grants(&["authorization_code", "refresh_token"]);
    let mut issue = token_issue_without_openid();
    issue.native_sso = Some(NativeSsoTokenBinding {
        device_secret: "device-secret".to_owned(),
        ds_hash: "device-hash".to_owned(),
        sid: "sid-1".to_owned(),
    });

    let response = issue_token_response(&state, &client, issue).await;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(oauth_error_code(response).await, "invalid_scope");
}

#[actix_web::test]
async fn attested_client_refresh_token_requires_client_instance_binding() {
    let mut state = issue_state_with_valid_signing_key();
    Arc::get_mut(&mut state.settings)
        .expect("test state owns its settings")
        .modules
        .enable_openid4vci_issuer = true;
    let mut client = client_with_grants(&["authorization_code", "refresh_token"]);
    client.token_endpoint_auth_method = "attest_jwt_client_auth".to_owned();
    let mut issue = token_issue_without_openid();
    issue.authorization_details = json!([{
        "type": "openid_credential",
        "credential_configuration_id": "org.iso.18013.5.1.mDL"
    }]);
    issue.include_refresh = true;
    issue.refresh_token_client_attestation_jkt = None;

    let response = issue_token_response(&state, &client, issue).await;

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let body = actix_web::body::to_bytes(response.into_body())
        .await
        .expect("response body should collect");
    let value: Value = serde_json::from_slice(&body).expect("OAuth error body should be JSON");
    assert_eq!(
        value
            .get("error")
            .and_then(serde_json::Value::as_str)
            .expect("OAuth JSON should contain an error code"),
        "invalid_client_attestation"
    );
    assert_eq!(
        value.get("error"),
        Some(&json!("invalid_client_attestation"))
    );
    assert!(value.get("access_token").is_none());
    assert!(value.get("refresh_token").is_none());
    assert!(value.get("id_token").is_none());
}

#[actix_web::test]
async fn refresh_token_persistence_failure_does_not_return_partial_refresh_token() {
    let state = issue_state_with_valid_signing_key();
    let client = client_with_grants(&["client_credentials", "refresh_token"]);
    let mut issue = token_issue_without_openid();
    issue.user_id = None;
    issue.subject = client.client_id.clone();
    issue.scopes = vec!["accounts".to_owned(), "offline_access".to_owned()];
    issue.include_refresh = true;

    let response = issue_token_response(&state, &client, issue).await;

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body = actix_web::body::to_bytes(response.into_body())
        .await
        .expect("response body should collect");
    let value: Value = serde_json::from_slice(&body).expect("OAuth error body should be JSON");
    assert_eq!(
        value
            .get("error")
            .and_then(serde_json::Value::as_str)
            .expect("OAuth JSON should contain an error code"),
        "server_error"
    );
    assert!(value.get("refresh_token").is_none());
}

#[actix_web::test]
async fn refresh_token_rotation_failure_does_not_return_partial_credentials() {
    let state = issue_state_with_valid_signing_key();
    let client = client_with_grants(&["authorization_code", "refresh_token"]);
    let mut issue = token_issue_without_openid();
    issue.user_id = None;
    issue.subject = client.client_id.clone();
    issue.scopes = vec!["accounts".to_owned(), "offline_access".to_owned()];
    issue.include_refresh = true;
    issue.refresh_token_policy = RefreshTokenPolicy::Rotate {
        family_id: Uuid::now_v7(),
        rotated_from_id: Uuid::now_v7(),
    };
    set_refresh_authority_for_issue(&state, &client, &mut issue);

    let response = issue_token_response(&state, &client, issue).await;

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body = actix_web::body::to_bytes(response.into_body())
        .await
        .expect("response body should collect");
    let value: Value = serde_json::from_slice(&body).expect("OAuth error body should be JSON");
    assert_eq!(
        value
            .get("error")
            .and_then(serde_json::Value::as_str)
            .expect("OAuth JSON should contain an error code"),
        "server_error"
    );
    assert!(value.get("access_token").is_none());
    assert!(value.get("refresh_token").is_none());
    assert!(value.get("id_token").is_none());
}

#[actix_web::test]
async fn native_sso_issue_requires_a_refresh_session_before_persisting_device_state() {
    let Some(state) = issue_state_with_live_database() else {
        return;
    };
    let mut client = client_with_grants(&["authorization_code"]);
    client.client_id = format!("issue-native-missing-refresh-{}", Uuid::now_v7());
    let user_id = Uuid::now_v7();
    insert_issue_client(&state, &client).await;
    insert_issue_user(&state, user_id).await;

    let mut issue = token_issue_with_sid(vec!["sid".to_owned()]);
    issue.user_id = Some(user_id);
    issue.subject = user_id.to_string();
    issue.native_sso = Some(NativeSsoTokenBinding {
        device_secret: format!("device-secret-{}", Uuid::now_v7()),
        ds_hash: "device-hash".to_owned(),
        sid: "native-sso-sid".to_owned(),
    });

    let response = issue_native_sso_token_response(&state, &client, issue).await;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let value: Value = serde_json::from_slice(&response_body(response).await)
        .expect("OAuth error body should be JSON");
    assert_eq!(
        value
            .get("error")
            .and_then(serde_json::Value::as_str)
            .expect("OAuth JSON should contain an error code"),
        "invalid_grant"
    );
    assert_eq!(value["error"], "invalid_grant");
    assert!(value.get("device_secret").is_none());
}

#[actix_web::test]
async fn native_sso_single_use_retry_is_rejected_with_live_refresh() {
    let state = issue_state_with_live_database()
        .expect("Native SSO regression requires PostgreSQL and Valkey");
    state
        .valkey
        .init()
        .await
        .expect("Native SSO test requires Valkey");
    let mut client = client_with_grants(&["authorization_code", "refresh_token"]);
    client.client_id = format!("native-expiry-{}", Uuid::now_v7());
    let user_id = Uuid::now_v7();
    insert_issue_client(&state, &client).await;
    insert_issue_user(&state, user_id).await;
    let grant_key = format!("native-expiry-{}", Uuid::now_v7());
    let issue = || {
        let mut issue = token_issue_with_sid(vec!["sid".to_owned()]);
        issue.user_id = Some(user_id);
        issue.subject = user_id.to_string();
        issue.scopes = vec!["openid".to_owned(), "offline_access".to_owned()];
        issue.include_refresh = true;
        issue.native_sso = Some(NativeSsoTokenBinding {
            device_secret: format!("new-secret-{}", Uuid::now_v7()),
            ds_hash: "device-hash".to_owned(),
            sid: "native-expiry-sid".to_owned(),
        });
        issue
    };
    let mut modules = state.active_module_snapshot();
    modules
        .accepting
        .insert(nazo_runtime_modules::ModuleId::NativeSso);
    let mode = TokenIssuanceMode::SingleUse {
        grant_key: grant_key.clone(),
        grant_expires_at: Utc::now() + chrono::Duration::minutes(5),
    };
    let first = issue_token_response_with_mode_and_modules_for_test(
        &state,
        &client,
        mode.clone(),
        issue(),
        modules.clone(),
    )
    .await;
    assert_eq!(first.status(), StatusCode::OK);
    let retry = issue_token_response_with_mode_and_modules_for_test(
        &state,
        &client,
        mode,
        issue(),
        modules,
    )
    .await;
    assert_eq!(retry.status(), StatusCode::BAD_REQUEST);
    let body: Value = serde_json::from_slice(&response_body(retry).await).unwrap();
    assert_eq!(
        body.get("error")
            .and_then(serde_json::Value::as_str)
            .expect("OAuth JSON should contain an error code"),
        "invalid_grant"
    );
    assert!(body.get("access_token").is_none());
    assert!(body.get("refresh_token").is_none());
    assert_eq!(refresh_token_row_count(&state, &client).await, 1);
}

#[actix_web::test]
async fn native_sso_issue_persists_device_state_with_the_refresh_family() {
    let Some(state) = issue_state_with_live_database() else {
        return;
    };
    state
        .valkey
        .init()
        .await
        .expect("live Native SSO fixture should connect to Valkey");
    let mut client = client_with_grants(&["authorization_code", "refresh_token"]);
    client.client_id = format!("issue-native-success-{}", Uuid::now_v7());
    let user_id = Uuid::now_v7();
    insert_issue_client(&state, &client).await;
    insert_issue_user(&state, user_id).await;

    let device_secret = format!("device-secret-{}", Uuid::now_v7());
    let mut issue = token_issue_with_sid(vec!["sid".to_owned()]);
    issue.user_id = Some(user_id);
    issue.subject = user_id.to_string();
    issue.scopes = vec!["openid".to_owned(), "offline_access".to_owned()];
    issue.include_refresh = true;
    issue.native_sso = Some(NativeSsoTokenBinding {
        device_secret: device_secret.clone(),
        ds_hash: "device-hash".to_owned(),
        sid: "native-sso-sid".to_owned(),
    });

    let response = issue_native_sso_token_response(&state, &client, issue).await;

    assert_eq!(response.status(), StatusCode::OK);
    let value: Value = serde_json::from_slice(&response_body(response).await)
        .expect("token response should be JSON");
    assert_eq!(value["device_secret"], device_secret);
    assert!(
        value["access_token"]
            .as_str()
            .is_some_and(|token| !token.is_empty())
    );
    assert!(
        value["id_token"]
            .as_str()
            .is_some_and(|token| !token.is_empty())
    );
    assert!(
        value["refresh_token"]
            .as_str()
            .is_some_and(|token| !token.is_empty())
    );
}

#[actix_web::test]
async fn refresh_rotation_conflict_fails_closed_without_returning_credentials() {
    let Some(state) = issue_state_with_live_database() else {
        return;
    };
    let mut client = client_with_grants(&["authorization_code", "refresh_token"]);
    client.client_id = format!("issue-rotation-conflict-{}", Uuid::now_v7());
    insert_issue_client(&state, &client).await;

    let mut issue = token_issue_without_openid();
    issue.user_id = None;
    issue.subject = client.client_id.clone();
    issue.scopes = vec!["accounts".to_owned(), "offline_access".to_owned()];
    issue.include_refresh = true;
    issue.refresh_token_policy = RefreshTokenPolicy::Rotate {
        family_id: Uuid::now_v7(),
        rotated_from_id: Uuid::now_v7(),
    };
    set_refresh_authority_for_issue(&state, &client, &mut issue);

    let response = issue_token_response(&state, &client, issue).await;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let value: Value = serde_json::from_slice(&response_body(response).await)
        .expect("OAuth error body should be JSON");
    assert_eq!(
        value
            .get("error")
            .and_then(serde_json::Value::as_str)
            .expect("OAuth JSON should contain an error code"),
        "invalid_grant"
    );
    assert_eq!(value["error"], "invalid_grant");
    assert!(value.get("access_token").is_none());
    assert!(value.get("refresh_token").is_none());
}

#[actix_web::test]
async fn native_sso_device_secret_failure_does_not_return_partial_credentials() {
    let Some(state) = issue_state_with_live_database_and_disconnected_valkey() else {
        return;
    };
    let mut client = client_with_grants(&["authorization_code", "refresh_token"]);
    client.client_id = format!("native-sso-store-error-{}", Uuid::now_v7());
    let user_id = Uuid::now_v7();
    insert_issue_client(&state, &client).await;
    insert_issue_user(&state, user_id).await;

    let mut issue = token_issue_with_sid(vec!["sid".to_owned()]);
    issue.user_id = Some(user_id);
    issue.subject = user_id.to_string();
    issue.scopes = vec!["openid".to_owned(), "offline_access".to_owned()];
    issue.include_refresh = true;
    issue.native_sso = Some(NativeSsoTokenBinding {
        device_secret: format!("device-secret-{}", Uuid::now_v7()),
        ds_hash: "device-hash".to_owned(),
        sid: "native-sso-sid".to_owned(),
    });

    let response = issue_native_sso_token_response(&state, &client, issue).await;

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let value: Value = serde_json::from_slice(&response_body(response).await)
        .expect("OAuth error body should be JSON");
    assert_eq!(
        value
            .get("error")
            .and_then(serde_json::Value::as_str)
            .expect("OAuth JSON should contain an error code"),
        "server_error"
    );
    assert_eq!(value["error"], "server_error");
    assert!(value.get("device_secret").is_none());
}

#[actix_web::test]
async fn refresh_issue_new_persistence_failure_uses_non_rotation_error_mapping() {
    let Some(state) = issue_state_with_live_database() else {
        return;
    };
    let mut client = client_with_grants(&["authorization_code", "refresh_token"]);
    client.client_id = format!("refresh-persist-error-{}", Uuid::now_v7());
    insert_issue_client(&state, &client).await;

    let grant_key = format!("refresh-persist-error-{}", Uuid::now_v7());
    let mut issue = token_issue_without_openid();
    issue.user_id = None;
    issue.subject = "subject-persist-error".to_owned();
    // The family row's `dpop_jkt VARCHAR(128)` bound makes this sender
    // constraint fail the refresh-family INSERT, exercising the
    // non-rotation error mapping on the fresh-issuance path.
    issue.refresh_token_dpop_jkt = Some("d".repeat(129));
    issue.scopes = vec!["accounts".to_owned(), "offline_access".to_owned()];
    issue.include_refresh = true;

    let response =
        issue_token_response_with_grant_for_test(&state, &client, &grant_key, issue).await;
    delete_token_issuance_for_grant(&state, &client, &grant_key).await;

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let value: Value = serde_json::from_slice(&response_body(response).await)
        .expect("OAuth error body should be JSON");
    assert_eq!(
        value
            .get("error")
            .and_then(serde_json::Value::as_str)
            .expect("OAuth JSON should contain an error code"),
        "server_error"
    );
    assert_eq!(value["error"], "server_error");
    assert!(value.get("refresh_token").is_none());
}

async fn protocol_native_sso_source_fixture() -> (TestInfrastructure, Value) {
    let state = issue_state_with_live_database()
        .expect("Native SSO audience regression requires isolated PostgreSQL and Valkey");
    state
        .valkey
        .init()
        .await
        .expect("isolated Valkey readiness");
    let mut source = client_with_grants(&["authorization_code", "refresh_token"]);
    source.client_id = format!("native-source-{}", Uuid::now_v7());
    source.scopes = vec![
        "openid".into(),
        "offline_access".into(),
        "device_sso".into(),
    ];
    let user_id = Uuid::now_v7();
    insert_issue_client(&state, &source).await;
    insert_issue_user(&state, user_id).await;
    let mut issue = token_issue_with_sid(vec!["sid".into()]);
    issue.user_id = Some(user_id);
    issue.subject = user_id.to_string();
    issue.scopes = source.scopes.clone();
    issue.include_refresh = true;
    issue.native_sso = nazo_oauth_server::token::native_sso::new_native_sso_token_binding(Some(
        "native-source-session",
    ));
    let source_response = issue_native_sso_token_response(&state, &source, issue).await;
    assert_eq!(source_response.status(), StatusCode::OK);
    let source_body: Value = serde_json::from_slice(&response_body(source_response).await).unwrap();
    (state, source_body)
}

#[actix_web::test]
async fn protocol_native_sso_exchange_checks_target_default_audience() {
    use nazo_oauth_server::contracts::token_forms::TokenForm;
    use nazo_oauth_server::token::native_sso::{
        NATIVE_SSO_DEVICE_SECRET_TYPE, NATIVE_SSO_ID_TOKEN_TYPE, token_native_sso_exchange,
    };
    let (state, source_body) = protocol_native_sso_source_fixture().await;
    let config = token_issuance_config(state.settings.as_ref());
    let authorization = test_support::test_authorization_service(&state);
    let service = ServerTokenService::new(
        crate::test_support::token_issuance_repository(state.diesel_db.clone()),
        Arc::new(nazo_valkey::TokenIssuanceStateAdapter::new(
            &state.valkey_connection(),
        )),
        state.keyset.clone(),
    );
    let mut modules = state.active_module_snapshot();
    modules
        .accepting
        .insert(nazo_runtime_modules::ModuleId::NativeSso);
    let issuance = TokenIssuanceContext {
        grant_type: Some(nazo_auth::GrantType::TokenExchange),
        client_epoch: 0,
        config: &config,
        modules: &modules,
        authorization: &authorization,
        security_audit: crate::http::authorization::test_support::test_security_audit(),
        remote_client_documents: crate::test_support::test_remote_client_documents(),
    };
    for allowed in [false, true] {
        let mut target = client_with_grants(&[
            "urn:ietf:params:oauth:grant-type:token-exchange",
            "refresh_token",
        ]);
        target.client_id = format!("native-target-{}", Uuid::now_v7());
        target.scopes = vec![
            "openid".into(),
            "offline_access".into(),
            "device_sso".into(),
        ];
        target.allowed_audiences = vec![if allowed {
            config.default_audience().into()
        } else {
            "resource://other".into()
        }];
        insert_issue_client(&state, &target).await;
        let form = TokenForm {
            grant_type: "urn:ietf:params:oauth:grant-type:token-exchange".into(),
            code: None,
            device_code: None,
            auth_req_id: None,
            redirect_uri: None,
            code_verifier: None,
            refresh_token: None,
            device_secret: None,
            scope: None,
            client_id: Some(target.client_id.clone()),
            client_secret: None,
            client_assertion_type: None,
            client_assertion: None,
            assertion: None,
            requested_token_type: None,
            subject_token: Some(source_body["id_token"].as_str().unwrap().into()),
            subject_token_type: Some(NATIVE_SSO_ID_TOKEN_TYPE.into()),
            actor_token: Some(source_body["device_secret"].as_str().unwrap().into()),
            actor_token_type: Some(NATIVE_SSO_DEVICE_SECRET_TYPE.into()),
            audiences: vec![config.issuer().into()],
            has_audience_param: true,
        };
        let request = actix_web::test::TestRequest::post()
            .uri("/token")
            .to_http_request();
        let facts = test_support::token_request_facts(&request, state.settings.as_ref());
        let response = present_token_result(
            token_native_sso_exchange(&service, &issuance, &facts, &target, &form, None, None)
                .await,
        );
        let status = response.status();
        let body: Value = serde_json::from_slice(&response_body(response).await).unwrap();
        if allowed {
            assert_eq!(
                status,
                StatusCode::OK,
                "allowed target must issue successfully"
            );
            let claims = nazo_crypto::jwt::dangerous::insecure_decode::<Value>(
                body["access_token"].as_str().unwrap(),
            )
            .unwrap()
            .claims;
            let audience = &claims["aud"];
            let audiences = audience
                .as_array()
                .map_or(std::slice::from_ref(audience), Vec::as_slice);
            assert_eq!(audiences, &[json!(config.default_audience())]);
            assert_eq!(refresh_token_row_count(&state, &target).await, 1);
        } else {
            assert_eq!(
                status,
                StatusCode::BAD_REQUEST,
                "disallowed target must reject before issuance"
            );
            assert_eq!(body["error"], "invalid_target");
            assert!(body.get("access_token").is_none());
            assert!(body.get("refresh_token").is_none());
            assert!(body.get("id_token").is_none());
            assert_eq!(refresh_token_row_count(&state, &target).await, 0);
            assert_eq!(token_issuance_row_count(&state, &target).await, 0);
        }
    }
}

async fn protocol_native_sso_attested_http_request(
    state: &TestInfrastructure,
    validator: Arc<nazo_oauth_server::domain::openid4vc::client_attestation::Openid4vcClientAttestationValidator>,
    attestation: Option<&str>,
    proof: Option<&str>,
    body: &str,
) -> HttpResponse {
    let mut request = actix_web::test::TestRequest::post()
        .uri("/token")
        .insert_header(("content-type", "application/x-www-form-urlencoded"));
    if let Some(attestation) = attestation {
        request = request.insert_header(("OAuth-Client-Attestation", attestation));
    }
    if let Some(proof) = proof {
        request = request.insert_header(("OAuth-Client-Attestation-PoP", proof));
    }
    let mut modules = state.active_module_snapshot().accepting;
    modules.insert(nazo_runtime_modules::ModuleId::NativeSso);
    crate::http::token::dispatch::tests::token_with_port_repositories_and_state_and_modules(
        actix_web::web::Data::new(state.clone()),
        Arc::new(crate::test_support::token_issuance_repository(
            state.diesel_db.clone(),
        )),
        Arc::new(nazo_postgres::AuthorizationFlowRepository::new(
            state.diesel_db.clone(),
            DEFAULT_TENANT_ID,
        )),
        Arc::new(nazo_valkey::AuthorizationStateAdapter::new(
            &state.valkey_connection(),
        )),
        Arc::new(
            crate::adapters::remote_client_documents::RemoteClientDocumentResolver::new(&[])
                .unwrap(),
        ),
        nazo_oauth_server::token::dispatch::Openid4vcTokenHandles {
            credential_issuer: None,
            client_attestation: Some(validator),
        },
        request.to_http_request(),
        actix_web::web::Bytes::from(body.to_owned()),
        modules,
    )
    .await
}

#[actix_web::test]
async fn protocol_native_sso_dispatch_preserves_verified_instance_binding() {
    use nazo_oauth_server::domain::openid4vc::client_attestation::{
        Openid4vcClientAttestationValidator, client_instance_key_thumbprint,
    };
    use nazo_oauth_server::token::native_sso::{
        NATIVE_SSO_DEVICE_SECRET_TYPE, NATIVE_SSO_ID_TOKEN_TYPE,
    };
    let (state, source_body) = protocol_native_sso_source_fixture().await;
    let config = token_issuance_config(state.settings.as_ref());
    let mut target = client_with_grants(&[
        "urn:ietf:params:oauth:grant-type:token-exchange",
        "refresh_token",
    ]);
    target.client_id = format!("native-attested-target-{}", Uuid::now_v7());
    target.client_type = "confidential".into();
    target.token_endpoint_auth_method = "attest_jwt_client_auth".into();
    target.scopes = vec![
        "openid".into(),
        "offline_access".into(),
        "device_sso".into(),
    ];
    target.allowed_audiences = vec![config.default_audience().into()];
    insert_issue_client(&state, &target).await;
    {
        let mut connection = get_conn(&state.diesel_db).await.unwrap();
        sql_query(
            "UPDATE oauth_clients SET allowed_audiences = $1 WHERE tenant_id = $2 AND id = $3",
        )
        .bind::<Jsonb, _>(json!(target.allowed_audiences))
        .bind::<SqlUuid, _>(target.tenant_id)
        .bind::<SqlUuid, _>(target.id)
        .execute(&mut connection)
        .await
        .unwrap();
    }
    let attester = client_signing_fixture(jsonwebtoken::Algorithm::ES256);
    let instance = client_signing_fixture(jsonwebtoken::Algorithm::ES256);
    let other_instance = client_signing_fixture(jsonwebtoken::Algorithm::ES256);
    let validator = Arc::new(
        Openid4vcClientAttestationValidator::new(
            "https://attester.example",
            json!({"keys":[attester.public_jwk("attester")]}),
        )
        .unwrap(),
    );
    let attestation_for = |key: &crate::test_support::ClientSigningFixture| {
        let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::ES256);
        header.typ = Some("oauth-client-attestation+jwt".into());
        header.kid = Some("attester".into());
        attester.encode_jwt(
            &header,
            &json!({
                "iss":"https://attester.example", "sub":target.client_id,
                "exp":Utc::now().timestamp()+600, "cnf":{"jwk":key.public_jwk("instance")},
            }),
        )
    };
    let proof_for = |key: &crate::test_support::ClientSigningFixture| {
        let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::ES256);
        header.typ = Some("oauth-client-attestation-pop+jwt".into());
        key.encode_jwt(
            &header,
            &json!({
                "iss":target.client_id, "aud":config.issuer(),
                "iat":Utc::now().timestamp(), "jti":Uuid::now_v7().to_string(),
            }),
        )
    };
    let attestation = attestation_for(&instance);
    let other_attestation = attestation_for(&other_instance);
    let form = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs([
            (
                "grant_type",
                "urn:ietf:params:oauth:grant-type:token-exchange",
            ),
            ("client_id", target.client_id.as_str()),
            ("audience", config.issuer()),
            ("subject_token", source_body["id_token"].as_str().unwrap()),
            ("subject_token_type", NATIVE_SSO_ID_TOKEN_TYPE),
            (
                "actor_token",
                source_body["device_secret"].as_str().unwrap(),
            ),
            ("actor_token_type", NATIVE_SSO_DEVICE_SECRET_TYPE),
        ])
        .finish();
    for (proof, status, error) in [
        (None, StatusCode::BAD_REQUEST, "invalid_request"),
        (
            Some(proof_for(&other_instance)),
            StatusCode::UNAUTHORIZED,
            "invalid_client_attestation",
        ),
    ] {
        let response = protocol_native_sso_attested_http_request(
            &state,
            validator.clone(),
            Some(&attestation),
            proof.as_deref(),
            &form,
        )
        .await;
        assert_eq!(
            response.status(),
            status,
            "invalid or missing proof must fail before exchange"
        );
        let body: Value = serde_json::from_slice(&response_body(response).await).unwrap();
        assert_eq!(body["error"], error);
        assert!(body.get("access_token").is_none() && body.get("refresh_token").is_none());
        assert_eq!(refresh_token_row_count(&state, &target).await, 0);
    }
    let response = protocol_native_sso_attested_http_request(
        &state,
        validator.clone(),
        Some(&attestation),
        Some(&proof_for(&instance)),
        &form,
    )
    .await;
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "verified instance must survive Native SSO dispatch"
    );
    let body: Value = serde_json::from_slice(&response_body(response).await).unwrap();
    assert!(body.get("access_token").is_some() && body.get("id_token").is_some());
    let refresh_token = body["refresh_token"].as_str().unwrap();
    let service = ServerTokenService::new(
        crate::test_support::token_issuance_repository(state.diesel_db.clone()),
        Arc::new(nazo_valkey::TokenIssuanceStateAdapter::new(
            &state.valkey_connection(),
        )),
        state.keyset.clone(),
    );
    let persisted = service
        .refresh_token_snapshot_with_subject(
            target.tenant_id,
            refresh_token,
            target.id,
            Utc::now(),
            false,
        )
        .await
        .expect("persisted refresh-token snapshot should load")
        .expect("Native SSO must persist a refresh family");
    assert_eq!(
        persisted.presented.client_attestation_jkt,
        Some(client_instance_key_thumbprint(&instance.public_jwk("instance")).unwrap()),
    );
    let refresh_form = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs([
            ("grant_type", "refresh_token"),
            ("client_id", target.client_id.as_str()),
            ("refresh_token", refresh_token),
        ])
        .finish();
    let response = protocol_native_sso_attested_http_request(
        &state,
        validator.clone(),
        Some(&other_attestation),
        Some(&proof_for(&other_instance)),
        &refresh_form,
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let denied: Value = serde_json::from_slice(&response_body(response).await).unwrap();
    assert_eq!(denied["error"], "invalid_client_attestation");
    assert!(denied.get("access_token").is_none() && denied.get("refresh_token").is_none());
    let response = protocol_native_sso_attested_http_request(
        &state,
        validator.clone(),
        Some(&attestation),
        None,
        &refresh_form,
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let denied: Value = serde_json::from_slice(&response_body(response).await).unwrap();
    assert_eq!(denied["error"], "invalid_request");
    let response = protocol_native_sso_attested_http_request(
        &state,
        validator,
        Some(&attestation),
        Some(&proof_for(&instance)),
        &refresh_form,
    )
    .await;
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "the originally verified instance must refresh"
    );
    let refreshed: Value = serde_json::from_slice(&response_body(response).await).unwrap();
    assert!(refreshed.get("access_token").is_some() && refreshed.get("refresh_token").is_some());
}
