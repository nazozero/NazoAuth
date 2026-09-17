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
    issue.subject = "s".repeat(129);
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
