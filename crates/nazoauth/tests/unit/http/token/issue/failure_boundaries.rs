use super::*;

#[actix_web::test]
async fn signing_failure_does_not_issue_any_tokens() {
    let Some(mut state) = issue_state_with_live_database() else {
        return;
    };
    state.keyset = crate::test_support::failing_key_manager();
    let mut client = client_with_grants(&["authorization_code", "refresh_token"]);
    client.client_type = "confidential".to_owned();
    client.token_endpoint_auth_method = "client_secret_basic".to_owned();
    let issue = token_issue_without_openid();

    let response = issue_token_response(&state, &client, issue).await;

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(
        response.headers().get(header::CACHE_CONTROL).unwrap(),
        HeaderValue::from_static("no-store")
    );
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
    assert_eq!(value.get("error"), Some(&json!("server_error")));
    assert!(value.get("access_token").is_none());
    assert!(value.get("refresh_token").is_none());
    assert!(value.get("id_token").is_none());
}

#[actix_web::test]
async fn invalid_authorization_details_state_fails_before_token_signing() {
    let state = issue_state_with_invalid_signing_key();
    let client = client_with_grants(&["authorization_code", "refresh_token"]);
    let mut issue = token_issue_without_openid();
    issue.authorization_details = json!({"type": "account_information"});

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
    assert_eq!(value.get("error"), Some(&json!("server_error")));
    assert!(value.get("access_token").is_none());
    assert!(value.get("refresh_token").is_none());
    assert!(value.get("id_token").is_none());
}

#[actix_web::test]
async fn consumed_authorization_code_marker_failure_returns_error_after_revocation_attempt() {
    let state = issue_state_with_valid_signing_key();
    let client = client_with_grants(&["authorization_code"]);
    let mut issue = token_issue_without_openid();
    issue.user_id = None;
    issue.subject = "subject-1".to_owned();
    issue.scopes = vec!["accounts".to_owned()];
    issue.include_refresh = false;
    issue.authorization_code_hash = Some("code-hash".to_owned());

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
}

#[actix_web::test]
async fn same_single_use_grant_retry_is_rejected_without_reissuing() {
    let Some(state) = issue_state_with_live_database() else {
        return;
    };
    let mut client = client_with_grants(&["client_credentials"]);
    client.client_id = format!("single-use-client-{}", Uuid::now_v7());
    insert_issue_client(&state, &client).await;
    let grant_key = format!("single-use-test-{}", Uuid::now_v7());
    let mut first_issue = token_issue_without_openid();
    first_issue.include_refresh = false;
    let first =
        issue_token_response_with_grant_for_test(&state, &client, &grant_key, first_issue).await;
    assert_eq!(first.status(), StatusCode::OK);

    let mut retry_issue = token_issue_without_openid();
    retry_issue.include_refresh = false;
    let retry =
        issue_token_response_with_grant_for_test(&state, &client, &grant_key, retry_issue).await;
    assert_eq!(retry.status(), StatusCode::BAD_REQUEST);
    assert_eq!(oauth_error_code(retry).await, "invalid_grant");
    assert_eq!(
        token_issuance_row_count(&state, &client).await,
        1,
        "the losing retry must not persist another issuance row"
    );
}

#[actix_web::test]
async fn concurrent_single_use_grants_issue_exactly_one_response() {
    let Some(state) = issue_state_with_live_database_pool_size(4) else {
        return;
    };
    let mut client = client_with_grants(&["client_credentials", "refresh_token"]);
    client.client_id = format!("concurrent-issue-client-{}", Uuid::now_v7());
    insert_issue_client(&state, &client).await;
    let grant_key = format!("conflict-test-{}", Uuid::now_v7());
    let initial_refresh_token_rows = refresh_token_row_count(&state, &client).await;
    let mut first_issue = token_issue_without_openid();
    first_issue.scopes.push("offline_access".to_owned());
    first_issue.include_refresh = true;
    let mut second_issue = token_issue_without_openid();
    second_issue.scopes.push("offline_access".to_owned());
    second_issue.include_refresh = true;

    let first_future =
        issue_token_response_with_grant_for_test(&state, &client, &grant_key, first_issue);
    let second_future =
        issue_token_response_with_grant_for_test(&state, &client, &grant_key, second_issue);
    let (first, second) = tokio::join!(first_future, second_future);

    let statuses = [first.status(), second.status()];
    assert!(
        statuses
            .iter()
            .filter(|status| **status == StatusCode::OK)
            .count()
            == 1
            && statuses
                .iter()
                .filter(|status| **status == StatusCode::BAD_REQUEST)
                .count()
                == 1,
        "exactly one concurrent single-use redemption may win: {statuses:?}"
    );
    let loser = if first.status() == StatusCode::BAD_REQUEST {
        first
    } else {
        second
    };
    assert_eq!(oauth_error_code(loser).await, "invalid_grant");
    assert_eq!(
        refresh_token_row_count(&state, &client).await,
        initial_refresh_token_rows + 1,
        "one stable grant must persist only one refresh-token row",
    );
    assert_eq!(
        token_issuance_row_count(&state, &client).await,
        1,
        "one stable grant must persist only one issuance row",
    );
}

#[actix_web::test]
async fn single_use_grant_replay_with_a_different_request_is_rejected() {
    let Some(state) = issue_state_with_live_database() else {
        return;
    };
    let mut client = client_with_grants(&["client_credentials"]);
    client.client_id = format!("replay-conflict-client-{}", Uuid::now_v7());
    let grant_key = format!("replay-conflict-{}", Uuid::now_v7());
    persist_consumed_single_use_grant_for_test(&state, &client, &grant_key).await;

    let mut replay = token_issue_without_openid();
    replay.subject = "different-subject".to_owned();
    let response =
        issue_token_response_with_grant_for_test(&state, &client, &grant_key, replay).await;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(oauth_error_code(response).await, "invalid_grant");
}

#[actix_web::test]
async fn id_token_signing_failure_does_not_issue_oidc_credentials() {
    let Some(mut state) = issue_state_with_live_database() else {
        return;
    };
    let _key_material = client_signing_fixture(jsonwebtoken::Algorithm::EdDSA);
    state.keyset = crate::test_support::test_key_manager();
    let mut client = client_with_grants(&["authorization_code"]);
    client.client_id = format!("issue-id-sign-{}", Uuid::now_v7());
    let user_id = Uuid::now_v7();
    insert_issue_client(&state, &client).await;
    insert_issue_user(&state, user_id).await;

    let mut issue = token_issue_with_sid(Vec::new());
    issue.user_id = Some(user_id);
    issue.subject = user_id.to_string();

    let response = issue_token_response(&state, &client, issue).await;

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
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
    assert!(value.get("id_token").is_none());
}

#[actix_web::test]
async fn id_token_encryption_failure_does_not_issue_an_unencrypted_token() {
    let Some(state) = issue_state_with_live_database() else {
        return;
    };
    let mut client = client_with_grants(&["authorization_code"]);
    client.client_id = format!("issue-id-encrypt-{}", Uuid::now_v7());
    client.id_token_encrypted_response_alg = Some("RSA-OAEP-256".to_owned());
    client.id_token_encrypted_response_enc = Some("A256GCM".to_owned());
    client.jwks = Some(json!({
        "keys": [{"kty": "RSA", "use": "enc", "alg": "RSA-OAEP-256"}]
    }));
    let user_id = Uuid::now_v7();
    insert_issue_client(&state, &client).await;
    insert_issue_user(&state, user_id).await;

    let mut issue = token_issue_with_sid(Vec::new());
    issue.user_id = Some(user_id);
    issue.subject = user_id.to_string();

    let response = issue_token_response(&state, &client, issue).await;

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
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
    assert!(value.get("id_token").is_none());
}

#[actix_web::test]
async fn authorization_code_marker_failure_revokes_the_issued_access_token() {
    let Some(state) = issue_state_with_live_database() else {
        return;
    };
    state
        .valkey
        .init()
        .await
        .expect("live authorization-code fixture should connect to Valkey");
    let mut client = client_with_grants(&["client_credentials"]);
    client.client_id = format!("issue-marker-failure-{}", Uuid::now_v7());
    insert_issue_client(&state, &client).await;
    let mut issue = token_issue_without_openid();
    issue.user_id = None;
    issue.subject = client.client_id.clone();
    issue.scopes = vec!["accounts".to_owned()];
    issue.include_refresh = false;
    issue.authorization_code_hash = Some(format!("missing-code-{}", Uuid::now_v7()));

    // The finalize path requires the SingleUse grant key that a real
    // authorization-code redemption carries.
    let response = issue_token_response_with_grant_for_test(
        &state,
        &client,
        &format!("grant-{}", Uuid::now_v7()),
        issue,
    )
    .await;

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
    assert!(value.get("access_token").is_none());
}
