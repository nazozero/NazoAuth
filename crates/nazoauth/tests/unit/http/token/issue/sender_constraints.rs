use super::*;

#[actix_web::test]
async fn client_credentials_issue_returns_dpop_and_authorization_details_metadata() {
    let Some(state) = issue_state_with_live_database() else {
        return;
    };
    state
        .valkey
        .init()
        .await
        .expect("live token issuance fixture should connect to Valkey");
    let mut client = client_with_grants(&["client_credentials"]);
    client.client_id = format!("issue-dpop-client-{}", Uuid::now_v7());
    insert_issue_client(&state, &client).await;

    let mut issue = token_issue_without_openid();
    issue.user_id = None;
    issue.subject = client.client_id.clone();
    issue.scopes = vec!["accounts".to_owned()];
    issue.include_refresh = false;
    issue.auth_time = None;
    issue.amr = Vec::new();
    issue.dpop_jkt = Some("dpop-thumbprint".to_owned());
    issue.authorization_details = json!([{"type": "account_information"}]);
    issue.issued_token_type = Some("urn:example:access-token".to_owned());

    let response = issue_token_response(&state, &client, issue).await;
    let has_dpop_nonce = response.headers().get("dpop-nonce").is_some();
    let status = response.status();
    let body = response_body(response).await;

    assert_eq!(
        status,
        StatusCode::OK,
        "live DPoP issuance failed: {}",
        String::from_utf8_lossy(&body)
    );
    assert!(has_dpop_nonce);
    let value: Value = serde_json::from_slice(&body).expect("token response should be JSON");
    assert_eq!(value["token_type"], "DPoP");
    assert_eq!(
        value["authorization_details"],
        json!([{"type": "account_information"}])
    );
    assert_eq!(value["issued_token_type"], "urn:example:access-token");
    assert!(
        value["access_token"]
            .as_str()
            .is_some_and(|token| !token.is_empty())
    );
}

#[actix_web::test]
async fn dpop_nonce_store_failure_stops_token_issue_before_access_token_signing() {
    let state = issue_state_with_valid_signing_key();
    let client = client_with_grants(&["client_credentials"]);
    let mut issue = token_issue_without_openid();
    issue.user_id = None;
    issue.subject = client.client_id.clone();
    issue.scopes = vec!["accounts".to_owned()];
    issue.include_refresh = false;
    issue.dpop_jkt = Some("dpop-thumbprint".to_owned());

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
async fn dpop_nonce_failure_is_reported_after_the_issuance_claim() {
    let Some(state) = issue_state_with_live_database_and_disconnected_valkey() else {
        return;
    };
    let client = client_with_grants(&["client_credentials"]);
    let grant_key = format!("dpop-error-{}", Uuid::now_v7());
    let mut issue = token_issue_without_openid();
    issue.user_id = None;
    issue.subject = client.client_id.clone();
    issue.scopes = vec!["accounts".to_owned()];
    issue.include_refresh = false;
    issue.dpop_jkt = Some("dpop-thumbprint".to_owned());

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
    assert!(value.get("access_token").is_none());
}
