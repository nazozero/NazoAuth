use super::*;

fn valid_keyset(_kid: &str) -> nazo_key_management::KeyManager {
    crate::test_support::test_key_manager_with_algorithm(jsonwebtoken::Algorithm::RS256)
}

fn jwt_payload(token: &str) -> Value {
    let payload = token
        .split('.')
        .nth(1)
        .expect("JWT should contain a payload segment");
    let decoded = URL_SAFE_NO_PAD
        .decode(payload)
        .expect("JWT payload should be base64url");
    serde_json::from_slice(&decoded).expect("JWT payload should be JSON")
}

#[actix_web::test]
async fn token_authorization_code_uses_client_pairwise_subject_sector() {
    let mut settings = LiveAuthorizationCodeFixture::settings();
    settings.protocol.pairwise_subject_secret =
        Some("0123456789012345678901234567890123456789".to_owned());
    let Some(fixture) = LiveAuthorizationCodeFixture::new_with_settings_and_keyset(
        settings,
        valid_keyset("auth-code-pairwise-test-kid"),
    )
    .await
    else {
        return;
    };

    let user = fixture.insert_user().await;
    let mut client = live_client(&format!("client-pairwise-{}", Uuid::now_v7()));
    client.subject_type = "pairwise".to_owned();
    client.sector_identifier_host = Some("registered-sector.example".to_owned());
    fixture.insert_client(&client).await;

    let mut payload = payload_for_client(&client);
    payload.user_id = user.id;
    payload.scopes = vec!["openid".to_owned()];
    let code = format!("code-{}", Uuid::now_v7());
    fixture
        .store_code_state(&code, &AuthorizationCodeState::Pending { payload })
        .await;

    let req = actix_web::test::TestRequest::post()
        .uri("/token")
        .to_http_request();
    let mut form = form_for_code(&code);
    form.client_id = Some(client.client_id.clone());
    let response = token_authorization_code(&fixture.state, &req, &client, &form, None).await;
    let (status, body) = token_json_body(response).await;

    assert_eq!(status, StatusCode::OK, "unexpected token response: {body}");
    let expected_subject = oidc_subject(
        fixture
            .state
            .settings
            .protocol
            .pairwise_subject_secret
            .as_ref()
            .expect("pairwise secret should be configured")
            .as_bytes(),
        &fixture.state.settings.endpoint.issuer,
        "registered-sector.example",
        user.id,
    );
    assert_ne!(expected_subject, user.id.to_string());
    assert_eq!(
        jwt_payload(
            body["access_token"]
                .as_str()
                .expect("access token should be returned")
        )["sub"],
        json!(expected_subject)
    );
    assert_eq!(
        jwt_payload(
            body["id_token"]
                .as_str()
                .expect("id token should be returned")
        )["sub"],
        json!(expected_subject)
    );
}

#[actix_web::test]
async fn token_authorization_code_fails_closed_when_pairwise_secret_is_missing() {
    let Some(fixture) = LiveAuthorizationCodeFixture::new_with_settings_and_keyset(
        LiveAuthorizationCodeFixture::settings(),
        valid_keyset("auth-code-subject-policy-test-kid"),
    )
    .await
    else {
        return;
    };

    let user = fixture.insert_user().await;
    let mut client = live_client(&format!("client-subject-policy-{}", Uuid::now_v7()));
    client.subject_type = "pairwise".to_owned();
    client.sector_identifier_host = Some("registered-sector.example".to_owned());
    fixture.insert_client(&client).await;

    let mut payload = payload_for_client(&client);
    payload.user_id = user.id;
    payload.scopes = vec!["openid".to_owned()];
    let code = format!("code-{}", Uuid::now_v7());
    fixture
        .store_code_state(&code, &AuthorizationCodeState::Pending { payload })
        .await;

    let req = actix_web::test::TestRequest::post()
        .uri("/token")
        .to_http_request();
    let mut form = form_for_code(&code);
    form.client_id = Some(client.client_id.clone());
    let response = token_authorization_code(&fixture.state, &req, &client, &form, None).await;

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(oauth_error_code(response).await, "server_error");
    match fixture.code_state(&code).await {
        AuthorizationCodeState::Failed { error, .. } => {
            assert_eq!(error, "subject_policy_invalid");
        }
        _ => panic!("invalid subject policy should mark the authorization code as failed"),
    }
}

#[test]
fn authorization_code_token_issue_preserves_independent_oidc_sid() {
    let payload = code_payload(true);
    let auth_time = payload.auth_time;

    let issue = token_issue_from_authorization_code(AuthorizationCodeIssueInput {
        payload,
        subject: "subject-1".to_owned(),
        audiences: vec!["resource://default".to_owned()],
        dpop_jkt: Some("dpop-jkt".to_owned()),
        mtls_x5t_s256: Some("mtls-thumbprint".to_owned()),
        code_hash: "code-hash".to_owned(),
        refresh_token_dpop_jkt: Some("refresh-dpop-jkt".to_owned()),
        refresh_token_mtls_x5t_s256: Some("refresh-mtls-thumbprint".to_owned()),
        refresh_token_client_attestation_jkt: Some("client-attestation-jkt".to_owned()),
    });

    assert_eq!(issue.subject, "subject-1");
    assert_eq!(issue.oidc_sid.as_deref(), Some("sid-1"));
    assert_eq!(issue.authorization_code_hash.as_deref(), Some("code-hash"));
    assert!(issue.include_refresh);
    assert_eq!(issue.refresh_token_policy, RefreshTokenPolicy::IssueNew);
    assert_eq!(issue.scopes, vec!["openid".to_owned()]);
    assert_eq!(issue.audiences, vec!["resource://default".to_owned()]);
    assert_eq!(issue.nonce, None);
    assert_eq!(issue.auth_time, Some(auth_time));
    assert_eq!(issue.dpop_jkt.as_deref(), Some("dpop-jkt"));
    assert_eq!(
        issue.refresh_token_mtls_x5t_s256.as_deref(),
        Some("refresh-mtls-thumbprint")
    );
    assert_eq!(
        issue.refresh_token_client_attestation_jkt.as_deref(),
        Some("client-attestation-jkt")
    );
}

#[test]
fn authorization_code_token_issue_creates_native_sso_binding_for_device_sso_scope() {
    let mut payload = code_payload(true);
    payload.scopes = vec![
        "openid".to_owned(),
        "offline_access".to_owned(),
        "device_sso".to_owned(),
    ];

    let issue = token_issue_from_authorization_code(AuthorizationCodeIssueInput {
        payload,
        subject: "subject-1".to_owned(),
        audiences: vec!["resource://default".to_owned()],
        dpop_jkt: None,
        mtls_x5t_s256: None,
        code_hash: "code-hash".to_owned(),
        refresh_token_dpop_jkt: None,
        refresh_token_mtls_x5t_s256: None,
        refresh_token_client_attestation_jkt: None,
    });

    let binding = issue
        .native_sso
        .as_ref()
        .expect("device_sso scope should create a Native SSO binding");
    assert_eq!(binding.sid, "sid-1");
    assert_eq!(
        binding.ds_hash,
        nazo_oauth_server::token::native_sso::native_sso_device_secret_hash(&binding.device_secret)
    );
}

#[test]
fn authorization_code_token_issue_preserves_requested_oidc_claims_and_acr() {
    let mut payload = code_payload(true);
    payload.acr = Some("urn:example:acr:phishing-resistant".to_owned());
    payload.userinfo_claims = vec!["name".to_owned(), "email".to_owned()];
    payload.userinfo_claim_requests = vec![OidcClaimRequest {
        name: "email".to_owned(),
        essential: true,
        value: Some(json!("alice@example.com")),
        values: Vec::new(),
    }];
    payload.id_token_claims = vec!["auth_time".to_owned(), "sid".to_owned()];
    payload.id_token_claim_requests = vec![OidcClaimRequest {
        name: "acr".to_owned(),
        essential: true,
        value: Some(json!("urn:example:acr:phishing-resistant")),
        values: Vec::new(),
    }];

    let issue = token_issue_from_authorization_code(AuthorizationCodeIssueInput {
        payload,
        subject: "subject-1".to_owned(),
        audiences: vec!["resource://default".to_owned()],
        dpop_jkt: None,
        mtls_x5t_s256: None,
        code_hash: "code-hash".to_owned(),
        refresh_token_dpop_jkt: None,
        refresh_token_mtls_x5t_s256: None,
        refresh_token_client_attestation_jkt: None,
    });

    assert_eq!(
        issue.acr.as_deref(),
        Some("urn:example:acr:phishing-resistant")
    );
    assert_eq!(issue.userinfo_claims, vec!["name", "email"]);
    assert_eq!(issue.userinfo_claim_requests.len(), 1);
    assert_eq!(issue.userinfo_claim_requests[0].name, "email");
    assert!(issue.userinfo_claim_requests[0].essential);
    assert_eq!(issue.id_token_claims, vec!["auth_time", "sid"]);
    assert_eq!(issue.id_token_claim_requests.len(), 1);
    assert_eq!(issue.id_token_claim_requests[0].name, "acr");
    assert!(issue.id_token_claim_requests[0].essential);
}
