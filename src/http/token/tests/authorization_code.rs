use super::*;

fn pkce_policy_client() -> ClientRow {
    ClientRow {
        id: Uuid::now_v7(),
        tenant_id: DEFAULT_TENANT_ID,
        realm_id: DEFAULT_REALM_ID,
        organization_id: DEFAULT_ORGANIZATION_ID,
        client_id: "client-1".to_owned(),
        client_name: "Client".to_owned(),
        client_type: "confidential".to_owned(),
        client_secret_argon2_hash: None,
        redirect_uris: json!(["https://client.example/callback"]),
        scopes: json!(["openid"]),
        allowed_audiences: json!(["resource://default"]),
        grant_types: json!(["authorization_code"]),
        token_endpoint_auth_method: "client_secret_basic".to_owned(),
        require_dpop_bound_tokens: false,
        require_mtls_bound_tokens: false,
        tls_client_auth_subject_dn: None,
        tls_client_auth_cert_sha256: None,
        tls_client_auth_san_dns: json!([]),
        tls_client_auth_san_uri: json!([]),
        tls_client_auth_san_ip: json!([]),
        tls_client_auth_san_email: json!([]),
        allow_client_assertion_audience_array: false,
        allow_client_assertion_endpoint_audience: false,
        require_par_request_object: false,
        allow_authorization_code_without_pkce: false,
        is_active: true,
        jwks: None,
        post_logout_redirect_uris: json!([]),
        backchannel_logout_uri: None,
        backchannel_logout_session_required: true,
    }
}

fn code_payload(redirect_uri_was_supplied: bool) -> CodePayload {
    let now = Utc::now();
    CodePayload {
        code_id: "code-1".to_owned(),
        user_id: Uuid::now_v7(),
        client_id: "client-1".to_owned(),
        redirect_uri: "https://client.example/callback".to_owned(),
        redirect_uri_was_supplied,
        scopes: vec!["openid".to_owned()],
        authorization_details: json!([]),
        nonce: None,
        auth_time: now.timestamp(),
        amr: vec!["password".to_owned()],
        oidc_sid: Some("sid-1".to_owned()),
        acr: None,
        userinfo_claims: Vec::new(),
        userinfo_claim_requests: Vec::new(),
        id_token_claims: Vec::new(),
        id_token_claim_requests: Vec::new(),
        code_challenge: Some("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ".to_owned()),
        code_challenge_method: Some("S256".to_owned()),
        dpop_jkt: None,
        mtls_x5t_s256: None,
        issued_at: now,
        expires_at: now + Duration::seconds(300),
    }
}

#[test]
fn token_redirect_uri_is_required_when_authorize_request_supplied_it() {
    let payload = code_payload(true);

    assert!(!redirect_uri_matches_authorization_request(&payload, None));
    assert!(redirect_uri_matches_authorization_request(
        &payload,
        Some("https://client.example/callback")
    ));
    assert!(!redirect_uri_matches_authorization_request(
        &payload,
        Some("https://client.example/callback/")
    ));
}

#[test]
fn token_redirect_uri_may_be_omitted_when_authorize_request_used_single_registered_uri() {
    let payload = code_payload(false);

    assert!(redirect_uri_matches_authorization_request(&payload, None));
    assert!(redirect_uri_matches_authorization_request(
        &payload,
        Some("https://client.example/callback")
    ));
    assert!(!redirect_uri_matches_authorization_request(
        &payload,
        Some("https://client.example/callback/")
    ));
}

#[test]
fn token_redirect_uri_is_still_bound_when_authorization_request_omitted_it() {
    let payload = code_payload(false);

    for attacker_redirect_uri in [
        "https://client.example/other-callback",
        "https://evil.example/callback",
        "http://client.example/callback",
        "https://client.example/callback?next=https://evil.example",
    ] {
        assert!(
            !redirect_uri_matches_authorization_request(&payload, Some(attacker_redirect_uri)),
            "authorization code exchange must not accept a different redirect_uri: {attacker_redirect_uri}"
        );
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
}

#[test]
fn authorization_code_consumption_parser_accepts_only_pending_payload_for_consuming_state() {
    let payload = code_payload(true);
    let raw = format!("consuming|{}", serde_json::to_string(&payload).unwrap());

    match parse_authorization_code_consumption_response(&raw) {
        AuthorizationCodeConsumption::Consuming(parsed) => {
            assert_eq!(parsed.code_id, "code-1");
            assert_eq!(parsed.client_id, "client-1");
            assert_eq!(parsed.redirect_uri, "https://client.example/callback");
            assert_eq!(parsed.code_challenge_method.as_deref(), Some("S256"));
        }
        _ => panic!("pending authorization code payload should enter consuming state"),
    }

    assert!(matches!(
        parse_authorization_code_consumption_response("consuming|not-json"),
        AuthorizationCodeConsumption::Malformed
    ));
    assert!(matches!(
        parse_authorization_code_consumption_response("consuming|[]"),
        AuthorizationCodeConsumption::Malformed
    ));
}

#[test]
fn authorization_code_consumption_parser_accepts_only_consumed_marker_for_replay_state() {
    let marker = ConsumedAuthorizationCode {
        client_id: Uuid::now_v7(),
        access_token_jti: "access-jti-1".to_owned(),
        access_token_expires_at: Utc::now().timestamp() + 300,
        refresh_token_family_id: Some(Uuid::now_v7()),
        consumed_at: Utc::now(),
    };
    let consumed = serde_json::to_string(&AuthorizationCodeState::Consumed {
        marker: marker.clone(),
    })
    .unwrap();
    let raw = format!("consumed|{consumed}");

    match parse_authorization_code_consumption_response(&raw) {
        AuthorizationCodeConsumption::Consumed(parsed) => {
            assert_eq!(parsed.client_id, marker.client_id);
            assert_eq!(parsed.access_token_jti, "access-jti-1");
            assert_eq!(
                parsed.refresh_token_family_id,
                marker.refresh_token_family_id
            );
        }
        _ => panic!("consumed authorization code marker should be replay evidence"),
    }

    let failed = serde_json::to_string(&AuthorizationCodeState::Failed {
        failed_at: Utc::now(),
        error: "pkce_failed".to_owned(),
    })
    .unwrap();
    assert!(matches!(
        parse_authorization_code_consumption_response(&format!("consumed|{failed}")),
        AuthorizationCodeConsumption::Malformed
    ));
    assert!(matches!(
        parse_authorization_code_consumption_response("consumed|not-json"),
        AuthorizationCodeConsumption::Malformed
    ));
}

#[test]
fn authorization_code_consumption_parser_maps_terminal_states_fail_closed() {
    for (raw, expected) in [
        ("busy", "busy"),
        ("failed", "failed"),
        ("missing", "missing"),
        ("pending", "malformed"),
        ("ok", "malformed"),
        ("", "malformed"),
    ] {
        let parsed = parse_authorization_code_consumption_response(raw);
        let actual = match parsed {
            AuthorizationCodeConsumption::Busy => "busy",
            AuthorizationCodeConsumption::Failed => "failed",
            AuthorizationCodeConsumption::Missing => "missing",
            AuthorizationCodeConsumption::Malformed => "malformed",
            AuthorizationCodeConsumption::Consuming(_) => "consuming",
            AuthorizationCodeConsumption::Consumed(_) => "consumed",
        };
        assert_eq!(actual, expected, "unexpected parser result for {raw:?}");
    }
}

#[test]
fn confidential_dpop_client_does_not_pin_refresh_token_to_initial_dpop_key() {
    let mut client = pkce_policy_client();
    client.client_type = "confidential".to_owned();
    client.require_dpop_bound_tokens = true;
    let mut payload = code_payload(true);
    payload.dpop_jkt = Some("request-dpop-jkt".to_owned());

    assert!(
        refresh_token_dpop_binding(&client, &payload, Some("verified-dpop-jkt".to_owned()))
            .is_none()
    );
}

#[test]
fn public_dpop_client_binds_refresh_token_to_dpop_key() {
    let mut client = pkce_policy_client();
    client.client_type = "public".to_owned();
    client.require_dpop_bound_tokens = false;
    let mut payload = code_payload(true);
    payload.dpop_jkt = None;

    assert_eq!(
        refresh_token_dpop_binding(&client, &payload, Some("verified-dpop-jkt".to_owned()))
            .as_deref(),
        Some("verified-dpop-jkt")
    );
}

#[test]
fn bearer_confidential_client_does_not_bind_refresh_token_to_access_token_dpop() {
    let mut client = pkce_policy_client();
    client.client_type = "confidential".to_owned();
    client.require_dpop_bound_tokens = false;
    let mut payload = code_payload(true);
    payload.dpop_jkt = None;

    assert!(
        refresh_token_dpop_binding(&client, &payload, Some("verified-dpop-jkt".to_owned()))
            .is_none()
    );
}

#[test]
fn authorization_code_pkce_policy_allows_only_explicit_confidential_compatibility() {
    let mut client = pkce_policy_client();
    let payload = code_payload(false);
    assert!(authorization_code_requires_pkce(&client, &payload));

    client.allow_authorization_code_without_pkce = true;
    assert!(!authorization_code_requires_pkce(&client, &payload));

    client.client_type = "public".to_owned();
    assert!(authorization_code_requires_pkce(&client, &payload));

    client.client_type = "confidential".to_owned();
    client.require_dpop_bound_tokens = true;
    assert!(authorization_code_requires_pkce(&client, &payload));

    client.require_dpop_bound_tokens = false;
    client.require_mtls_bound_tokens = true;
    assert!(authorization_code_requires_pkce(&client, &payload));

    client.require_mtls_bound_tokens = false;
    let mut holder_bound_payload = code_payload(false);
    holder_bound_payload.dpop_jkt = Some("thumbprint".to_owned());
    assert!(authorization_code_requires_pkce(
        &client,
        &holder_bound_payload
    ));

    holder_bound_payload.dpop_jkt = None;
    holder_bound_payload.mtls_x5t_s256 = Some("thumbprint".to_owned());
    assert!(authorization_code_requires_pkce(
        &client,
        &holder_bound_payload
    ));
}

fn oauth_error_code(response: &HttpResponse) -> String {
    response
        .extensions()
        .get::<OAuthJsonErrorFields>()
        .map(|fields| fields.error.clone())
        .expect("OAuth error response should record its error code")
}

#[test]
fn authorization_code_dpop_missing_proof_uses_invalid_grant() {
    let response = authorization_code_dpop_error_response(DpopError::MissingProof);

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(oauth_error_code(&response), "invalid_grant");
    assert!(response.headers().get(header::WWW_AUTHENTICATE).is_none());
}

#[test]
fn authorization_code_dpop_holder_key_failures_use_invalid_grant() {
    for error in [
        DpopError::MalformedProof,
        DpopError::InvalidProof,
        DpopError::ReplayDetected,
        DpopError::BindingMismatch,
        DpopError::TokenNotBound,
    ] {
        let response = authorization_code_dpop_error_response(error);

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(oauth_error_code(&response), "invalid_grant");
        assert!(
            response.headers().get(header::WWW_AUTHENTICATE).is_none(),
            "authorization code holder-of-key failures are OAuth grant errors, not DPoP challenges"
        );
    }
}

#[test]
fn authorization_code_dpop_nonce_challenge_keeps_dpop_error() {
    let response =
        authorization_code_dpop_error_response(DpopError::UseNonce("nonce-1".to_owned()));

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(oauth_error_code(&response), "use_dpop_nonce");
    assert_eq!(
        response.headers().get("dpop-nonce").unwrap(),
        HeaderValue::from_static("nonce-1")
    );
    assert_eq!(
        response.headers().get(header::WWW_AUTHENTICATE).unwrap(),
        HeaderValue::from_static(r#"DPoP error="use_dpop_nonce""#)
    );
}

#[test]
fn authorization_code_mtls_holder_key_failures_use_invalid_request() {
    let response = authorization_code_mtls_holder_error_response();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(oauth_error_code(&response), "invalid_request");
    assert!(response.headers().get(header::WWW_AUTHENTICATE).is_none());
}

#[test]
fn authorization_code_client_mismatch_uses_invalid_grant() {
    let response = authorization_code_client_mismatch_response();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(oauth_error_code(&response), "invalid_grant");
    assert!(response.headers().get(header::WWW_AUTHENTICATE).is_none());
}
