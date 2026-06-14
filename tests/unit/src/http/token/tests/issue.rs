use super::*;

fn client_with_grants(grant_types: &[&str]) -> ClientRow {
    ClientRow {
        id: Uuid::now_v7(),
        tenant_id: DEFAULT_TENANT_ID,
        realm_id: DEFAULT_REALM_ID,
        organization_id: DEFAULT_ORGANIZATION_ID,
        client_id: "client-1".to_owned(),
        client_name: "Client".to_owned(),
        client_type: "public".to_owned(),
        client_secret_argon2_hash: None,
        redirect_uris: json!(["https://client.example/callback"]),
        scopes: json!(["openid", "offline_access"]),
        allowed_audiences: json!(["resource://default"]),
        grant_types: json!(grant_types),
        token_endpoint_auth_method: "none".to_owned(),
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

#[test]
fn refresh_token_requires_offline_access_scope_and_client_grant() {
    let client = client_with_grants(&["authorization_code", "refresh_token"]);
    let scopes = vec!["openid".to_owned(), "profile".to_owned()];
    assert!(!should_issue_refresh_token(&client, &scopes));

    let scopes = vec!["openid".to_owned(), "offline_access".to_owned()];
    assert!(should_issue_refresh_token(&client, &scopes));

    let client = client_with_grants(&["authorization_code"]);
    assert!(!should_issue_refresh_token(&client, &scopes));
}

#[test]
fn refresh_token_grant_matching_is_exact_and_scope_case_sensitive() {
    let client = client_with_grants(&["authorization_code", "refresh_token:legacy"]);
    let scopes = vec!["openid".to_owned(), "offline_access".to_owned()];
    assert!(
        !should_issue_refresh_token(&client, &scopes),
        "refresh issuance must require the exact refresh_token grant"
    );

    let client = client_with_grants(&["authorization_code", "refresh_token"]);
    for scopes in [
        vec!["openid".to_owned(), "OFFLINE_ACCESS".to_owned()],
        vec!["openid".to_owned(), "offline_access ".to_owned()],
        vec!["openid".to_owned(), "offline".to_owned()],
    ] {
        assert!(
            !should_issue_refresh_token(&client, &scopes),
            "refresh issuance must require exact offline_access authorization scope: {scopes:?}"
        );
    }
}

#[test]
fn consumed_authorization_code_transition_requires_active_consuming_state() {
    assert!(authorization_code_state::consumed_authorization_code_transition_result("ok").is_ok());

    for state in [
        "missing",
        "pending",
        "consumed",
        "failed",
        "busy",
        "malformed",
    ] {
        let error = authorization_code_state::consumed_authorization_code_transition_result(state)
            .expect_err("non-consuming authorization code state must fail consumed marker write");
        assert!(
            error.to_string().contains(state),
            "error should preserve the unexpected state for diagnostics"
        );
    }
}

#[test]
fn failed_authorization_code_transition_is_idempotent_only_for_terminal_or_missing_states() {
    for state in ["ok", "missing", "failed", "consumed"] {
        assert!(
            authorization_code_state::failed_authorization_code_transition_result(state).is_ok(),
            "failed marker cleanup should tolerate {state}"
        );
    }

    for state in ["pending", "busy", "malformed"] {
        let error = authorization_code_state::failed_authorization_code_transition_result(state)
            .expect_err("failed marker must not hide an unexpected active state");
        assert!(
            error.to_string().contains(state),
            "error should preserve the unexpected state for diagnostics"
        );
    }
}

fn token_issue_with_sid(id_token_claims: Vec<String>) -> TokenIssue {
    TokenIssue {
        user_id: None,
        subject: "subject-1".to_owned(),
        scopes: vec!["openid".to_owned()],
        authorization_details: json!([]),
        audiences: vec!["resource://default".to_owned()],
        nonce: None,
        auth_time: Some(1_000),
        amr: vec!["password".to_owned()],
        oidc_sid: Some("op-session-sid".to_owned()),
        acr: None,
        userinfo_claims: Vec::new(),
        userinfo_claim_requests: Vec::new(),
        id_token_claims,
        id_token_claim_requests: Vec::new(),
        include_refresh: false,
        refresh_token_policy: RefreshTokenPolicy::IssueNew,
        dpop_jkt: None,
        refresh_token_dpop_jkt: None,
        mtls_x5t_s256: None,
        refresh_token_mtls_x5t_s256: None,
        authorization_code_hash: None,
    }
}

#[test]
fn id_token_sid_is_omitted_unless_explicitly_requested() {
    let issue = token_issue_with_sid(Vec::new());
    assert_eq!(id_token_session_sid(&issue), None);

    let issue = token_issue_with_sid(vec!["sid".to_owned()]);
    assert_eq!(id_token_session_sid(&issue), Some("op-session-sid"));
}

#[test]
fn id_token_sid_request_object_also_allows_session_sid() {
    let mut issue = token_issue_with_sid(Vec::new());
    issue.id_token_claim_requests.push(OidcClaimRequest {
        name: "sid".to_owned(),
        essential: true,
        value: None,
        values: Vec::new(),
    });

    assert_eq!(id_token_session_sid(&issue), Some("op-session-sid"));
}
