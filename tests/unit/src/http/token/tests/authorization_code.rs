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

fn oauth_error_code(response: &HttpResponse) -> String {
    response
        .extensions()
        .get::<OAuthJsonErrorFields>()
        .map(|fields| fields.error.clone())
        .expect("OAuth error response should record its error code")
}

#[path = "authorization_code/consumption.rs"]
mod consumption;
#[path = "authorization_code/error_mapping.rs"]
mod error_mapping;
#[path = "authorization_code/pkce.rs"]
mod pkce;
#[path = "authorization_code/redirect_uri.rs"]
mod redirect_uri;
