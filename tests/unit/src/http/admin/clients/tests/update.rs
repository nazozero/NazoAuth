use super::*;

fn current_client() -> ClientRow {
    ClientRow {
        id: Uuid::now_v7(),
        tenant_id: DEFAULT_TENANT_ID,
        realm_id: DEFAULT_REALM_ID,
        organization_id: DEFAULT_ORGANIZATION_ID,
        client_id: "client-1".to_owned(),
        client_name: "Existing client".to_owned(),
        client_type: "confidential".to_owned(),
        client_secret_argon2_hash: None,
        redirect_uris: json!(["https://client.example/callback"]),
        scopes: json!(["openid", "payments"]),
        allowed_audiences: json!(["https://api.example"]),
        grant_types: json!(["authorization_code", "refresh_token"]),
        token_endpoint_auth_method: "client_secret_basic".to_owned(),
        require_dpop_bound_tokens: true,
        require_mtls_bound_tokens: false,
        tls_client_auth_subject_dn: None,
        tls_client_auth_cert_sha256: None,
        tls_client_auth_san_dns: json!([]),
        tls_client_auth_san_uri: json!([]),
        tls_client_auth_san_ip: json!([]),
        tls_client_auth_san_email: json!([]),
        allow_client_assertion_audience_array: false,
        allow_client_assertion_endpoint_audience: false,
        require_par_request_object: true,
        allow_authorization_code_without_pkce: false,
        is_active: true,
        jwks: None,
        post_logout_redirect_uris: json!(["https://client.example/logout"]),
        backchannel_logout_uri: Some("https://client.example/backchannel".to_owned()),
        backchannel_logout_session_required: true,
    }
}

fn empty_patch() -> PatchClientRequest {
    PatchClientRequest {
        client_name: None,
        redirect_uris: None,
        post_logout_redirect_uris: None,
        scopes: None,
        allowed_audiences: None,
        grant_types: None,
        require_dpop_bound_tokens: None,
        allow_client_assertion_audience_array: None,
        allow_client_assertion_endpoint_audience: None,
        require_par_request_object: None,
        allow_authorization_code_without_pkce: None,
        backchannel_logout_uri: None,
        backchannel_logout_session_required: None,
        tls_client_auth_subject_dn: None,
        tls_client_auth_cert_sha256: None,
        tls_client_auth_san_dns: None,
        tls_client_auth_san_uri: None,
        tls_client_auth_san_ip: None,
        tls_client_auth_san_email: None,
        jwks: None,
        is_active: None,
    }
}

#[test]
fn patch_preserves_unsubmitted_security_metadata() {
    let mut patch = empty_patch();
    patch.client_name = Some("Renamed client".to_owned());
    patch.is_active = Some(false);

    let prepared = prepare_client_patch(&current_client(), patch)
        .expect("renaming a client must not require resubmitting security metadata");

    assert_eq!(prepared.client_name, "Renamed client");
    assert_eq!(
        prepared.redirect_uris,
        json!(["https://client.example/callback"])
    );
    assert_eq!(
        prepared.post_logout_redirect_uris,
        json!(["https://client.example/logout"])
    );
    assert_eq!(prepared.scopes, json!(["openid", "payments"]));
    assert_eq!(prepared.allowed_audiences, json!(["https://api.example"]));
    assert_eq!(
        prepared.grant_types,
        json!(["authorization_code", "refresh_token"])
    );
    assert!(prepared.require_dpop_bound_tokens);
    assert!(prepared.require_par_request_object);
    assert!(!prepared.allow_authorization_code_without_pkce);
    assert!(!prepared.is_active);
}

#[test]
fn patch_rejects_redirect_uri_with_surrounding_whitespace() {
    let mut patch = empty_patch();
    patch.redirect_uris = Some(vec![" https://client.example/callback ".to_owned()]);

    let error = prepare_client_patch(&current_client(), patch)
        .err()
        .expect("redirect_uri metadata must be an exact registered value");

    assert!(
        error.to_string().contains("redirect_uri"),
        "error should identify the exact redirect_uri metadata boundary: {error}"
    );
}

#[test]
fn patch_rejects_post_logout_redirect_uri_with_surrounding_whitespace() {
    let mut patch = empty_patch();
    patch.post_logout_redirect_uris = Some(vec![" https://client.example/logout ".to_owned()]);

    let error = prepare_client_patch(&current_client(), patch)
        .err()
        .expect("post_logout_redirect_uri metadata must not be silently normalized");

    assert!(
        error.to_string().contains("post_logout_redirect_uri"),
        "error should identify the exact post_logout_redirect_uri boundary: {error}"
    );
}
