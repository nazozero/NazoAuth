use super::*;

fn client_row() -> ClientRow {
    ClientRow {
        id: Uuid::now_v7(),
        tenant_id: DEFAULT_TENANT_ID,
        realm_id: DEFAULT_REALM_ID,
        organization_id: DEFAULT_ORGANIZATION_ID,
        client_id: "client-1".to_owned(),
        client_name: "Client".to_owned(),
        client_type: "confidential".to_owned(),
        client_secret_argon2_hash: Some("argon2-secret".to_owned()),
        redirect_uris: json!(["https://client.example/callback"]),
        scopes: json!(["openid"]),
        allowed_audiences: json!(["https://api.example"]),
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

#[actix_web::test]
async fn client_detail_response_does_not_expose_secret_hash_or_tenant_context() {
    let response = client_detail_response(client_row());

    assert_eq!(response.status(), StatusCode::OK);
    let body = actix_web::body::to_bytes(response.into_body())
        .await
        .expect("client detail response body should collect");
    let body: Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(body["client_id"], json!("client-1"));
    assert_eq!(
        body["token_endpoint_auth_method"],
        json!("client_secret_basic")
    );
    assert!(body.get("client_secret_argon2_hash").is_none());
    assert!(body.get("tenant_id").is_none());
    assert!(body.get("realm_id").is_none());
    assert!(body.get("organization_id").is_none());
}

#[test]
fn client_detail_not_found_response_uses_stable_oauth_error() {
    let response = client_detail_not_found_response();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        response
            .extensions()
            .get::<OAuthJsonErrorFields>()
            .map(|fields| fields.error.as_str()),
        Some("invalid_request")
    );
}
