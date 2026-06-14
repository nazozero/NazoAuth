use super::*;

fn client_row(client_id: &str, secret_hash: Option<&str>) -> ClientRow {
    ClientRow {
        id: Uuid::now_v7(),
        tenant_id: DEFAULT_TENANT_ID,
        realm_id: DEFAULT_REALM_ID,
        organization_id: DEFAULT_ORGANIZATION_ID,
        client_id: client_id.to_owned(),
        client_name: format!("{client_id} name"),
        client_type: "confidential".to_owned(),
        client_secret_argon2_hash: secret_hash.map(ToOwned::to_owned),
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
async fn clients_list_response_preserves_pagination_and_omits_secret_hashes() {
    let response = clients_list_response(
        2,
        3,
        20,
        vec![
            client_row("client-1", Some("argon2-secret")),
            client_row("client-2", None),
        ],
    );

    assert_eq!(response.status(), StatusCode::OK);
    let body = actix_web::body::to_bytes(response.into_body())
        .await
        .expect("client list response body should collect");
    let body: Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(body["total"], json!(2));
    assert_eq!(body["page"], json!(3));
    assert_eq!(body["page_size"], json!(20));
    let items = body["items"].as_array().expect("items should be an array");
    assert_eq!(items.len(), 2);
    assert_eq!(items[0]["client_id"], json!("client-1"));
    assert_eq!(items[1]["client_id"], json!("client-2"));
    for item in items {
        assert!(item.get("client_secret_argon2_hash").is_none());
        assert!(item.get("tenant_id").is_none());
        assert!(item.get("realm_id").is_none());
        assert!(item.get("organization_id").is_none());
    }
}
