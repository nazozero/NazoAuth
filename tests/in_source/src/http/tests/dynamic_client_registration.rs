use super::*;
use serde_json::json;

#[test]
fn oidc_dynamic_registration_defaults_to_confidential_authorization_code_client() {
    let request = DynamicClientRegistrationRequest {
        redirect_uris: Some(vec!["https://client.example/callback".to_owned()]),
        scope: Some("openid profile email".to_owned()),
        client_name: Some("OIDF Dynamic Client".to_owned()),
        ..Default::default()
    };

    let prepared = prepare_dynamic_client_registration(
        request,
        DynamicRegistrationDefaults {
            default_audience: "https://issuer.example/fapi/resource",
        },
    )
    .expect("valid OIDC dynamic registration metadata should be accepted");

    assert_eq!(prepared.client_name, "OIDF Dynamic Client");
    assert_eq!(prepared.client_type, "confidential");
    assert_eq!(prepared.token_endpoint_auth_method, "client_secret_basic");
    assert_eq!(
        prepared.redirect_uris,
        vec!["https://client.example/callback"]
    );
    assert_eq!(prepared.scopes, vec!["openid", "profile", "email"]);
    assert_eq!(
        prepared.allowed_audiences,
        vec!["https://issuer.example/fapi/resource"]
    );
    assert_eq!(prepared.grant_types, vec!["authorization_code"]);
    assert_eq!(prepared.response_types, vec!["code"]);
}

#[test]
fn dynamic_registration_rejects_inconsistent_grant_and_response_types() {
    let request = DynamicClientRegistrationRequest {
        redirect_uris: Some(vec!["https://client.example/callback".to_owned()]),
        grant_types: Some(vec!["client_credentials".to_owned()]),
        response_types: Some(vec!["code".to_owned()]),
        ..Default::default()
    };

    let err = prepare_dynamic_client_registration(
        request,
        DynamicRegistrationDefaults {
            default_audience: "https://issuer.example/fapi/resource",
        },
    )
    .expect_err("client_credentials must not be registered with code response type");

    assert_eq!(err.error, "invalid_client_metadata");
}

#[test]
fn dynamic_registration_rejects_jwks_uri_and_jwks_in_same_request() {
    let request = DynamicClientRegistrationRequest {
        redirect_uris: Some(vec!["https://client.example/callback".to_owned()]),
        jwks_uri: Some("https://client.example/jwks.json".to_owned()),
        jwks: Some(json!({"keys": []})),
        ..Default::default()
    };

    let err = prepare_dynamic_client_registration(
        request,
        DynamicRegistrationDefaults {
            default_audience: "https://issuer.example/fapi/resource",
        },
    )
    .expect_err("RFC 7591 forbids jwks_uri and jwks in the same request");

    assert_eq!(err.error, "invalid_client_metadata");
}

#[test]
fn dynamic_registration_accepts_request_uris_metadata_when_request_uri_is_not_supported() {
    let request = DynamicClientRegistrationRequest {
        redirect_uris: Some(vec!["https://client.example/callback".to_owned()]),
        request_uris: vec!["https://client.example/request.jwt".to_owned()],
        ..Default::default()
    };

    let prepared = prepare_dynamic_client_registration(
        request,
        DynamicRegistrationDefaults {
            default_audience: "https://issuer.example/fapi/resource",
        },
    )
    .expect("request_uris metadata should not block registration when request_uri is unsupported");

    assert_eq!(
        prepared.redirect_uris,
        vec!["https://client.example/callback"]
    );
}

#[test]
fn dynamic_registration_rejects_malformed_request_uris_metadata() {
    let request = DynamicClientRegistrationRequest {
        redirect_uris: Some(vec!["https://client.example/callback".to_owned()]),
        request_uris: vec!["urn:ietf:params:oauth:request_uri:external".to_owned()],
        ..Default::default()
    };

    let err = prepare_dynamic_client_registration(
        request,
        DynamicRegistrationDefaults {
            default_audience: "https://issuer.example/fapi/resource",
        },
    )
    .expect_err("request_uris metadata should remain syntactically constrained");

    assert_eq!(err.error, "invalid_client_metadata");
}

#[actix_web::test]
async fn dynamic_registration_accepts_oidf_inline_jwks_without_kid_for_secret_clients() {
    let request = DynamicClientRegistrationRequest {
        redirect_uris: Some(vec!["https://nginx:8443/test/a/client/callback".to_owned()]),
        jwks: Some(json!({
            "keys": [{
                "kty": "RSA",
                "e": "AQAB",
                "use": "sig",
                "alg": "RS256",
                "n": "tHZtslxU00LSm1czViLa4PGegfMzw2LJci1nDiwws-UgJdPRgwffLBUoFDW1FZVFt7dDUK8H1emYG4QimXPS6BuE6XZQ6MN2y9rbfs6pvQz6bsITuOjNAxydM4FNiU4M4SlA9bqOf7PAU8NMsNBLP8_3HpWogUPvafgr8pymHgWmV6NJgRp41LQtul-1qzsDbO-pvLRWeFX0d2mFdKVPJttxK2_eIJVCtMzIcGfFj0bPEvQWxMUMRAra3Qu-HqTzzV3DnsZWs1B3bSBRedZVSroLzKBIfKXo5JhqqZsDu_CRL3g2V0D8gs0zmM2A46XEX-PlUq-39mEswFgTGQ3y4Q"
            }]
        })),
        ..Default::default()
    };

    let prepared = prepare_dynamic_client_registration(
        request,
        DynamicRegistrationDefaults {
            default_audience: "https://issuer.example/fapi/resource",
        },
    )
    .expect("OIDF Basic dynamic registration metadata should parse");

    let create_request = prepared.to_create_client_request();
    assert_eq!(create_request.scopes, vec!["openid"]);
    assert!(!create_request.allow_authorization_code_without_pkce);

    crate::http::admin::prepare_client_insert(create_request, None, "https://issuer.example")
        .await
        .expect("OIDF inline jwks without kid should be accepted for secret clients");
}

#[test]
fn dynamic_registration_refresh_clients_do_not_receive_offline_access_by_default() {
    let request = DynamicClientRegistrationRequest {
        redirect_uris: Some(vec!["https://client.example/callback".to_owned()]),
        grant_types: Some(vec![
            "authorization_code".to_owned(),
            "refresh_token".to_owned(),
        ]),
        ..Default::default()
    };

    let prepared = prepare_dynamic_client_registration(
        request,
        DynamicRegistrationDefaults {
            default_audience: "https://issuer.example/fapi/resource",
        },
    )
    .expect("refresh-capable dynamic registration metadata should be accepted");

    assert_eq!(prepared.scopes, vec!["openid"]);
}

#[test]
fn protected_dynamic_registration_requires_matching_initial_access_token() {
    assert!(!initial_access_token_authorized(None, None));
    assert!(initial_access_token_authorized(
        Some("Bearer register-token"),
        Some("register-token")
    ));
    assert!(!initial_access_token_authorized(
        None,
        Some("register-token")
    ));
    assert!(!initial_access_token_authorized(
        Some("Bearer wrong-token"),
        Some("register-token")
    ));
    assert!(!initial_access_token_authorized(
        Some("Basic cmVnaXN0ZXItdG9rZW4="),
        Some("register-token")
    ));
}

#[actix_web::test]
async fn dynamic_registration_rejects_private_key_jwt_jwks_without_kid() {
    let request = DynamicClientRegistrationRequest {
        redirect_uris: Some(vec!["https://client.example/callback".to_owned()]),
        token_endpoint_auth_method: Some("private_key_jwt".to_owned()),
        jwks: Some(json!({
            "keys": [{
                "kty": "RSA",
                "e": "AQAB",
                "use": "sig",
                "alg": "RS256",
                "n": "tHZtslxU00LSm1czViLa4PGegfMzw2LJci1nDiwws-UgJdPRgwffLBUoFDW1FZVFt7dDUK8H1emYG4QimXPS6BuE6XZQ6MN2y9rbfs6pvQz6bsITuOjNAxydM4FNiU4M4SlA9bqOf7PAU8NMsNBLP8_3HpWogUPvafgr8pymHgWmV6NJgRp41LQtul-1qzsDbO-pvLRWeFX0d2mFdKVPJttxK2_eIJVCtMzIcGfFj0bPEvQWxMUMRAra3Qu-HqTzzV3DnsZWs1B3bSBRedZVSroLzKBIfKXo5JhqqZsDu_CRL3g2V0D8gs0zmM2A46XEX-PlUq-39mEswFgTGQ3y4Q"
            }]
        })),
        ..Default::default()
    };

    let prepared = prepare_dynamic_client_registration(
        request,
        DynamicRegistrationDefaults {
            default_audience: "https://issuer.example/fapi/resource",
        },
    )
    .expect("private_key_jwt registration metadata should parse before key policy validation");

    let result = crate::http::admin::prepare_client_insert(
        prepared.to_create_client_request(),
        None,
        "https://issuer.example",
    )
    .await;
    assert!(
        result.is_err(),
        "private_key_jwt clients must register signing keys with kid"
    );
}

#[test]
fn dynamic_registration_secret_response_is_not_cacheable() {
    let now = chrono::Utc::now();
    let client = ClientRow {
        id: uuid::Uuid::now_v7(),
        tenant_id: uuid::Uuid::now_v7(),
        realm_id: uuid::Uuid::now_v7(),
        organization_id: uuid::Uuid::now_v7(),
        client_id: "dynamic-client".to_owned(),
        client_name: "Dynamic Client".to_owned(),
        client_type: "confidential".to_owned(),
        client_secret_argon2_hash: Some("argon2-secret".to_owned()),
        redirect_uris: json!(["https://client.example/callback"]),
        scopes: json!(["openid"]),
        allowed_audiences: json!(["https://issuer.example/fapi/resource"]),
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
        introspection_encrypted_response_alg: None,
        introspection_encrypted_response_enc: None,
        post_logout_redirect_uris: json!([]),
        backchannel_logout_uri: None,
        backchannel_logout_session_required: true,
        subject_type: "public".to_owned(),
        sector_identifier_uri: None,
        sector_identifier_host: None,
    };

    let response = dynamic_registration_created_response(
        &client,
        &["code".to_owned()],
        Some("issued-secret".to_owned()),
        now,
    );

    assert_eq!(response.status(), StatusCode::CREATED);
    assert_eq!(
        response.headers().get(header::CACHE_CONTROL).unwrap(),
        HeaderValue::from_static("no-store")
    );
    assert_eq!(
        response.headers().get(header::PRAGMA).unwrap(),
        HeaderValue::from_static("no-cache")
    );
}
