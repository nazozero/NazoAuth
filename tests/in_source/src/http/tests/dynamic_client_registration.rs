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
fn protected_dynamic_registration_requires_matching_initial_access_token() {
    assert!(initial_access_token_authorized(None, None));
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
