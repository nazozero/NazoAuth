use super::*;
use std::path::PathBuf;

use crate::settings::{
    AuthorizationServerProfile, DpopNoncePolicy, EmailDelivery, EmailSettings, PasskeySettings,
    RateLimitSettings, RequestObjectJtiPolicy, SubjectType,
};
use crate::support::{ClientIpHeaderMode, IpCidr};

fn settings(profile: AuthorizationServerProfile) -> Settings {
    Settings {
        issuer: "https://issuer.example".to_owned(),
        mtls_endpoint_base_url: "https://issuer.example".to_owned(),
        frontend_base_url: "https://app.example".to_owned(),
        cors_allowed_origins: vec!["https://app.example".to_owned()],
        default_audience: "resource://default".to_owned(),
        authorization_server_profile: profile,
        dpop_nonce_policy: DpopNoncePolicy::Required,
        request_object_jti_policy: RequestObjectJtiPolicy::Optional,
        session_cookie_name: "sid".to_owned(),
        csrf_cookie_name: "csrf".to_owned(),
        cookie_secure: true,
        session_ttl_seconds: 3600,
        auth_code_ttl_seconds: 60,
        access_token_ttl_seconds: 300,
        id_token_ttl_seconds: 600,
        refresh_token_ttl_seconds: 2_592_000,
        avatar_max_bytes: 2_097_152,
        client_delivery_ttl_seconds: 86_400,
        rate_limit: RateLimitSettings {
            window_seconds: 60,
            auth_max_requests: 30,
            token_max_requests: 60,
            token_management_max_requests: 120,
        },
        email: EmailSettings {
            delivery: EmailDelivery::Disabled,
            code_ttl_seconds: 900,
            send_cooldown_seconds: 60,
            send_peer_cooldown_seconds: 5,
        },
        email_code_dev_response_enabled: false,
        avatar_storage_dir: PathBuf::from("runtime/avatars"),
        jwk_keys_dir: PathBuf::from("runtime/keys"),
        signing_external_command: Vec::new(),
        signing_external_timeout_ms: 2_000,
        trusted_proxy_cidrs: Vec::<IpCidr>::new(),
        client_ip_header_mode: ClientIpHeaderMode::None,
        subject_type: SubjectType::Public,
        pairwise_subject_secret: None,
        par_ttl_seconds: 90,
        require_pushed_authorization_requests: profile.requires_fapi2_security(),
        scim_bearer_token: None,
        passkey: PasskeySettings {
            rp_id: "issuer.example".to_owned(),
            rp_name: "Nazo OAuth".to_owned(),
            origin: "https://issuer.example".to_owned(),
            require_user_verification: true,
            require_user_handle: true,
            strict_base64: true,
        },
        federation: crate::settings::FederationSettings {
            oidc: None,
            saml_gateway: None,
        },
    }
}

fn client() -> ClientRow {
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
        scopes: json!(["accounts", "payments", "openid"]),
        allowed_audiences: json!(["resource://default", "https://api.example.com"]),
        grant_types: json!(["client_credentials"]),
        token_endpoint_auth_method: "private_key_jwt".to_owned(),
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

fn form(scope: Option<&str>, audiences: &[&str]) -> TokenForm {
    TokenForm {
        grant_type: "client_credentials".to_owned(),
        code: None,
        redirect_uri: None,
        code_verifier: None,
        refresh_token: None,
        scope: scope.map(ToOwned::to_owned),
        client_id: Some("client-1".to_owned()),
        client_secret: None,
        client_assertion_type: None,
        client_assertion: None,
        audiences: audiences.iter().map(|value| (*value).to_owned()).collect(),
    }
}

fn oauth_error_code(response: &HttpResponse) -> String {
    response
        .extensions()
        .get::<OAuthJsonErrorFields>()
        .map(|fields| fields.error.clone())
        .expect("OAuth error response should record its error code")
}

#[test]
fn client_credentials_defaults_to_allowed_scopes_and_default_audience() {
    let settings = settings(AuthorizationServerProfile::Oauth2Baseline);
    let client = client();

    let issue = client_credentials_issue_request(&settings, &client, &form(None, &[]))
        .expect("confidential client may use client_credentials");

    assert_eq!(
        issue.scopes,
        vec![
            "accounts".to_owned(),
            "payments".to_owned(),
            "openid".to_owned()
        ]
    );
    assert_eq!(issue.audiences, vec!["resource://default".to_owned()]);
}

#[test]
fn client_credentials_scope_request_may_only_narrow_registered_scopes() {
    let settings = settings(AuthorizationServerProfile::Oauth2Baseline);
    let client = client();

    let issue = client_credentials_issue_request(
        &settings,
        &client,
        &form(Some("payments accounts"), &["https://api.example.com"]),
    )
    .expect("subset scopes and registered audience should be accepted");

    assert_eq!(
        issue.scopes,
        vec!["payments".to_owned(), "accounts".to_owned()]
    );
    assert_eq!(issue.audiences, vec!["https://api.example.com".to_owned()]);

    let response = client_credentials_issue_request(&settings, &client, &form(Some("admin"), &[]))
        .expect_err("client_credentials must reject scope privilege expansion");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(oauth_error_code(&response), "invalid_scope");
}

#[test]
fn client_credentials_rejects_public_clients_before_issue_construction() {
    let mut client = client();
    client.client_type = "public".to_owned();
    client.token_endpoint_auth_method = "none".to_owned();

    let response = reject_non_confidential_client_credentials_client(&client)
        .expect("public clients must not receive client_credentials tokens");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(oauth_error_code(&response), "unauthorized_client");

    let mut confidential = client;
    confidential.client_type = "confidential".to_owned();
    assert!(
        reject_non_confidential_client_credentials_client(&confidential).is_none(),
        "confidential client must proceed to sender-constraint and grant validation"
    );
}

#[test]
fn client_credentials_rejects_unregistered_audience() {
    let settings = settings(AuthorizationServerProfile::Oauth2Baseline);
    let client = client();

    let response = client_credentials_issue_request(
        &settings,
        &client,
        &form(Some("accounts"), &["https://evil.example.com"]),
    )
    .expect_err("client_credentials access token audience must be client-registered");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(oauth_error_code(&response), "invalid_target");
}
