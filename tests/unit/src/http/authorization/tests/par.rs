use super::*;
use std::path::PathBuf;
use std::sync::Arc;

use crate::config::ConfigSource;
use crate::db::create_pool;
use crate::domain::{ActiveSigningKey, Keyset};
use crate::settings::{
    AuthorizationServerProfile, DpopNoncePolicy, EmailDelivery, EmailSettings, RateLimitSettings,
    RequestObjectJtiPolicy, SubjectType,
};
use crate::support::{ClientIpHeaderMode, IpCidr};
use actix_web::test::TestRequest;

fn client(require_dpop_bound_tokens: bool) -> ClientRow {
    ClientRow {
        id: Uuid::now_v7(),
        tenant_id: DEFAULT_TENANT_ID,
        realm_id: DEFAULT_REALM_ID,
        organization_id: DEFAULT_ORGANIZATION_ID,
        client_id: "client-a".to_owned(),
        client_name: "Client A".to_owned(),
        client_type: "confidential".to_owned(),
        client_secret_argon2_hash: None,
        redirect_uris: json!(["https://client.example/callback"]),
        scopes: json!(["openid"]),
        allowed_audiences: json!([]),
        grant_types: json!(["authorization_code"]),
        token_endpoint_auth_method: "private_key_jwt".to_owned(),
        require_dpop_bound_tokens,
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

fn baseline_settings() -> Settings {
    Settings {
        issuer: "https://issuer.example".to_owned(),
        mtls_endpoint_base_url: "https://issuer.example".to_owned(),
        frontend_base_url: "https://app.example".to_owned(),
        cors_allowed_origins: vec!["https://app.example".to_owned()],
        default_audience: "resource://default".to_owned(),
        authorization_server_profile: AuthorizationServerProfile::Oauth2Baseline,
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
        require_pushed_authorization_requests: false,
        scim_bearer_token: None,
        passkey: crate::settings::PasskeySettings {
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

fn oauth_error_code(response: &HttpResponse) -> Option<String> {
    response
        .extensions()
        .get::<OAuthJsonErrorFields>()
        .map(|fields| fields.error.clone())
}

fn par_state_without_live_services() -> Data<AppState> {
    let mut settings =
        Settings::from_config(&ConfigSource::default()).expect("default settings should load");
    settings.rate_limit.token_management_max_requests = 100_000;
    let mut valkey_builder = fred::prelude::Builder::from_config(
        fred::prelude::Config::from_url("redis://127.0.0.1:1")
            .expect("unavailable Valkey URL should parse"),
    );
    valkey_builder.with_performance_config(|performance: &mut fred::prelude::PerformanceConfig| {
        performance.default_command_timeout = std::time::Duration::from_millis(50);
    });
    valkey_builder.with_connection_config(|connection: &mut fred::prelude::ConnectionConfig| {
        connection.connection_timeout = std::time::Duration::from_millis(50);
        connection.internal_command_timeout = std::time::Duration::from_millis(50);
        connection.max_command_attempts = 1;
    });

    Data::new(AppState {
        diesel_db: create_pool(
            "postgres://nazo_par_test_invalid:nazo_par_test_invalid@127.0.0.1:1/nazo".to_owned(),
            1,
        )
        .expect("pool construction should not connect"),
        valkey: valkey_builder
            .build()
            .expect("valkey client construction should not connect"),
        settings: Arc::new(settings),
        keyset: Arc::new(Keyset {
            active_kid: "test-kid".to_owned(),
            active_alg: jsonwebtoken::Algorithm::EdDSA,
            active_signing_key: ActiveSigningKey::LocalPkcs8Der(Vec::new()),
            verification_keys: Vec::new(),
        }),
    })
}

fn par_form_request() -> HttpRequest {
    TestRequest::post()
        .uri("/oauth/par")
        .insert_header((header::CONTENT_TYPE, "application/x-www-form-urlencoded"))
        .to_http_request()
}

async fn par_json_body(response: HttpResponse) -> (StatusCode, Value) {
    let status = response.status();
    let body = actix_web::body::to_bytes(response.into_body())
        .await
        .expect("PAR response body should collect");
    let value = serde_json::from_slice(&body).expect("PAR error response should be JSON");
    (status, value)
}

#[test]
fn par_does_not_require_request_object_for_dpop_bound_clients() {
    let mut params = HashMap::new();
    params.insert(
        "redirect_uri".to_owned(),
        "https://client.example/callback".to_owned(),
    );

    assert!(validate_pushed_authorization_request(&client(true), &params).is_ok());
}

#[test]
fn par_policy_requires_request_object_when_enabled() {
    let mut policy_client = client(true);
    policy_client.require_par_request_object = true;
    let settings = baseline_settings();

    assert!(!pushed_authorization_request_requires_request_object(
        &settings,
        &client(true)
    ));
    assert!(pushed_authorization_request_requires_request_object(
        &settings,
        &policy_client
    ));
}

#[test]
fn message_signing_profile_requires_request_object_at_par() {
    let settings = Settings {
        authorization_server_profile: AuthorizationServerProfile::Fapi2MessageSigningAuthzRequest,
        require_pushed_authorization_requests: true,
        ..baseline_settings()
    };

    assert!(pushed_authorization_request_requires_request_object(
        &settings,
        &client(true)
    ));
}

#[test]
fn baseline_profile_does_not_reject_legacy_par_client_auth_combinations() {
    let settings = baseline_settings();
    let public_client = ClientRow {
        client_type: "public".to_owned(),
        token_endpoint_auth_method: "none".to_owned(),
        require_dpop_bound_tokens: false,
        ..client(false)
    };

    assert!(
        validate_pushed_authorization_request_profile(&settings, &public_client, "none").is_ok()
    );
}

#[test]
fn fapi2_profile_requires_confidential_clients() {
    let settings = Settings {
        authorization_server_profile: AuthorizationServerProfile::Fapi2Security,
        ..baseline_settings()
    };
    let public_client = ClientRow {
        client_type: "public".to_owned(),
        token_endpoint_auth_method: "none".to_owned(),
        require_dpop_bound_tokens: true,
        ..client(true)
    };

    let response = validate_pushed_authorization_request_profile(&settings, &public_client, "none")
        .expect_err("FAPI2 PAR must reject public clients");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        oauth_error_code(&response).as_deref(),
        Some("unauthorized_client")
    );
}

#[test]
fn fapi2_profile_requires_private_key_jwt_or_mtls_client_auth() {
    let settings = Settings {
        authorization_server_profile: AuthorizationServerProfile::Fapi2Security,
        ..baseline_settings()
    };
    let confidential_client = ClientRow {
        require_dpop_bound_tokens: true,
        token_endpoint_auth_method: "client_secret_basic".to_owned(),
        ..client(true)
    };

    let response = validate_pushed_authorization_request_profile(
        &settings,
        &confidential_client,
        "client_secret_basic",
    )
    .expect_err("FAPI2 PAR must reject shared-secret client authentication");

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        oauth_error_code(&response).as_deref(),
        Some("invalid_client")
    );

    assert!(
        validate_pushed_authorization_request_profile(
            &settings,
            &confidential_client,
            "private_key_jwt",
        )
        .is_ok()
    );
    assert!(
        validate_pushed_authorization_request_profile(
            &settings,
            &confidential_client,
            "tls_client_auth",
        )
        .is_ok()
    );
}

#[test]
fn fapi2_profile_requires_sender_constrained_tokens() {
    let settings = Settings {
        authorization_server_profile: AuthorizationServerProfile::Fapi2Security,
        ..baseline_settings()
    };
    let bearer_client = ClientRow {
        require_dpop_bound_tokens: false,
        require_mtls_bound_tokens: false,
        ..client(false)
    };

    let response =
        validate_pushed_authorization_request_profile(&settings, &bearer_client, "private_key_jwt")
            .expect_err("FAPI2 PAR must reject bearer-only access token clients");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        oauth_error_code(&response).as_deref(),
        Some("invalid_request")
    );
}

#[test]
fn par_rejects_request_uri_after_request_object_expansion() {
    assert!(!pushed_authorization_request_contains_request_uri(
        &HashMap::new()
    ));

    let mut params = HashMap::new();
    params.insert(
        "request_uri".to_owned(),
        "urn:example:bwc4JK-ESC0w8acc191e-Y1LTC2".to_owned(),
    );
    assert!(pushed_authorization_request_contains_request_uri(&params));
}

#[test]
fn par_rejects_explicit_unsupported_response_type() {
    assert!(!pushed_authorization_request_has_unsupported_response_type(
        &HashMap::new()
    ));

    let mut params = HashMap::new();
    params.insert("response_type".to_owned(), "code".to_owned());
    assert!(!pushed_authorization_request_has_unsupported_response_type(
        &params
    ));

    params.insert("response_type".to_owned(), "code id_token".to_owned());
    assert!(pushed_authorization_request_has_unsupported_response_type(
        &params
    ));
}

#[test]
fn par_validation_binds_request_uri_to_registered_redirect_uri() {
    let mut params = HashMap::from([("response_type".to_owned(), "code".to_owned())]);

    assert!(
        validate_pushed_authorization_request(&client(false), &params).is_ok(),
        "single registered redirect_uri remains unambiguous when omitted"
    );

    let mut multi_redirect_client = client(false);
    multi_redirect_client.redirect_uris = json!([
        "https://client.example/callback",
        "https://client.example/secondary-callback"
    ]);
    let missing = validate_pushed_authorization_request(&multi_redirect_client, &params)
        .expect_err("PAR must not mint a request_uri when redirect_uri is ambiguous");
    assert_eq!(missing.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        oauth_error_code(&missing).as_deref(),
        Some("invalid_request")
    );

    params.insert(
        "redirect_uri".to_owned(),
        "https://attacker.example/callback".to_owned(),
    );
    let invalid = validate_pushed_authorization_request(&client(false), &params)
        .expect_err("PAR must bind only pre-registered redirect_uri values");
    assert_eq!(invalid.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        oauth_error_code(&invalid).as_deref(),
        Some("invalid_request")
    );

    params.insert(
        "redirect_uri".to_owned(),
        "https://client.example/callback".to_owned(),
    );
    assert!(validate_pushed_authorization_request(&client(false), &params).is_ok());
}

#[actix_web::test]
async fn par_rejects_non_form_content_type_before_client_lookup() {
    let response = par_after_rate_limit(
        par_state_without_live_services(),
        TestRequest::post()
            .uri("/oauth/par")
            .insert_header((header::CONTENT_TYPE, "application/json"))
            .to_http_request(),
        Bytes::from_static(br#"{"client_id":"client-a"}"#),
    )
    .await;

    let (status, body) = par_json_body(response).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body.get("error"), Some(&json!("invalid_request")));
}

#[actix_web::test]
async fn par_rejects_malformed_or_ambiguous_authorization_parameters_before_client_lookup() {
    let cases: &[&[u8]] = &[
        b"client_id=\xff",
        b"client_id=client-a&request_uri=urn%3Aietf%3Aparams%3Aoauth%3Arequest_uri%3Ax",
        b"client_id=client-a&unsupported=value",
        b"client_id=client-a&client_id=client-b",
        b"response_type=code&redirect_uri=https%3A%2F%2Fclient.example%2Fcallback",
    ];

    for body in cases {
        let response = par_after_rate_limit(
            par_state_without_live_services(),
            par_form_request(),
            Bytes::copy_from_slice(body),
        )
        .await;
        let (status, value) = par_json_body(response).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(value.get("error"), Some(&json!("invalid_request")));
    }
}
