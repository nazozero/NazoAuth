use super::*;
use actix_web::{App, HttpResponse, http::StatusCode, test, web};
use std::path::PathBuf;

use crate::settings::{
    AuthorizationServerProfile, DpopNoncePolicy, EmailDelivery, EmailSettings, FederationSettings,
    PasskeySettings, RateLimitSettings, RequestObjectJtiPolicy, SubjectType,
};
use crate::support::ClientIpHeaderMode;

#[actix_web::test]
async fn cors_preflight_allows_only_configured_origin_methods_and_security_headers() {
    let settings = test_settings(vec!["https://app.example".to_owned()]);
    let app = test::init_service(App::new().wrap(cors_browser_oauth(&settings)).route(
        "/token",
        web::post().to(|| async { HttpResponse::Ok().finish() }),
    ))
    .await;

    let allowed = test::TestRequest::default()
        .method(actix_web::http::Method::OPTIONS)
        .uri("/token")
        .insert_header((header::ORIGIN, "https://app.example"))
        .insert_header((header::ACCESS_CONTROL_REQUEST_METHOD, "POST"))
        .insert_header((header::ACCESS_CONTROL_REQUEST_HEADERS, "dpop, x-csrf-token"))
        .to_request();
    let response = test::call_service(&app, allowed).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
            .unwrap(),
        "https://app.example"
    );
    assert!(
        response
            .headers()
            .get(header::ACCESS_CONTROL_ALLOW_CREDENTIALS)
            .is_none(),
        "cors_browser_oauth must NOT allow credentials (no cookies)"
    );
    assert!(
        response
            .headers()
            .get(header::ACCESS_CONTROL_ALLOW_HEADERS)
            .unwrap()
            .to_str()
            .unwrap()
            .contains("dpop"),
        "DPoP proofs must be explicitly allowed for browser token requests"
    );

    let denied = test::TestRequest::default()
        .method(actix_web::http::Method::OPTIONS)
        .uri("/token")
        .insert_header((header::ORIGIN, "https://attacker.example"))
        .insert_header((header::ACCESS_CONTROL_REQUEST_METHOD, "POST"))
        .to_request();
    let response = test::call_service(&app, denied).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(
        response
            .headers()
            .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
            .is_none(),
        "unregistered browser origins must not receive CORS authorization"
    );
}

#[actix_web::test]
async fn cors_actual_response_exposes_oauth_challenge_nonce_and_retry_headers() {
    let settings = test_settings(vec!["https://app.example".to_owned()]);
    let app = test::init_service(App::new().wrap(cors_browser_oauth(&settings)).route(
        "/resource",
        web::get().to(|| async {
            HttpResponse::Unauthorized()
                .insert_header((header::WWW_AUTHENTICATE, "DPoP error=\"use_dpop_nonce\""))
                .insert_header(("dpop-nonce", "nonce-1"))
                .insert_header((header::RETRY_AFTER, "5"))
                .finish()
        }),
    ))
    .await;

    let request = test::TestRequest::get()
        .uri("/resource")
        .insert_header((header::ORIGIN, "https://app.example"))
        .to_request();
    let response = test::call_service(&app, request).await;

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let expose = response
        .headers()
        .get(header::ACCESS_CONTROL_EXPOSE_HEADERS)
        .unwrap()
        .to_str()
        .unwrap();
    assert!(expose.contains("www-authenticate"));
    assert!(expose.contains("dpop-nonce"));
    assert!(expose.contains("retry-after"));
}

#[actix_web::test]
async fn cors_well_known_allows_get_and_head_only() {
    let settings = test_settings(vec!["https://app.example".to_owned()]);
    let app = test::init_service(App::new().wrap(cors_well_known(&settings)).route(
        "/.well-known/openid-configuration",
        web::get().to(|| async { HttpResponse::Ok().finish() }),
    ))
    .await;

    let allowed = test::TestRequest::default()
        .method(actix_web::http::Method::OPTIONS)
        .uri("/.well-known/openid-configuration")
        .insert_header((header::ORIGIN, "https://app.example"))
        .insert_header((header::ACCESS_CONTROL_REQUEST_METHOD, "GET"))
        .to_request();
    let response = test::call_service(&app, allowed).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        response
            .headers()
            .get(header::ACCESS_CONTROL_ALLOW_CREDENTIALS)
            .is_none(),
        "cors_well_known must NOT allow credentials"
    );
}

fn test_settings(cors_allowed_origins: Vec<String>) -> Settings {
    Settings {
        issuer: "https://issuer.example".to_owned(),
        mtls_endpoint_base_url: "https://issuer.example".to_owned(),
        frontend_base_url: "https://app.example".to_owned(),
        cors_allowed_origins,
        default_audience: "resource://default".to_owned(),
        authorization_server_profile: AuthorizationServerProfile::Oauth2Baseline,
        dpop_nonce_policy: DpopNoncePolicy::Required,
        request_object_jti_policy: RequestObjectJtiPolicy::Optional,
        session_cookie_name: "session".to_owned(),
        csrf_cookie_name: "csrf".to_owned(),
        cookie_secure: true,
        session_ttl_seconds: 28_800,
        auth_code_ttl_seconds: 300,
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
        signing_key_rotation_interval_seconds: 7_776_000,
        signing_key_prepublish_seconds: 86_400,
        trusted_proxy_cidrs: Vec::new(),
        client_ip_header_mode: ClientIpHeaderMode::None,
        subject_type: SubjectType::Public,
        pairwise_subject_secret: None,
        par_ttl_seconds: 90,
        require_pushed_authorization_requests: false,
        scim_bearer_token: None,
        passkey: PasskeySettings {
            rp_id: "issuer.example".to_owned(),
            rp_name: "Nazo OAuth".to_owned(),
            origin: "https://issuer.example".to_owned(),
            require_user_verification: true,
            require_user_handle: true,
            strict_base64: true,
        },
        federation: FederationSettings {
            oidc: None,
            saml_gateway: None,
        },
        enable_request_object: false,
        enable_request_uri_parameter: false,
        enable_par_request_object: false,
        enable_authorization_details: false,
        enable_legacy_audience_param: false,
    }
}
