use super::*;
use actix_web::{App, HttpResponse, http::StatusCode, test, web};
use std::sync::Arc;

use crate::bootstrap::routes;
use crate::domain::{AppState, DynamicRegistrationHandles};
#[actix_web::test]
async fn browser_token_management_cors_allows_post_dpop_without_credentials() {
    let settings = test_settings(vec!["https://app.example".to_owned()]);
    let app = test::init_service(
        App::new()
            .wrap(cors_browser_token_management(&settings))
            .route(
                "/token",
                web::post().to(|| async { HttpResponse::Ok().finish() }),
            ),
    )
    .await;

    let allowed = test::TestRequest::default()
        .method(actix_web::http::Method::OPTIONS)
        .uri("/token")
        .insert_header((header::ORIGIN, "https://app.example"))
        .insert_header((header::ACCESS_CONTROL_REQUEST_METHOD, "POST"))
        .insert_header((header::ACCESS_CONTROL_REQUEST_HEADERS, "content-type, dpop"))
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
        "browser token management must NOT allow credentials (no cookies)"
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
async fn browser_userinfo_cors_allows_get_and_post_bearer_or_dpop() {
    let settings = test_settings(vec!["https://app.example".to_owned()]);
    for method in ["GET", "POST"] {
        let app = test::init_service(
            App::new()
                .wrap(cors_browser_userinfo(&settings))
                .route(
                    "/userinfo",
                    web::get().to(|| async { HttpResponse::Ok().finish() }),
                )
                .route(
                    "/userinfo",
                    web::post().to(|| async { HttpResponse::Ok().finish() }),
                ),
        )
        .await;
        let request = test::TestRequest::default()
            .method(actix_web::http::Method::OPTIONS)
            .uri("/userinfo")
            .insert_header((header::ORIGIN, "https://app.example"))
            .insert_header((header::ACCESS_CONTROL_REQUEST_METHOD, method))
            .insert_header((
                header::ACCESS_CONTROL_REQUEST_HEADERS,
                "authorization, dpop",
            ))
            .to_request();
        let response = test::call_service(&app, request).await;
        assert_eq!(response.status(), StatusCode::OK, "method={method}");
        assert!(
            response
                .headers()
                .get(header::ACCESS_CONTROL_ALLOW_CREDENTIALS)
                .is_none()
        );
    }
}

#[actix_web::test]
async fn authorization_endpoint_is_not_cors_enabled() {
    let settings = test_settings(vec!["https://app.example".to_owned()]);
    let app =
        test::init_service(App::new().configure(|cfg| routes::configure(cfg, &settings, false)))
            .await;

    let request = test::TestRequest::default()
        .method(actix_web::http::Method::OPTIONS)
        .uri("/authorize")
        .insert_header((header::ORIGIN, "https://app.example"))
        .insert_header((header::ACCESS_CONTROL_REQUEST_METHOD, "GET"))
        .to_request();
    let response = test::call_service(&app, request).await;

    assert_ne!(
        response.status(),
        StatusCode::OK,
        "authorization endpoint must not answer browser CORS preflight"
    );
    assert!(
        response
            .headers()
            .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
            .is_none(),
        "authorization endpoint must not expose itself to browser XHR through CORS"
    );
    assert!(
        response
            .headers()
            .get(header::ACCESS_CONTROL_ALLOW_CREDENTIALS)
            .is_none(),
        "authorization endpoint must not allow credentialed CORS"
    );
}

#[actix_web::test]
async fn disabled_dynamic_client_registration_rejects_before_body_parsing() {
    let settings = Arc::new(test_settings(vec!["https://app.example".to_owned()]));
    let state = web::Data::new(AppState {
        diesel_db: nazo_postgres::create_pool(
            "postgres://disabled_dcr:disabled_dcr@127.0.0.1:1/nazo".to_owned(),
            1,
        )
        .expect("test pool construction should not connect"),
        valkey: fred::prelude::Builder::default_centralized()
            .build()
            .expect("test Valkey client construction should not connect"),
        settings: settings.clone(),
        keyset: crate::test_support::test_key_manager(),
    });
    let dynamic_registration_handles =
        web::Data::new(DynamicRegistrationHandles::from_app_state(state.get_ref()));
    let app = test::init_service(
        App::new()
            .app_data(state)
            .app_data(dynamic_registration_handles)
            .configure(|cfg| routes::configure(cfg, &settings, false)),
    )
    .await;

    let request = test::TestRequest::post()
        .uri("/register")
        .insert_header((header::CONTENT_TYPE, "text/plain"))
        .set_payload("not json")
        .to_request();
    let response = test::call_service(&app, request).await;

    assert_eq!(
        response.status(),
        StatusCode::NOT_FOUND,
        "disabled dynamic registration must reject before parsing an invalid body"
    );
}

#[actix_web::test]
async fn openid_federation_route_is_not_registered() {
    let settings = test_settings(vec!["https://app.example".to_owned()]);
    let app =
        test::init_service(App::new().configure(|cfg| routes::configure(cfg, &settings, false)))
            .await;

    let request = test::TestRequest::get()
        .uri("/.well-known/openid-federation")
        .to_request();
    let response = test::call_service(&app, request).await;

    assert_eq!(
        response.status(),
        StatusCode::NOT_FOUND,
        "OpenID Federation is not part of the product surface"
    );
}

#[actix_web::test]
async fn perf_metrics_route_is_controlled_by_the_typed_startup_flag() {
    let settings = test_settings(Vec::new());
    let disabled =
        test::init_service(App::new().configure(|cfg| routes::configure(cfg, &settings, false)))
            .await;
    let response = test::call_service(
        &disabled,
        test::TestRequest::get().uri("/__perf/metrics").to_request(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    let enabled =
        test::init_service(App::new().configure(|cfg| routes::configure(cfg, &settings, true)))
            .await;
    let response = test::call_service(
        &enabled,
        test::TestRequest::get().uri("/__perf/metrics").to_request(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
}

#[actix_web::test]
async fn cors_actual_response_exposes_oauth_challenge_nonce_and_retry_headers() {
    let settings = test_settings(vec!["https://app.example".to_owned()]);
    let app = test::init_service(App::new().wrap(cors_browser_userinfo(&settings)).route(
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

#[actix_web::test]
async fn cors_admin_allows_csrf_header_for_credentialed_write_requests() {
    let settings = test_settings(vec!["https://admin.example".to_owned()]);
    let app = test::init_service(App::new().wrap(cors_admin(&settings)).route(
        "/admin/clients",
        web::post().to(|| async { HttpResponse::Ok().finish() }),
    ))
    .await;

    let request = test::TestRequest::default()
        .method(actix_web::http::Method::OPTIONS)
        .uri("/admin/clients")
        .insert_header((header::ORIGIN, "https://admin.example"))
        .insert_header((header::ACCESS_CONTROL_REQUEST_METHOD, "POST"))
        .insert_header((
            header::ACCESS_CONTROL_REQUEST_HEADERS,
            "x-csrf-token, content-type",
        ))
        .to_request();
    let response = test::call_service(&app, request).await;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get(header::ACCESS_CONTROL_ALLOW_CREDENTIALS)
            .unwrap(),
        "true"
    );
    assert!(
        response
            .headers()
            .get(header::ACCESS_CONTROL_ALLOW_HEADERS)
            .unwrap()
            .to_str()
            .unwrap()
            .contains("x-csrf-token")
    );
}

#[actix_web::test]
async fn cors_auth_api_credentials_are_limited_to_configured_origins_and_csrf_headers() {
    let settings = test_settings(vec!["https://app.example".to_owned()]);
    let app = test::init_service(App::new().wrap(cors_auth_api(&settings)).route(
        "/auth/me",
        web::patch().to(|| async { HttpResponse::Ok().finish() }),
    ))
    .await;

    let allowed = test::TestRequest::default()
        .method(actix_web::http::Method::OPTIONS)
        .uri("/auth/me")
        .insert_header((header::ORIGIN, "https://app.example"))
        .insert_header((header::ACCESS_CONTROL_REQUEST_METHOD, "PATCH"))
        .insert_header((
            header::ACCESS_CONTROL_REQUEST_HEADERS,
            "x-csrf-token, content-type",
        ))
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
    assert_eq!(
        response
            .headers()
            .get(header::ACCESS_CONTROL_ALLOW_CREDENTIALS)
            .unwrap(),
        "true"
    );
    assert!(
        response
            .headers()
            .get(header::ACCESS_CONTROL_ALLOW_HEADERS)
            .unwrap()
            .to_str()
            .unwrap()
            .contains("x-csrf-token"),
        "credentialed auth API writes must allow only explicit CSRF-bearing CORS requests"
    );

    let denied = test::TestRequest::default()
        .method(actix_web::http::Method::OPTIONS)
        .uri("/auth/me")
        .insert_header((header::ORIGIN, "https://attacker.example"))
        .insert_header((header::ACCESS_CONTROL_REQUEST_METHOD, "PATCH"))
        .insert_header((
            header::ACCESS_CONTROL_REQUEST_HEADERS,
            "x-csrf-token, content-type",
        ))
        .to_request();
    let response = test::call_service(&app, denied).await;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(
        response
            .headers()
            .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
            .is_none(),
        "credentialed auth API CORS must not authorize unregistered browser origins"
    );
    assert!(
        response
            .headers()
            .get(header::ACCESS_CONTROL_ALLOW_CREDENTIALS)
            .is_none(),
        "credentialed auth API CORS must not expose cookies to unregistered origins"
    );
}

#[actix_web::test]
async fn cors_scim_allows_put_without_browser_credentials() {
    let settings = test_settings(vec!["https://scim-admin.example".to_owned()]);
    let app = test::init_service(App::new().wrap(cors_scim(&settings)).route(
        "/scim/v2/Users/user-1",
        web::put().to(|| async { HttpResponse::Ok().finish() }),
    ))
    .await;

    let request = test::TestRequest::default()
        .method(actix_web::http::Method::OPTIONS)
        .uri("/scim/v2/Users/user-1")
        .insert_header((header::ORIGIN, "https://scim-admin.example"))
        .insert_header((header::ACCESS_CONTROL_REQUEST_METHOD, "PUT"))
        .insert_header((
            header::ACCESS_CONTROL_REQUEST_HEADERS,
            "authorization, content-type",
        ))
        .to_request();
    let response = test::call_service(&app, request).await;

    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        response
            .headers()
            .get(header::ACCESS_CONTROL_ALLOW_CREDENTIALS)
            .is_none(),
        "SCIM uses bearer authentication and must not authorize browser credentials"
    );
}

#[actix_web::test]
async fn production_token_route_rejects_get_csrf_and_unknown_origins() {
    let settings = test_settings(vec!["https://spa.example".to_owned()]);
    let app =
        test::init_service(App::new().configure(|cfg| routes::configure(cfg, &settings, false)))
            .await;

    for (origin, method, headers) in [
        ("https://spa.example", "GET", "content-type"),
        ("https://spa.example", "POST", "x-csrf-token"),
        ("https://attacker.example", "POST", "content-type"),
    ] {
        let request = test::TestRequest::default()
            .method(actix_web::http::Method::OPTIONS)
            .uri("/token")
            .insert_header((header::ORIGIN, origin))
            .insert_header((header::ACCESS_CONTROL_REQUEST_METHOD, method))
            .insert_header((header::ACCESS_CONTROL_REQUEST_HEADERS, headers))
            .to_request();
        let response = test::call_service(&app, request).await;
        assert_eq!(
            response.status(),
            StatusCode::BAD_REQUEST,
            "token preflight must reject origin={origin}, method={method}, headers={headers}"
        );
        assert!(
            response
                .headers()
                .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
                .is_none(),
            "rejected token preflight must not authorize its origin"
        );
    }
}

#[actix_web::test]
async fn production_browser_oauth_routes_expose_only_required_cors() {
    let settings = test_settings(vec!["https://spa.example".to_owned()]);
    let app =
        test::init_service(App::new().configure(|cfg| routes::configure(cfg, &settings, false)))
            .await;

    for (path, method, headers) in [
        ("/token", "POST", "content-type, dpop"),
        ("/revoke", "POST", "content-type, authorization, dpop"),
        ("/userinfo", "GET", "authorization, dpop"),
        ("/userinfo", "POST", "authorization, content-type, dpop"),
    ] {
        let request = test::TestRequest::default()
            .method(actix_web::http::Method::OPTIONS)
            .uri(path)
            .insert_header((header::ORIGIN, "https://spa.example"))
            .insert_header((header::ACCESS_CONTROL_REQUEST_METHOD, method))
            .insert_header((header::ACCESS_CONTROL_REQUEST_HEADERS, headers))
            .to_request();
        let response = test::call_service(&app, request).await;
        assert_eq!(response.status(), StatusCode::OK, "{path} {method}");
        assert!(
            response
                .headers()
                .get(header::ACCESS_CONTROL_ALLOW_CREDENTIALS)
                .is_none(),
            "public browser OAuth routes must not authorize cookies"
        );
    }
}

fn test_settings(cors_allowed_origins: Vec<String>) -> Settings {
    let mut settings =
        Settings::from_config(&crate::config::ConfigSource::default()).expect("settings");
    settings.endpoint.issuer = "https://issuer.example".to_owned();
    settings.endpoint.mtls_endpoint_base_url = "https://issuer.example".to_owned();
    settings.endpoint.frontend_base_url = "https://app.example".to_owned();
    settings.endpoint.cors_allowed_origins = cors_allowed_origins;
    settings.session.cookie_secure = true;
    settings
}
