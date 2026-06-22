use super::*;
use actix_web::{HttpResponse, test as actix_test};

#[actix_web::test]
async fn security_headers_are_added_to_core_responses() {
    let app = actix_test::init_service(App::new().wrap(security_headers()).route(
        "/ok",
        web::get().to(|| async { HttpResponse::Ok().finish() }),
    ))
    .await;

    let request = actix_test::TestRequest::get().uri("/ok").to_request();
    let response = actix_test::call_service(&app, request).await;
    let headers = response.headers();

    assert_eq!(
        headers.get(header::X_CONTENT_TYPE_OPTIONS).unwrap(),
        "nosniff"
    );
    assert_eq!(headers.get("Referrer-Policy").unwrap(), "no-referrer");
    assert_eq!(
        headers.get("Permissions-Policy").unwrap(),
        "interest-cohort=()"
    );
    assert_eq!(headers.get(header::X_FRAME_OPTIONS).unwrap(), "DENY");
    assert!(
        headers
            .get("Content-Security-Policy")
            .unwrap()
            .to_str()
            .unwrap()
            .contains("frame-ancestors 'none'")
    );
}

#[actix_web::test]
async fn signing_key_refresh_interval_is_bounded_by_prepublish_window() {
    let mut settings = Settings::from_config(&ConfigSource::from_pairs_for_test([
        ("ISSUER", "https://issuer.example"),
        ("FRONTEND_BASE_URL", "https://frontend.example"),
        ("COOKIE_SECURE", "true"),
        ("DATABASE_URL", "postgres://unused"),
        ("VALKEY_URL", "redis://127.0.0.1:6379/0"),
    ]))
    .unwrap();

    settings.signing_key_prepublish_seconds = 86_400;
    assert_eq!(
        signing_key_refresh_interval(&settings),
        Duration::from_secs(3_600)
    );

    settings.signing_key_prepublish_seconds = 30;
    assert_eq!(
        signing_key_refresh_interval(&settings),
        Duration::from_secs(15)
    );

    settings.signing_key_prepublish_seconds = 1;
    assert_eq!(
        signing_key_refresh_interval(&settings),
        Duration::from_secs(1)
    );
}

#[test]
#[should_panic(expected = "signing key lifecycle refresh failed")]
fn signing_key_refresh_failure_is_fail_closed_in_test_build() {
    terminate_after_keyset_refresh_failure(anyhow::anyhow!("keyset refresh failed"));
}
