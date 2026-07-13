use super::*;

use actix_web::middleware::from_fn;
use actix_web::{App, test as actix_test, web};
use nazo_http_actix::security_headers;

use crate::support::sessions::{SessionHttpConfig, SessionProfileHandles};

fn disabled_session_profile_handles() -> Data<SessionProfileHandles> {
    let pool = nazo_postgres::create_pool(
        "postgres://session_profile_invalid:session_profile_invalid@127.0.0.1:1/nazo".to_owned(),
        1,
    )
    .expect("test pool construction should not connect");
    let client = nazo_valkey::test_support::Builder::default_centralized()
        .build()
        .expect("test Valkey client construction should not connect");
    let connection = nazo_valkey::ValkeyConnection::from_existing_client(client);
    Data::new(SessionProfileHandles::new(
        nazo_valkey::SessionStore::new(&connection),
        nazo_postgres::UserRepository::new(pool),
        SessionHttpConfig::new("sid", "csrf", true),
        "https://issuer.example",
        false,
    ))
}

#[test]
fn oidc_session_state_is_origin_client_and_salt_bound() {
    let salt = random_urlsafe_token();
    let state = oidc_session_state("client-1", "https://client.example", "opbs-1", &salt);

    assert!(state.ends_with(&format!(".{salt}")));
    assert_eq!(
        state,
        oidc_session_state("client-1", "https://client.example", "opbs-1", &salt)
    );
    assert_ne!(
        state,
        oidc_session_state("client-2", "https://client.example", "opbs-1", &salt)
    );
    assert_ne!(
        state,
        oidc_session_state("client-1", "https://other.example", "opbs-1", &salt)
    );
}

#[test]
fn issue_oidc_session_state_uses_redirect_uri_origin() {
    let state = issue_oidc_session_state(
        "client-1",
        "https://client.example:8443/callback?code=unused",
        "opbs-1",
    )
    .expect("absolute redirect URI should produce a session_state");
    let (_, salt) = state.rsplit_once('.').expect("session_state contains salt");

    assert_eq!(
        state,
        oidc_session_state("client-1", "https://client.example:8443", "opbs-1", salt)
    );
    assert!(issue_oidc_session_state("client-1", "not-a-uri", "opbs-1").is_none());
}

#[test]
fn session_management_iframe_document_escapes_status_endpoint() {
    let html = session_management_iframe_document("https://issuer.example/check?x=1&y='z'");

    assert!(html.contains("https://issuer.example/check?x=1\\u0026y=\\'z\\'"));
    assert!(!html.contains("x=1&y='z'"));
    assert!(!html.contains("var statusEndpoint = '\n"));
    assert!(html.contains("new XMLHttpRequest()"));
    assert!(!html.contains("fetch("));
}

#[actix_web::test]
async fn disabled_session_management_route_contract_is_stable_for_all_registered_methods() {
    let app = actix_test::init_service(
        App::new()
            .wrap(from_fn(security_headers))
            .app_data(disabled_session_profile_handles())
            .route("/check_session", web::get().to(check_session_iframe))
            .route("/check_session/status", web::get().to(check_session_status)),
    )
    .await;

    let cases = [
        ("/check_session", false),
        (
            "/check_session/status?client_id=client&origin=https%3A%2F%2Fclient.example&session_state=digest.salt",
            true,
        ),
    ];
    for (uri, frame_protection_expected) in cases {
        for method in [
            actix_web::http::Method::GET,
            actix_web::http::Method::POST,
            actix_web::http::Method::OPTIONS,
        ] {
            let request = actix_test::TestRequest::default()
                .method(method.clone())
                .uri(uri)
                .insert_header((header::ORIGIN, "https://client.example"))
                .to_request();
            let response = actix_test::call_service(&app, request).await;
            assert_eq!(response.status(), StatusCode::NOT_FOUND, "{method} {uri}");
            assert!(response.headers().get(header::CONTENT_TYPE).is_none());
            assert!(
                response
                    .headers()
                    .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
                    .is_none()
            );
            assert!(response.headers().get(header::CACHE_CONTROL).is_none());
            assert_eq!(
                response
                    .headers()
                    .get(header::X_CONTENT_TYPE_OPTIONS)
                    .unwrap(),
                "nosniff"
            );
            assert_eq!(
                response.headers().get("Referrer-Policy").unwrap(),
                "no-referrer"
            );
            if frame_protection_expected {
                assert_eq!(
                    response.headers().get(header::X_FRAME_OPTIONS).unwrap(),
                    "DENY"
                );
                assert!(
                    response
                        .headers()
                        .get("Content-Security-Policy")
                        .unwrap()
                        .to_str()
                        .unwrap()
                        .contains("frame-ancestors 'none'")
                );
            } else {
                assert!(response.headers().get(header::X_FRAME_OPTIONS).is_none());
                assert!(
                    !response
                        .headers()
                        .get("Content-Security-Policy")
                        .unwrap()
                        .to_str()
                        .unwrap()
                        .contains("frame-ancestors 'none'")
                );
            }
            let body = actix_web::body::to_bytes(response.into_body())
                .await
                .expect("disabled route response should collect");
            assert!(body.is_empty());
        }
    }
}
