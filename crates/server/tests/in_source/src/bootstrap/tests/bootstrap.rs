use super::*;
use actix_web::{HttpResponse, test as actix_test};

#[actix_web::test]
async fn security_headers_are_added_to_core_responses() {
    let app = actix_test::init_service(App::new().wrap(from_fn(security_headers)).route(
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
async fn check_session_iframe_is_frameable_by_relying_parties() {
    let app = actix_test::init_service(App::new().wrap(from_fn(security_headers)).route(
        "/check_session",
        web::get().to(|| async { HttpResponse::Ok().finish() }),
    ))
    .await;

    let request = actix_test::TestRequest::get()
        .uri("/check_session")
        .to_request();
    let response = actix_test::call_service(&app, request).await;
    let headers = response.headers();

    assert!(headers.get(header::X_FRAME_OPTIONS).is_none());
    assert!(
        !headers
            .get("Content-Security-Policy")
            .unwrap()
            .to_str()
            .unwrap()
            .contains("frame-ancestors 'none'")
    );
}
