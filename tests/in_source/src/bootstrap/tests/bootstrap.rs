use super::*;
use actix_web::{HttpResponse, test};

#[actix_web::test]
async fn security_headers_are_added_to_core_responses() {
    let app = test::init_service(App::new().wrap(security_headers()).route(
        "/ok",
        web::get().to(|| async { HttpResponse::Ok().finish() }),
    ))
    .await;

    let request = test::TestRequest::get().uri("/ok").to_request();
    let response = test::call_service(&app, request).await;
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
