use super::*;
use actix_web::{App, HttpResponse, test as awtest};

#[actix_web::test]
async fn business_namespaces_bypass_tenant_selection_and_keep_host_fallback() {
    let app = awtest::init_service(
        App::new()
            .route(
                "/api",
                web::get().to(|| async { HttpResponse::Ok().body("business") }),
            )
            .default_service(web::to(|| async {
                HttpResponse::NotFound().body("host fallback")
            }))
            .wrap(DynamicMount::new(TenantRuntimeRegistry::empty(), &["/api"]).unwrap()),
    )
    .await;
    for path in ["/api", "/%61pi"] {
        let request = awtest::TestRequest::get()
            .uri(path)
            .insert_header(("host", "unknown.example"))
            .to_request();
        let response = awtest::call_service(&app, request).await;
        assert_eq!(response.status(), actix_web::http::StatusCode::OK);
        assert_eq!(awtest::read_body(response).await, "business");
    }
    let request = awtest::TestRequest::get().uri("/api/missing").to_request();
    let response = awtest::call_service(&app, request).await;
    assert_eq!(awtest::read_body(response).await, "host fallback");

    // A prefix without a segment boundary does not reserve an auth namespace.
    let request = awtest::TestRequest::get()
        .uri("/api-extra")
        .insert_header(("host", "unknown.example"))
        .to_request();
    let response = awtest::call_service(&app, request).await;
    assert_eq!(response.status(), actix_web::http::StatusCode::NOT_FOUND);
    assert!(response.headers().contains_key("x-content-type-options"));
    assert!(awtest::read_body(response).await.is_empty());
    for target in ["/token", "https://unknown.example/token"] {
        for host in [None, Some("unknown.example:abc")] {
            let mut request = awtest::TestRequest::get().uri(target);
            if let Some(host) = host {
                request = request.insert_header(("host", host));
            }
            let response = awtest::call_service(&app, request.to_request()).await;
            assert_eq!(response.status(), actix_web::http::StatusCode::BAD_REQUEST);
            assert!(response.headers().contains_key("x-content-type-options"));
        }
    }
}

#[actix_web::test]
async fn unknown_authorities_fail_closed_without_trusting_forwarded_headers() {
    let app = awtest::init_service(
        App::new()
            .default_service(web::to(|| async { HttpResponse::Ok().body("host") }))
            .wrap(DynamicMount::new(TenantRuntimeRegistry::empty(), &[]).unwrap()),
    )
    .await;
    let request = awtest::TestRequest::post()
        .uri("/token")
        .insert_header(("host", "unknown.example"))
        .insert_header(("forwarded", "host=trusted.example;proto=https"))
        .insert_header(("x-forwarded-host", "trusted.example"))
        .set_payload("grant_type=client_credentials")
        .to_request();
    let response = awtest::call_service(&app, request).await;
    assert_eq!(response.status(), actix_web::http::StatusCode::NOT_FOUND);
    assert!(response.headers().contains_key("x-content-type-options"));
    assert!(awtest::read_body(response).await.is_empty());
}

#[test]
fn authority_uses_the_original_transport_authority() {
    let http1 = awtest::TestRequest::get()
        .uri("https://absolute.example/token")
        .insert_header(("host", "header.example:8443"))
        .insert_header(("x-forwarded-host", "untrusted.example"))
        .to_http_request();
    assert_eq!(request_authority(&http1), Ok("absolute.example"));
    let origin = awtest::TestRequest::get()
        .uri("/token")
        .insert_header(("host", "header.example:8443"))
        .to_http_request();
    assert_eq!(request_authority(&origin), Ok("header.example:8443"));
    let http2 = awtest::TestRequest::get()
        .uri("https://absolute.example/token")
        .version(Version::HTTP_2)
        .insert_header(("host", "header.example"))
        .to_http_request();
    assert_eq!(
        request_authority(&http2),
        Err(http::StatusCode::BAD_REQUEST)
    );
    for (version, target, host, expected) in [
        (
            Version::HTTP_2,
            "https://absolute.example/token",
            Some("ABSOLUTE.example"),
            Ok("absolute.example"),
        ),
        (
            Version::HTTP_2,
            "https://absolute.example/token",
            Some("absolute.example:443"),
            Ok("absolute.example"),
        ),
        (
            Version::HTTP_2,
            "https://absolute.example/token",
            Some("absolute.example:8443"),
            Err(http::StatusCode::BAD_REQUEST),
        ),
        (
            Version::HTTP_2,
            "https://absolute.example/token",
            None,
            Ok("absolute.example"),
        ),
        (
            Version::HTTP_2,
            "/token",
            Some("absolute.example"),
            Err(http::StatusCode::BAD_REQUEST),
        ),
        (
            Version::HTTP_3,
            "/token",
            Some("absolute.example"),
            Ok("absolute.example"),
        ),
        (
            Version::HTTP_3,
            "https://absolute.example/token",
            Some("header.example"),
            Err(http::StatusCode::BAD_REQUEST),
        ),
        (
            Version::HTTP_3,
            "https://absolute.example/token",
            Some("absolute.example"),
            Ok("absolute.example"),
        ),
    ] {
        let mut builder = awtest::TestRequest::get().version(version).uri(target);
        if let Some(host) = host {
            builder = builder.insert_header(("host", host));
        }
        assert_eq!(request_authority(&builder.to_http_request()), expected);
    }
    let duplicated = awtest::TestRequest::get()
        .uri("/token")
        .append_header(("host", "first.example"))
        .append_header(("host", "second.example"))
        .to_http_request();
    assert_eq!(
        request_authority(&duplicated),
        Err(http::StatusCode::BAD_REQUEST)
    );
    let absolute_duplicate = awtest::TestRequest::get()
        .uri("https://absolute.example/token")
        .append_header(("host", "first.example"))
        .append_header(("host", "second.example"))
        .to_http_request();
    assert_eq!(
        request_authority(&absolute_duplicate),
        Err(http::StatusCode::BAD_REQUEST)
    );
}
