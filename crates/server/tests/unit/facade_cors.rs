use bytes::Bytes;
use http::header;

#[actix_web::test]
async fn disabled_dynamic_client_registration_keeps_the_static_route_contract() {
    let state = super::infrastructure(false).await;
    let facade = crate::test_support::facade::application(&state)
        .await
        .unwrap();
    let requests = [
        (http::Method::POST, "/register", http::StatusCode::NOT_FOUND),
        (
            http::Method::GET,
            "/register/client-test",
            http::StatusCode::NOT_FOUND,
        ),
        (
            http::Method::PUT,
            "/register/client-test",
            http::StatusCode::NOT_FOUND,
        ),
        (
            http::Method::DELETE,
            "/register/client-test",
            http::StatusCode::NOT_FOUND,
        ),
        (
            http::Method::OPTIONS,
            "/register",
            http::StatusCode::METHOD_NOT_ALLOWED,
        ),
    ];

    for (method, uri, expected_status) in requests {
        let response = facade
            .handle(
                http::Request::builder()
                    .method(method)
                    .uri(uri)
                    .header(header::ORIGIN, "https://browser.example")
                    .header(header::ACCESS_CONTROL_REQUEST_METHOD, "POST")
                    .header(header::CONTENT_TYPE, "text/plain")
                    .body(Bytes::from_static(b"not json"))
                    .unwrap(),
            )
            .await;

        assert_eq!(response.status(), expected_status, "{uri}");
        if expected_status == http::StatusCode::METHOD_NOT_ALLOWED {
            assert_eq!(response.headers().get(header::ALLOW).unwrap(), "POST");
        }
        assert!(
            response.headers().get(header::CONTENT_TYPE).is_none(),
            "{uri}"
        );
        assert!(
            response.headers().get(header::CACHE_CONTROL).is_none(),
            "{uri}"
        );
        assert!(
            response
                .headers()
                .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
                .is_none(),
            "{uri}"
        );
        assert!(
            response
                .headers()
                .get(header::ACCESS_CONTROL_ALLOW_CREDENTIALS)
                .is_none(),
            "{uri}"
        );
        assert_eq!(
            response
                .headers()
                .get(header::X_CONTENT_TYPE_OPTIONS)
                .unwrap(),
            "nosniff",
            "{uri}"
        );
        assert_eq!(
            response.headers().get(header::X_FRAME_OPTIONS).unwrap(),
            "DENY",
            "{uri}"
        );
        assert_eq!(
            response.headers().get("Referrer-Policy").unwrap(),
            "no-referrer",
            "{uri}"
        );
        assert_eq!(
            response.headers().get("Permissions-Policy").unwrap(),
            "interest-cohort=()",
            "{uri}"
        );
        assert!(
            response
                .headers()
                .get("Content-Security-Policy")
                .unwrap()
                .to_str()
                .unwrap()
                .contains("frame-ancestors 'none'"),
            "{uri}"
        );
        let body = response.body();
        assert_eq!(body.as_ref(), b"", "{uri}");
    }
}
