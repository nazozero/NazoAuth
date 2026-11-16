use std::sync::Arc;

use actix_web::{App, test, web};
use bytes::Bytes;
use http::{Method, Request, StatusCode, header};

#[actix_web::test]
async fn unknown_scopes_keep_cors_and_control_guard_order_through_the_adapter() {
    const ORIGIN: &str = "https://admin.example";
    let mut state = super::infrastructure(true).await;
    Arc::make_mut(&mut state.settings)
        .endpoint
        .cors_allowed_origins = vec![ORIGIN.to_owned()];
    let application = crate::test_support::facade::application(&state)
        .await
        .unwrap();
    let app = test::init_service(
        App::new()
            .app_data(web::Data::from(application.clone()))
            .configure(nazo_http_actix::configure),
    )
    .await;
    for (path, preflight_status, cors) in [
        ("/auth/me/missing", StatusCode::OK, true),
        ("/.well-known/missing", StatusCode::OK, true),
        ("/admin/openid4vci/missing", StatusCode::OK, true),
        ("/admin/tenants/missing", StatusCode::OK, true),
        (
            "/admin/controller-registry/missing",
            StatusCode::NOT_FOUND,
            false,
        ),
        (
            "/.well-known/nazoauth-control",
            StatusCode::NOT_FOUND,
            false,
        ),
        ("/auth/meal", StatusCode::NOT_FOUND, false),
    ] {
        for method in [Method::GET, Method::OPTIONS] {
            let request = Request::builder()
                .method(method.clone())
                .uri(path)
                .header(header::ORIGIN, ORIGIN)
                .header(header::ACCESS_CONTROL_REQUEST_METHOD, "GET")
                .body(Bytes::new())
                .unwrap();
            let expected = application.handle(request.clone()).await;
            assert_eq!(
                expected.status(),
                if method == Method::OPTIONS {
                    preflight_status
                } else {
                    StatusCode::NOT_FOUND
                },
                "{method} {path}"
            );
            assert_eq!(
                expected
                    .headers()
                    .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
                    .map(|value| value.as_bytes()),
                cors.then_some(ORIGIN.as_bytes()),
                "{method} {path}"
            );
            assert_eq!(
                expected.headers()[header::X_CONTENT_TYPE_OPTIONS],
                "nosniff"
            );
            let actual = super::standard_response(
                test::call_service(&app, super::framework_request(&request).to_request())
                    .await
                    .into_parts()
                    .1,
            )
            .await;
            nazoauth::integration::conformance::assert_response(&expected, &actual);
        }
    }
}

#[actix_web::test]
async fn unavailable_routes_and_methods_reject_before_polling_the_body() {
    let state = super::infrastructure(true).await;
    let application = crate::test_support::facade::application(&state)
        .await
        .unwrap();
    for (method, path, status) in [
        (Method::POST, "/missing", StatusCode::NOT_FOUND),
        (Method::GET, "/token", StatusCode::METHOD_NOT_ALLOWED),
        (
            Method::POST,
            "/openid4vci/credential",
            StatusCode::NOT_FOUND,
        ),
        (
            Method::POST,
            "/openid4vp/presentations",
            StatusCode::NOT_FOUND,
        ),
        (
            Method::POST,
            "/.well-known/nazoauth-control",
            StatusCode::NOT_FOUND,
        ),
        (Method::POST, "/register", StatusCode::NOT_FOUND),
    ] {
        let body = futures_util::stream::poll_fn(
            |_: &mut std::task::Context<'_>| -> std::task::Poll<Option<Result<Bytes, std::io::Error>>> {
                panic!("rejected ingress must not poll its payload")
            },
        );
        let request = Request::builder()
            .method(method.clone())
            .uri(path)
            .header(header::CONTENT_TYPE, "application/json")
            .body(body)
            .unwrap();
        let response = application.handle_stream(request).await;
        assert_eq!(response.status(), status, "{method} {path}");
    }
}
