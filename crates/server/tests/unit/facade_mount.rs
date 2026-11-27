use std::sync::Arc;

use actix_web::{App, HttpResponse, test as awtest, web};
use bytes::Bytes;
use nazoauth::{ConnectionFacts, NazoAuth, integration::conformance};

async fn application(prefix: &str, resource_path: Option<&str>) -> Arc<NazoAuth> {
    let mut state = super::infrastructure(false).await;
    let suffix = if prefix == "/" { "" } else { prefix };
    let settings = Arc::make_mut(&mut state.settings);
    settings.endpoint.issuer = format!("https://issuer.example{suffix}");
    settings.endpoint.mtls_endpoint_base_url = format!("https://mtls.example{suffix}");
    settings.endpoint.frontend_base_url = format!("https://issuer.example{suffix}/ui");
    settings.protocol.protected_resource_identifier = resource_path.map_or_else(
        || format!("https://issuer.example{suffix}/fapi/resource"),
        |path| format!("https://issuer.example{path}"),
    );
    settings.endpoint.cors_allowed_origins = vec!["https://browser.example".to_owned()];
    let cookie_suffix = suffix.replace('/', "_");
    settings.session.session_cookie_name = format!("__Host-nazo{cookie_suffix}_session");
    settings.session.csrf_cookie_name = format!("__Host-nazo{cookie_suffix}_csrf");
    settings.session.remembered_mfa_cookie_name = format!("__Host-nazo{cookie_suffix}_mfa");
    settings.session.federation_binding_cookie_name =
        format!("__Host-nazo{cookie_suffix}_federation");
    Arc::new(
        crate::test_support::facade::builder(&state, Default::default())
            .unwrap()
            .mount_path(prefix)
            .build()
            .await
            .unwrap(),
    )
}

#[actix_web::test]
async fn one_call_mount_preserves_host_routes_and_shared_http_contract() {
    for prefix in ["/", "/testauth", "/services/auth"] {
        let facade = application(prefix, None).await;
        let suffix = if prefix == "/" { "" } else { prefix };
        let ui = format!("{suffix}/ui/index.html");
        let app = awtest::init_service(
            App::new()
                .route(
                    "/api/ping",
                    web::get().to(|| async { HttpResponse::Ok().body("existing api") }),
                )
                .route(
                    "/users/me",
                    web::get().to(|| async { HttpResponse::Ok().body("existing user") }),
                )
                .configure(
                    nazo_http_actix::mount(facade.clone(), &["/api", "/users", &ui]).unwrap(),
                )
                .service(
                    web::resource(&ui)
                        .wrap(actix_web::middleware::from_fn(
                            nazo_http_actix::security_headers,
                        ))
                        .to(|| async { HttpResponse::Ok().body("host owned ui") }),
                ),
        )
        .await;
        conformance::assert_adapter(&facade, |request| {
            let app = &app;
            async move {
                super::standard_response(
                    awtest::call_service(app, super::framework_request(&request).to_request())
                        .await
                        .into_parts()
                        .1,
                )
                .await
            }
        })
        .await;

        // The decoder must use the mounted route while the signed target keeps
        // its original escaping and repeated query parameters.
        const GZIP: &[u8] = &[
            31, 139, 8, 0, 0, 0, 0, 0, 2, 3, 75, 47, 74, 204, 43, 137, 47, 169, 44, 72, 181, 77,
            206, 79, 73, 85, 75, 71, 240, 139, 82, 211, 138, 82, 139, 51, 226, 75, 242, 179, 83,
            243, 0, 10, 63, 124, 67, 40, 0, 0, 0,
        ];
        let mut request = http::Request::builder()
            .method(http::Method::POST)
            .uri(format!("{suffix}/%74oken?state=%2F&state=two"))
            .header(
                http::header::CONTENT_TYPE,
                "application/x-www-form-urlencoded",
            )
            .header(http::header::CONTENT_ENCODING, "gzip")
            .body(Bytes::from_static(
                b"grant_type=code&grant_type=refresh_token",
            ))
            .unwrap();
        request.extensions_mut().insert(ConnectionFacts {
            peer_addr: Some("192.0.2.20:43125".parse().unwrap()),
            ..ConnectionFacts::default()
        });
        let expected = facade.handle(request.clone()).await;
        let compressed = request.map(|_| Bytes::from_static(GZIP));
        let actual = super::standard_response(
            awtest::call_service(&app, super::framework_request(&compressed).to_request())
                .await
                .into_parts()
                .1,
        )
        .await;
        assert_eq!(expected.status(), http::StatusCode::BAD_REQUEST);
        conformance::assert_response(&expected, &actual);

        for (path, body) in [
            ("/api/ping", "existing api"),
            ("/users/me", "existing user"),
            (ui.as_str(), "host owned ui"),
        ] {
            let response =
                awtest::call_service(&app, awtest::TestRequest::get().uri(path).to_request()).await;
            assert_eq!(response.status(), actix_web::http::StatusCode::OK, "{path}");
            if path == ui {
                assert!(response.headers().contains_key("content-security-policy"));
            }
            assert_eq!(awtest::read_body(response).await.as_ref(), body.as_bytes());
        }
        if prefix != "/" {
            for path in ["/token".to_owned(), format!("{prefix}2/token")] {
                let response =
                    awtest::call_service(&app, awtest::TestRequest::post().uri(&path).to_request())
                        .await;
                assert_eq!(response.status(), actix_web::http::StatusCode::NOT_FOUND);
                assert!(!response.headers().contains_key("content-security-policy"));
            }
        }
    }
}

#[actix_web::test]
async fn mounting_rejects_declared_conflicts_before_registration() {
    let facade = application("/testauth", None).await;
    for occupied in [
        "/testauth",
        "/testauth/token",
        "/.well-known/oauth-authorization-server/testauth",
    ] {
        assert!(
            nazo_http_actix::mount(facade.clone(), &[occupied]).is_err(),
            "accepted conflicting host route {occupied}"
        );
    }
    assert!(nazo_http_actix::mount(facade.clone(), &["/testauth2", "/api"]).is_ok());
}

#[actix_web::test]
async fn separate_mounts_keep_their_own_tenant_data_and_discovery() {
    let first = application("/first", None).await;
    let second = application("/second", None).await;
    let first_reserved = std::iter::once(second.mount().path())
        .chain(second.mount().discovery_paths())
        .collect::<Vec<_>>();
    let second_reserved = std::iter::once(first.mount().path())
        .chain(first.mount().discovery_paths())
        .collect::<Vec<_>>();
    let first_mount = nazo_http_actix::mount(first.clone(), &first_reserved).unwrap();
    let second_mount = nazo_http_actix::mount(second.clone(), &second_reserved).unwrap();
    let app = awtest::init_service(
        App::new()
            .wrap(actix_web::middleware::from_fn(
                nazo_http_actix::security_headers,
            ))
            .configure(first_mount)
            .configure(second_mount),
    )
    .await;
    for prefix in ["/first", "/second"] {
        for path in [
            format!("{prefix}/.well-known/openid-configuration"),
            format!("/.well-known/oauth-authorization-server{prefix}"),
        ] {
            let response =
                awtest::call_service(&app, awtest::TestRequest::get().uri(&path).to_request())
                    .await;
            assert_eq!(response.status(), actix_web::http::StatusCode::OK, "{path}");
            let body: serde_json::Value = awtest::read_body_json(response).await;
            assert_eq!(body["issuer"], format!("https://issuer.example{prefix}"));
            assert_eq!(
                body["token_endpoint"],
                format!("https://issuer.example{prefix}/token"),
            );
        }
        let response = awtest::call_service(
            &app,
            awtest::TestRequest::get()
                .uri(&format!("{prefix}/check_session"))
                .to_request(),
        )
        .await;
        assert_eq!(response.status(), actix_web::http::StatusCode::OK);
        assert!(!response.headers().contains_key("x-frame-options"));
    }
}

#[actix_web::test]
async fn discovery_paths_match_raw_identifiers_and_preserve_other_host_resources() {
    for (resource_path, host_alias, rewritten_alias) in [
        ("/api%61", "/apia", "/api%2561"),
        ("/api%2Fone", "/api/one", "/api%2fone"),
        ("/api*", "/api-anything", "/api%2A"),
    ] {
        let facade = application("/testauth", Some(resource_path)).await;
        let metadata = format!("/.well-known/oauth-protected-resource{resource_path}");
        let host_alias = format!("/.well-known/oauth-protected-resource{host_alias}");
        let app = awtest::init_service(
            App::new()
                .configure(
                    nazo_http_actix::mount(facade.clone(), &[&host_alias, "/.well-known/host"])
                        .unwrap(),
                )
                .route(
                    &host_alias,
                    web::get().to(|| async { HttpResponse::Ok().body("host alias") }),
                )
                .route(
                    "/.well-known/host",
                    web::get().to(|| async { HttpResponse::Ok().body("host metadata") }),
                ),
        )
        .await;
        let target = format!("{metadata}?state=%2F&state=two");
        let request = http::Request::builder()
            .uri(&target)
            .body(Bytes::new())
            .unwrap();
        let expected = facade.handle(request.clone()).await;
        let actual =
            awtest::call_service(&app, super::framework_request(&request).to_request()).await;
        assert_eq!(actual.request().uri().to_string(), target);
        let actual = super::standard_response(actual.into_parts().1).await;
        assert_eq!(actual.status(), http::StatusCode::OK, "{metadata}");
        conformance::assert_response(&expected, &actual);
        let body: serde_json::Value = serde_json::from_slice(actual.body()).unwrap();
        assert_eq!(
            body["resource"],
            format!("https://issuer.example{resource_path}"),
        );

        for (path, body) in [
            (host_alias.as_str(), "host alias"),
            ("/.well-known/host", "host metadata"),
        ] {
            let response =
                awtest::call_service(&app, awtest::TestRequest::get().uri(path).to_request()).await;
            assert_eq!(response.status(), actix_web::http::StatusCode::OK, "{path}");
            assert!(!response.headers().contains_key("content-security-policy"));
            assert_eq!(awtest::read_body(response).await.as_ref(), body.as_bytes());
        }
        for path in [
            format!("/.well-known/oauth-protected-resource{rewritten_alias}"),
            "/%2ewell-known/oauth-authorization-server/testauth".to_owned(),
        ] {
            let response =
                awtest::call_service(&app, awtest::TestRequest::get().uri(&path).to_request())
                    .await;
            assert_eq!(
                response.status(),
                actix_web::http::StatusCode::NOT_FOUND,
                "{path}"
            );
            assert!(!response.headers().contains_key("content-security-policy"));
        }
    }
}
