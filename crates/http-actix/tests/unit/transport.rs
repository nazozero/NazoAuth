use super::*;
use actix_web::{App, body::to_bytes, test as awtest};
use futures_util::StreamExt as _;
use nazoauth::integration::{BodyMode, conformance};

fn framework_request(request: &http::Request<Bytes>) -> awtest::TestRequest {
    let mut builder = awtest::TestRequest::with_uri(&request.uri().to_string())
        .method(actix_web::http::Method::from_bytes(request.method().as_str().as_bytes()).unwrap());
    for (name, value) in request.headers() {
        let mut converted =
            actix_web::http::header::HeaderValue::from_bytes(value.as_bytes()).unwrap();
        converted.set_sensitive(value.is_sensitive());
        builder = builder.append_header((name.as_str(), converted));
    }
    if let Some(peer) = request
        .extensions()
        .get::<ConnectionFacts>()
        .and_then(|facts| facts.peer_addr)
    {
        builder = builder.peer_addr(peer);
    }
    builder
}

async fn standard_response(response: HttpResponse) -> http::Response<Bytes> {
    let mut standard = http::Response::builder().status(response.status().as_u16());
    for (name, value) in response.headers() {
        standard = standard.header(name.as_str(), value.as_bytes());
    }
    standard
        .body(match response.into_body().try_into_bytes() {
            Ok(bytes) => bytes,
            Err(stream) => to_bytes(stream).await.unwrap(),
        })
        .unwrap()
}

#[test]
fn raw_request_targets_duplicate_values_and_body_storage_are_preserved() {
    for mut expected in conformance::transport_requests() {
        let mut private = http::HeaderValue::from_static("private");
        private.set_sensitive(true);
        expected.headers_mut().append("x-context", private);
        expected
            .headers_mut()
            .append("x-context", http::HeaderValue::from_static("public"));
        let mut binary = http::HeaderValue::from_bytes(&[b'x', 0x80, 0xff]).unwrap();
        binary.set_sensitive(true);
        expected.headers_mut().append("x-context", binary);
        let request = framework_request(&expected).to_http_request();
        let actual = forward_request(&request, expected.body().clone());
        conformance::assert_request(&expected, &actual);
        assert_eq!(actual.body().as_ptr(), expected.body().as_ptr());
        if let Some(path) = request.uri().path_and_query() {
            assert_eq!(
                actual.uri().path_and_query().unwrap().as_str(),
                path.as_str(),
            );
        }
        for name in request.headers().keys() {
            for (source, target) in request
                .headers()
                .get_all(name.as_str())
                .zip(actual.headers().get_all(name.as_str()).iter())
            {
                assert_eq!(source.as_bytes(), target.as_bytes());
                assert_eq!(source.is_sensitive(), target.is_sensitive());
            }
        }
    }
}

#[actix_web::test]
async fn registered_request_conversion_obeys_resource_head_requirements() {
    let app = awtest::init_service(App::new().configure(configure)).await;
    for (method, path, expected_facts) in [
        (
            http::Method::GET,
            "/.well-known/openid-configuration",
            false,
        ),
        (
            http::Method::GET,
            "/.well-known/oauth-authorization-server",
            false,
        ),
        (
            http::Method::GET,
            "/.well-known/oauth-protected-resource",
            false,
        ),
        (
            http::Method::GET,
            "/.well-known/oauth-protected-resource/",
            true,
        ),
        (
            http::Method::GET,
            "/.well-known/oauth-protected-resource/api/child",
            true,
        ),
        (http::Method::GET, "/jwks.json", false),
        (http::Method::HEAD, "/jwks.json", false),
        (http::Method::OPTIONS, "/jwks.json", false),
        (http::Method::POST, "/jwks.json", false),
        (http::Method::POST, "/openid4vci/nonce", true),
        (http::Method::GET, "/openid4vci/nonce", true),
        (http::Method::GET, "/userinfo", true),
        (http::Method::GET, "/not-a-route", true),
        (http::Method::GET, "/.well-known/not-a-route", true),
    ] {
        let mut private = http::HeaderValue::from_static("private");
        private.set_sensitive(true);
        let mut expected = http::Request::builder()
            .method(method)
            .uri(format!("{path}?state=%2F&state=%252F"))
            .header(http::header::HOST, "issuer.example")
            .header("x-context", private)
            .header("x-context", "public")
            .body(Bytes::from(vec![0, 255, b'=', b'&']))
            .unwrap();
        let mut origin = http::HeaderValue::from_str("https://app.example").unwrap();
        origin.set_sensitive(true);
        for (name, values) in [
            (
                http::header::ORIGIN,
                [
                    origin,
                    http::HeaderValue::from_static("https://other.example"),
                ],
            ),
            (
                http::header::ACCESS_CONTROL_REQUEST_METHOD,
                [
                    http::HeaderValue::from_static("GET"),
                    http::HeaderValue::from_static("HEAD"),
                ],
            ),
            (
                http::header::ACCESS_CONTROL_REQUEST_HEADERS,
                [
                    http::HeaderValue::from_static("accept"),
                    http::HeaderValue::from_static("content-type"),
                ],
            ),
        ] {
            for value in values {
                expected.headers_mut().append(name.clone(), value);
            }
        }
        expected.extensions_mut().insert(ConnectionFacts {
            peer_addr: Some("192.0.2.20:43125".parse().unwrap()),
            ..ConnectionFacts::default()
        });
        let response = awtest::call_service(&app, framework_request(&expected).to_request()).await;
        let original = response.request();
        // The public conversion always preserves facts, including metadata.
        let complete = forward_request(original, expected.body().clone());
        conformance::assert_request(&expected, &complete);

        let route = nazoauth::integration::route_for_path(original.uri().path());
        let actual = forward_request_for_route(original, expected.body().clone(), route);
        assert_eq!(
            actual.extensions().get::<ConnectionFacts>().is_some(),
            expected_facts,
            "{path}"
        );
        if !expected_facts {
            expected.extensions_mut().remove::<ConnectionFacts>();
            assert!(actual.extensions().is_empty());
            expected.headers_mut().remove(http::header::HOST);
            expected.headers_mut().remove("x-context");
        }
        conformance::assert_request(&expected, &actual);
        assert_eq!(actual.body().as_ptr(), expected.body().as_ptr());
        assert_eq!(
            actual.uri().path_and_query().unwrap().as_str(),
            original.uri().path_and_query().unwrap().as_str(),
        );
        for name in actual.headers().keys() {
            for (source, target) in original
                .headers()
                .get_all(name.as_str())
                .zip(actual.headers().get_all(name.as_str()).iter())
            {
                assert_eq!(source.as_bytes(), target.as_bytes());
                assert_eq!(source.is_sensitive(), target.is_sensitive());
            }
        }
    }
}

#[actix_web::test]
async fn production_response_presenters_survive_conversion_without_body_copy() {
    for (name, mut expected) in conformance::response_cases() {
        let mut private = http::HeaderValue::from_static("private");
        private.set_sensitive(true);
        expected.headers_mut().append("x-context", private);
        expected
            .headers_mut()
            .append("x-context", http::HeaderValue::from_static("public"));
        let mut binary = http::HeaderValue::from_bytes(&[b'x', 0x80, 0xff]).unwrap();
        binary.set_sensitive(true);
        expected.headers_mut().append("x-context", binary);
        let pointer = expected.body().as_ptr();
        let forwarded = forward_response(expected.clone());
        for name in expected.headers().keys() {
            for (source, target) in expected
                .headers()
                .get_all(name)
                .iter()
                .zip(forwarded.headers().get_all(name.as_str()))
            {
                assert_eq!(source.as_bytes(), target.as_bytes());
                assert_eq!(source.is_sensitive(), target.is_sensitive());
            }
        }
        let actual = standard_response(forwarded).await;
        conformance::assert_response(&expected, &actual);
        if !expected.body().is_empty() {
            assert_eq!(
                actual.body().as_ptr(),
                pointer,
                "{name} copied response bytes"
            );
        }
    }
}

#[actix_web::test]
async fn every_manifest_binding_reaches_the_production_forwarder() {
    // A missing facade rejects at the ordinary Data extractor. A framework
    // routing or method rejection would instead produce its own 404 or 405.
    let app = awtest::init_service(
        App::new()
            .route(
                "/ui/ping",
                web::get().to(|| async { HttpResponse::Accepted().finish() }),
            )
            .configure(configure),
    )
    .await;
    for (route, request) in conformance::registration_requests() {
        let response = awtest::call_service(&app, framework_request(&request).to_request()).await;
        assert_eq!(
            response.status(),
            actix_web::http::StatusCode::INTERNAL_SERVER_ERROR
        );
        assert!(response.request().match_pattern().is_none());
        let matched = nazoauth::integration::route_for_path(response.request().uri().path())
            .expect("canonical path retains its transport metadata");
        assert!(
            std::ptr::eq(matched, route),
            "{}: {}",
            route.path,
            matched.path
        );
        assert_eq!(
            matched.body(
                &http::Method::from_bytes(response.request().method().as_str().as_bytes()).unwrap()
            ),
            route.body(request.method())
        );
    }
    let native = awtest::call_service(
        &app,
        awtest::TestRequest::get().uri("/ui/ping").to_request(),
    )
    .await;
    assert_eq!(native.status(), actix_web::http::StatusCode::ACCEPTED);
    assert_eq!(
        native.request().match_pattern().as_deref(),
        Some("/ui/ping")
    );
    for path in [
        "/not-a-route",
        "/.well-known",
        "/.well-known/",
        "/.well-known/not-a-route",
        "/admin",
        "/admin/",
        "/admin/controller-registry/not-a-route",
        "/auth",
        "/auth/",
        "/auth/me/not-a-route",
        "/authentic/not-a-route",
        "/authorize/",
        "/device/",
        "/check_session/",
        "/register/",
        "/scim/v2/not-a-route",
        "/openid4vci/not-a-route",
        "/openid4vp/not-a-route",
    ] {
        let response =
            awtest::call_service(&app, awtest::TestRequest::get().uri(path).to_request()).await;
        // Unknown prefixes and trailing separators use the same production
        // forwarder; the facade owns their final status and CORS policy.
        assert_eq!(
            response.status(),
            actix_web::http::StatusCode::INTERNAL_SERVER_ERROR,
            "{path}"
        );
        assert!(response.request().match_pattern().is_none(), "{path}");
        assert!(
            nazoauth::integration::route_for_path(path).is_none(),
            "{path}"
        );
    }
}

#[actix_web::test]
async fn uncompressed_stream_chunks_keep_their_original_storage() {
    let bytes = Bytes::from(vec![0x91; 2048]);
    let pointer = bytes.as_ptr();
    let (request, payload) = awtest::TestRequest::post()
        .set_payload(bytes)
        .to_http_parts();
    let stream = forward_payload(&request, payload, BodyMode::Bytes);
    futures_util::pin_mut!(stream);
    let chunk = stream.next().await.unwrap().unwrap();
    assert_eq!(chunk.as_ptr(), pointer);
    assert!(stream.next().await.is_none());
}

#[actix_web::test]
async fn compressed_stream_is_bounded_before_delivering_an_oversized_chunk() {
    // gzip("a" repeated 4096 times), deliberately larger than this body budget.
    const GZIP: &[u8] = &[
        31, 139, 8, 0, 0, 0, 0, 0, 2, 3, 237, 193, 1, 13, 0, 0, 0, 194, 160, 172, 239, 95, 194, 30,
        14, 40, 0, 0, 0, 224, 221, 0, 115, 220, 153, 156, 0, 16, 0, 0,
    ];
    let (request, payload) = awtest::TestRequest::post()
        .insert_header(("content-encoding", "gzip"))
        .set_payload(Bytes::from_static(GZIP))
        .to_http_parts();
    let stream = forward_payload(&request, payload, BodyMode::Json { limit: 32 });
    futures_util::pin_mut!(stream);
    let error = stream.next().await.unwrap().unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::FileTooLarge);

    let (request, payload) = awtest::TestRequest::post()
        .insert_header(("content-encoding", "gzip"))
        .set_payload(Bytes::from_static(GZIP))
        .to_http_parts();
    let stream = forward_payload(&request, payload, BodyMode::Raw { limit: 16 * 1024 });
    futures_util::pin_mut!(stream);
    assert_eq!(
        stream.next().await.unwrap().unwrap(),
        Bytes::from_static(GZIP)
    );
}

#[actix_web::test]
async fn host_response_middleware_uses_neutral_policy_without_overwriting_headers() {
    let app = awtest::init_service(
        App::new()
            .wrap(actix_web::middleware::from_fn(security_headers))
            .route(
                "/failure",
                web::get().to(|| async {
                    HttpResponse::Unauthorized()
                        .insert_header(("content-security-policy", "default-src 'none'"))
                        .finish()
                }),
            )
            .route(
                "/check_session",
                web::get().to(|| async { HttpResponse::Ok().finish() }),
            ),
    )
    .await;
    for target in ["/failure", "/missing", "/check_session"] {
        let response =
            awtest::call_service(&app, awtest::TestRequest::get().uri(target).to_request()).await;
        for (name, value) in nazoauth::integration::security_headers(target) {
            if target == "/failure" && name == http::header::CONTENT_SECURITY_POLICY {
                assert_eq!(
                    response.headers().get(name.as_str()).unwrap(),
                    "default-src 'none'"
                );
            } else {
                assert_eq!(
                    response.headers().get(name.as_str()).unwrap().as_bytes(),
                    value.as_bytes()
                );
            }
        }
        if target == "/check_session" {
            assert!(!response.headers().contains_key("x-frame-options"));
        }
    }
}

#[actix_web::test]
async fn connection_facts_come_from_the_connection_and_ignore_proxy_claims() {
    use nazoauth::integration::ClientCertificateFacts;
    let certificate = ClientCertificateFacts {
        thumbprint: Some("fixture-thumbprint".to_owned()),
        subject_dn: Some("CN=fixture-client".to_owned()),
        san_dns: vec!["client.example".to_owned()],
        ..ClientCertificateFacts::default()
    };
    let expected = ConnectionFacts {
        peer_addr: None,
        authenticated_client_ip: None,
        server_name: Some("issuer.example".into()),
        client_certificate: Some(std::sync::Arc::new(certificate)),
    };
    let connection = expected.clone();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server = actix_web::HttpServer::new(move || {
        let expected = expected.clone();
        App::new().route(
            "/facts",
            web::to(move |request: HttpRequest| {
                let mut expected = expected.clone();
                async move {
                    let route = nazoauth::integration::routes()
                        .iter()
                        .find(|route| route.path == "/jwks.json")
                        .unwrap();
                    let omitted = forward_request_for_route(&request, Bytes::new(), Some(route));
                    assert!(omitted.extensions().is_empty());
                    assert!(omitted.headers().is_empty());
                    assert_eq!(omitted.headers().capacity(), 0);
                    let forwarded = forward_request(&request, Bytes::new());
                    expected.peer_addr = request.peer_addr();
                    assert_eq!(
                        forwarded.extensions().get::<ConnectionFacts>(),
                        Some(&expected)
                    );
                    let actual = forwarded.extensions().get::<ConnectionFacts>().unwrap();
                    assert!(std::sync::Arc::ptr_eq(
                        actual.server_name.as_ref().unwrap(),
                        expected.server_name.as_ref().unwrap(),
                    ));
                    assert!(std::sync::Arc::ptr_eq(
                        actual.client_certificate.as_ref().unwrap(),
                        expected.client_certificate.as_ref().unwrap(),
                    ));
                    assert!(expected.peer_addr.unwrap().ip().is_loopback());
                    HttpResponse::Ok().finish()
                }
            }),
        )
    })
    .workers(1)
    .on_connect(move |_, extensions| {
        extensions.insert(connection.clone());
    })
    .listen(listener)
    .unwrap()
    .run();
    let handle = server.handle();
    let running = actix_web::rt::spawn(server);
    let stream = actix_web::rt::net::TcpStream::connect(address)
        .await
        .unwrap();
    let request = b"GET /facts HTTP/1.1\r\nHost: issuer.example\r\nForwarded: for=203.0.113.55;host=attacker.example\r\nClient-Cert: forged\r\nConnection: close\r\n\r\n";
    let mut written = 0;
    while written < request.len() {
        stream.writable().await.unwrap();
        match stream.try_write(&request[written..]) {
            Ok(count) => written += count,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
            Err(error) => panic!("write failed: {error}"),
        }
    }
    let mut response = Vec::new();
    loop {
        stream.readable().await.unwrap();
        let mut buffer = [0; 1024];
        match stream.try_read(&mut buffer) {
            Ok(0) => break,
            Ok(count) => response.extend_from_slice(&buffer[..count]),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
            Err(error) => panic!("read failed: {error}"),
        }
    }
    handle.stop(true).await;
    running.await.unwrap().unwrap();
    assert!(response.starts_with(b"HTTP/1.1 200 OK\r\n"));
}

#[test]
fn metadata_version_conversion_preserves_all_supported_versions() {
    use actix_web::http::Version;
    for (native, standard) in [
        (Version::HTTP_09, http::Version::HTTP_09),
        (Version::HTTP_10, http::Version::HTTP_10),
        (Version::HTTP_11, http::Version::HTTP_11),
        (Version::HTTP_2, http::Version::HTTP_2),
        (Version::HTTP_3, http::Version::HTTP_3),
    ] {
        let request = awtest::TestRequest::default()
            .version(native)
            .to_http_request();
        assert_eq!(forward_request(&request, Bytes::new()).version(), standard);
    }
}
