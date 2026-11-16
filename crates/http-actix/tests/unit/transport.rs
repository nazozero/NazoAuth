use super::*;
use actix_web::{App, body::to_bytes, test as awtest};
use futures_util::StreamExt as _;
use nazoauth::integration::{BodyMode, conformance};

fn framework_request(request: &http::Request<Bytes>) -> awtest::TestRequest {
    let mut builder = awtest::TestRequest::with_uri(&request.uri().to_string())
        .method(actix_web::http::Method::from_bytes(request.method().as_str().as_bytes()).unwrap());
    for (name, value) in request.headers() {
        builder =
            builder.append_header((actix_header_name(name), actix_header_value(value.clone())));
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
    for expected in conformance::transport_requests() {
        let request = framework_request(&expected).to_http_request();
        let actual = forward_request(&request, expected.body().clone());
        conformance::assert_request(&expected, &actual);
        assert_eq!(actual.body().as_ptr(), expected.body().as_ptr());
        for name in request.headers().keys() {
            for (source, target) in request
                .headers()
                .get_all(name)
                .zip(actual.headers().get_all(name.as_str()).iter())
            {
                assert_eq!(source.as_bytes().as_ptr(), target.as_bytes().as_ptr());
            }
        }
    }
}

#[actix_web::test]
async fn production_response_presenters_survive_conversion_without_body_copy() {
    for (name, expected) in conformance::response_cases() {
        let pointer = expected.body().as_ptr();
        let forwarded = forward_response(expected.clone());
        for name in expected.headers().keys() {
            for (source, target) in expected
                .headers()
                .get_all(name)
                .iter()
                .zip(forwarded.headers().get_all(name.as_str()))
            {
                assert_eq!(source.as_bytes().as_ptr(), target.as_bytes().as_ptr());
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
async fn every_manifest_binding_reaches_an_explicit_production_resource() {
    // The missing application rejects at the ordinary Data extractor. Looking
    // at the matched resource distinguishes a registered binding from fallback
    // without constructing a second protocol implementation.
    let app = awtest::init_service(App::new().configure(configure)).await;
    for (route, request) in conformance::registration_requests() {
        let response = awtest::call_service(&app, framework_request(&request).to_request()).await;
        assert_eq!(
            response.request().match_pattern().as_deref(),
            Some(actix_path(route.path).as_ref()),
            "unregistered canonical resource {} {}",
            request.method(),
            request.uri(),
        );
    }
    let response = awtest::call_service(
        &app,
        awtest::TestRequest::get().uri("/not-a-route").to_request(),
    )
    .await;
    assert!(response.request().match_pattern().is_none());
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
