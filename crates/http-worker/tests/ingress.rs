#![cfg(target_arch = "wasm32")]

use std::io::{self, Write};

use bytes::{Bytes, BytesMut};
use futures_util::{StreamExt, stream};
use nazo_http_worker::{direct_ingress_facts, forward_request, forward_response};
use nazoauth::{ConnectionFacts, integration::conformance};
use wasm_bindgen_test::wasm_bindgen_test;
use worker::{
    js_sys::Uint8Array,
    wasm_bindgen::{JsCast, JsValue},
};

fn platform_body(chunks: impl IntoIterator<Item = Vec<u8>>) -> worker::Body {
    let chunks = chunks
        .into_iter()
        .map(|bytes| Ok::<JsValue, JsValue>(Uint8Array::from(bytes.as_slice()).into()))
        .collect::<Vec<_>>();
    worker::Body::new(
        wasm_streams::ReadableStream::from_stream(stream::iter(chunks))
            .into_raw()
            .unchecked_into(),
    )
}

async fn read_body(body: nazo_http_worker::RequestBody) -> io::Result<Bytes> {
    futures_util::pin_mut!(body);
    let mut bytes = BytesMut::new();
    while let Some(chunk) = body.next().await {
        bytes.extend_from_slice(&chunk?);
    }
    Ok(bytes.freeze())
}

#[wasm_bindgen_test]
async fn canonical_routes_preserve_their_original_http_heads() {
    for (_, expected) in conformance::registration_requests() {
        let actual = forward_request(expected.clone().map(|_| worker::Body::empty()));
        let (parts, body) = actual.into_parts();
        let actual = http::Request::from_parts(parts, read_body(body).await.unwrap());
        conformance::assert_request(&expected, &actual);
    }
}

#[wasm_bindgen_test]
fn production_response_cases_keep_their_contract_in_wasm() {
    // Fetch conversion also uses Cloudflare's FixedLengthStream. The workerd
    // integration suite covers that platform boundary; Node has no such API.
    for (name, expected) in conformance::response_cases() {
        let pointer = expected.body().as_ptr();
        let actual =
            forward_response(expected.clone()).map(|body| body.into_inner().unwrap_or_default());
        conformance::assert_response(&expected, &actual);
        if !expected.body().is_empty() {
            assert_eq!(actual.body().as_ptr(), pointer, "{name}");
        }
    }
}

#[wasm_bindgen_test]
fn normalized_runtime_headers_are_forwarded_without_inventing_duplicate_values() {
    let request = http::Request::builder()
        .uri("https://issuer.example/token?state=%2F&state=%252F")
        .header("dpop", "first-proof")
        .header("dpop", "second-proof")
        .body(http_body_util::Full::new(Bytes::new()))
        .unwrap();
    let runtime = worker::request_to_wasm(request).unwrap();
    let request = worker::request_from_wasm(runtime).unwrap();
    let actual = forward_request(request);
    assert_eq!(actual.headers()["dpop"], "first-proof, second-proof");
    assert_eq!(actual.headers().get_all("dpop").iter().count(), 1);
    assert_eq!(actual.uri().query(), Some("state=%2F&state=%252F"));
}

#[wasm_bindgen_test]
async fn raw_targets_duplicate_values_and_supplied_facts_survive_ingress() {
    for expected in conformance::transport_requests() {
        let request = expected.clone().map(|body| platform_body([body.to_vec()]));
        let actual = forward_request(request);
        let (parts, body) = actual.into_parts();
        let actual = http::Request::from_parts(parts, read_body(body).await.unwrap());
        conformance::assert_request(&expected, &actual);
    }
}

#[wasm_bindgen_test]
fn client_forwarding_and_certificate_headers_never_create_connection_facts() {
    let request = http::Request::builder()
        .uri("https://issuer.example/token")
        .header("cf-connecting-ip", "192.0.2.9")
        .header("x-forwarded-for", "192.0.2.9")
        .header("forwarded", "for=192.0.2.9;proto=https")
        .header("client-cert", ":Y2xpZW50LWNvbnRyb2xsZWQ=:")
        .body(worker::Body::empty())
        .unwrap();
    assert!(
        forward_request(request)
            .extensions()
            .get::<ConnectionFacts>()
            .is_none()
    );
}

fn mark_platform_request(request: &mut worker::HttpRequest) {
    let properties: worker::worker_sys::IncomingRequestCfProperties =
        worker::js_sys::Object::new().unchecked_into();
    request
        .extensions_mut()
        .insert(worker::Cf::from(properties));
}

#[wasm_bindgen_test]
fn direct_ingress_requires_platform_context_and_rejects_worker_subrequests() {
    for ip in ["198.51.100.7", "2001:db8::7"] {
        let mut request = http::Request::builder()
            .uri("https://issuer.example/token")
            .header("cf-connecting-ip", ip)
            .header("forwarded", "for=192.0.2.9")
            .header("x-real-ip", "192.0.2.9")
            .body(worker::Body::empty())
            .unwrap();
        assert!(direct_ingress_facts(&request).is_err());
        mark_platform_request(&mut request);
        let facts = direct_ingress_facts(&request).unwrap();
        assert_eq!(facts.authenticated_client_ip, Some(ip.parse().unwrap()));
        assert_eq!(facts.peer_addr, None);
        assert_eq!(facts.server_name, None);
        assert_eq!(facts.client_certificate, None);
        request
            .headers_mut()
            .insert("cf-worker", http::HeaderValue::from_static("example.com"));
        assert!(direct_ingress_facts(&request).is_err());
    }
    for addresses in [
        vec![],
        vec!["not-an-ip"],
        vec!["198.51.100.7, 192.0.2.9"],
        vec!["198.51.100.7", "192.0.2.9"],
        vec!["2a06:98c0:3600::103"],
    ] {
        let mut request = http::Request::new(worker::Body::empty());
        for address in addresses {
            request.headers_mut().append(
                "cf-connecting-ip",
                http::HeaderValue::from_str(address).unwrap(),
            );
        }
        mark_platform_request(&mut request);
        assert!(direct_ingress_facts(&request).is_err());
    }
}

#[wasm_bindgen_test]
async fn each_manifest_budget_is_enforced_before_an_oversized_copy() {
    for (path, limit) in [
        ("/token", 256 * 1024),
        ("/authorize/decision", 32 * 1024),
        ("/bc-authorize", 16 * 1024),
        ("/auth/passkey/begin", 2 * 1024 * 1024),
    ] {
        for chunks in [vec![vec![0; limit + 1]], vec![vec![0; limit], vec![0]]] {
            let request = http::Request::builder()
                .method(http::Method::POST)
                .uri(path)
                .body(platform_body(chunks))
                .unwrap();
            let error = read_body(forward_request(request).into_body())
                .await
                .unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::FileTooLarge, "{path}");
        }
    }
}

#[wasm_bindgen_test]
async fn multipart_is_incremental_without_a_total_transport_limit() {
    let request = http::Request::builder()
        .method(http::Method::POST)
        .uri("/auth/me/avatar")
        .body(platform_body([vec![7; 3 * 1024 * 1024]]))
        .unwrap();
    let mut body = forward_request(request).into_body();
    let mut length = 0;
    while let Some(chunk) = body.next().await {
        let chunk = chunk.unwrap();
        assert!(chunk.len() <= 64 * 1024);
        assert!(chunk.iter().all(|byte| *byte == 7));
        length += chunk.len();
    }
    assert_eq!(length, 3 * 1024 * 1024);
}

fn compress(encoding: &str, data: &[u8]) -> Vec<u8> {
    if encoding == "gzip" {
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        encoder.write_all(data).unwrap();
        encoder.finish().unwrap()
    } else {
        let mut encoder = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::fast());
        encoder.write_all(data).unwrap();
        encoder.finish().unwrap()
    }
}

#[wasm_bindgen_test]
async fn compression_uses_the_decoded_budget_and_raw_routes_keep_wire_bytes() {
    for encoding in ["gzip", "deflate"] {
        let data = b"grant_type=authorization_code&code=opaque&state=%2F";
        let compressed = compress(encoding, data);
        for (path, expected) in [("/token", data.as_slice()), ("/bc-authorize", &compressed)] {
            let request = http::Request::builder()
                .method(http::Method::POST)
                .uri(path)
                .header(http::header::CONTENT_ENCODING, encoding)
                .body(platform_body([compressed.clone()]))
                .unwrap();
            let actual = read_body(forward_request(request).into_body())
                .await
                .unwrap();
            assert_eq!(actual.as_ref(), expected, "{encoding} {path}");
        }
        let compressed = compress(encoding, &vec![0; 256 * 1024 + 1]);
        let request = http::Request::builder()
            .method(http::Method::POST)
            .uri("/token")
            .header(http::header::CONTENT_ENCODING, encoding)
            .body(platform_body([compressed]))
            .unwrap();
        let error = read_body(forward_request(request).into_body())
            .await
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::FileTooLarge);
    }
}

#[wasm_bindgen_test]
async fn unsupported_or_malformed_encoding_fails_and_unknown_routes_never_read() {
    for encoding in ["br", "gzip, deflate", "zstd", "gzip"] {
        let request = http::Request::builder()
            .method(http::Method::POST)
            .uri("/token")
            .header(http::header::CONTENT_ENCODING, encoding)
            .body(platform_body([b"invalid compressed bytes".to_vec()]))
            .unwrap();
        assert!(
            read_body(forward_request(request).into_body())
                .await
                .is_err()
        );
    }
    for path in ["/unknown", "/jwks.json"] {
        let request = http::Request::builder()
            .uri(path)
            .header(http::header::CONTENT_ENCODING, "gzip")
            .body(platform_body([b"invalid compressed bytes".to_vec()]))
            .unwrap();
        assert!(
            read_body(forward_request(request).into_body())
                .await
                .unwrap()
                .is_empty()
        );
    }
}
