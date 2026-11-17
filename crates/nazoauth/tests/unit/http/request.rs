use super::*;
use http::Method;
use serde::Deserialize;
use serde_json::{Value, json};

#[derive(Debug, Deserialize, PartialEq)]
struct Name {
    name: String,
}

#[test]
fn json_media_type_and_known_or_streamed_limits_keep_distinct_errors() {
    for content_type in [
        "application/json",
        "application/scim+json",
        "text/json; charset=utf-8",
    ] {
        let request = http::Request::builder()
            .header(header::CONTENT_TYPE, content_type)
            .body(Bytes::from_static(br#"{"name":"Alice"}"#))
            .unwrap();
        assert_eq!(parse_json::<Name>(&request).unwrap().name, "Alice");
    }
    let missing_type = http::Request::new(Bytes::from_static(b"{}"));
    let response = parse_json::<Value>(&missing_type).unwrap_err();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(response.body(), "Content type error");
    assert_eq!(
        response.headers()[header::CONTENT_TYPE],
        "text/plain; charset=utf-8"
    );

    let mut request = http::Request::builder()
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::CONTENT_LENGTH, "10")
        .body(Bytes::from_static(b"null "))
        .unwrap();
    let known = parse_json_limit::<Value>(&request, 4).unwrap_err();
    assert_eq!(known.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(
        known.body(),
        "JSON payload (10 bytes) is larger than allowed (limit: 4 bytes)"
    );
    request.headers_mut().remove(header::CONTENT_LENGTH);
    let streamed = parse_json_limit::<Value>(&request, 4).unwrap_err();
    assert_eq!(streamed.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(streamed.body(), "JSON payload has exceeded limit (4 bytes)");
}

#[test]
fn form_encoding_and_length_errors_match_the_boundary_contract() {
    let request = http::Request::builder()
        .header(
            header::CONTENT_TYPE,
            "application/x-www-form-urlencoded; charset=windows-1252",
        )
        .body(Bytes::from_static(b"name=Andr\xe9"))
        .unwrap();
    assert_eq!(parse_form::<Name>(&request).unwrap().name, "André");
    let request = http::Request::builder()
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(header::CONTENT_LENGTH, "unknown")
        .body(Bytes::new())
        .unwrap();
    let response = parse_form::<Name>(&request).unwrap_err();
    assert_eq!(response.status(), StatusCode::LENGTH_REQUIRED);
    assert_eq!(response.body(), "Payload size is now known");
}

#[test]
fn path_percent_decoding_preserves_encoded_delimiters_and_rejects_invalid_utf8() {
    assert_eq!(
        parse_path::<String>("client%2Fwith%20space").unwrap(),
        "client/with space"
    );
    assert_eq!(parse_path::<u64>("%34%32").unwrap(), 42);
    assert_eq!(parse_path::<String>("literal%ZZ").unwrap(), "literal%ZZ");
    for response in [
        parse_path::<String>("%FF").unwrap_err(),
        parse_path::<u64>("invalid").unwrap_err(),
    ] {
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert!(response.body().is_empty());
    }
}

#[test]
fn body_collection_preserves_single_chunk_storage_and_concatenates_only_when_needed() {
    futures_executor::block_on(async {
        let method = crate::routes::resolve(&Method::POST, "/token")
            .unwrap()
            .method;
        let bytes = Bytes::from(vec![42; 64]);
        let pointer = bytes.as_ptr();
        let body = collect_route_body(
            method,
            futures_util::stream::iter([
                Ok::<_, std::io::Error>(Bytes::new()),
                Ok(bytes),
                Ok(Bytes::new()),
            ]),
        )
        .await
        .unwrap();
        assert_eq!(body.as_ptr(), pointer);
        let body = collect_route_body(
            method,
            futures_util::stream::iter([
                Ok::<_, std::io::Error>(Bytes::from_static(b"first")),
                Ok(Bytes::from_static(b"second")),
                Ok(Bytes::from_static(b"third")),
            ]),
        )
        .await
        .unwrap();
        assert_eq!(body, "firstsecondthird");
    });
}

#[test]
fn routes_without_a_body_do_not_poll_the_transport() {
    futures_executor::block_on(async {
        let method = crate::routes::resolve(&Method::GET, "/live")
            .unwrap()
            .method;
        let stream = futures_util::stream::poll_fn(
            |_| -> std::task::Poll<Option<Result<Bytes, std::io::Error>>> {
                panic!("bodyless route must not poll")
            },
        );
        assert!(collect_route_body(method, stream).await.unwrap().is_empty());
    });
}

#[test]
fn decoder_and_collector_overflows_keep_each_endpoints_error_presentation() {
    futures_executor::block_on(async {
        for (path, status, description) in [
            (
                "/token",
                StatusCode::PAYLOAD_TOO_LARGE,
                "Payload reached size limit",
            ),
            (
                "/auth/me/mfa/step-up",
                StatusCode::BAD_REQUEST,
                "MFA request body is invalid.",
            ),
            (
                "/auth/passkey/begin",
                StatusCode::BAD_REQUEST,
                "passkey request body is invalid.",
            ),
            (
                "/bc-authorize",
                StatusCode::PAYLOAD_TOO_LARGE,
                "CIBA body is too large.",
            ),
            (
                "/logout",
                StatusCode::PAYLOAD_TOO_LARGE,
                "logout request body is too large.",
            ),
        ] {
            let method = crate::routes::resolve(&Method::POST, path).unwrap().method;
            for decoder_overflow in [false, true] {
                let item = if decoder_overflow {
                    Err(std::io::Error::from(std::io::ErrorKind::FileTooLarge))
                } else {
                    Ok(Bytes::from(vec![0; method.body.limit().unwrap() + 1]))
                };
                let response = collect_route_body(method, futures_util::stream::iter([item]))
                    .await
                    .unwrap_err();
                assert_eq!(response.status(), status, "{path}");
                if path == "/token" {
                    assert_eq!(response.body(), description);
                } else {
                    let body: Value = serde_json::from_slice(response.body()).unwrap();
                    assert_eq!(body["error_description"], description);
                }
            }
        }
    });
}

#[test]
fn optional_wallet_nonce_form_skips_invalid_heads_and_ignores_read_failure() {
    futures_executor::block_on(async {
        let path = "/openid4vp/request/00000000-0000-0000-0000-000000000001";
        let method = crate::routes::resolve(&Method::GET, path).unwrap().method;
        let request = http::Request::new(Bytes::new());
        assert!(!validate_route_body_head(&request, method).unwrap());
        let body = collect_route_body(
            method,
            futures_util::stream::iter([Err::<Bytes, _>(std::io::Error::other("connection lost"))]),
        )
        .await
        .unwrap();
        assert!(body.is_empty());
    });
}

#[test]
fn serialization_preserves_explicit_media_type_and_moves_byte_storage() {
    let response = super::super::json(
        http::Response::builder().header(header::CONTENT_TYPE, "application/scim+json"),
        json!({"ok": true}),
    );
    assert_eq!(
        response.headers()[header::CONTENT_TYPE],
        "application/scim+json"
    );
    assert_eq!(
        response
            .headers()
            .get_all(header::CONTENT_TYPE)
            .iter()
            .count(),
        1
    );
    let bytes = vec![7; 128];
    let pointer = bytes.as_ptr();
    let response = finish(http::Response::builder(), bytes);
    assert_eq!(response.body().as_ptr(), pointer);
}
