use std::io::{self, Write};

use async_compression::tokio::bufread::ZstdEncoder;
use bytes::Bytes;
use futures_util::TryStreamExt;
use http::{Request, header};
use http_body_util::{BodyExt, Full, StreamBody};
use hyper::body::Frame;
use nazoauth::integration::{BodyMode, conformance};
use tokio::io::AsyncReadExt;

use super::{forward_request, forward_response};

#[tokio::test]
async fn shared_transport_contract_and_uncompressed_storage_are_preserved() {
    for expected in conformance::transport_requests() {
        let pointer = expected.body().as_ptr();
        let actual = forward_request(expected.clone().map(Full::new), BodyMode::None);
        let (head, body) = actual.into_parts();
        let chunks: Vec<Bytes> = body.try_collect().await.unwrap();
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].as_ptr(), pointer);
        let actual = Request::from_parts(head, chunks.into_iter().next().unwrap());
        conformance::assert_request(&expected, &actual);
    }
    for (_, expected) in conformance::response_cases() {
        let pointer = expected.body().as_ptr();
        let actual = forward_response(expected.clone());
        let (head, body) = actual.into_parts();
        let body = body.collect().await.unwrap().to_bytes();
        assert_eq!(body.as_ptr(), pointer);
        conformance::assert_response(&expected, &http::Response::from_parts(head, body));
    }
}

fn gzip(body: &[u8]) -> Bytes {
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    encoder.write_all(body).unwrap();
    Bytes::from(encoder.finish().unwrap())
}

#[tokio::test]
async fn content_encoding_accepts_optional_whitespace_and_case_like_actix() {
    let request = Request::builder()
        .header(header::CONTENT_ENCODING, " GZIP \t")
        .body(Full::new(gzip(b"grant_type=client_credentials")))
        .unwrap();
    let decoded = forward_request(request, BodyMode::Form);
    assert_eq!(decoded.headers()[header::CONTENT_ENCODING], " GZIP \t");
    let chunks: Vec<Bytes> = decoded.into_body().try_collect().await.unwrap();
    assert_eq!(chunks.concat(), b"grant_type=client_credentials");
}

#[tokio::test]
async fn declared_decoding_is_bounded_and_raw_multipart_is_unchanged() {
    let bytes = Bytes::from(vec![b'x'; 64 * 1024]);
    let compressed = gzip(&bytes);
    let request = || {
        Request::builder()
            .uri("/testauth/token")
            .header(header::CONTENT_ENCODING, "gzip")
            .body(Full::new(compressed.clone()))
            .unwrap()
    };
    let decoded = forward_request(request(), BodyMode::Json { limit: 2048 });
    assert_eq!(decoded.uri(), "/testauth/token");
    assert_eq!(decoded.headers()[header::CONTENT_ENCODING], "gzip");
    let chunks: Vec<Bytes> = decoded.into_body().try_collect().await.unwrap();
    assert_eq!(chunks.iter().map(Bytes::len).sum::<usize>(), 2049);
    assert!(chunks.iter().all(|chunk| chunk.len() <= 2049));

    let raw = forward_request(request(), BodyMode::Multipart);
    let chunks: Vec<Bytes> = raw.into_body().try_collect().await.unwrap();
    assert_eq!(chunks.as_slice(), std::slice::from_ref(&compressed));
    assert_eq!(chunks[0].as_ptr(), compressed.as_ptr());
}

#[tokio::test]
async fn compressed_bodies_require_complete_wire_input() {
    const BODY: &[u8] = b"hello\n";
    let mut deflate = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::fast());
    deflate.write_all(BODY).unwrap();
    let mut zstd = Vec::new();
    ZstdEncoder::new(BODY).read_to_end(&mut zstd).await.unwrap();
    for (encoding, compressed) in [
        ("gzip", gzip(BODY)),
        ("deflate", Bytes::from(deflate.finish().unwrap())),
        ("br", Bytes::from_static(b"\x8f\x02\x80hello\n\x03")),
        ("zstd", Bytes::from(zstd)),
    ] {
        for (parts, expected) in [
            (vec![compressed.clone()], Some(BODY.to_vec())),
            (
                vec![compressed.slice(..1), compressed.slice(1..)],
                Some(BODY.to_vec()),
            ),
            (
                vec![Bytes::from([compressed.as_ref(), b"trailing"].concat())],
                None,
            ),
            (
                vec![compressed.clone(), Bytes::from_static(b"trailing")],
                None,
            ),
            (vec![compressed.slice(..compressed.len() - 1)], None),
            (
                vec![compressed.clone(), compressed.clone()],
                (encoding == "zstd").then(|| BODY.repeat(2)),
            ),
        ] {
            let body = StreamBody::new(futures_util::stream::iter(
                parts
                    .into_iter()
                    .map(|part| Ok::<_, io::Error>(Frame::data(part))),
            ));
            let request = Request::builder()
                .header(header::CONTENT_ENCODING, encoding)
                .body(body)
                .unwrap();
            let decoded: Result<Vec<Bytes>, _> = forward_request(request, BodyMode::Form)
                .into_body()
                .try_collect()
                .await;
            match expected {
                Some(expected) => assert_eq!(decoded.unwrap().concat(), expected, "{encoding}"),
                None => assert!(decoded.is_err(), "{encoding} accepted invalid wire input"),
            }
        }
    }
}

#[tokio::test]
async fn brotli_large_window_is_rejected_before_decoding() {
    // One uncompressed "hello\n" metablock with the large-window WBITS=25 header.
    let compressed = Bytes::from_static(b"\x11\x19\x0a\x00\x02hello\n\x03");
    for parts in [
        vec![compressed.clone()],
        vec![Bytes::new(), compressed.slice(..1), compressed.slice(1..)],
    ] {
        let body = StreamBody::new(futures_util::stream::iter(
            parts
                .into_iter()
                .map(|part| Ok::<_, io::Error>(Frame::data(part))),
        ));
        let request = Request::builder()
            .header(header::CONTENT_ENCODING, "br")
            .body(body)
            .unwrap();
        let error = forward_request(request, BodyMode::Form)
            .into_body()
            .try_collect::<Vec<Bytes>>()
            .await
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(error.to_string(), "Brotli large window is not supported");
    }
    let request = Request::builder()
        .header(header::CONTENT_ENCODING, "br")
        .body(Full::new(compressed.clone()))
        .unwrap();
    let raw: Vec<Bytes> = forward_request(request, BodyMode::Multipart)
        .into_body()
        .try_collect()
        .await
        .unwrap();
    assert_eq!(raw.as_slice(), std::slice::from_ref(&compressed));
    assert_eq!(raw[0].as_ptr(), compressed.as_ptr());
}
