use super::*;
use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpListener},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    thread,
    time::Duration,
};

use rcgen::{CertificateParams, KeyPair, PKCS_ECDSA_P256_SHA256};

#[test]
fn private_origin_allowlist_is_exact_and_https_only() {
    assert!(RemoteClientDocumentResolver::new(&["http://web:8443".to_owned()]).is_err());
    assert!(RemoteClientDocumentResolver::new(&["https://web:8443/path".to_owned()]).is_err());
    let resolver = RemoteClientDocumentResolver::new(&["https://web:8443".to_owned()]).unwrap();
    assert!(
        resolver
            .private_network_origins
            .contains("https://web:8443")
    );
}

#[test]
fn content_types_are_narrowly_accepted() {
    assert!(RemoteDocumentKind::Jwks.accepts_content_type("application/jwk-set+json"));
    assert!(RemoteDocumentKind::Jwks.accepts_content_type("application/json; charset=utf-8"));
    assert!(!RemoteDocumentKind::Jwks.accepts_content_type("application/jsonp"));
    assert!(!RemoteDocumentKind::Jwks.accepts_content_type("text/plain"));
    assert!(RemoteDocumentKind::RequestObject.accepts_content_type("application/jwt"));
    assert!(!RemoteDocumentKind::RequestObject.accepts_content_type("application/json"));
    assert!(
        RemoteDocumentKind::SectorIdentifier
            .accepts_content_type("application/json; charset=utf-8")
    );
    assert!(!RemoteDocumentKind::SectorIdentifier.accepts_content_type("application/jwk-set+json"));
}

fn tls_server(
    status: u16,
    content_type: &str,
    body: Vec<u8>,
    content_length: bool,
) -> (SocketAddr, thread::JoinHandle<()>, Vec<u8>) {
    tls_server_sequence(vec![(
        status,
        content_type.to_owned(),
        body,
        content_length,
    )])
}

pub(crate) fn tls_server_sequence(
    responses: Vec<(u16, String, Vec<u8>, bool)>,
) -> (SocketAddr, thread::JoinHandle<()>, Vec<u8>) {
    let (address, handle, certificate_der, _) = tls_server_sequence_with_request_count(responses);
    (address, handle, certificate_der)
}

fn tls_server_sequence_with_request_count(
    responses: Vec<(u16, String, Vec<u8>, bool)>,
) -> (
    SocketAddr,
    thread::JoinHandle<()>,
    Vec<u8>,
    Arc<AtomicUsize>,
) {
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("generate TLS test key");
    let certificate = CertificateParams::new(vec!["localhost".to_owned()])
        .expect("TLS certificate params")
        .self_signed(&key)
        .expect("self-sign TLS test certificate");
    let certificate_der = certificate.der().to_vec();
    let private_key = rustls::pki_types::PrivatePkcs8KeyDer::from(key.serialize_der());
    let provider = rustls::crypto::aws_lc_rs::default_provider();
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("configure TLS test server")
        .with_no_client_auth()
        .with_single_cert(vec![certificate.der().clone()], private_key.into())
        .expect("configure TLS test identity");
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind TLS test listener");
    let address = listener
        .local_addr()
        .expect("read TLS test listener address");
    let request_count = Arc::new(AtomicUsize::new(0));
    let accepted_requests = Arc::clone(&request_count);
    let handle = thread::spawn(move || {
        for (status, content_type, body, content_length) in responses {
            let (stream, _) = listener.accept().expect("accept TLS test request");
            accepted_requests.fetch_add(1, Ordering::SeqCst);
            let connection = rustls::ServerConnection::new(Arc::new(config.clone()))
                .expect("create TLS connection");
            let mut stream = rustls::StreamOwned::new(connection, stream);
            let _ = stream.conn.complete_io(&mut stream.sock);
            let mut request = [0_u8; 4096];
            let _ = stream.read(&mut request);
            let reason = match status {
                200 => "OK",
                400 => "Bad Request",
                404 => "Not Found",
                500 => "Internal Server Error",
                _ => "Test Response",
            };
            let length = content_length.then(|| format!("Content-Length: {}\r\n", body.len()));
            let response = format!(
                "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\n{}Connection: close\r\n\r\n",
                length.unwrap_or_default()
            );
            stream
                .write_all(response.as_bytes())
                .expect("write TLS test headers");
            stream.write_all(&body).expect("write TLS test body");
        }
    });
    (address, handle, certificate_der, request_count)
}

pub(crate) fn resolver_for(
    address: SocketAddr,
    certificate_der: &[u8],
) -> RemoteClientDocumentResolver {
    let certificate =
        reqwest::Certificate::from_der(certificate_der).expect("test TLS certificate should parse");
    RemoteClientDocumentResolver::new_with_root_certificates(
        &[format!("https://localhost:{}", address.port())],
        vec![certificate],
    )
    .expect("test resolver should build")
}

#[tokio::test]
async fn concurrent_cold_jwks_requests_share_one_network_result() {
    for status in [200, 500] {
        let (address, server, certificate_der, request_count) =
            tls_server_sequence_with_request_count(vec![(
                status,
                "application/json".to_owned(),
                br#"{"keys":[{"kid":"shared"}]}"#.to_vec(),
                true,
            )]);
        let resolver = resolver_for(address, &certificate_der);
        let uri = format!("https://localhost:{}/jwks", address.port());
        let results = futures_util::future::join_all(
            (0..32).map(|_| resolver.jwks_for_kid(&uri, Some("shared"))),
        )
        .await;
        for result in &results {
            assert_eq!(result, &results[0]);
            assert_eq!(result.is_ok(), status == 200);
        }
        assert_eq!(request_count.load(Ordering::SeqCst), 1);
        server.join().expect("shared JWKS server should exit");
    }
}

#[tokio::test]
async fn jwks_fetches_valid_documents_and_reuses_a_matching_cache_entry() {
    let body = br#"{"keys":[{"kid":"key-1","kty":"OKP"}]}"#.to_vec();
    let (address, server, certificate_der) = tls_server(200, "application/json", body, true);
    let resolver = resolver_for(address, &certificate_der);
    let uri = format!("https://localhost:{}/jwks", address.port());

    let first = resolver
        .jwks_for_kid(&uri, Some("key-1"))
        .await
        .expect("valid JWKS should fetch");
    assert_eq!(first["keys"][0]["kid"], "key-1");
    let cached = resolver
        .jwks_for_kid(&uri, Some("key-1"))
        .await
        .expect("matching kid should use cache");
    assert_eq!(cached, first);
    server.join().expect("TLS test server should exit");
}

#[tokio::test]
async fn jwks_refreshes_for_an_unknown_kid_and_rejects_bad_payloads() {
    let (address, server, certificate_der) = tls_server_sequence(vec![
        (
            200,
            "application/json".to_owned(),
            br#"{"keys":[{"kid":"old"}]}"#.to_vec(),
            true,
        ),
        (
            200,
            "application/jwk-set+json; charset=utf-8".to_owned(),
            br#"{"keys":[{"kid":"new"}]}"#.to_vec(),
            true,
        ),
    ]);
    let resolver = resolver_for(address, &certificate_der);
    let uri = format!("https://localhost:{}/jwks", address.port());
    resolver
        .jwks_for_kid(&uri, Some("old"))
        .await
        .expect("initial JWKS should fetch");
    let refreshed = resolver
        .jwks_for_kid(&uri, Some("new"))
        .await
        .expect("unknown kid should refresh the cached JWKS");
    assert_eq!(refreshed["keys"][0]["kid"], "new");
    server.join().expect("refresh TLS server should exit");

    for (status, content_type, body) in [
        (500, "application/json", br#"{}"#.to_vec()),
        (200, "text/plain", br#"{}"#.to_vec()),
        (200, "application/json", b"not-json".to_vec()),
        (200, "application/json", br#"{"keys":{}}"#.to_vec()),
    ] {
        let (address, server, certificate_der) = tls_server(status, content_type, body, true);
        let resolver = resolver_for(address, &certificate_der);
        let uri = format!("https://localhost:{}/jwks", address.port());
        assert!(resolver.jwks_for_kid(&uri, None).await.is_err());
        server.join().expect("bad-payload TLS server should exit");
    }
}

#[tokio::test]
async fn jwks_unknown_kids_share_one_forced_refresh_budget_and_merge_waiters() {
    let (address, server, certificate_der, request_count) =
        tls_server_sequence_with_request_count(vec![
            (
                200,
                "application/json".to_owned(),
                br#"{"keys":[{"kid":"old"}]}"#.to_vec(),
                true,
            ),
            (
                200,
                "application/json".to_owned(),
                br#"{"keys":[{"kid":"rotated"}]}"#.to_vec(),
                true,
            ),
        ]);
    let resolver = resolver_for(address, &certificate_der);
    let uri = format!("https://localhost:{}/jwks", address.port());
    resolver
        .jwks_for_kid(&uri, Some("old"))
        .await
        .expect("initial JWKS should fetch");

    let (rotated, attacker) = tokio::join!(
        resolver.jwks_for_kid(&uri, Some("rotated")),
        resolver.jwks_for_kid(&uri, Some("attacker-kid")),
    );
    assert!(rotated.is_ok());
    assert!(attacker.is_ok());

    let suppressed = resolver
        .jwks_for_kid(&uri, Some("another-attacker-kid"))
        .await;
    assert!(suppressed.is_ok());
    assert_eq!(request_count.load(Ordering::SeqCst), 2);

    server
        .join()
        .expect("bounded JWKS refresh server should exit");
}

#[tokio::test]
async fn jwks_failed_forced_refresh_consumes_the_uri_budget_without_stale_success() {
    let (address, server, certificate_der, request_count) =
        tls_server_sequence_with_request_count(vec![
            (
                200,
                "application/json".to_owned(),
                br#"{"keys":[{"kid":"old"}]}"#.to_vec(),
                true,
            ),
            (500, "application/json".to_owned(), br#"{}"#.to_vec(), true),
        ]);
    let resolver = resolver_for(address, &certificate_der);
    let uri = format!("https://localhost:{}/jwks", address.port());
    resolver
        .jwks_for_kid(&uri, Some("old"))
        .await
        .expect("initial JWKS should fetch");

    assert!(
        resolver
            .jwks_for_kid(&uri, Some("missing-one"))
            .await
            .is_err()
    );
    assert_eq!(
        resolver
            .jwks_for_kid(&uri, Some("missing-two"))
            .await
            .expect("a cooldown-suppressed miss should return the cached JWKS")["keys"][0]["kid"],
        "old"
    );
    assert_eq!(request_count.load(Ordering::SeqCst), 2);
    assert_eq!(
        resolver
            .jwks_for_kid(&uri, Some("old"))
            .await
            .expect("a matching key may still use the cached document")["keys"][0]["kid"],
        "old"
    );
    server
        .join()
        .expect("failed-refresh JWKS server should exit");
}

#[tokio::test]
async fn jwks_initial_miss_allows_one_immediate_rotation_refresh() {
    let (address, server, certificate_der, request_count) =
        tls_server_sequence_with_request_count(vec![
            (
                200,
                "application/json".to_owned(),
                br#"{"keys":[{"kid":"old"}]}"#.to_vec(),
                true,
            ),
            (
                200,
                "application/json".to_owned(),
                br#"{"keys":[{"kid":"new"}]}"#.to_vec(),
                true,
            ),
        ]);
    let resolver = resolver_for(address, &certificate_der);
    let uri = format!("https://localhost:{}/jwks", address.port());

    assert_eq!(
        resolver
            .jwks_for_kid(&uri, Some("new"))
            .await
            .expect("an initial fetch returns the valid JWKS even for an unknown hint")["keys"][0]
            ["kid"],
        "old"
    );
    assert_eq!(request_count.load(Ordering::SeqCst), 1);
    assert_eq!(
        resolver
            .jwks_for_kid(&uri, Some("new"))
            .await
            .expect("an initial key miss may immediately confirm rotation")["keys"][0]["kid"],
        "new"
    );
    assert_eq!(request_count.load(Ordering::SeqCst), 2);
    server.join().expect("initial-miss JWKS server should exit");
}

#[tokio::test]
async fn jwks_cold_refresh_after_expiry_restores_the_forced_refresh_budget() {
    let (address, server, certificate_der, request_count) =
        tls_server_sequence_with_request_count(vec![
            (
                200,
                "application/json".to_owned(),
                br#"{"keys":[{"kid":"old"}]}"#.to_vec(),
                true,
            ),
            (
                200,
                "application/json".to_owned(),
                br#"{"keys":[{"kid":"rotated"}]}"#.to_vec(),
                true,
            ),
            (
                200,
                "application/json".to_owned(),
                br#"{"keys":[{"kid":"cold"}]}"#.to_vec(),
                true,
            ),
        ]);
    let resolver = resolver_for(address, &certificate_der);
    let uri = format!("https://localhost:{}/jwks", address.port());
    resolver
        .jwks_for_kid(&uri, Some("old"))
        .await
        .expect("initial JWKS should fetch");
    resolver
        .jwks_for_kid(&uri, Some("rotated"))
        .await
        .expect("unknown kid should trigger one forced refresh");

    let mut resolver = resolver;
    resolver.cache_epoch -= JWKS_CACHE_TTL;
    assert_eq!(
        resolver
            .jwks_for_kid(&uri, Some("cold"))
            .await
            .expect("an evicted entry should cold-refresh")["keys"][0]["kid"],
        "cold"
    );
    assert_eq!(request_count.load(Ordering::SeqCst), 3);
    server.join().expect("cold-refresh JWKS server should exit");
}

#[tokio::test]
async fn request_objects_validate_utf8_size_and_content_type() {
    let (address, server, certificate_der) =
        tls_server(200, "application/jwt", b"  signed.jwt \n".to_vec(), true);
    let resolver = resolver_for(address, &certificate_der);
    let uri = format!("https://localhost:{}/request", address.port());
    assert_eq!(
        resolver
            .request_object(&uri)
            .await
            .expect("request object should load"),
        "signed.jwt"
    );
    server
        .join()
        .expect("request object TLS server should exit");

    for body in [Vec::new(), vec![0xff, 0xfe]] {
        let (address, server, certificate_der) = tls_server(200, "application/jwt", body, true);
        let resolver = resolver_for(address, &certificate_der);
        let uri = format!("https://localhost:{}/request", address.port());
        assert!(resolver.request_object(&uri).await.is_err());
        server
            .join()
            .expect("invalid request object server should exit");
    }
}

#[tokio::test]
async fn sector_identifier_fetch_always_rejects_private_destinations() {
    let resolver = RemoteClientDocumentResolver::new(&["https://localhost:1".to_owned()]).unwrap();

    let error = resolver
        .sector_identifier_uris("https://localhost:1/sector.json")
        .await
        .expect_err("sector identifier documents must use public destinations");
    assert!(error.contains("blocked network"));
}

#[tokio::test]
async fn remote_fetch_rejects_oversize_bodies_dns_failures_and_exhausted_slots() {
    let (address, server, certificate_der) = tls_server(
        200,
        "application/json",
        vec![b'x'; MAX_RESPONSE_BYTES as usize + 1],
        true,
    );
    let resolver = resolver_for(address, &certificate_der);
    let uri = format!("https://localhost:{}/jwks", address.port());
    assert!(resolver.jwks_for_kid(&uri, None).await.is_err());
    tokio::task::spawn_blocking(move || server.join())
        .await
        .expect("oversized TLS join task should complete")
        .expect("oversized TLS server should exit");

    let (address, server, certificate_der) = tls_server(
        200,
        "application/json",
        vec![b'x'; MAX_RESPONSE_BYTES as usize + 1],
        false,
    );
    let resolver = resolver_for(address, &certificate_der);
    let uri = format!("https://localhost:{}/jwks", address.port());
    assert!(resolver.jwks_for_kid(&uri, None).await.is_err());
    tokio::task::spawn_blocking(move || server.join())
        .await
        .expect("streamed oversized TLS join task should complete")
        .expect("streamed oversized TLS server should exit");

    let resolver = RemoteClientDocumentResolver::new(&[]).expect("resolver should build");
    let Err(blocked_error) = resolver
        .fetch(
            "https://localhost:1/jwks",
            RemoteDocumentKind::Jwks,
            tokio::time::Instant::now() + Duration::from_secs(2),
        )
        .await
    else {
        panic!("private addresses must be blocked without an exact origin allowlist");
    };
    assert!(blocked_error.contains("blocked network"));

    let Err(dns_error) = resolver
        .fetch(
            "https://does-not-exist.invalid/jwks",
            RemoteDocumentKind::Jwks,
            tokio::time::Instant::now() + Duration::from_secs(2),
        )
        .await
    else {
        panic!("unresolvable host should fail closed");
    };
    assert!(
        dns_error.contains("DNS") || dns_error.contains("blocked"),
        "unexpected remote fetch error: {dns_error}"
    );

    let permits = resolver
        .fetch_slots
        .clone()
        .try_acquire_many_owned(REMOTE_FETCH_CONCURRENCY as u32)
        .expect("all test fetch slots should be acquirable");
    let slot_error = resolver
        .sector_identifier_uris("https://example.com/sector.json")
        .await
        .expect_err("exhausted fetch slots should fail closed");
    assert!(slot_error.contains("concurrency"));
    drop(permits);
}

#[test]
fn remote_uri_validation_and_kid_selection_are_fail_closed() {
    assert!(canonical_cache_key("http://client.example/jwks").is_err());
    assert!(canonical_cache_key("https://client.example/jwks").is_ok());
    assert!(validate_https_url("https://user:pass@client.example/jwks", true).is_err());
    assert!(validate_https_url("https://client.example/jwks#fragment", false).is_err());
    assert!(validate_https_url("https://client.example/jwks#fragment", true).is_ok());
    let document = serde_json::json!({"keys": [{"kid": "one"}]});
    assert!(jwks_contains_kid(&document, None));
    assert!(jwks_contains_kid(&document, Some("one")));
    assert!(!jwks_contains_kid(&document, Some("two")));
    assert!(!jwks_contains_kid(
        &serde_json::json!({"keys": []}),
        Some("one")
    ));
}
