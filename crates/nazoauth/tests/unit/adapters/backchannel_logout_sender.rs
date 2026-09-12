use super::*;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use url::Url;

async fn local_status_endpoint(status: u16) -> (String, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("loopback listener binds");
    let address = listener
        .local_addr()
        .expect("loopback address is available");
    let task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("request arrives");
        let mut request = Vec::new();
        loop {
            let mut chunk = [0_u8; 16];
            let size = stream.read(&mut chunk).await.expect("request is readable");
            assert_ne!(size, 0, "request must contain its declared body");
            request.extend_from_slice(&chunk[..size]);
            let Some(header_end) = request.windows(4).position(|value| value == b"\r\n\r\n") else {
                continue;
            };
            let headers = String::from_utf8_lossy(&request[..header_end]);
            let content_length = headers
                .lines()
                .find_map(|line| {
                    line.to_ascii_lowercase()
                        .strip_prefix("content-length: ")
                        .map(str::to_owned)
                })
                .and_then(|value| value.parse::<usize>().ok())
                .expect("request declares content length");
            if request.len() >= header_end + 4 + content_length {
                break;
            }
        }
        let request = String::from_utf8_lossy(&request);
        assert!(request.starts_with("POST /logout HTTP/1.1"));
        assert!(
            request
                .to_ascii_lowercase()
                .contains("content-type: application/x-www-form-urlencoded")
        );
        assert!(request.contains("logout_token=logout-token"));
        assert!(
            request
                .to_ascii_lowercase()
                .contains("idempotency-key: nazo-backchannel-logout-")
        );
        stream
            .write_all(
                format!(
                    "HTTP/1.1 {status} Test\r\nContent-Length: 0\r\nLocation: /followed\r\nConnection: close\r\n\r\n"
                )
                .as_bytes(),
            )
            .await
            .expect("response is writable");
    });
    (format!("http://{address}/logout"), task)
}

async fn post_to_local_status(status: u16) -> anyhow::Result<http::StatusCode> {
    let (logout_uri, server) = local_status_endpoint(status).await;
    let origin = Url::parse(&logout_uri)
        .expect("local endpoint is a URL")
        .origin()
        .ascii_serialization();
    let result = post_logout_token(&HashSet::from([origin]), &logout_uri, "logout-token").await;
    server.await.expect("local endpoint completes");
    result
}

#[test]
fn backchannel_endpoint_validation_rejects_unsafe_transport_shapes() {
    assert!(validate_backchannel_endpoint("https://rp.example/logout?tenant=a").is_ok());
    assert!(validate_backchannel_endpoint("http://localhost:8080/logout").is_ok());
    for endpoint in [
        "http://rp.example/logout",
        "file:///tmp/logout",
        "https://user@rp.example/logout",
        "https://rp.example/logout#fragment",
        "not-a-uri",
    ] {
        assert!(
            validate_backchannel_endpoint(endpoint).is_err(),
            "endpoint {endpoint}"
        );
    }
}

#[test]
fn backchannel_endpoint_length_is_bounded_and_idempotency_is_stable() {
    let prefix = "https://rp.example/";
    let at_limit = format!(
        "{prefix}{}",
        "x".repeat(nazo_auth::MAX_CIBA_LOGOUT_URI_BYTES - prefix.len())
    );
    assert!(validate_backchannel_endpoint(&at_limit).is_ok());
    assert!(validate_backchannel_endpoint(&format!("{at_limit}x")).is_err());

    assert_eq!(
        backchannel_idempotency_key("logout-token"),
        backchannel_idempotency_key("logout-token")
    );
    assert_ne!(
        backchannel_idempotency_key("logout-token"),
        backchannel_idempotency_key("other-logout-token")
    );
}

#[test]
fn private_network_origin_configuration_is_exact_and_normalized() {
    let origins = parse_private_network_origins(&[
        "https://rp.example".to_owned(),
        "http://localhost:8080".to_owned(),
    ])
    .expect("valid origins are accepted");
    assert_eq!(
        origins,
        HashSet::from([
            "https://rp.example".to_owned(),
            "http://localhost:8080".to_owned(),
        ])
    );

    for invalid in [
        "https://rp.example/logout",
        "https://rp.example?tenant=a",
        "http://rp.example",
    ] {
        let error = parse_private_network_origins(&[invalid.to_owned()])
            .expect_err("non-origin or unsafe entries are rejected");
        assert!(
            error
                .to_string()
                .contains("BACKCHANNEL_LOGOUT_PRIVATE_ORIGINS")
        );
    }
}

#[tokio::test]
async fn backchannel_post_enforces_network_and_response_policy() {
    assert_eq!(
        post_to_local_status(204).await.expect("204 is delivered"),
        http::StatusCode::NO_CONTENT
    );
    assert_eq!(
        post_to_local_status(400)
            .await
            .expect("400 is a terminal response"),
        http::StatusCode::BAD_REQUEST
    );
    assert_eq!(
        post_to_local_status(302)
            .await
            .expect("redirects are terminal and are not followed"),
        http::StatusCode::FOUND
    );
    assert_eq!(
        post_to_local_status(503)
            .await
            .expect("sender returns retryable status without deciding retry"),
        http::StatusCode::SERVICE_UNAVAILABLE
    );

    let blocked = post_logout_token(&HashSet::new(), "http://127.0.0.1:9/logout", "logout-token")
        .await
        .expect_err("private networks require an exact-origin allowlist");
    assert!(blocked.to_string().contains("blocked network"));
}
