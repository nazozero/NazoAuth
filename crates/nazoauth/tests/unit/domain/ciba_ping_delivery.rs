use std::{
    io::{ErrorKind, Read as _, Write as _},
    net::TcpListener,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread,
    time::Duration,
};

use rcgen::{CertificateParams, CertifiedIssuer, KeyPair, PKCS_ECDSA_P256_SHA256};

use crate::adapters::ciba_ping_tls::{CIBA_PING_TLS_MAX, CIBA_PING_TLS_MIN};
use nazo_oauth_server::{
    ports::transient_state::CibaPingDelivery, workers::ciba_ping::CibaPingSender,
};

/// A self-signed test CA plus its reqwest trust-anchor form. Test servers
/// present CA-signed certificates so every client keeps real certificate
/// validation enabled; the tests only trust this throwaway CA.
struct TestCa {
    issuer: CertifiedIssuer<'static, KeyPair>,
    certificate: reqwest::Certificate,
}

fn test_ca() -> TestCa {
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("generate test CA key");
    let mut params = CertificateParams::default();
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params.key_usages = vec![
        rcgen::KeyUsagePurpose::KeyCertSign,
        rcgen::KeyUsagePurpose::CrlSign,
    ];
    let issuer = CertifiedIssuer::self_signed(params, key).expect("self-signed test CA");
    let certificate = reqwest::Certificate::from_pem(issuer.pem().as_bytes()).expect("test CA PEM");
    TestCa {
        issuer,
        certificate,
    }
}

fn server_identity(
    ca: &CertifiedIssuer<'_, KeyPair>,
) -> (
    rustls::pki_types::PrivateKeyDer<'static>,
    rustls::pki_types::CertificateDer<'static>,
) {
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("generate server key");
    let mut params =
        CertificateParams::new(vec!["127.0.0.1".to_owned()]).expect("server certificate params");
    params.is_ca = rcgen::IsCa::NoCa;
    params.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
    let certificate = params
        .signed_by(&key, ca)
        .expect("CA-signed server certificate");
    let private_key = rustls::pki_types::PrivatePkcs8KeyDer::from(key.serialize_der());
    (private_key.into(), certificate.der().clone())
}

fn tls_server(
    version: &'static rustls::SupportedProtocolVersion,
    private_key: rustls::pki_types::PrivateKeyDer<'static>,
    certificate: rustls::pki_types::CertificateDer<'static>,
    response: String,
) -> (std::net::SocketAddr, thread::JoinHandle<()>) {
    let provider = rustls::crypto::aws_lc_rs::default_provider();
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[version])
        .expect("configure single-version TLS server")
        .with_no_client_auth()
        .with_single_cert(vec![certificate], private_key)
        .expect("configure TLS test identity");
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind TLS test server");
    let address = listener.local_addr().expect("read TLS test address");
    let handle = thread::spawn(move || {
        let (stream, _) = listener.accept().expect("accept TLS test connection");
        let connection =
            rustls::ServerConnection::new(Arc::new(config)).expect("create TLS server connection");
        let mut stream = rustls::StreamOwned::new(connection, stream);
        if stream.conn.complete_io(&mut stream.sock).is_ok() {
            let mut request = [0_u8; 2048];
            let _ = stream.read(&mut request);
            stream
                .write_all(response.as_bytes())
                .expect("write TLS test response");
        }
    });
    (address, handle)
}

fn single_version_tls_server(
    version: &'static rustls::SupportedProtocolVersion,
    ca: &CertifiedIssuer<'_, KeyPair>,
) -> (std::net::SocketAddr, thread::JoinHandle<()>) {
    single_version_tls_server_with_status(version, 204, ca)
}

fn single_version_tls_server_with_status(
    version: &'static rustls::SupportedProtocolVersion,
    status: u16,
    ca: &CertifiedIssuer<'_, KeyPair>,
) -> (std::net::SocketAddr, thread::JoinHandle<()>) {
    let (key, certificate) = server_identity(ca);
    let reason = match status {
        200 => "OK",
        204 => "No Content",
        400 => "Bad Request",
        500 => "Internal Server Error",
        _ => "Test Response",
    };
    tls_server(
        version,
        key,
        certificate,
        format!("HTTP/1.1 {status} {reason}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"),
    )
}

/// Counts TCP connections so tests can prove a request never left the intended
/// path (redirect target, environment proxy, or a blocked resolution).
struct RecordingListener {
    address: std::net::SocketAddr,
    connections: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
}

impl RecordingListener {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind recording listener");
        listener
            .set_nonblocking(true)
            .expect("nonblocking recording listener");
        let address = listener.local_addr().expect("recording listener address");
        let connections = Arc::new(AtomicUsize::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let handle = thread::spawn({
            let connections = Arc::clone(&connections);
            let stop = Arc::clone(&stop);
            move || {
                while !stop.load(Ordering::Relaxed) {
                    match listener.accept() {
                        Ok((stream, _)) => {
                            connections.fetch_add(1, Ordering::Relaxed);
                            drop(stream);
                        }
                        Err(error) if error.kind() == ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(5));
                        }
                        Err(_) => break,
                    }
                }
            }
        });
        Self {
            address,
            connections,
            stop,
            handle: Some(handle),
        }
    }

    /// A dialed connection lands in the accept backlog before `send` returns,
    /// so a short settle window makes the counter deterministic.
    fn settled_connection_count(&self) -> usize {
        thread::sleep(Duration::from_millis(100));
        self.connections.load(Ordering::Relaxed)
    }
}

impl Drop for RecordingListener {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            handle.join().expect("join recording listener");
        }
    }
}

fn ciba_delivery(endpoint: String) -> CibaPingDelivery {
    CibaPingDelivery {
        auth_req_id_hash: "request-hash".into(),
        auth_req_id: "request-id".into(),
        endpoint,
        client_notification_token: uuid::Uuid::now_v7().to_string(),
        attempts: 0,
        expires_at: chrono::Utc::now().timestamp() + 60,
    }
}

async fn post_to_server(
    address: std::net::SocketAddr,
    server: thread::JoinHandle<()>,
    ca: &TestCa,
) -> reqwest::Result<reqwest::Response> {
    let client = super::apply_ciba_ping_client_policy(
        reqwest::Client::builder().tls_certs_only([ca.certificate.clone()]),
    )
    .expect("apply CIBA ping client policy")
    .connect_timeout(Duration::from_secs(15))
    .timeout(Duration::from_secs(30))
    .build()
    .expect("build CIBA ping test client");

    let result = client
        .post(format!("https://{address}/ciba-notification-endpoint"))
        .send()
        .await;
    server.join().expect("join TLS test server");
    result
}

async fn post_to_single_version_server(
    version: &'static rustls::SupportedProtocolVersion,
    ca: &TestCa,
) -> reqwest::Result<reqwest::Response> {
    let (address, server) = single_version_tls_server(version, &ca.issuer);
    post_to_server(address, server, ca).await
}

async fn post_to_single_version_server_with_status(
    version: &'static rustls::SupportedProtocolVersion,
    status: u16,
    ca: &TestCa,
) -> reqwest::Result<reqwest::Response> {
    let (address, server) = single_version_tls_server_with_status(version, status, &ca.issuer);
    post_to_server(address, server, ca).await
}

#[test]
fn ciba_ping_transport_policy_is_bounded_to_tls12_and_tls13() {
    assert!(matches!(CIBA_PING_TLS_MIN, reqwest::tls::Version::TLS_1_2));
    assert!(matches!(CIBA_PING_TLS_MAX, reqwest::tls::Version::TLS_1_3));
}

#[tokio::test]
async fn ciba_ping_transport_supports_the_tls12_fapi_baseline() {
    let ca = test_ca();
    let response = post_to_single_version_server(&rustls::version::TLS12, &ca)
        .await
        .expect("CIBA Ping must interoperate with a TLS 1.2-only FAPI endpoint");

    assert_eq!(response.status(), reqwest::StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn ciba_ping_transport_supports_tls13() {
    let ca = test_ca();
    let (address, server) = single_version_tls_server(&rustls::version::TLS13, &ca.issuer);
    let response = post_to_server(address, server, &ca)
        .await
        .expect("CIBA Ping must offer TLS 1.3 when the endpoint supports it");

    assert_eq!(response.status(), reqwest::StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn ciba_ping_transport_preserves_terminal_and_retry_http_statuses() {
    let ca = test_ca();
    let terminal = post_to_single_version_server_with_status(&rustls::version::TLS12, 400, &ca)
        .await
        .expect("TLS 1.2 endpoint should return its terminal status");
    assert_eq!(terminal.status(), reqwest::StatusCode::BAD_REQUEST);

    let retry = post_to_single_version_server_with_status(&rustls::version::TLS13, 500, &ca)
        .await
        .expect("TLS 1.3 endpoint should return its retry status");
    assert_eq!(retry.status(), reqwest::StatusCode::INTERNAL_SERVER_ERROR);
}

#[test]
fn ciba_ping_sender_private_network_exceptions_require_https_origins() {
    use super::CibaPingHttpSender;
    let sender =
        CibaPingHttpSender::new(&["https://Example.COM:443".to_owned()]).expect("HTTPS origin");
    assert!(
        sender
            .private_network_origins
            .contains("https://example.com")
    );
    for invalid in [
        "http://example.com",
        "https://example.com/path",
        "https://example.com/?query=yes",
    ] {
        assert!(
            CibaPingHttpSender::new(&[invalid.to_owned()]).is_err(),
            "{invalid}"
        );
    }
}

#[test]
fn ciba_ping_sender_preserves_notification_idempotency_key() {
    assert_eq!(
        super::ciba_ping_idempotency_key("request-hash"),
        "nazo-ciba-ping-request-hash"
    );
}

#[tokio::test]
async fn ciba_ping_sender_blocks_private_networks_and_keeps_certificate_validation_for_exceptions()
{
    let ca = test_ca();
    let (address, server) = single_version_tls_server(&rustls::version::TLS13, &ca.issuer);
    let origin = format!("https://{address}");
    let delivery = ciba_delivery(format!("{origin}/notify"));
    let denied = super::CibaPingHttpSender::new(&[])
        .unwrap()
        .send(&delivery)
        .await
        .unwrap_err();
    assert!(denied.to_string().contains("blocked network"));
    let sender = super::CibaPingHttpSender::new(&[origin]).unwrap();
    let error = sender.send(&delivery).await.unwrap_err();
    assert!(error.to_string().contains("CIBA ping request failed"));
    server.join().unwrap();
}

#[tokio::test]
async fn ciba_ping_sender_never_dials_blocked_resolutions() {
    let listener = RecordingListener::start();
    let sender = super::CibaPingHttpSender::new(&[]).expect("sender without exceptions");
    let error = sender
        .send(&ciba_delivery(format!(
            "https://{}/notify",
            listener.address
        )))
        .await
        .expect_err("a blocked resolution must fail delivery");
    assert!(error.to_string().contains("blocked network"));
    assert_eq!(
        listener.settled_connection_count(),
        0,
        "the blocked address must never be dialed"
    );
}

/// Build a client through the production CIBA ping client policy. The client
/// keeps certificate validation enabled and only trusts the per-test CA.
fn ciba_ping_client(
    builder: reqwest::ClientBuilder,
    address: std::net::SocketAddr,
    ca: &TestCa,
) -> reqwest::Client {
    super::apply_ciba_ping_client_policy(builder.tls_certs_only([ca.certificate.clone()]))
        .expect("apply CIBA ping client policy")
        .resolve_to_addrs("127.0.0.1", &[address])
        .build()
        .expect("build CIBA ping test client")
}

#[tokio::test]
async fn ciba_ping_client_surfaces_redirects_without_following_them() {
    let redirect_target = RecordingListener::start();
    let ca = test_ca();
    let (key, certificate) = server_identity(&ca.issuer);
    let (address, server) = tls_server(
        &rustls::version::TLS12,
        key,
        certificate,
        format!(
            "HTTP/1.1 302 Found
Location: https://{}/notify
Content-Length: 0
Connection: close

",
            redirect_target.address
        ),
    );
    let response = ciba_ping_client(reqwest::Client::builder(), address, &ca)
        .post(format!("https://{address}/notify"))
        .send()
        .await
        .expect("a redirect is a terminal response, not a request failure");
    server.join().expect("join TLS server");
    assert_eq!(response.status(), reqwest::StatusCode::FOUND);
    assert_eq!(
        redirect_target.settled_connection_count(),
        0,
        "the notification token must not leak to a redirect target"
    );
}

#[tokio::test]
async fn ciba_ping_client_bypasses_configured_and_environment_proxies() {
    // Environment proxies feed the same `proxies`/`auto_sys_proxy` builder
    // configuration that `no_proxy()` clears, so an explicitly configured proxy
    // exercises the identical bypass path without mutating process state.
    let proxy = RecordingListener::start();
    let ca = test_ca();
    let (key, certificate) = server_identity(&ca.issuer);
    let (address, server) = tls_server(
        &rustls::version::TLS13,
        key,
        certificate,
        "HTTP/1.1 204 No Content
Content-Length: 0
Connection: close

"
        .to_owned(),
    );
    let client = ciba_ping_client(
        reqwest::Client::builder()
            .proxy(reqwest::Proxy::all(format!("http://{}", proxy.address)).expect("test proxy")),
        address,
        &ca,
    );
    let response = client
        .post(format!("https://{address}/notify"))
        .send()
        .await
        .expect("delivery must reach the endpoint directly");
    server.join().expect("join TLS server");
    assert_eq!(response.status(), reqwest::StatusCode::NO_CONTENT);
    assert_eq!(
        proxy.settled_connection_count(),
        0,
        "proxy settings must not intercept CIBA callbacks"
    );
}
