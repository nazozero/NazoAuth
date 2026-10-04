#![cfg(target_os = "linux")]

use std::{
    fs,
    io::{Read, Write},
    net::TcpListener,
    process::Command,
    sync::Arc,
    thread,
    time::{Duration, Instant},
};

use nazo_identity::{TenantId, ports::AvatarDirectUploadPort};
use nazo_oauth_server_object_store::{S3AvatarObjectStore, S3AvatarObjectStoreConfig};
use rcgen::{BasicConstraints, CertificateParams, CertifiedIssuer, IsCa, KeyPair};
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use uuid::Uuid;

#[test]
fn s3_platform_trust_requires_a_trusted_ca_and_matching_hostname() {
    let mut params = CertificateParams::default();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca = CertifiedIssuer::self_signed(params.clone(), KeyPair::generate().unwrap()).unwrap();
    let unrelated_ca = CertifiedIssuer::self_signed(params, KeyPair::generate().unwrap()).unwrap();
    for (name, hostname, trusted_ca, succeeds) in [
        ("trusted", "localhost", ca.pem(), true),
        ("untrusted", "localhost", unrelated_ca.pem(), false),
        ("wrong-host", "wrong.example", ca.pem(), false),
    ] {
        let leaf_key = KeyPair::generate().unwrap();
        let leaf = CertificateParams::new(vec![hostname.to_owned()])
            .unwrap()
            .signed_by(&leaf_key, &ca)
            .unwrap();
        let server = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![leaf.der().clone()],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der())),
            )
            .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        listener.set_nonblocking(true).unwrap();
        let handler = thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(10);
            let stream = loop {
                match listener.accept() {
                    Ok((stream, _)) => break stream,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        assert!(Instant::now() < deadline, "TLS fixture was not contacted");
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(error) => panic!("TLS fixture accept: {error}"),
                }
            };
            stream
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            stream
                .set_write_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            let mut stream = rustls::StreamOwned::new(
                rustls::ServerConnection::new(Arc::new(server)).unwrap(),
                stream,
            );
            let mut request = Vec::new();
            while !request.ends_with(b"\r\n\r\n") {
                let mut byte = [0];
                match stream.read(&mut byte) {
                    Ok(1) => request.push(byte[0]),
                    Ok(_) | Err(_) => return false,
                }
                assert!(request.len() < 16_384);
            }
            let request = String::from_utf8(request).unwrap();
            assert!(request.starts_with("DELETE /avatars/avatars/final/"));
            assert!(
                request
                    .to_ascii_lowercase()
                    .contains("authorization: aws4-hmac-sha256 ")
            );
            stream
                .write_all(
                    b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .unwrap();
            stream.flush().unwrap();
            true
        });
        let directory = std::env::temp_dir().join(format!("nazo-s3-tls-{}", Uuid::now_v7()));
        fs::create_dir(&directory).unwrap();
        let trust = directory.join("ca.pem");
        fs::write(&trust, trusted_ca).unwrap();
        let output = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "s3_platform_tls_child",
                "--ignored",
                "--nocapture",
            ])
            .env("SSL_CERT_FILE", &trust)
            .env("SSL_CERT_DIR", &directory)
            .env(
                "NAZO_S3_TLS_CHILD_ENDPOINT",
                format!("https://localhost:{port}"),
            )
            .env("NAZO_S3_TLS_CHILD_SUCCEEDS", succeeds.to_string())
            .env_remove("HTTPS_PROXY")
            .env_remove("https_proxy")
            .env_remove("ALL_PROXY")
            .env_remove("all_proxy")
            .output()
            .unwrap();
        let http_received = handler.join().unwrap();
        fs::remove_dir_all(&directory).unwrap();
        assert!(
            output.status.success(),
            "{name}: {}",
            String::from_utf8_lossy(&output.stdout)
        );
        assert_eq!(
            http_received, succeeds,
            "{name}: rejected TLS must not carry a signed S3 request"
        );
    }
}

#[tokio::test]
#[ignore = "invoked by the parent test with an isolated platform trust environment"]
async fn s3_platform_tls_child() {
    let endpoint = std::env::var("NAZO_S3_TLS_CHILD_ENDPOINT").unwrap();
    let succeeds = std::env::var("NAZO_S3_TLS_CHILD_SUCCEEDS").unwrap() == "true";
    let store = S3AvatarObjectStore::new(
        S3AvatarObjectStoreConfig {
            endpoint,
            region: "us-east-1".to_owned(),
            bucket: "avatars".to_owned(),
            access_key: "tls-fixture-access".to_owned(),
            secret_key: "tls-fixture-secret-only".to_owned(),
            path_style: true,
        },
        TenantId::new(Uuid::now_v7()).unwrap(),
    )
    .unwrap();
    let result = tokio::time::timeout(Duration::from_secs(5), store.delete_final("object"))
        .await
        .expect("TLS handshake and request must terminate");
    assert_eq!(result.is_ok(), succeeds);
}
