use std::{
    io::{Read as _, Write as _},
    net::TcpListener,
    thread,
    time::Duration,
};

use openssl::{
    asn1::Asn1Time,
    bn::{BigNum, MsbOption},
    hash::MessageDigest,
    pkey::PKey,
    rsa::Rsa,
    ssl::{SslAcceptor, SslMethod, SslVersion},
    x509::{X509, X509NameBuilder},
};

use super::ciba_ping_tls::apply_ciba_ping_tls_policy;

fn single_version_tls_server(
    version: SslVersion,
) -> (std::net::SocketAddr, thread::JoinHandle<()>) {
    let key = PKey::from_rsa(Rsa::generate(2048).expect("generate test RSA key"))
        .expect("construct test key");
    let mut name = X509NameBuilder::new().expect("create certificate name");
    name.append_entry_by_text("CN", "localhost")
        .expect("set certificate CN");
    let name = name.build();
    let mut serial = BigNum::new().expect("create serial");
    serial
        .rand(128, MsbOption::MAYBE_ZERO, false)
        .expect("generate serial");
    let serial = serial.to_asn1_integer().expect("encode serial");
    let mut certificate = X509::builder().expect("create certificate");
    certificate.set_version(2).expect("set certificate version");
    certificate
        .set_serial_number(&serial)
        .expect("set certificate serial");
    certificate
        .set_subject_name(&name)
        .expect("set certificate subject");
    certificate
        .set_issuer_name(&name)
        .expect("set certificate issuer");
    certificate.set_pubkey(&key).expect("set certificate key");
    certificate
        .set_not_before(&Asn1Time::days_from_now(0).expect("set not-before"))
        .expect("apply not-before");
    certificate
        .set_not_after(&Asn1Time::days_from_now(1).expect("set not-after"))
        .expect("apply not-after");
    certificate
        .sign(&key, MessageDigest::sha256())
        .expect("sign certificate");

    let mut acceptor =
        SslAcceptor::mozilla_intermediate(SslMethod::tls_server()).expect("create TLS acceptor");
    acceptor.set_private_key(&key).expect("set TLS private key");
    acceptor
        .set_certificate(&certificate.build())
        .expect("set TLS certificate");
    acceptor
        .set_min_proto_version(Some(version))
        .expect("set TLS minimum");
    acceptor
        .set_max_proto_version(Some(version))
        .expect("set TLS maximum");
    let acceptor = acceptor.build();
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind TLS test server");
    let address = listener.local_addr().expect("read TLS test address");
    let handle = thread::spawn(move || {
        let (stream, _) = listener.accept().expect("accept TLS test connection");
        if let Ok(mut stream) = acceptor.accept(stream) {
            let mut request = [0_u8; 2048];
            let _ = stream.read(&mut request);
            stream
                .write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
                .expect("write TLS test response");
        }
    });
    (address, handle)
}

async fn post_to_single_version_server(version: SslVersion) -> reqwest::Result<reqwest::Response> {
    let (address, server) = single_version_tls_server(version);
    let client =
        apply_ciba_ping_tls_policy(reqwest::Client::builder().danger_accept_invalid_certs(true))
            .connect_timeout(Duration::from_secs(3))
            .timeout(Duration::from_secs(5))
            .build()
            .expect("build CIBA Ping test client");

    let result = client
        .post(format!("https://{address}/ciba-notification-endpoint"))
        .send()
        .await;
    server.join().expect("join TLS test server");
    result
}

#[tokio::test]
async fn ciba_ping_transport_rejects_tls11() {
    let result = post_to_single_version_server(SslVersion::TLS1_1).await;

    assert!(
        result.is_err(),
        "CIBA Ping delivery must reject notification endpoints below TLS 1.2"
    );
}

#[tokio::test]
async fn ciba_ping_transport_supports_the_tls12_fapi_baseline() {
    let response = post_to_single_version_server(SslVersion::TLS1_2)
        .await
        .expect("CIBA Ping must interoperate with a TLS 1.2-only FAPI endpoint");

    assert_eq!(response.status(), reqwest::StatusCode::NO_CONTENT);
}

#[tokio::test]
#[cfg(not(target_os = "windows"))]
async fn ciba_ping_transport_supports_tls13() {
    let response = post_to_single_version_server(SslVersion::TLS1_3)
        .await
        .expect("CIBA Ping must offer TLS 1.3 when the endpoint supports it");

    assert_eq!(response.status(), reqwest::StatusCode::NO_CONTENT);
}
