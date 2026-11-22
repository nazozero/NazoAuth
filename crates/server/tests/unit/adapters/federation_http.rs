use super::*;
use std::{
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

#[tokio::test]
async fn discovered_transport_rejects_normalized_private_literals_and_dns_answers() {
    let client = FederationClient::new().unwrap();
    for host in ["127.0.0.1", "2130706433", "[::1]", "[::ffff:127.0.0.1]"] {
        let request = http::Request::get(format!("https://{host}/token"))
            .body(Bytes::new())
            .unwrap();
        let error = client.send_discovered(request, 1024).await.unwrap_err();
        assert!(error.to_string().contains("blocked network"));
    }
    let error = PublicFederationDns
        .resolve("localhost".parse().unwrap())
        .await
        .err()
        .expect("loopback DNS answers must be rejected before connection");
    assert!(error.to_string().contains("blocked network"));
}

struct FixtureDns {
    address: SocketAddr,
    calls: Arc<AtomicUsize>,
}

impl Resolve for FixtureDns {
    fn resolve(&self, _: Name) -> Resolving {
        self.calls.fetch_add(1, Ordering::Relaxed);
        let address = self.address;
        Box::pin(async move { Ok(Box::new(std::iter::once(address)) as Addrs) })
    }
}

#[actix_web::test]
async fn discovered_transport_reuses_verified_tls_connection_without_following_redirects() {
    use actix_web::{App, HttpResponse, HttpServer, web};
    let key = rcgen::KeyPair::generate().unwrap();
    let certificate = rcgen::CertificateParams::new(vec!["issuer.example".to_owned()])
        .unwrap()
        .self_signed(&key)
        .unwrap();
    let root = reqwest::Certificate::from_der(certificate.der()).unwrap();
    let tls = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(
        vec![certificate.der().clone()],
        rustls::pki_types::PrivatePkcs8KeyDer::from(key.serialize_der()).into(),
    )
    .unwrap();
    let connections = Arc::new(AtomicUsize::new(0));
    let accepted = Arc::clone(&connections);
    let server = HttpServer::new(|| {
        App::new()
            .route(
                "/document",
                web::get().to(|| async { HttpResponse::Ok().body("{}") }),
            )
            .route(
                "/redirect",
                web::get().to(|| async {
                    HttpResponse::Found()
                        .insert_header(("location", "/document"))
                        .finish()
                }),
            )
    })
    .workers(1)
    .on_connect(move |_, _| {
        accepted.fetch_add(1, Ordering::Relaxed);
    })
    .bind_rustls_0_23(("127.0.0.1", 0), tls)
    .unwrap();
    let address = server.addrs()[0];
    let server = server.run();
    let handle = server.handle();
    actix_web::rt::spawn(server);

    let resolutions = Arc::new(AtomicUsize::new(0));
    let client = FederationClient {
        configured: federation_client().build().unwrap(),
        discovered: federation_client()
            .https_only(true)
            .http1_only()
            .tls_certs_only([root])
            .dns_resolver(FixtureDns {
                address,
                calls: Arc::clone(&resolutions),
            })
            .build()
            .unwrap(),
    };
    for _ in 0..2 {
        let request = http::Request::get(format!(
            "https://issuer.example:{}/document",
            address.port()
        ))
        .body(Bytes::new())
        .unwrap();
        let response = client.send_discovered(request, 1024).await.unwrap();
        assert_eq!(response.body().as_ref(), b"{}");
    }
    let redirect = http::Request::get(format!(
        "https://issuer.example:{}/redirect",
        address.port()
    ))
    .body(Bytes::new())
    .unwrap();
    let error = client.send_discovered(redirect, 1024).await.unwrap_err();
    handle.stop(false).await;
    assert!(error.to_string().contains("non-success status"));
    assert_eq!(connections.load(Ordering::Relaxed), 1);
    assert_eq!(resolutions.load(Ordering::Relaxed), 1);
}

struct PendingDns;

impl Resolve for PendingDns {
    fn resolve(&self, _: Name) -> Resolving {
        Box::pin(std::future::pending())
    }
}

#[tokio::test(start_paused = true)]
async fn discovered_transport_deadline_includes_dns_resolution() {
    let client = FederationClient {
        configured: federation_client().build().unwrap(),
        discovered: federation_client()
            .https_only(true)
            .dns_resolver(PendingDns)
            .build()
            .unwrap(),
    };
    let request = http::Request::get("https://issuer.example/token")
        .body(Bytes::new())
        .unwrap();
    let started = tokio::time::Instant::now();
    let error = client.send_discovered(request, 1024).await.unwrap_err();
    assert!(error.downcast_ref::<reqwest::Error>().unwrap().is_timeout());
    assert_eq!(started.elapsed(), DEADLINE);
}
