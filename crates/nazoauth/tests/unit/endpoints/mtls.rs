use super::*;
use crate::ConnectionFacts;
use bytes::Bytes;
use http::HeaderValue;
use std::sync::atomic::{AtomicUsize, Ordering};

fn certificate() -> (String, ClientCertificateFacts) {
    let params = rcgen::CertificateParams::new(vec!["client.example".to_owned()]).unwrap();
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let cert = params.self_signed(&key).unwrap();
    let der = cert.der().to_vec();
    let encoded = format!(":{}:", STANDARD.encode(&der));
    let identity = certificate_chain_identity(vec![der.into()].into()).unwrap();
    (encoded, identity)
}

fn request(peer: &str) -> Request {
    let mut request = http::Request::builder().body(Bytes::new()).unwrap();
    request.extensions_mut().insert(ConnectionFacts {
        peer_addr: Some(peer.parse().unwrap()),
        ..ConnectionFacts::default()
    });
    request
}

struct Verifier(AtomicUsize);
impl CertificateChainVerifier for Verifier {
    fn verify(&self, chain: &[CertificateDer<'static>]) -> bool {
        self.0.fetch_add(1, Ordering::Relaxed);
        assert_eq!(chain.len(), 1);
        true
    }
}

#[test]
fn forwarded_certificate_is_lazy_and_verified_once() {
    let (encoded, identity) = certificate();
    let verifier = Arc::new(Verifier(AtomicUsize::new(0)));
    let source = Arc::new(MtlsCertificateSource::new(
        MtlsCertificateSourceMode::Rfc9440,
        &[IpCidr::parse("192.0.2.0/24").unwrap()],
        Some(verifier.clone()),
    ));
    let mut request = request("192.0.2.10:443");
    request
        .headers_mut()
        .insert("client-cert", HeaderValue::from_str(&encoded).unwrap());
    source.prepare_request(&mut request);
    assert_eq!(verifier.0.load(Ordering::Relaxed), 0);
    assert!(
        request
            .extensions()
            .get::<ForwardedClientCertificate>()
            .unwrap()
            .0
            .get()
            .is_none()
    );
    let parsed = request_mtls_client_certificate(&request).unwrap();
    assert_eq!(parsed.thumbprint, identity.thumbprint);
    assert!(parsed.deployment_trusted_chain);
    assert_eq!(request_mtls_thumbprint(&request), identity.thumbprint);
    assert_eq!(verifier.0.load(Ordering::Relaxed), 1);
    let borrowed =
        with_request_mtls_client_certificate(&request, |certificate| certificate.unwrap());
    let cached = request
        .extensions()
        .get::<ForwardedClientCertificate>()
        .unwrap()
        .0
        .get()
        .unwrap()
        .as_ref()
        .unwrap();
    assert!(std::ptr::eq(borrowed, cached));
    let token_facts = crate::endpoints::token::dispatch::token_request_facts(&request);
    assert!(std::ptr::eq(token_facts.certificate.unwrap(), cached));
    assert_eq!(verifier.0.load(Ordering::Relaxed), 1);
}

#[test]
fn untrusted_peer_cannot_supply_certificate_facts() {
    let (encoded, _) = certificate();
    let verifier = Arc::new(Verifier(AtomicUsize::new(0)));
    let source = Arc::new(MtlsCertificateSource::new(
        MtlsCertificateSourceMode::Rfc9440,
        &[IpCidr::parse("192.0.2.0/24").unwrap()],
        Some(verifier.clone()),
    ));
    let mut request = request("198.51.100.10:443");
    request
        .headers_mut()
        .insert("client-cert", HeaderValue::from_str(&encoded).unwrap());
    request
        .headers_mut()
        .insert("forwarded", HeaderValue::from_static("for=192.0.2.10"));
    source.prepare_request(&mut request);
    assert!(request_mtls_client_certificate(&request).is_none());
    assert_eq!(verifier.0.load(Ordering::Relaxed), 0);
}

#[test]
fn duplicate_and_malformed_certificate_headers_are_rejected() {
    let (encoded, _) = certificate();
    let mut headers = HeaderMap::new();
    headers.insert("client-cert", HeaderValue::from_str(&encoded).unwrap());
    assert!(request_mtls_client_certificate_from_rfc9440(&headers).is_some());
    headers.append("client-cert", HeaderValue::from_static(":AA==:"));
    assert!(request_mtls_client_certificate_from_rfc9440(&headers).is_none());
    for value in ["::", ":AA AA:", "AA==", ":AA=="] {
        let mut headers = HeaderMap::new();
        headers.insert("client-cert", HeaderValue::from_str(value).unwrap());
        assert!(request_mtls_client_certificate_from_rfc9440(&headers).is_none());
    }
    let mut headers = HeaderMap::new();
    headers.insert("client-cert", HeaderValue::from_str(&encoded).unwrap());
    headers.append(
        "client-cert-chain",
        HeaderValue::from_str(&encoded).unwrap(),
    );
    headers.append(
        "client-cert-chain",
        HeaderValue::from_str(&encoded).unwrap(),
    );
    assert!(request_mtls_client_certificate_from_rfc9440(&headers).is_none());
}

#[test]
fn direct_tls_shares_certificate_bytes_and_ignores_forwarding_headers() {
    let (encoded, identity) = certificate();
    let chain = identity.certificate_chain_der.clone();
    let source = Arc::new(MtlsCertificateSource::new(
        MtlsCertificateSourceMode::DirectTls,
        &[],
        None,
    ));
    let mut request = request("192.0.2.10:443");
    request
        .extensions_mut()
        .get_mut::<ConnectionFacts>()
        .unwrap()
        .client_certificate = Some(Arc::new(identity));
    request
        .headers_mut()
        .insert("client-cert", HeaderValue::from_str(&encoded).unwrap());
    source.prepare_request(&mut request);
    let borrowed =
        with_request_mtls_client_certificate(&request, |certificate| certificate.unwrap());
    let connection_identity = request
        .extensions()
        .get::<ConnectionFacts>()
        .unwrap()
        .client_certificate
        .as_deref()
        .unwrap();
    assert!(std::ptr::eq(borrowed, connection_identity));
    let token_facts = crate::endpoints::token::dispatch::token_request_facts(&request);
    assert!(std::ptr::eq(
        token_facts.certificate.unwrap(),
        connection_identity
    ));
    let parsed = request_mtls_client_certificate(&request).unwrap();
    assert!(Arc::ptr_eq(&chain, &parsed.certificate_chain_der));
    assert!(!parsed.deployment_trusted_chain);
    assert!(
        request
            .extensions()
            .get::<ForwardedClientCertificate>()
            .is_none()
    );
}

#[test]
fn disabled_mode_and_nonstandard_headers_do_not_assert_tls_identity() {
    let (_, identity) = certificate();
    let source = Arc::new(MtlsCertificateSource::new(
        MtlsCertificateSourceMode::Disabled,
        &[],
        None,
    ));
    let mut request = request("192.0.2.10:443");
    request
        .extensions_mut()
        .get_mut::<ConnectionFacts>()
        .unwrap()
        .client_certificate = Some(Arc::new(identity));
    request
        .headers_mut()
        .insert("x-ssl-client-verify", HeaderValue::from_static("SUCCESS"));
    source.prepare_request(&mut request);
    assert!(request_mtls_client_certificate(&request).is_none());
}
