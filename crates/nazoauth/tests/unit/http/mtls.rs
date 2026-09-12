use super::*;
use actix_web::{
    http::header::{self, HeaderValue},
    test::TestRequest,
};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use nazo_oauth_server::security::mtls::certificate_chain_trusted;
use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair, PKCS_ECDSA_P256_SHA256};
use sha2::{Digest, Sha256};
struct TestCertificate {
    x5c: String,
    thumbprint: String,
}

#[test]
fn rfc9440_client_cert_uses_single_der_byte_sequence() {
    let certificate = test_certificate("rfc9440-client", -60, 60);
    let headers = {
        let mut headers = header::HeaderMap::new();
        headers.insert(
            header::HeaderName::from_static("client-cert"),
            HeaderValue::from_str(&format!(":{}:", certificate.x5c)).unwrap(),
        );
        headers
    };
    let parsed =
        request_mtls_client_certificate_from_rfc9440(&headers).expect("valid RFC 9440 certificate");
    assert_eq!(
        parsed.thumbprint.as_deref(),
        Some(certificate.thumbprint.as_str())
    );

    let mut duplicate = headers;
    duplicate.append(
        header::HeaderName::from_static("client-cert"),
        HeaderValue::from_static(":AA==:"),
    );
    assert!(request_mtls_client_certificate_from_rfc9440(&duplicate).is_none());

    for malformed in ["::", ":AA AA:", "AA==", ":AA=="] {
        let mut headers = header::HeaderMap::new();
        headers.insert(
            header::HeaderName::from_static("client-cert"),
            HeaderValue::from_str(malformed).unwrap(),
        );
        assert!(request_mtls_client_certificate_from_rfc9440(&headers).is_none());
    }
}

#[test]
fn mtls_certificate_source_requires_explicit_supported_mode() {
    assert_eq!(
        MtlsCertificateSourceMode::from_config(None).unwrap(),
        MtlsCertificateSourceMode::Disabled
    );
    assert_eq!(
        MtlsCertificateSourceMode::from_config(Some("rfc9440")).unwrap(),
        MtlsCertificateSourceMode::Rfc9440
    );
    assert_eq!(
        MtlsCertificateSourceMode::from_config(Some("direct-tls")).unwrap(),
        MtlsCertificateSourceMode::DirectTls
    );
    assert_eq!(
        MtlsCertificateSourceMode::from_config(Some("disabled")).unwrap(),
        MtlsCertificateSourceMode::Disabled
    );
    assert!(MtlsCertificateSourceMode::from_config(Some("legacy-verified-headers")).is_err());
    assert!(MtlsCertificateSourceMode::from_config(Some("direct")).is_err());
}

#[test]
fn disabled_certificate_source_cannot_fall_back_to_forwarded_headers() {
    let disabled = TestRequest::default()
        .app_data(Data::new(MtlsCertificateSource::new(
            MtlsCertificateSourceMode::Disabled,
        )))
        .insert_header(("x-ssl-client-verify", "SUCCESS"))
        .to_http_request();
    assert!(request_mtls_client_certificate_from_configured_source(&disabled, &[]).is_none());
}

#[test]
fn rfc9440_source_accepts_only_a_trusted_peer() {
    let certificate = test_certificate("rfc9440-request", -60, 3600);
    let source = Data::new(MtlsCertificateSource::new(
        MtlsCertificateSourceMode::Rfc9440,
    ));
    let trusted_proxy = [IpCidr::parse("192.0.2.0/24").expect("trusted proxy CIDR")];
    let header_value = format!(":{}:", certificate.x5c);

    let trusted = TestRequest::default()
        .app_data(source.clone())
        .peer_addr("192.0.2.10:443".parse().expect("trusted peer address"))
        .insert_header(("client-cert", header_value.as_str()))
        .to_http_request();
    assert_eq!(
        request_mtls_client_certificate_from_configured_source(&trusted, &trusted_proxy)
            .and_then(|certificate| certificate.thumbprint)
            .as_deref(),
        Some(certificate.thumbprint.as_str())
    );
    assert!(
        trusted
            .extensions()
            .get::<ForwardedClientCertificate>()
            .is_some()
    );
    assert_eq!(
        request_mtls_thumbprint(&trusted, &trusted_proxy).as_deref(),
        Some(certificate.thumbprint.as_str())
    );
    assert!(
        request_mtls_client_certificate(&trusted, &[]).is_none(),
        "cached facts must not bypass the caller's trusted proxy policy"
    );

    let untrusted = TestRequest::default()
        .app_data(source)
        .peer_addr("198.51.100.10:443".parse().expect("untrusted peer address"))
        .insert_header(("client-cert", header_value.as_str()))
        .to_http_request();
    assert!(
        request_mtls_client_certificate_from_configured_source(&untrusted, &trusted_proxy)
            .is_none()
    );
}

#[test]
fn rfc9440_source_ignores_removed_nonstandard_headers() {
    let request = TestRequest::default()
        .app_data(Data::new(MtlsCertificateSource::new(
            MtlsCertificateSourceMode::Rfc9440,
        )))
        .peer_addr("192.0.2.10:443".parse().expect("trusted peer address"))
        .insert_header(("x-ssl-client-verify", "SUCCESS"))
        .insert_header((
            "x-forwarded-tls-client-cert-sha256",
            "ABEiM0RVZneImaq7zN3u_wARIjNEVWZ3iJmqu8zd7v8",
        ))
        .to_http_request();
    let trusted_proxy = [IpCidr::parse("192.0.2.0/24").expect("trusted proxy CIDR")];

    assert!(
        request_mtls_client_certificate_from_configured_source(&request, &trusted_proxy).is_none()
    );
}

fn test_certificate(
    common_name: &str,
    not_before_offset: i64,
    not_after_offset: i64,
) -> TestCertificate {
    let mut params = CertificateParams::default();
    params.distinguished_name = DistinguishedName::new();
    params
        .distinguished_name
        .push(DnType::CommonName, common_name);
    let now = time::OffsetDateTime::now_utc();
    params.not_before = now + time::Duration::seconds(not_before_offset);
    params.not_after = now + time::Duration::seconds(not_after_offset);
    finish_test_certificate(params)
}

fn finish_test_certificate(params: CertificateParams) -> TestCertificate {
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("test P-256 key");
    let der = params
        .self_signed(&key)
        .expect("test certificate")
        .der()
        .to_vec();
    TestCertificate {
        x5c: STANDARD.encode(&der),
        thumbprint: URL_SAFE_NO_PAD.encode(Sha256::digest(&der)),
    }
}

#[test]
fn pki_certificate_requires_the_selected_trust_anchor_and_valid_chain() {
    use rcgen::{
        BasicConstraints, CertifiedIssuer, ExtendedKeyUsagePurpose, IsCa, KeyUsagePurpose,
    };
    let mut root_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    root_params.is_ca = IsCa::Ca(BasicConstraints::Constrained(1));
    root_params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
    let root =
        CertifiedIssuer::self_signed(root_params.clone(), KeyPair::generate().unwrap()).unwrap();
    let other_root =
        CertifiedIssuer::self_signed(root_params, KeyPair::generate().unwrap()).unwrap();
    let mut intermediate_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    intermediate_params
        .distinguished_name
        .push(DnType::CommonName, "Client intermediate");
    intermediate_params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    intermediate_params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
    let intermediate =
        CertifiedIssuer::signed_by(intermediate_params, KeyPair::generate().unwrap(), &root)
            .unwrap();
    let mut leaf_params = CertificateParams::new(vec!["client.example".to_owned()]).unwrap();
    leaf_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    leaf_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    let leaf = leaf_params
        .signed_by(&KeyPair::generate().unwrap(), &intermediate)
        .unwrap();
    let mut headers = header::HeaderMap::new();
    headers.insert(
        header::HeaderName::from_static("client-cert"),
        HeaderValue::from_str(&format!(":{}:", STANDARD.encode(leaf.der()))).unwrap(),
    );
    headers.insert(
        header::HeaderName::from_static("client-cert-chain"),
        HeaderValue::from_str(&format!(":{}:", STANDARD.encode(intermediate.der()))).unwrap(),
    );
    let certificate = request_mtls_client_certificate_from_rfc9440(&headers).unwrap();
    assert!(
        !certificate.deployment_trusted_chain,
        "forwarding does not attest PKI verification"
    );
    assert!(certificate_chain_trusted(&certificate, &root.pem()));
    assert!(!certificate_chain_trusted(&certificate, &other_root.pem()));
    let mut roots = rustls::RootCertStore::empty();
    roots.add(root.der().clone()).unwrap();
    let verifier: std::sync::Arc<dyn rustls::server::danger::ClientCertVerifier> =
        rustls::server::WebPkiClientVerifier::builder_with_provider(
            std::sync::Arc::new(roots),
            std::sync::Arc::new(rustls::crypto::aws_lc_rs::default_provider()),
        )
        .build()
        .unwrap();
    let proxy_request = |peer: &str| {
        actix_web::test::TestRequest::default()
            .app_data(Data::new(MtlsCertificateSource::new(
                MtlsCertificateSourceMode::Rfc9440,
            )))
            .app_data(Data::from(verifier.clone()))
            .peer_addr(peer.parse().unwrap())
            .insert_header(("client-cert", headers.get("client-cert").unwrap().clone()))
            .insert_header((
                "client-cert-chain",
                headers.get("client-cert-chain").unwrap().clone(),
            ))
            .to_http_request()
    };
    let trusted_peers = [IpCidr::parse("127.0.0.1/32").unwrap()];
    assert!(
        request_mtls_client_certificate(&proxy_request("127.0.0.1:1234"), &trusted_peers)
            .unwrap()
            .deployment_trusted_chain
    );
    assert!(
        request_mtls_client_certificate(&proxy_request("192.0.2.1:1234"), &trusted_peers).is_none(),
        "a valid chain does not authorize caller-supplied proxy headers"
    );
    assert!(
        !certificate_chain_trusted(&certificate, ""),
        "revoked trust cannot be cached in certificate facts"
    );
    let mut missing_intermediate = certificate.clone();
    missing_intermediate.certificate_chain_der.truncate(1);
    assert!(!certificate_chain_trusted(
        &missing_intermediate,
        &root.pem()
    ));
    headers.insert(
        header::HeaderName::from_static("client-cert-chain"),
        HeaderValue::from_static(":not base64:"),
    );
    assert!(request_mtls_client_certificate_from_rfc9440(&headers).is_none());
}
