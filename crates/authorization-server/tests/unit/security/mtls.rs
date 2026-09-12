use super::*;
use nazo_identity::{DEFAULT_ORGANIZATION_ID, DEFAULT_REALM_ID, DEFAULT_TENANT_ID};
use rcgen::{
    CertificateParams, DistinguishedName, DnType, KeyPair, PKCS_ECDSA_P256_SHA256, SanType,
};
use serde_json::json;
use uuid::Uuid;
struct TestCertificate {
    der: Vec<u8>,
    x5c: String,
    thumbprint: String,
}

fn client() -> ClientRow {
    ClientRow {
        id: Uuid::now_v7(),
        tenant_id: DEFAULT_TENANT_ID,
        realm_id: DEFAULT_REALM_ID,
        organization_id: DEFAULT_ORGANIZATION_ID,
        require_mtls_bound_tokens: false,
        is_active: true,
        registration: nazo_auth::ValidatedClientRegistration {
            client_id: "client-1".to_owned(),
            client_name: "Client".to_owned(),
            client_type: "confidential".to_owned(),
            redirect_uris: vec!["https://client.example/callback".to_owned()],
            scopes: vec!["openid".to_owned()],
            allowed_audiences: vec!["resource://default".to_owned()],
            grant_types: vec!["authorization_code".to_owned()],
            token_endpoint_auth_method: "tls_client_auth".to_owned(),
            require_dpop_bound_tokens: false,
            tls_client_auth_subject_dn: None,
            tls_client_auth_cert_sha256: None,
            tls_client_auth_san_dns: Vec::new(),
            tls_client_auth_san_uri: Vec::new(),
            tls_client_auth_san_ip: Vec::new(),
            tls_client_auth_san_email: Vec::new(),
            allow_client_assertion_audience_array: false,
            allow_client_assertion_endpoint_audience: false,
            require_par_request_object: false,
            jwks_uri: None,
            jwks: None,
            request_uris: Vec::new(),
            initiate_login_uri: None,
            presentation: nazo_auth::ClientPresentationMetadata::default(),
            id_token_signed_response_alg: None,
            id_token_encrypted_response_alg: None,
            id_token_encrypted_response_enc: None,
            request_object_signing_alg: None,
            request_object_encryption_alg: None,
            request_object_encryption_enc: None,
            token_endpoint_auth_signing_alg: None,
            introspection_signed_response_alg: None,
            introspection_encrypted_response_alg: None,
            introspection_encrypted_response_enc: None,
            userinfo_signed_response_alg: None,
            userinfo_encrypted_response_alg: None,
            userinfo_encrypted_response_enc: None,
            authorization_signed_response_alg: None,
            authorization_encrypted_response_alg: None,
            authorization_encrypted_response_enc: None,
            post_logout_redirect_uris: Vec::new(),
            backchannel_logout_uri: None,
            backchannel_logout_session_required: true,
            backchannel_token_delivery_mode: "poll".to_owned(),
            backchannel_client_notification_endpoint: None,
            backchannel_authentication_request_signing_alg: None,
            backchannel_user_code_parameter: false,
            frontchannel_logout_uri: None,
            frontchannel_logout_session_required: true,
            subject_type: "public".to_owned(),
            sector_identifier_uri: None,
            sector_identifier_host: None,
            security_policy: nazo_auth::ClientSecurityPolicy::default(),
        },
    }
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

fn test_certificate_with_sans() -> TestCertificate {
    let mut params = current_test_certificate_params();
    params
        .distinguished_name
        .push(DnType::CommonName, "client, one");
    params
        .distinguished_name
        .push(DnType::OrganizationName, "Example + Org");
    params.subject_alt_names = vec![
        SanType::DnsName("client.example".try_into().unwrap()),
        SanType::DnsName("api.client.example".try_into().unwrap()),
        SanType::URI("urn:client:one".try_into().unwrap()),
        SanType::Rfc822Name("client@example.com".try_into().unwrap()),
        SanType::IpAddress("192.0.2.44".parse().unwrap()),
        SanType::IpAddress("2001:db8::44".parse().unwrap()),
    ];
    finish_test_certificate(params)
}

fn test_certificate_with_full_subject() -> TestCertificate {
    let mut params = current_test_certificate_params();
    params.distinguished_name.push(DnType::CountryName, "US");
    params
        .distinguished_name
        .push(DnType::StateOrProvinceName, "CA");
    params
        .distinguished_name
        .push(DnType::LocalityName, "San Francisco");
    params
        .distinguished_name
        .push(DnType::OrganizationalUnitName, "Security");
    params.distinguished_name.push(
        DnType::CustomDnType(vec![1, 2, 840, 113549, 1, 9, 1]),
        "client@example.com",
    );
    finish_test_certificate(params)
}

fn current_test_certificate_params() -> CertificateParams {
    let mut params = CertificateParams::default();
    params.distinguished_name = DistinguishedName::new();
    let now = time::OffsetDateTime::now_utc();
    params.not_before = now - time::Duration::minutes(1);
    params.not_after = now + time::Duration::hours(1);
    params
}

fn finish_test_certificate(params: CertificateParams) -> TestCertificate {
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("test P-256 key");
    let der = params
        .self_signed(&key)
        .expect("test certificate")
        .der()
        .to_vec();
    TestCertificate {
        der: der.clone(),
        x5c: STANDARD.encode(&der),
        thumbprint: URL_SAFE_NO_PAD.encode(Sha256::digest(&der)),
    }
}

#[test]
fn normalizes_colon_hex_sha256_to_x5t_s256() {
    let raw = "00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff";

    assert_eq!(
        normalize_sha256_thumbprint(raw).as_deref(),
        Some("ABEiM0RVZneImaq7zN3u_wARIjNEVWZ3iJmqu8zd7v8")
    );
}

#[test]
fn rejects_invalid_sha256_thumbprints() {
    assert!(normalize_sha256_thumbprint("not-a-thumbprint").is_none());
    assert!(normalize_sha256_thumbprint(&"a".repeat(63)).is_none());
    assert!(normalize_sha256_thumbprint(&"!".repeat(43)).is_none());
    assert!(normalize_sha256_thumbprint(&URL_SAFE_NO_PAD.encode([0u8; 31])).is_none());
}

#[test]
fn certificate_der_identity_rejects_trailing_data() {
    let certificate = test_certificate("client-trailing-data", -60, 3600);
    let mut der = STANDARD.decode(certificate.x5c).unwrap();
    der.extend_from_slice(b"trailing-data");

    assert!(certificate_der_identity(&der).is_none());
}

#[test]
fn certificate_der_identity_extracts_san_values_and_escapes_subject_dn() {
    let certificate = test_certificate_with_sans();
    let parsed = certificate_der_identity(&certificate.der).expect("certificate should parse");

    assert_eq!(
        parsed.subject_dn.as_deref(),
        Some(r"CN=client\, one,O=Example \+ Org")
    );
    assert_eq!(
        parsed.san_dns,
        vec!["api.client.example".to_owned(), "client.example".to_owned()]
    );
    assert_eq!(parsed.san_uri, vec!["urn:client:one".to_owned()]);
    assert_eq!(parsed.san_email, vec!["client@example.com".to_owned()]);
    assert_eq!(
        parsed.san_ip,
        vec!["192.0.2.44".to_owned(), "2001:db8::44".to_owned()]
    );
}

#[test]
fn certificate_der_identity_extracts_full_subject_dn_names() {
    let certificate = test_certificate_with_full_subject();
    let parsed = certificate_der_identity(&certificate.der).expect("certificate should parse");

    assert_eq!(
        parsed.subject_dn.as_deref(),
        Some("C=US,ST=CA,L=San Francisco,OU=Security,emailAddress=client@example.com")
    );
}

#[test]
fn certificate_der_identity_rejects_future_and_expired_certificates() {
    let future = test_certificate("client-future", 3600, 7200);
    assert!(certificate_der_identity(&future.der).is_none());

    let expired = test_certificate("client-expired", -7200, -3600);
    assert!(certificate_der_identity(&expired.der).is_none());
}

#[test]
fn client_certificate_matches_registered_subject_dn() {
    let mut client = client();
    client.tls_client_auth_subject_dn = Some("CN=client-1,O=Example".to_owned());
    let certificate = ClientCertificateFacts {
        subject_dn: Some("CN=CLIENT-1,O=example".to_owned()),
        ..ClientCertificateFacts::default()
    };

    assert!(client_mtls_certificate_matches(&client, &certificate));
}

#[test]
fn administrator_thumbprint_pin_can_only_narrow_registered_subject_match() {
    let mut client = client();
    client.tls_client_auth_subject_dn = Some("CN=client-1,O=Example".to_owned());
    client.tls_client_auth_cert_sha256 =
        Some("00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff".to_owned());
    let certificate = ClientCertificateFacts {
        thumbprint: Some("ABEiM0RVZneImaq7zN3u_wARIjNEVWZ3iJmqu8zd7v8".to_owned()),
        subject_dn: Some("CN=client-1,O=Example".to_owned()),
        ..ClientCertificateFacts::default()
    };

    assert!(client_mtls_certificate_matches(&client, &certificate));

    let wrong_subject = ClientCertificateFacts {
        thumbprint: certificate.thumbprint.clone(),
        subject_dn: Some("CN=other,O=Example".to_owned()),
        ..ClientCertificateFacts::default()
    };
    assert!(!client_mtls_certificate_matches(&client, &wrong_subject));

    let mut pin_without_standard_subject = client;
    pin_without_standard_subject.tls_client_auth_subject_dn = None;
    assert!(!client_mtls_certificate_matches(
        &pin_without_standard_subject,
        &certificate
    ));
}

#[test]
fn client_certificate_matches_registered_san_dns() {
    let mut client = client();
    client.tls_client_auth_san_dns = vec!["client.example".to_owned()];
    let certificate = ClientCertificateFacts {
        san_dns: vec!["api.client.example".to_owned(), "CLIENT.EXAMPLE".to_owned()],
        ..ClientCertificateFacts::default()
    };

    assert!(client_mtls_certificate_matches(&client, &certificate));
}

#[test]
fn client_certificate_matches_registered_san_uri_ip_and_email() {
    let certificate = ClientCertificateFacts {
        san_uri: vec!["urn:client:one".to_owned()],
        san_ip: vec!["2001:db8::2c".to_owned()],
        san_email: vec!["client@EXAMPLE.COM".to_owned()],
        ..ClientCertificateFacts::default()
    };

    let mut uri_client = client();
    uri_client.tls_client_auth_san_uri = vec!["urn:client:one".to_owned()];
    assert!(client_mtls_certificate_matches(&uri_client, &certificate));

    let mut ip_client = client();
    ip_client.tls_client_auth_san_ip = vec!["2001:0db8:0000:0000:0000:0000:0000:002c".to_owned()];
    assert!(client_mtls_certificate_matches(&ip_client, &certificate));

    let mut email_client = client();
    email_client.tls_client_auth_san_email = vec!["client@example.com".to_owned()];
    assert!(client_mtls_certificate_matches(&email_client, &certificate));
}

#[test]
fn client_certificate_rejects_unregistered_subject_and_san() {
    let mut client = client();
    client.tls_client_auth_subject_dn = Some("CN=client-1,O=Example".to_owned());
    client.tls_client_auth_san_uri = vec!["urn:client:1".to_owned()];
    let certificate = ClientCertificateFacts {
        subject_dn: Some("CN=other,O=Example".to_owned()),
        san_uri: vec!["urn:client:2".to_owned()],
        ..ClientCertificateFacts::default()
    };

    assert!(!client_mtls_certificate_matches(&client, &certificate));
}

#[test]
fn client_certificate_rejects_legacy_rows_with_multiple_rfc8705_selectors() {
    let mut client = client();
    client.tls_client_auth_subject_dn = Some("CN=client-1,O=Example".to_owned());
    client.tls_client_auth_san_dns = vec!["client.example".to_owned()];
    let certificate = ClientCertificateFacts {
        subject_dn: Some("CN=client-1,O=Example".to_owned()),
        san_dns: vec!["client.example".to_owned()],
        ..ClientCertificateFacts::default()
    };

    assert!(!client_mtls_certificate_matches(&client, &certificate));
}

#[test]
fn self_signed_client_certificate_rejects_subject_dn_and_thumbprint_shortcuts() {
    let mut client = client();
    client.token_endpoint_auth_method = "self_signed_tls_client_auth".to_owned();
    client.tls_client_auth_subject_dn = Some("CN=client-1,O=Example".to_owned());
    let certificate = ClientCertificateFacts {
        subject_dn: Some("CN=client-1,O=Example".to_owned()),
        ..ClientCertificateFacts::default()
    };

    assert!(!client_mtls_certificate_matches(&client, &certificate));

    client.tls_client_auth_cert_sha256 =
        Some("00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff".to_owned());
    let certificate = ClientCertificateFacts {
        thumbprint: Some("ABEiM0RVZneImaq7zN3u_wARIjNEVWZ3iJmqu8zd7v8".to_owned()),
        subject_dn: Some("CN=other,O=Example".to_owned()),
        ..ClientCertificateFacts::default()
    };

    assert!(!client_mtls_certificate_matches(&client, &certificate));
}

#[test]
fn self_signed_client_certificate_matches_registered_x5c() {
    let registered = test_certificate("client-1", -60, 3600);
    let mut client = client();
    client.token_endpoint_auth_method = "self_signed_tls_client_auth".to_owned();
    client.jwks = Some(json!({"keys": [{"kid": "cert-1", "x5c": [registered.x5c]}]}));
    let certificate = ClientCertificateFacts {
        thumbprint: Some(registered.thumbprint),
        verified_certificate_expiry: true,
        ..ClientCertificateFacts::default()
    };

    assert!(client_mtls_certificate_matches(&client, &certificate));
}

#[test]
fn self_signed_client_certificate_ignores_non_leaf_x5c_entries() {
    let leaf = test_certificate("client-leaf", -60, 3600);
    let chain_member = test_certificate("client-chain-member", -60, 3600);
    let mut client = client();
    client.token_endpoint_auth_method = "self_signed_tls_client_auth".to_owned();
    client.jwks = Some(json!({
        "keys": [{
            "kid": "cert-chain",
            "x5c": [chain_member.x5c, leaf.x5c]
        }]
    }));
    let certificate = ClientCertificateFacts {
        thumbprint: Some(leaf.thumbprint),
        verified_certificate_expiry: true,
        ..ClientCertificateFacts::default()
    };

    assert!(!client_mtls_certificate_matches(&client, &certificate));
}

#[test]
fn self_signed_client_certificate_rotation_accepts_only_registered_x5c_set() {
    let old = test_certificate("client-old", -60, 3600);
    let new = test_certificate("client-new", -60, 3600);
    let mut client = client();
    client.token_endpoint_auth_method = "self_signed_tls_client_auth".to_owned();
    client.jwks = Some(json!({
        "keys": [
            {"kid": "old", "x5c": [old.x5c.clone()]},
            {"kid": "new", "x5c": [new.x5c.clone()]}
        ]
    }));
    let old_certificate = ClientCertificateFacts {
        thumbprint: Some(old.thumbprint.clone()),
        verified_certificate_expiry: true,
        ..ClientCertificateFacts::default()
    };
    let new_certificate = ClientCertificateFacts {
        thumbprint: Some(new.thumbprint.clone()),
        verified_certificate_expiry: true,
        ..ClientCertificateFacts::default()
    };
    assert!(client_mtls_certificate_matches(&client, &old_certificate));
    assert!(client_mtls_certificate_matches(&client, &new_certificate));

    client.jwks = Some(json!({"keys": [{"kid": "new", "x5c": [new.x5c]}]}));
    assert!(!client_mtls_certificate_matches(&client, &old_certificate));
    assert!(client_mtls_certificate_matches(&client, &new_certificate));
}

#[test]
fn self_signed_client_certificate_rejects_expired_x5c() {
    let expired = test_certificate("client-expired", -7200, -3600);
    let mut client = client();
    client.token_endpoint_auth_method = "self_signed_tls_client_auth".to_owned();
    client.jwks = Some(json!({"keys": [{"kid": "expired", "x5c": [expired.x5c]}]}));
    let certificate = ClientCertificateFacts {
        thumbprint: Some(expired.thumbprint),
        verified_certificate_expiry: true,
        ..ClientCertificateFacts::default()
    };

    assert!(!client_mtls_certificate_matches(&client, &certificate));
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
    let mut certificate = certificate_der_identity(leaf.der()).unwrap();
    certificate
        .certificate_chain_der
        .push(intermediate.der().to_vec());
    assert!(certificate_chain_trusted(&certificate, &root.pem()));
    assert!(!certificate_chain_trusted(&certificate, &other_root.pem()));
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
}

#[test]
fn mtls_ipaddress_parser_rejects_invalid_san_lengths() {
    assert!(ipaddress_to_string(&[192, 0, 2]).is_none());
}
