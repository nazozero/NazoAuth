use super::*;
use openssl::asn1::Asn1Time;
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::{PKey, Private};
use openssl::rsa::Rsa;
use openssl::x509::{X509Builder, X509Name};

fn client_with_redirects(redirect_uris: &[&str]) -> ClientRow {
    ClientRow {
        id: Uuid::now_v7(),
        tenant_id: DEFAULT_TENANT_ID,
        realm_id: DEFAULT_REALM_ID,
        organization_id: DEFAULT_ORGANIZATION_ID,
        client_id: "client-1".to_owned(),
        client_name: "Client".to_owned(),
        client_type: "public".to_owned(),
        client_secret_argon2_hash: None,
        redirect_uris: json!(redirect_uris),
        scopes: json!(["openid"]),
        allowed_audiences: json!(["resource://default"]),
        grant_types: json!(["authorization_code"]),
        token_endpoint_auth_method: "none".to_owned(),
        require_dpop_bound_tokens: false,
        require_mtls_bound_tokens: false,
        tls_client_auth_subject_dn: None,
        tls_client_auth_cert_sha256: None,
        tls_client_auth_san_dns: json!([]),
        tls_client_auth_san_uri: json!([]),
        tls_client_auth_san_ip: json!([]),
        tls_client_auth_san_email: json!([]),
        allow_client_assertion_audience_array: false,
        allow_client_assertion_endpoint_audience: false,
        require_par_request_object: false,
        allow_authorization_code_without_pkce: false,
        is_active: true,
        jwks: None,
        post_logout_redirect_uris: json!([]),
        backchannel_logout_uri: None,
        backchannel_logout_session_required: true,
    }
}

#[allow(clippy::too_many_arguments)]
fn metadata<'a>(
    client_type: &'a str,
    redirect_uris: &'a [String],
    scopes: &'a [String],
    allowed_audiences: &'a [String],
    grant_types: &'a [String],
    token_endpoint_auth_method: &'a str,
    jwks: Option<&'a Value>,
    mtls_binding: Option<&'a ClientMtlsMetadata>,
) -> ClientMetadata<'a> {
    ClientMetadata {
        client_type,
        redirect_uris,
        post_logout_redirect_uris: &[],
        scopes,
        allowed_audiences,
        grant_types,
        token_endpoint_auth_method,
        backchannel_logout_uri: None,
        jwks,
        mtls_binding,
    }
}

fn test_x5c(common_name: &str, not_before_offset: i64, not_after_offset: i64) -> String {
    let key: PKey<Private> =
        PKey::from_rsa(Rsa::generate(2048).expect("test rsa key")).expect("test pkey");
    let mut name = X509Name::builder().expect("x509 name builder");
    name.append_entry_by_nid(Nid::COMMONNAME, common_name)
        .expect("test common name");
    let name = name.build();
    let mut builder = X509Builder::new().expect("x509 builder");
    builder.set_version(2).expect("x509 version");
    builder.set_subject_name(&name).expect("x509 subject");
    builder.set_issuer_name(&name).expect("x509 issuer");
    builder.set_pubkey(&key).expect("x509 pubkey");
    let now = Utc::now().timestamp();
    let not_before = Asn1Time::from_unix(now + not_before_offset).expect("x509 not_before");
    let not_after = Asn1Time::from_unix(now + not_after_offset).expect("x509 not_after");
    builder
        .set_not_before(&not_before)
        .expect("set x509 not_before");
    builder
        .set_not_after(&not_after)
        .expect("set x509 not_after");
    builder
        .sign(&key, MessageDigest::sha256())
        .expect("sign test cert");
    STANDARD.encode(builder.build().to_der().expect("cert der"))
}

#[test]
fn redirect_uri_uses_single_registered_uri_when_omitted() {
    let client = client_with_redirects(&["https://client.example/callback"]);

    assert_eq!(
        registered_redirect_uri(&client, None).unwrap(),
        "https://client.example/callback"
    );
}

#[test]
fn redirect_uri_requires_exact_match() {
    let client = client_with_redirects(&["https://client.example/callback"]);

    assert_eq!(
        registered_redirect_uri(&client, Some("https://client.example/callback/")),
        Err(RedirectUriError::Invalid)
    );
}

#[test]
fn public_loopback_redirect_uri_allows_runtime_port() {
    let client = client_with_redirects(&["http://127.0.0.1:3000/callback"]);

    assert_eq!(
        registered_redirect_uri(&client, Some("http://127.0.0.1:49152/callback")).unwrap(),
        "http://127.0.0.1:49152/callback"
    );
}

#[test]
fn pkce_values_follow_rfc7636_length_and_charset() {
    assert!(is_valid_pkce_value(
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ"
    ));
    assert!(!is_valid_pkce_value("short"));
    assert!(!is_valid_pkce_value(
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNO!"
    ));
}

#[test]
fn client_metadata_rejects_removed_or_unsafe_grants() {
    let result = validate_client_metadata(metadata(
        "public",
        &["https://client.example/callback".to_owned()],
        &["openid".to_owned()],
        &["resource://default".to_owned()],
        &["password".to_owned()],
        "none",
        None,
        None,
    ));

    assert!(result.is_err());
}

#[test]
fn client_metadata_rejects_non_loopback_http_redirect_uri() {
    let result = validate_client_metadata(metadata(
        "public",
        &["http://client.example/callback".to_owned()],
        &["openid".to_owned()],
        &["resource://default".to_owned()],
        &["authorization_code".to_owned()],
        "none",
        None,
        None,
    ));

    assert!(result.is_err());
}

#[test]
fn client_metadata_requires_refresh_grant_for_offline_access() {
    let result = validate_client_metadata(metadata(
        "public",
        &["https://client.example/callback".to_owned()],
        &["openid".to_owned(), "offline_access".to_owned()],
        &["resource://default".to_owned()],
        &["authorization_code".to_owned()],
        "none",
        None,
        None,
    ));

    assert!(result.is_err());

    let result = validate_client_metadata(metadata(
        "public",
        &["https://client.example/callback".to_owned()],
        &["openid".to_owned(), "offline_access".to_owned()],
        &["resource://default".to_owned()],
        &["authorization_code".to_owned(), "refresh_token".to_owned()],
        "none",
        None,
        None,
    ));

    assert!(result.is_ok());
}

#[test]
fn client_metadata_requires_public_jwks_for_private_key_jwt() {
    let jwks = json!({
        "keys": [{
            "kty": "OKP",
            "crv": "Ed25519",
            "x": URL_SAFE_NO_PAD.encode([7u8; 32]),
            "alg": "EdDSA",
            "use": "sig",
            "kid": "key-1"
        }]
    });

    let result = validate_client_metadata(metadata(
        "confidential",
        &["https://client.example/callback".to_owned()],
        &["openid".to_owned()],
        &["resource://default".to_owned()],
        &["authorization_code".to_owned()],
        "private_key_jwt",
        None,
        None,
    ));
    assert!(result.is_err());

    let result = validate_client_metadata(metadata(
        "confidential",
        &["https://client.example/callback".to_owned()],
        &["openid".to_owned()],
        &["resource://default".to_owned()],
        &["authorization_code".to_owned()],
        "private_key_jwt",
        Some(&jwks),
        None,
    ));
    assert!(result.is_ok());
}

#[test]
fn client_metadata_validates_optional_jwks_for_all_auth_methods() {
    let private_jwk = json!({
        "keys": [{
            "kty": "OKP",
            "crv": "Ed25519",
            "x": URL_SAFE_NO_PAD.encode([7u8; 32]),
            "d": URL_SAFE_NO_PAD.encode([8u8; 32]),
            "kid": "key-1"
        }]
    });

    let result = validate_client_metadata(metadata(
        "confidential",
        &["https://client.example/callback".to_owned()],
        &["openid".to_owned()],
        &["resource://default".to_owned()],
        &["authorization_code".to_owned()],
        "client_secret_basic",
        Some(&private_jwk),
        None,
    ));
    assert!(result.is_err());

    let result = validate_client_metadata(metadata(
        "confidential",
        &["https://client.example/callback".to_owned()],
        &["openid".to_owned()],
        &["resource://default".to_owned()],
        &["authorization_code".to_owned()],
        "client_secret_basic",
        None,
        None,
    ));
    assert!(result.is_ok());
}

#[test]
fn client_metadata_requires_mtls_binding_material() {
    let empty_mtls = ClientMtlsMetadata::default();
    let result = validate_client_metadata(metadata(
        "confidential",
        &["https://client.example/callback".to_owned()],
        &["accounts".to_owned()],
        &["resource://default".to_owned()],
        &["authorization_code".to_owned()],
        "tls_client_auth",
        None,
        Some(&empty_mtls),
    ));
    assert!(result.is_err());

    let subject_mtls = ClientMtlsMetadata {
        tls_client_auth_subject_dn: Some("CN=client-1,O=Example".to_owned()),
        ..ClientMtlsMetadata::default()
    };
    let result = validate_client_metadata(metadata(
        "confidential",
        &["https://client.example/callback".to_owned()],
        &["accounts".to_owned()],
        &["resource://default".to_owned()],
        &["authorization_code".to_owned()],
        "tls_client_auth",
        None,
        Some(&subject_mtls),
    ));
    assert!(result.is_ok());
}

#[test]
fn client_metadata_requires_self_signed_mtls_x5c_jwks() {
    let subject_only = ClientMtlsMetadata {
        tls_client_auth_subject_dn: Some("CN=client-1,O=Example".to_owned()),
        ..ClientMtlsMetadata::default()
    };
    let result = validate_client_metadata(metadata(
        "confidential",
        &["https://client.example/callback".to_owned()],
        &["accounts".to_owned()],
        &["resource://default".to_owned()],
        &["authorization_code".to_owned()],
        "self_signed_tls_client_auth",
        None,
        Some(&subject_only),
    ));
    assert!(result.is_err());

    let thumbprint = ClientMtlsMetadata {
        tls_client_auth_cert_sha256: Some(
            "00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff"
                .to_owned(),
        ),
        ..ClientMtlsMetadata::default()
    };
    let result = validate_client_metadata(metadata(
        "confidential",
        &["https://client.example/callback".to_owned()],
        &["accounts".to_owned()],
        &["resource://default".to_owned()],
        &["authorization_code".to_owned()],
        "self_signed_tls_client_auth",
        None,
        Some(&thumbprint),
    ));
    assert!(result.is_err());

    let invalid_jwks = json!({
        "keys": [{
            "kid": "cert-1",
            "x5c": ["invalid-certificate"]
        }]
    });
    assert!(!validate_self_signed_mtls_jwks(&invalid_jwks));

    let result = validate_client_metadata(metadata(
        "confidential",
        &["https://client.example/callback".to_owned()],
        &["accounts".to_owned()],
        &["resource://default".to_owned()],
        &["authorization_code".to_owned()],
        "self_signed_tls_client_auth",
        Some(&invalid_jwks),
        None,
    ));
    assert!(result.is_err());

    let valid_jwks = json!({
        "keys": [{
            "kid": "cert-1",
            "x5c": [test_x5c("client-1", -60, 3600)]
        }]
    });
    assert!(validate_self_signed_mtls_jwks(&valid_jwks));
    let result = validate_client_metadata(metadata(
        "confidential",
        &["https://client.example/callback".to_owned()],
        &["accounts".to_owned()],
        &["resource://default".to_owned()],
        &["authorization_code".to_owned()],
        "self_signed_tls_client_auth",
        Some(&valid_jwks),
        None,
    ));
    assert!(result.is_ok());

    let expired_jwks = json!({
        "keys": [{
            "kid": "expired",
            "x5c": [test_x5c("client-expired", -7200, -3600)]
        }]
    });
    assert!(!validate_self_signed_mtls_jwks(&expired_jwks));
}

#[test]
fn client_jwks_requires_non_empty_unique_kids() {
    let missing_kid = json!({
        "keys": [{
            "kty": "OKP",
            "crv": "Ed25519",
            "x": URL_SAFE_NO_PAD.encode([7u8; 32]),
            "alg": "EdDSA",
            "use": "sig"
        }]
    });
    assert!(validate_client_jwks(&missing_kid).is_err());

    let duplicate_kid = json!({
        "keys": [
            {
                "kty": "OKP",
                "crv": "Ed25519",
                "x": URL_SAFE_NO_PAD.encode([7u8; 32]),
                "alg": "EdDSA",
                "use": "sig",
                "kid": "key-1"
            },
            {
                "kty": "OKP",
                "crv": "Ed25519",
                "x": URL_SAFE_NO_PAD.encode([8u8; 32]),
                "alg": "EdDSA",
                "use": "sig",
                "kid": "key-1"
            }
        ]
    });
    assert!(validate_client_jwks(&duplicate_kid).is_err());
}

#[test]
fn client_jwks_rejects_private_key_material() {
    let private_jwk = json!({
        "keys": [{
            "kty": "OKP",
            "crv": "Ed25519",
            "x": URL_SAFE_NO_PAD.encode([7u8; 32]),
            "alg": "EdDSA",
            "d": URL_SAFE_NO_PAD.encode([8u8; 32]),
            "kid": "key-1"
        }]
    });

    assert!(validate_client_jwks(&private_jwk).is_err());
}

#[test]
fn client_jwks_accepts_supported_public_key_algorithms() {
    let jwks = json!({
        "keys": [
            {
                "kty": "OKP",
                "crv": "Ed25519",
                "x": URL_SAFE_NO_PAD.encode([7u8; 32]),
                "alg": "EdDSA",
                "use": "sig",
                "kid": "ed-key"
            },
            {
                "kty": "RSA",
                "n": URL_SAFE_NO_PAD.encode([0x91u8; 256]),
                "e": URL_SAFE_NO_PAD.encode([0x01u8, 0x00, 0x01]),
                "alg": "RS256",
                "use": "sig",
                "kid": "rs-key"
            },
            {
                "kty": "EC",
                "crv": "P-256",
                "x": "w7JAoU_gJbZJvV-zCOvU9yFJq0FNC_edCMRM78P8eQQ",
                "y": "wQg1EytcsEmGrM70Gb53oluoDbVhCZ3Uq3hHMslHVb4",
                "alg": "ES256",
                "use": "sig",
                "kid": "es-key"
            },
            {
                "kty": "RSA",
                "n": URL_SAFE_NO_PAD.encode([0x92u8; 256]),
                "e": URL_SAFE_NO_PAD.encode([0x01u8, 0x00, 0x01]),
                "alg": "PS256",
                "use": "sig",
                "kid": "ps-key"
            }
        ]
    });

    assert!(validate_client_jwks(&jwks).is_ok());
}

#[test]
fn client_jwks_rejects_algorithm_key_type_mismatch() {
    let jwks = json!({
        "keys": [{
            "kty": "OKP",
            "crv": "Ed25519",
            "x": URL_SAFE_NO_PAD.encode([7u8; 32]),
            "alg": "RS256",
            "use": "sig",
            "kid": "wrong-alg"
        }]
    });

    assert!(validate_client_jwks(&jwks).is_err());
}
