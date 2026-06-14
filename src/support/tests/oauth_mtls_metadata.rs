use super::*;
use openssl::asn1::Asn1Time;
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::{PKey, Private};
use openssl::rsa::Rsa;
use openssl::x509::{X509Builder, X509Name};

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
    let error = result.expect_err("tls_client_auth requires registered certificate binding");
    assert!(
        error
            .to_string()
            .contains("tls_client_auth 客户端必须注册 subject DN、SAN 或证书 SHA-256 绑定材料"),
        "unexpected error: {error}"
    );

    let subject_mtls = ClientMtlsMetadata {
        tls_client_auth_subject_dn: Some("CN=client-1,O=Example".to_owned()),
        ..ClientMtlsMetadata::default()
    };
    validate_client_metadata(metadata(
        "confidential",
        &["https://client.example/callback".to_owned()],
        &["accounts".to_owned()],
        &["resource://default".to_owned()],
        &["authorization_code".to_owned()],
        "tls_client_auth",
        None,
        Some(&subject_mtls),
    ))
    .expect("tls_client_auth may bind by registered subject DN");
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
    let error = result.expect_err("self_signed_tls_client_auth must be bound to x5c jwks");
    assert!(
        error
            .to_string()
            .contains("self_signed_tls_client_auth 客户端必须注册有效 x5c 证书"),
        "unexpected error: {error}"
    );

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
    assert!(
        result
            .expect_err("self_signed_tls_client_auth must not accept bare SHA-256 binding")
            .to_string()
            .contains("self_signed_tls_client_auth 客户端必须注册有效 x5c 证书")
    );

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
    assert!(
        result
            .expect_err("invalid x5c certificate must fail closed")
            .to_string()
            .contains("self_signed_tls_client_auth 客户端必须注册有效 x5c 证书")
    );

    let valid_jwks = json!({
        "keys": [{
            "kid": "cert-1",
            "x5c": [test_x5c("client-1", -60, 3600)]
        }]
    });
    assert!(validate_self_signed_mtls_jwks(&valid_jwks));
    validate_client_metadata(metadata(
        "confidential",
        &["https://client.example/callback".to_owned()],
        &["accounts".to_owned()],
        &["resource://default".to_owned()],
        &["authorization_code".to_owned()],
        "self_signed_tls_client_auth",
        Some(&valid_jwks),
        None,
    ))
    .expect("valid x5c certificate jwks should satisfy self-signed mTLS registration");

    let expired_jwks = json!({
        "keys": [{
            "kid": "expired",
            "x5c": [test_x5c("client-expired", -7200, -3600)]
        }]
    });
    assert!(!validate_self_signed_mtls_jwks(&expired_jwks));
}
