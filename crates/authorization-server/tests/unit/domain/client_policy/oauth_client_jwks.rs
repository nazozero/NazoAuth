use crate::domain::client_policy::{refresh_client_jwks, refresh_client_jwks_for_encryption};
use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use nazo_key_management::{validate_client_jwks, validate_self_signed_mtls_jwks};
use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair, PKCS_ECDSA_P256_SHA256};
use serde_json::json;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

fn test_x5c(common_name: &str, not_before_offset: i64, not_after_offset: i64) -> String {
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("test P-256 key");
    let mut params = CertificateParams::default();
    params.distinguished_name = DistinguishedName::new();
    params
        .distinguished_name
        .push(DnType::CommonName, common_name);
    let now = time::OffsetDateTime::now_utc();
    params.not_before = now + time::Duration::seconds(not_before_offset);
    params.not_after = now + time::Duration::seconds(not_after_offset);
    STANDARD.encode(params.self_signed(&key).expect("test cert").der())
}

#[test]
fn self_signed_mtls_jwks_requires_a_current_parseable_x5c_certificate() {
    let invalid = json!({ "keys": [{ "kid": "invalid", "x5c": ["not-a-certificate"] }] });
    assert!(!validate_self_signed_mtls_jwks(&invalid));

    let current = json!({
        "keys": [{
            "kid": "current",
            "x5c": [test_x5c("client-current", -60, 3600)]
        }]
    });
    assert!(validate_self_signed_mtls_jwks(&current));

    let expired = json!({
        "keys": [{
            "kid": "expired",
            "x5c": [test_x5c("client-expired", -7200, -3600)]
        }]
    });
    assert!(!validate_self_signed_mtls_jwks(&expired));
}

#[test]
fn client_jwks_allows_one_unidentified_key_class_but_rejects_empty_or_duplicate_kids() {
    let empty = json!({ "keys": [] });
    let error = validate_client_jwks(&empty).expect_err("empty jwks keys must fail closed");
    assert!(
        error.to_string().contains("jwks.keys 不能为空"),
        "unexpected error: {error}"
    );

    let missing_kid = json!({
        "keys": [{
            "kty": "OKP",
            "crv": "Ed25519",
            "x": URL_SAFE_NO_PAD.encode([7u8; 32]),
            "alg": "EdDSA",
            "use": "sig"
        }]
    });
    validate_client_jwks(&missing_kid)
        .expect("RFC 7517 defines kid as optional when selection remains unambiguous");

    let empty_kid = json!({
        "keys": [{
            "kty": "OKP",
            "crv": "Ed25519",
            "x": URL_SAFE_NO_PAD.encode([7u8; 32]),
            "alg": "EdDSA",
            "use": "sig",
            "kid": ""
        }]
    });
    let error = validate_client_jwks(&empty_kid).expect_err("an explicit empty kid must fail");
    assert!(
        error.to_string().contains("kid"),
        "unexpected error: {error}"
    );

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
    let error =
        validate_client_jwks(&duplicate_kid).expect_err("duplicate JWK kid must fail closed");
    assert!(
        error.to_string().contains("jwks kid 不能重复: key-1"),
        "unexpected error: {error}"
    );
}

#[test]
fn client_jwks_accepts_encryption_keys_for_introspection_jwe() {
    let encryption_use = json!({
        "keys": [{
            "kty": "RSA",
            "n": URL_SAFE_NO_PAD.encode([0x91u8; 256]),
            "e": URL_SAFE_NO_PAD.encode([0x01u8, 0x00, 0x01]),
            "alg": "RSA-OAEP-256",
            "use": "enc",
            "kid": "enc-key"
        }]
    });
    validate_client_jwks(&encryption_use)
        .expect("registered client JWKS may include RSA encryption keys for RFC 9701 JWE");
}

#[test]
fn client_jwks_requires_declared_algorithm() {
    let missing_alg = json!({
        "keys": [{
            "kty": "OKP",
            "crv": "Ed25519",
            "x": URL_SAFE_NO_PAD.encode([7u8; 32]),
            "use": "sig",
            "kid": "no-alg"
        }]
    });
    let error = validate_client_jwks(&missing_alg).expect_err("registered JWKs must declare alg");
    assert!(
        error.to_string().contains("jwks 公钥必须声明 alg"),
        "unexpected error: {error}"
    );

    let unsupported_alg = json!({
        "keys": [{
            "kty": "RSA",
            "n": URL_SAFE_NO_PAD.encode([0x91u8; 256]),
            "e": URL_SAFE_NO_PAD.encode([0x01u8, 0x00, 0x01]),
            "alg": "HS256",
            "use": "sig",
            "kid": "unsupported-alg"
        }]
    });
    let error =
        validate_client_jwks(&unsupported_alg).expect_err("unsupported JWS alg must fail closed");
    assert!(
        error.to_string().contains("jwks alg 必须是"),
        "unexpected error: {error}"
    );
}

#[test]
fn client_jwks_rejects_encryption_algorithm_key_type_mismatch() {
    let jwks = json!({
        "keys": [{
            "kty": "OKP",
            "crv": "Ed25519",
            "x": URL_SAFE_NO_PAD.encode([7u8; 32]),
            "alg": "RSA-OAEP-256",
            "use": "enc",
            "kid": "wrong-enc-alg"
        }]
    });

    let error = validate_client_jwks(&jwks)
        .expect_err("declared JWE algorithm must match JWK key type and material");
    assert!(
        error.to_string().contains("jwks 公钥材料与 alg 不匹配"),
        "unexpected error: {error}"
    );
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

    let error = validate_client_jwks(&private_jwk).expect_err("registered JWK must not contain d");
    assert!(
        error.to_string().contains("jwks 不能包含私钥材料"),
        "unexpected error: {error}"
    );
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
            },
            {
                "kty": "RSA",
                "n": URL_SAFE_NO_PAD.encode([0x93u8; 256]),
                "e": URL_SAFE_NO_PAD.encode([0x01u8, 0x00, 0x01]),
                "alg": "RSA-OAEP-256",
                "use": "enc",
                "kid": "enc-key"
            }
        ]
    });

    validate_client_jwks(&jwks)
        .expect("supported public signing keys should be accepted for private_key_jwt");
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

    let error = validate_client_jwks(&jwks)
        .expect_err("declared JWS algorithm must match JWK key type and material");
    assert!(
        error.to_string().contains("jwks 公钥材料与 alg 不匹配"),
        "unexpected error: {error}"
    );
}

struct StubRemoteJwks;

impl nazo_http_actix::RemoteJwksResolverPort for StubRemoteJwks {
    fn resolve<'a>(
        &'a self,
        _uri: &'a str,
        _expected_kid: Option<&'a str>,
    ) -> nazo_http_actix::RemoteJwksFuture<'a> {
        Box::pin(async {
            Ok(json!({
                "keys": [{
                    "kty": "OKP",
                    "crv": "Ed25519",
                    "x": URL_SAFE_NO_PAD.encode([9u8; 32]),
                    "alg": "EdDSA",
                    "use": "sig",
                    "kid": "remote"
                }]
            }))
        })
    }
}

struct CountingRemoteJwks {
    calls: Arc<AtomicUsize>,
}

impl nazo_http_actix::RemoteJwksResolverPort for CountingRemoteJwks {
    fn resolve<'a>(
        &'a self,
        _uri: &'a str,
        _expected_kid: Option<&'a str>,
    ) -> nazo_http_actix::RemoteJwksFuture<'a> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        Box::pin(async { Err("unexpected remote key resolution".to_owned()) })
    }
}

fn client_for_jwks_refresh() -> crate::domain::ClientRow {
    client_row! {
        id: uuid::Uuid::now_v7(),
        tenant_id: uuid::Uuid::now_v7(),
        realm_id: uuid::Uuid::now_v7(),
        organization_id: uuid::Uuid::now_v7(),
        client_id: "refresh-client".to_owned(),
        client_name: "Refresh Client".to_owned(),
        client_type: "confidential".to_owned(),
        client_secret_hash: None,
        redirect_uris: json!(["https://client.example/cb"]),
        scopes: json!(["openid"]),
        allowed_audiences: json!(["resource"]),
        grant_types: json!(["authorization_code"]),
        token_endpoint_auth_method: "private_key_jwt".to_owned(),
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
        is_active: true, jwks: Some(json!({"keys": []})),
        introspection_encrypted_response_alg: None,
        introspection_encrypted_response_enc: None,
        userinfo_signed_response_alg: None,
        userinfo_encrypted_response_alg: None,
        userinfo_encrypted_response_enc: None,
        authorization_signed_response_alg: None,
        authorization_encrypted_response_alg: None,
        authorization_encrypted_response_enc: None,
        post_logout_redirect_uris: json!([]),
        backchannel_logout_uri: None,
        backchannel_logout_session_required: false,
        frontchannel_logout_uri: None,
        frontchannel_logout_session_required: false,
        subject_type: "public".to_owned(),
        sector_identifier_uri: None,
        sector_identifier_host: None,
    }
}

#[tokio::test]
async fn refresh_client_jwks_uses_registered_uri_and_preserves_snapshot_without_one() {
    let resolver = StubRemoteJwks;
    let mut client = client_for_jwks_refresh();
    client.jwks_uri = Some("https://client.example/jwks".to_owned());
    assert!(
        refresh_client_jwks(&mut client, &resolver, Some("remote"))
            .await
            .is_ok()
    );
    assert_eq!(
        client.jwks.as_ref().expect("remote JWKS")["keys"][0]["kid"],
        "remote"
    );

    client.jwks_uri = None;
    client.jwks = Some(json!({"keys": [{"kid": "persisted"}]}));
    refresh_client_jwks(&mut client, &resolver, Some("remote"))
        .await
        .expect("clients without jwks_uri keep their persisted snapshot");
    assert_eq!(
        client.jwks.as_ref().expect("persisted JWKS")["keys"][0]["kid"],
        "persisted"
    );
}

#[tokio::test]
async fn refresh_client_jwks_does_not_replace_snapshot_when_resolution_fails() {
    let calls = Arc::new(AtomicUsize::new(0));
    let resolver = CountingRemoteJwks {
        calls: calls.clone(),
    };
    let mut client = client_for_jwks_refresh();
    client.jwks_uri = Some("https://client.example/jwks".to_owned());
    client.jwks = Some(json!({"keys": [{"kid": "persisted"}]}));

    let error = refresh_client_jwks(&mut client, &resolver, Some("remote"))
        .await
        .expect_err("remote resolver failure must propagate");
    assert_eq!(error, "unexpected remote key resolution");
    assert_eq!(calls.load(Ordering::Relaxed), 1);
    assert_eq!(
        client.jwks.as_ref().expect("persisted JWKS")["keys"][0]["kid"],
        "persisted",
        "failed resolution must preserve the prior snapshot"
    );
}

#[tokio::test]
async fn encrypted_response_refresh_is_noop_without_policy_and_uses_remote_keys_with_policy() {
    let resolver = StubRemoteJwks;
    let mut client = client_for_jwks_refresh();
    client.jwks_uri = Some("https://client.example/jwks".to_owned());
    refresh_client_jwks_for_encryption(&mut client, &resolver, false)
        .await
        .expect("no response encryption policy should not resolve keys");
    assert_eq!(
        client.jwks.as_ref().expect("initial JWKS")["keys"]
            .as_array()
            .expect("keys array")
            .len(),
        0
    );

    client.introspection_encrypted_response_alg = Some("RSA-OAEP-256".to_owned());
    refresh_client_jwks_for_encryption(&mut client, &resolver, true)
        .await
        .expect("encrypted response policy should resolve keys");
    assert_eq!(
        client.jwks.as_ref().expect("remote JWKS")["keys"][0]["kid"],
        "remote"
    );
}

#[tokio::test]
async fn response_encryption_refresh_does_not_fetch_when_the_selected_response_is_plain() {
    let calls = Arc::new(AtomicUsize::new(0));
    let resolver = CountingRemoteJwks {
        calls: calls.clone(),
    };
    let mut client = client_for_jwks_refresh();
    client.jwks_uri = Some("https://client.example/jwks".to_owned());
    client.userinfo_encrypted_response_alg = Some("RSA-OAEP-256".to_owned());

    refresh_client_jwks_for_encryption(&mut client, &resolver, false)
        .await
        .expect("plain selected response must not resolve a remote key");
    assert_eq!(calls.load(Ordering::Relaxed), 0);
    assert_eq!(
        client.jwks.as_ref().expect("initial JWKS")["keys"],
        json!([])
    );
}
