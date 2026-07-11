use std::{sync::Arc, time::Duration};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::{Value, json};
use uuid::Uuid;

use super::*;
use crate::domain::{ActiveSigningKey, ClientRow, ExternalSigningKey, Keyset, VerificationKey};
use crate::support::{
    DEFAULT_ORGANIZATION_ID, DEFAULT_REALM_ID, DEFAULT_TENANT_ID, generate_key_material,
    public_jwk_from_private_der, sign_local_jwt_input,
};

fn client(jwks: Value) -> ClientRow {
    ClientRow {
        id: Uuid::now_v7(),
        tenant_id: DEFAULT_TENANT_ID,
        realm_id: DEFAULT_REALM_ID,
        organization_id: DEFAULT_ORGANIZATION_ID,
        client_id: "client-1".to_owned(),
        client_name: "Client".to_owned(),
        client_type: "confidential".to_owned(),
        client_secret_hash: None,
        redirect_uris: json!([]),
        scopes: json!(["openid"]),
        allowed_audiences: json!(["resource://default"]),
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
        allow_authorization_code_without_pkce: false,
        is_active: true,
        jwks: Some(jwks),
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

fn local_keyset(algorithm: jsonwebtoken::Algorithm) -> Keyset {
    let kid = format!("{algorithm:?}-kid");
    let material = generate_key_material(algorithm).unwrap();
    let public_jwk =
        public_jwk_from_private_der(&kid, algorithm, &material.private_pkcs8_der).unwrap();
    Keyset {
        active_kid: kid.clone(),
        active_alg: algorithm,
        active_signing_key: ActiveSigningKey::LocalPkcs8Der(material.private_pkcs8_der.clone()),
        verification_keys: vec![VerificationKey {
            kid,
            public_jwk,
            local_signing_key: Some(material.private_pkcs8_der),
        }],
    }
}

#[tokio::test]
async fn detached_signing_maps_only_fapi_algorithms_and_verifies_raw_bytes() {
    for (jwt_algorithm, http_algorithm) in [
        (jsonwebtoken::Algorithm::EdDSA, "ed25519"),
        (jsonwebtoken::Algorithm::RS256, "rsa-v1_5-sha256"),
        (jsonwebtoken::Algorithm::ES256, "ecdsa-p256-sha256"),
    ] {
        let keyset = local_keyset(jwt_algorithm);
        let signed = keyset
            .sign_http_message(b"exact signature base")
            .await
            .unwrap();
        assert_eq!(signed.algorithm, http_algorithm);
        assert_eq!(signed.kid, keyset.active_kid);
        let mut public_jwk = keyset.verification_keys[0].public_jwk.clone();
        public_jwk.as_object_mut().unwrap().remove("alg");
        verify_client_http_message(
            &client(json!({"keys": [public_jwk]})),
            DEFAULT_TENANT_ID,
            "client-1",
            &signed.kid,
            signed.algorithm,
            b"exact signature base",
            &signed.signature,
        )
        .unwrap();
    }
}

#[tokio::test]
async fn detached_signing_rejects_ps256_active_server_key() {
    let error = local_keyset(jsonwebtoken::Algorithm::PS256)
        .sign_http_message(b"input")
        .await
        .unwrap_err();
    assert!(format!("{error:#}").contains("unsupported"));
}

#[test]
fn verification_requires_exact_tenant_client_and_unique_kid() {
    let keyset = local_keyset(jsonwebtoken::Algorithm::EdDSA);
    let jwk = keyset.verification_keys[0].public_jwk.clone();
    let client = client(json!({"keys": [jwk.clone(), jwk]}));

    for result in [
        verify_client_http_message(
            &client,
            Uuid::now_v7(),
            "client-1",
            &keyset.active_kid,
            "ed25519",
            b"x",
            b"x",
        ),
        verify_client_http_message(
            &client,
            DEFAULT_TENANT_ID,
            "other-client",
            &keyset.active_kid,
            "ed25519",
            b"x",
            b"x",
        ),
        verify_client_http_message(
            &client,
            DEFAULT_TENANT_ID,
            "client-1",
            "other-kid",
            "ed25519",
            b"x",
            b"x",
        ),
        verify_client_http_message(
            &client,
            DEFAULT_TENANT_ID,
            "client-1",
            &keyset.active_kid,
            "ed25519",
            b"x",
            b"x",
        ),
    ] {
        assert!(result.is_err());
    }
}

#[test]
fn verification_rejects_unknown_or_jwk_mismatched_algorithm() {
    let keyset = local_keyset(jsonwebtoken::Algorithm::EdDSA);
    let client = client(json!({"keys": [keyset.verification_keys[0].public_jwk.clone()]}));
    for algorithm in ["rsa-v1_5-sha256", "unknown"] {
        assert!(
            verify_client_http_message(
                &client,
                DEFAULT_TENANT_ID,
                "client-1",
                &keyset.active_kid,
                algorithm,
                b"input",
                b"signature",
            )
            .is_err()
        );
    }
}

#[test]
fn http_verification_accepts_supported_public_jwks_without_alg() {
    for algorithm in [
        jsonwebtoken::Algorithm::EdDSA,
        jsonwebtoken::Algorithm::RS256,
        jsonwebtoken::Algorithm::ES256,
    ] {
        let mut jwk = local_keyset(algorithm).verification_keys[0]
            .public_jwk
            .clone();
        jwk.as_object_mut().unwrap().remove("alg");

        assert!(http_jwk_decoding_key(&jwk, algorithm).is_some());
    }
}

#[test]
fn http_verification_rejects_every_private_jwk_member() {
    let public = local_keyset(jsonwebtoken::Algorithm::EdDSA).verification_keys[0]
        .public_jwk
        .clone();
    for member in ["d", "p", "q", "dp", "dq", "qi", "oth"] {
        let mut jwk = public.clone();
        jwk[member] = if member == "oth" {
            json!([])
        } else {
            json!("private")
        };
        assert!(
            http_jwk_decoding_key(&jwk, jsonwebtoken::Algorithm::EdDSA).is_none(),
            "accepted private member {member}"
        );
    }
}

#[test]
fn http_verification_enforces_well_formed_verify_key_ops() {
    let public = local_keyset(jsonwebtoken::Algorithm::EdDSA).verification_keys[0]
        .public_jwk
        .clone();
    let with_ops = |key_ops: Value| {
        let mut jwk = public.clone();
        jwk["key_ops"] = key_ops;
        http_jwk_decoding_key(&jwk, jsonwebtoken::Algorithm::EdDSA).is_some()
    };

    assert!(with_ops(json!(["verify"])));
    assert!(with_ops(json!(["sign", "verify"])));
    assert!(!with_ops(json!(["sign"])));
    assert!(!with_ops(json!(["encrypt"])));
    assert!(!with_ops(json!([])));
    assert!(!with_ops(json!(["verify", "verify"])));
    assert!(!with_ops(json!(["verify", 7])));
    assert!(!with_ops(json!("verify")));
}

#[test]
fn http_verification_requires_signing_jwk_use_when_present() {
    let public = local_keyset(jsonwebtoken::Algorithm::EdDSA).verification_keys[0]
        .public_jwk
        .clone();
    let usable = |use_value: Value, key_ops: Value| {
        let mut jwk = public.clone();
        jwk["use"] = use_value;
        jwk["key_ops"] = key_ops;
        http_jwk_decoding_key(&jwk, jsonwebtoken::Algorithm::EdDSA).is_some()
    };

    assert!(usable(json!("sig"), json!(["verify"])));
    assert!(!usable(json!("enc"), json!(["verify"])));
    assert!(!usable(json!(7), json!(["verify"])));
    assert!(!usable(json!("sig"), json!(["encrypt"])));
}

#[test]
fn http_rsa_policy_uses_unsigned_modulus_bit_length() {
    let mut jwk = local_keyset(jsonwebtoken::Algorithm::RS256).verification_keys[0]
        .public_jwk
        .clone();
    assert!(http_jwk_decoding_key(&jwk, jsonwebtoken::Algorithm::RS256).is_some());

    let mut modulus = URL_SAFE_NO_PAD.decode(jwk["n"].as_str().unwrap()).unwrap();
    modulus.insert(0, 0);
    jwk["n"] = json!(URL_SAFE_NO_PAD.encode(&modulus));
    assert!(
        http_jwk_decoding_key(&jwk, jsonwebtoken::Algorithm::RS256).is_some(),
        "a leading zero must not change an unsigned 2048-bit modulus"
    );

    for modulus in [[&[0x7f][..], &[0xff; 255][..]].concat(), vec![0xff; 255]] {
        jwk["n"] = json!(URL_SAFE_NO_PAD.encode(modulus));
        assert!(http_jwk_decoding_key(&jwk, jsonwebtoken::Algorithm::RS256).is_none());
    }
}

#[test]
fn verification_rejects_private_incompatible_and_weak_jwks() {
    let mut private = local_keyset(jsonwebtoken::Algorithm::EdDSA).verification_keys[0]
        .public_jwk
        .clone();
    private["d"] = json!(URL_SAFE_NO_PAD.encode([7u8; 32]));
    let incompatible = json!({
        "kid": "kid", "kty": "EC", "crv": "P-384", "alg": "ES256",
        "x": URL_SAFE_NO_PAD.encode([1u8; 32]), "y": URL_SAFE_NO_PAD.encode([2u8; 32])
    });
    let weak_rsa = json!({
        "kid": "kid", "kty": "RSA", "alg": "RS256",
        "n": URL_SAFE_NO_PAD.encode([3u8; 128]), "e": "AQAB"
    });

    for (jwk, kid, algorithm) in [
        (private, "EdDSA-kid", "ed25519"),
        (incompatible, "kid", "ecdsa-p256-sha256"),
        (weak_rsa, "kid", "rsa-v1_5-sha256"),
    ] {
        assert!(
            verify_client_http_message(
                &client(json!({"keys": [jwk]})),
                DEFAULT_TENANT_ID,
                "client-1",
                kid,
                algorithm,
                b"input",
                b"signature"
            )
            .is_err()
        );
    }
}

#[cfg(windows)]
fn output_command(output: &str) -> Arc<Vec<String>> {
    Arc::new(vec![
        "pwsh".to_owned(),
        "-NoLogo".to_owned(),
        "-NoProfile".to_owned(),
        "-Command".to_owned(),
        format!(
            "$null=[Console]::In.ReadToEnd();[Console]::Out.Write('{}')",
            output.replace('\'', "''")
        ),
    ])
}

#[cfg(unix)]
fn output_command(output: &str) -> Arc<Vec<String>> {
    Arc::new(vec![
        "sh".to_owned(),
        "-c".to_owned(),
        format!(
            "cat >/dev/null; printf '%s' '{}'",
            output.replace('\'', "'\"'\"'")
        ),
    ])
}

#[tokio::test]
async fn external_signer_output_is_verified_against_exact_message() {
    let local = local_keyset(jsonwebtoken::Algorithm::EdDSA);
    let signature = sign_local_jwt_input(
        jsonwebtoken::Algorithm::EdDSA,
        match &local.active_signing_key {
            ActiveSigningKey::LocalPkcs8Der(key) => key,
            _ => unreachable!(),
        },
        b"expected",
    )
    .unwrap();
    let external = Keyset {
        active_kid: local.active_kid.clone(),
        active_alg: jsonwebtoken::Algorithm::EdDSA,
        active_signing_key: ActiveSigningKey::ExternalCommand(ExternalSigningKey {
            command: output_command(&json!({"signature": signature}).to_string()),
            key_ref: "kms://test/key".to_owned(),
            timeout: Duration::from_secs(2),
        }),
        verification_keys: local.verification_keys,
    };

    assert!(external.sign_http_message(b"expected").await.is_ok());
    assert!(external.sign_http_message(b"tampered").await.is_err());
}
