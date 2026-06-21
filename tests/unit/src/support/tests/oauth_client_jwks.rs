use super::*;

#[test]
fn client_jwks_requires_non_empty_unique_kids() {
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
    let error = validate_client_jwks(&missing_kid).expect_err("JWK without kid must fail closed");
    assert!(
        error.to_string().contains("jwks 公钥必须包含 kid"),
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
fn client_jwks_requires_signing_use_and_declared_algorithm() {
    let encryption_use = json!({
        "keys": [{
            "kty": "OKP",
            "crv": "Ed25519",
            "x": URL_SAFE_NO_PAD.encode([7u8; 32]),
            "alg": "EdDSA",
            "use": "enc",
            "kid": "enc-key"
        }]
    });
    let error = validate_client_jwks(&encryption_use).expect_err("JWK use must be absent or sig");
    assert!(
        error.to_string().contains("jwks 公钥 use 必须为 sig"),
        "unexpected error: {error}"
    );

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
