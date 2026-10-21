use p256::{
    SecretKey,
    elliptic_curve::{Generate, sec1::ToSec1Point},
};
use serde_json::json;

use super::*;

#[test]
fn policy_validation_crypto_has_no_keyset_and_exposes_compiled_algorithms() {
    let crypto = ClientRegistrationCrypto::for_policy_validation();
    assert_eq!(
        crypto.response_signing_algorithms(),
        ["EdDSA", "RS256", "ES256", "PS256"].map(str::to_owned)
    );
    assert_eq!(
        crypto.id_token_signing_algorithms(),
        ["EdDSA", "RS256", "ES256", "PS256"].map(str::to_owned)
    );
}

#[test]
fn client_secret_digest_preserves_persisted_v1_format() {
    assert_eq!(
        client_secret_digest("secret", "pepper", "salt"),
        "client-secret-v1:salt:9H5GZ-kyQt1opgZoNCnaRK1w3aTK1xF1-HoStANbmzM"
    );
}

#[test]
fn registration_rejects_unusable_public_material_before_advertising_capability() {
    let mut short_padded_modulus = [0_u8; 256];
    short_padded_modulus[255] = 3;
    for key in [
        json!({"kty":"RSA", "alg":"RS256", "n":URL_SAFE_NO_PAD.encode(short_padded_modulus), "e":"AQAB"}),
        json!({"kty":"RSA", "alg":"PS256", "n":URL_SAFE_NO_PAD.encode([255_u8; 256]), "e":"Ag"}),
        json!({"kty":"EC", "crv":"P-256", "alg":"ES256", "x":URL_SAFE_NO_PAD.encode([0_u8; 32]), "y":URL_SAFE_NO_PAD.encode([0_u8; 32])}),
    ] {
        let jwks = json!({"keys":[key]});
        assert!(validate_client_jwks(&jwks).is_err());
        assert!(
            inspect_client_jwks(&jwks, true)
                .unwrap()
                .signing_algorithms
                .is_empty()
        );
    }
}

#[test]
fn client_jwks_reject_private_key_material() {
    let error = validate_client_jwks(&json!({
        "keys": [{
            "kid": "private",
            "use": "sig",
            "alg": "RS256",
            "kty": "RSA",
            "n": "AQ",
            "e": "AQAB",
            "d": "private"
        }]
    }))
    .expect_err("private key material must be rejected");
    assert_eq!(error, "jwks 不能包含私钥材料或对称密钥材料");
}

#[test]
fn client_jwks_accept_supported_ecdh_encryption_keys() {
    let jwks = json!({
        "keys": [
            p256_encryption_jwk("ecdh-direct", "ECDH-ES"),
            p256_encryption_jwk("ecdh-a128kw", "ECDH-ES+A128KW"),
            p256_encryption_jwk("ecdh-a256kw", "ECDH-ES+A256KW")
        ]
    });

    let keys =
        validate_client_jwks(&jwks).expect("supported ECDH encryption keys should be accepted");
    assert_eq!(keys.encryption_key_counts["ECDH-ES"], 1);
    assert_eq!(keys.encryption_key_counts["ECDH-ES+A128KW"], 1);
    assert_eq!(keys.encryption_key_counts["ECDH-ES+A256KW"], 1);
}

#[test]
fn algorithm_specific_signing_key_selection_requires_matching_public_material() {
    let signing = p256_signing_jwk("signing", "ES256");
    let jwks = json!({"keys": [signing]});

    let keys = validate_client_jwks(&jwks).unwrap();
    assert!(keys.signing_algorithms.contains("ES256"));
    assert!(!keys.signing_algorithms.contains("RS256"));
    let keys = inspect_client_jwks(
        &json!({"keys": [p256_encryption_jwk("enc", "ECDH-ES")]}),
        true,
    )
    .unwrap();
    assert!(keys.signing_algorithms.is_empty());
    for jwks in [
        json!({"keys": [{"use": "sig", "alg": "none"}]}),
        json!({"not_keys": []}),
    ] {
        assert!(
            inspect_client_jwks(&jwks, true)
                .unwrap()
                .signing_algorithms
                .is_empty()
        );
    }
}

#[test]
fn certificate_auth_only_advertises_usable_jose_keys_and_preserves_ambiguity() {
    let jwks = json!({"keys": [
        p256_signing_jwk("signing", "ES256"),
        p256_encryption_jwk("enc-a", "ECDH-ES"),
        p256_encryption_jwk("enc-b", "ECDH-ES"),
        {"use": "sig", "alg": "RS256", "kty": "RSA", "n": "invalid", "e": "AQAB"},
        {"x5c": ["invalid"]}
    ]});
    let keys = inspect_client_jwks(&jwks, true).unwrap();
    assert_eq!(
        keys.signing_algorithms.into_iter().collect::<Vec<_>>(),
        ["ES256"]
    );
    assert_eq!(keys.encryption_key_counts["ECDH-ES"], 2);
    assert!(!keys.has_current_mtls_certificate);
    assert!(validate_client_jwks(&jwks).is_err());
}

#[test]
fn signing_coordinates_reject_wrong_length_and_invalid_base64() {
    for invalid in [
        URL_SAFE_NO_PAD.encode([1_u8; 31]),
        URL_SAFE_NO_PAD.encode([1_u8; 33]),
        "invalid!".to_owned(),
    ] {
        for coordinate in ["x", "y"] {
            let mut key = p256_signing_jwk("signing", "ES256");
            key[coordinate] = json!(invalid);
            assert!(validate_client_jwks(&json!({"keys": [key]})).is_err());
        }
        let key = json!({"kty": "OKP", "crv": "Ed25519", "alg": "EdDSA", "x": invalid});
        assert!(validate_client_jwks(&json!({"keys": [key]})).is_err());
    }
}

#[test]
fn client_jwks_reject_symmetric_jwe_keys() {
    let error = validate_client_jwks(&json!({
        "keys": [{
            "kid": "sym",
            "use": "enc",
            "alg": "A256KW",
            "kty": "oct",
            "k": URL_SAFE_NO_PAD.encode([0xA5_u8; 32])
        }]
    }))
    .expect_err("symmetric keys must not enter client jwks");

    assert_eq!(error, "jwks 不能包含私钥材料或对称密钥材料");
}

#[test]
fn client_jwks_reject_unsupported_ecdh_key_wrap_width() {
    let error = validate_client_jwks(&json!({
        "keys": [p256_encryption_jwk("ecdh-a192kw", "ECDH-ES+A192KW")]
    }))
    .expect_err("unsupported ECDH key-wrap width must be rejected");

    assert_eq!(error, "jwks 公钥材料与 alg 不匹配");
}

#[test]
fn client_jwks_accepts_optional_key_ids_but_rejects_duplicate_values() {
    let mut without_kid = p256_encryption_jwk("unused", "ECDH-ES");
    without_kid
        .as_object_mut()
        .expect("fixture is an object")
        .remove("kid");
    validate_client_jwks(&json!({"keys": [without_kid]}))
        .expect("RFC 7517 defines kid as optional");

    let mut empty_kid = p256_encryption_jwk("unused", "ECDH-ES");
    empty_kid["kid"] = Value::String(String::new());
    assert_eq!(
        validate_client_jwks(&json!({"keys": [empty_kid]})),
        Err("jwks kid 不能为空或包含首尾空白".to_owned())
    );

    let error = validate_client_jwks(&json!({
        "keys": [
            p256_encryption_jwk("duplicate", "ECDH-ES"),
            p256_encryption_jwk("duplicate", "ECDH-ES+A256KW")
        ]
    }))
    .expect_err("duplicate key identifiers make key selection ambiguous");
    assert_eq!(error, "jwks kid 不能重复: duplicate");
}

#[test]
fn rfc4514_distinguished_names_are_parsed_and_compared_canonically() {
    validate_rfc4514_dn("CN=client-1,O=Example").expect("a valid RFC 4514 name is accepted");
    assert!(rfc4514_dn_matches(
        "CN=client-1,O=Example",
        "CN=CLIENT-1,O=example"
    ));
    assert!(!rfc4514_dn_matches(
        "CN=client-1,O=Example",
        "CN=other,O=Example"
    ));
    assert!(validate_rfc4514_dn("not-a-distinguished-name").is_err());
    assert!(validate_rfc4514_dn(" CN=client-1").is_err());
}

fn p256_encryption_jwk(kid: &str, alg: &str) -> Value {
    let key = SecretKey::generate();
    let point = key.public_key().to_sec1_point(false);
    json!({
        "kid": kid,
        "use": "enc",
        "alg": alg,
        "kty": "EC",
        "crv": "P-256",
        "x": URL_SAFE_NO_PAD.encode(point.x().expect("P-256 x coordinate")),
        "y": URL_SAFE_NO_PAD.encode(point.y().expect("P-256 y coordinate"))
    })
}

fn p256_signing_jwk(kid: &str, alg: &str) -> Value {
    let key = SecretKey::generate();
    let point = key.public_key().to_sec1_point(false);
    json!({
        "kid": kid,
        "use": "sig",
        "alg": alg,
        "kty": "EC",
        "crv": "P-256",
        "x": URL_SAFE_NO_PAD.encode(point.x().expect("P-256 x coordinate")),
        "y": URL_SAFE_NO_PAD.encode(point.y().expect("P-256 y coordinate"))
    })
}
