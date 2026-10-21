use super::*;
use aws_lc_rs::key_wrap::{AES_128, AES_256, AesKek, KeyWrap};
use p256::{
    PublicKey, SecretKey,
    ecdh::diffie_hellman,
    elliptic_curve::{Generate, sec1::ToSec1Point},
};
use serde_json::json;

#[test]
fn client_jwe_key_selects_first_published_rotation_key_with_unique_identifier() {
    let mut jwks = json!({
        "keys": [
            {
                "kty": "RSA",
                "kid": "enc-1",
                "use": "enc",
                "alg": "RSA-OAEP-256",
                "n": URL_SAFE_NO_PAD.encode([0x91u8; 256]),
                "e": "AQAB"
            },
            {
                "kty": "RSA",
                "kid": "enc-2",
                "use": "enc",
                "alg": "RSA-OAEP-256",
                "n": URL_SAFE_NO_PAD.encode([0x92u8; 256]),
                "e": "AQAB"
            }
        ]
    });

    let select = |jwks: &serde_json::Value| {
        client_jwe_key(
            Some(jwks),
            Some("RSA-OAEP-256"),
            Some("A256GCM"),
            "userinfo",
        )
        .map(|key| key.map(|key| key.kid.map(str::to_owned)))
    };
    assert_eq!(select(&jwks).unwrap().flatten().as_deref(), Some("enc-1"));
    jwks["keys"].as_array_mut().unwrap().reverse();
    assert_eq!(select(&jwks).unwrap().flatten().as_deref(), Some("enc-2"));
    jwks["keys"][1]["kid"] = json!("enc-2");
    assert!(select(&jwks).is_err());
    jwks["keys"][0].as_object_mut().unwrap().remove("kid");
    assert!(select(&jwks).is_err());
}

#[test]
fn client_jwe_encrypts_with_supported_ecdh_key_management_algorithms() {
    for alg in ["ECDH-ES", "ECDH-ES+A128KW", "ECDH-ES+A256KW"] {
        let recipient = SecretKey::generate();
        let mut public = public_p256_jwk(recipient.public_key());
        let kid = format!("{alg}-\"-\\-\n-密钥").repeat(64);
        public["kid"] = json!(kid);
        public["use"] = json!("enc");
        public["alg"] = json!(alg);
        let jwks = json!({ "keys": [public] });
        let key = client_jwe_key(Some(&jwks), Some(alg), Some("A256GCM"), "userinfo")
            .expect("supported ECDH JWE key metadata")
            .expect("ECDH JWE key should be selected");

        let compact =
            encrypt_compact_jwe(&key, br#"{"sub":"user"}"#.to_vec(), JwePayloadKind::Claims)
                .expect("encrypt ECDH compact JWE");

        let header: Value = serde_json::from_slice(
            &URL_SAFE_NO_PAD
                .decode(compact.split('.').next().unwrap())
                .unwrap(),
        )
        .unwrap();
        assert_eq!(header["kid"], kid);
        assert_eq!(header["typ"], "JWT");
        assert!(header.get("cty").is_none());

        assert_eq!(
            decrypt_ecdh_compact_jwe(&compact, &recipient),
            br#"{"sub":"user"}"#
        );
    }
}

#[test]
fn ecdh_rejects_truncated_oversized_and_invalid_coordinates() {
    let recipient = SecretKey::generate();
    for name in ["x", "y"] {
        for coordinate in [
            URL_SAFE_NO_PAD.encode([1; 31]),
            URL_SAFE_NO_PAD.encode([1; 33]),
            "!".to_owned(),
        ] {
            let mut public = public_p256_jwk(recipient.public_key());
            public[name] = json!(coordinate);
            let key = ClientJweKey {
                kid: None,
                alg: "ECDH-ES",
                enc: "A256GCM",
                jwk: &public,
            };
            assert!(encrypt_compact_jwe(&key, b"claims".to_vec(), JwePayloadKind::Claims).is_err());
        }
    }
}

#[test]
fn client_jwe_key_rejects_unsupported_ecdh_and_symmetric_algorithms() {
    let recipient = SecretKey::generate();
    let mut public = public_p256_jwk(recipient.public_key());
    public["kid"] = json!("enc");
    public["use"] = json!("enc");
    public["alg"] = json!("ECDH-ES+A192KW");
    let jwks = json!({ "keys": [public] });

    let error = match client_jwe_key(
        Some(&jwks),
        Some("ECDH-ES+A192KW"),
        Some("A256GCM"),
        "userinfo",
    ) {
        Ok(_) => panic!("unsupported ECDH key-wrap algorithm must fail"),
        Err(error) => error,
    };
    assert!(error.to_string().contains("unsupported userinfo JWE alg"));

    let symmetric = json!({
        "keys": [{
            "kty": "oct",
            "kid": "sym",
            "use": "enc",
            "alg": "A256KW",
            "k": URL_SAFE_NO_PAD.encode([0xA5_u8; 32])
        }]
    });
    let error = match client_jwe_key(
        Some(&symmetric),
        Some("A256KW"),
        Some("A256GCM"),
        "userinfo",
    ) {
        Ok(_) => panic!("symmetric client JWE key management must not be accepted"),
        Err(error) => error,
    };
    assert!(error.to_string().contains("unsupported userinfo JWE alg"));
}

fn decrypt_ecdh_compact_jwe(compact: &str, recipient: &SecretKey) -> Vec<u8> {
    let parts = compact.split('.').collect::<Vec<_>>();
    assert_eq!(parts.len(), 5);
    let header: Value =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[0]).expect("decode protected"))
            .expect("protected header JSON");
    assert_eq!(header.get("enc").and_then(Value::as_str), Some("A256GCM"));
    let alg = header
        .get("alg")
        .and_then(Value::as_str)
        .expect("JWE alg header");
    let ephemeral = parse_p256_public_jwk(header.get("epk").expect("epk header")).expect("epk");
    let ephemeral = PublicKey::from_sec1_bytes(&ephemeral).expect("epk point");
    let shared = diffie_hellman(recipient.to_nonzero_scalar(), ephemeral.as_affine());
    let cek = if alg == "ECDH-ES" {
        assert!(parts[1].is_empty());
        concat_kdf(
            shared.raw_secret_bytes().as_slice(),
            "A256GCM",
            &[],
            &[],
            256,
        )
        .to_vec()
    } else {
        let kek_bits = match alg {
            "ECDH-ES+A128KW" => 128,
            "ECDH-ES+A256KW" => 256,
            other => panic!("unexpected alg: {other}"),
        };
        let kek = concat_kdf(
            shared.raw_secret_bytes().as_slice(),
            alg,
            &[],
            &[],
            kek_bits,
        );
        let encrypted_key = URL_SAFE_NO_PAD.decode(parts[1]).expect("encrypted key");
        aes_key_unwrap(&kek[..(kek_bits / 8) as usize], &encrypted_key)
    };
    let iv: [u8; 12] = URL_SAFE_NO_PAD
        .decode(parts[2])
        .expect("iv")
        .try_into()
        .expect("96-bit IV");
    let ciphertext = URL_SAFE_NO_PAD.decode(parts[3]).expect("ciphertext");
    let tag: [u8; 16] = URL_SAFE_NO_PAD
        .decode(parts[4])
        .expect("tag")
        .try_into()
        .expect("128-bit tag");
    crate::crypto_test_support::aes_256_gcm_decrypt(
        &cek,
        &iv,
        parts[0].as_bytes(),
        &ciphertext,
        &tag,
    )
    .expect("decrypt compact JWE")
}

fn aes_key_unwrap(kek: &[u8], encrypted_key: &[u8]) -> Vec<u8> {
    let mut output = vec![0_u8; encrypted_key.len() - 8];
    let unwrapped = match kek.len() {
        16 => AesKek::new(&AES_128, kek)
            .expect("A128KW")
            .unwrap(encrypted_key, &mut output),
        32 => AesKek::new(&AES_256, kek)
            .expect("A256KW")
            .unwrap(encrypted_key, &mut output),
        other => panic!("unexpected KEK length: {other}"),
    }
    .expect("unwrap CEK");
    unwrapped.to_vec()
}

fn public_p256_jwk(key: PublicKey) -> Value {
    let point = key.to_sec1_point(false);
    json!({
        "kty": "EC",
        "crv": "P-256",
        "x": URL_SAFE_NO_PAD.encode(point.x().expect("uncompressed P-256 point has x")),
        "y": URL_SAFE_NO_PAD.encode(point.y().expect("uncompressed P-256 point has y")),
    })
}

#[test]
fn ownership_introspection_signs_then_encrypts_without_changing_inner_jwt() {
    use nazo_auth::{IntrospectionSignInput, TokenSignerPort};
    use nazo_crypto::jwt::{Algorithm, Validation, VerificationKey};
    futures_executor::block_on(async {
        let manager = nazo_key_management::KeyManager::for_test_with_auxiliary(Algorithm::PS256);
        let body = json!({"active": true, "aud": ["a", "a", "\u{7b7e}\u{540d}"]});
        for requested in [None, Some("PS256")] {
            let signed = manager
                .sign_introspection_response(IntrospectionSignInput {
                    issuer: "https://issuer.example",
                    audience: "client",
                    body: &body,
                    signing_algorithm: requested,
                })
                .await
                .unwrap();
            let header = nazo_crypto::jwt::decode_header(&signed).unwrap();
            let algorithm = if requested.is_some() {
                Algorithm::PS256
            } else {
                Algorithm::EdDSA
            };
            assert_eq!(header.alg, algorithm);
            assert_eq!(header.typ.as_deref(), Some("token-introspection+jwt"));
            let snapshot = manager.snapshot();
            let jwk = &snapshot
                .verification_key(header.kid.as_deref().unwrap())
                .unwrap()
                .public_jwk;
            let verification = match algorithm {
                Algorithm::PS256 => VerificationKey::from_rsa_components(
                    jwk["n"].as_str().unwrap(),
                    jwk["e"].as_str().unwrap(),
                )
                .unwrap(),
                Algorithm::EdDSA => {
                    VerificationKey::from_ed_components(jwk["x"].as_str().unwrap()).unwrap()
                }
                _ => unreachable!(),
            };
            let mut validation = Validation::new(algorithm);
            validation.required_spec_claims.remove("exp");
            validation.set_issuer(&["https://issuer.example"]);
            validation.set_audience(&["client"]);
            for alg in ["ECDH-ES", "ECDH-ES+A128KW", "ECDH-ES+A256KW"] {
                let recipient = SecretKey::generate();
                let mut public = public_p256_jwk(recipient.public_key());
                public["kid"] = json!("enc");
                public["use"] = json!("enc");
                public["alg"] = json!(alg);
                let jwks = json!({"keys": [public]});
                let key = client_jwe_key(Some(&jwks), Some(alg), Some("A256GCM"), "introspection")
                    .unwrap()
                    .unwrap();
                let encrypted = encrypt_compact_jwe(
                    &key,
                    signed.clone().into_bytes(),
                    JwePayloadKind::NestedJwt,
                )
                .unwrap();
                let protected: Value = serde_json::from_slice(
                    &URL_SAFE_NO_PAD
                        .decode(encrypted.split('.').next().unwrap())
                        .unwrap(),
                )
                .unwrap();
                assert_eq!(protected["cty"], "JWT");
                assert_eq!(protected["alg"], alg);
                assert_eq!(protected["kid"], "enc");
                let inner = decrypt_ecdh_compact_jwe(&encrypted, &recipient);
                assert_eq!(inner, signed.as_bytes());
                let claims = nazo_crypto::jwt::decode::<Value>(
                    std::str::from_utf8(&inner).unwrap(),
                    &verification,
                    &validation,
                )
                .unwrap()
                .claims;
                assert_eq!(claims["token_introspection"], body);
            }
        }
    });
}
