//! Contract tests for the nazo-crypto boundary. Native dependencies are used
//! here only as oracles for the old implementations being replaced.

use nazo_crypto::CryptoError;

#[test]
fn crypto_errors_are_backend_free() {
    use std::error::Error as _;

    let cases = [
        (
            CryptoError::UnsupportedAlgorithm,
            "unsupported cryptographic algorithm",
        ),
        (CryptoError::InvalidKey, "invalid cryptographic key"),
        (CryptoError::InvalidInput, "invalid cryptographic input"),
        (CryptoError::InvalidSignature, "invalid signature"),
        (CryptoError::AuthenticationFailed, "authentication failed"),
        (CryptoError::InvalidToken, "invalid token"),
        (
            CryptoError::OperationFailed,
            "cryptographic operation failed",
        ),
    ];
    for (error, message) in cases {
        assert_eq!(error.to_string(), message);
        assert!(error.source().is_none());
        let copied = error;
        assert_eq!(error, copied);
        assert_ne!(format!("{error:?}"), "");
    }
    assert_eq!(format!("{:?}", CryptoError::InvalidKey), "InvalidKey");
}

#[cfg(feature = "jose")]
mod jose {
    use aws_lc_rs::{
        encoding::{AsDer, PublicKeyX509Der},
        key_wrap::{AES_128, AES_256, AesKek, KeyWrap as _},
        rsa::{
            OAEP_SHA256_MGF1SHA256, OaepPrivateDecryptingKey, OaepPublicEncryptingKey,
            PrivateDecryptingKey, PublicEncryptingKey,
        },
        signature::KeyPair as _,
    };
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use nazo_crypto::jwt::{Algorithm, VerificationKey};
    use nazo_crypto::{CryptoError, jwt, key_wrap, signature};
    use serde::Deserialize;

    const ED25519_PKCS8_PREFIX: &[u8] = &[
        0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04,
        0x20,
    ];

    /// Prepares signing material from DER and performs one raw sign call,
    /// matching the request-time prepared-key usage in production.
    fn sign_raw(algorithm: Algorithm, private_der: &[u8], message: &[u8]) -> Vec<u8> {
        signature::PreparedSigningKey::new(algorithm, private_der)
            .unwrap()
            .sign(message)
            .unwrap()
    }

    /// Base64url public-key components (x | n,e | x,y) for a private key.
    fn public_components(algorithm: Algorithm, private_der: &[u8]) -> Vec<String> {
        match algorithm {
            Algorithm::EdDSA => {
                let seed: [u8; 32] = private_der[ED25519_PKCS8_PREFIX.len()..]
                    .try_into()
                    .expect("Ed25519 PKCS#8 is prefix + seed");
                let public = ed25519_dalek::SigningKey::from_bytes(&seed).verifying_key();
                vec![URL_SAFE_NO_PAD.encode(public.to_bytes())]
            }
            Algorithm::RS256 | Algorithm::PS256 => {
                let pair = aws_lc_rs::rsa::KeyPair::from_der(private_der)
                    .expect("generated RSA key parses");
                let public = pair.public_key();
                vec![
                    URL_SAFE_NO_PAD.encode(public.modulus().big_endian_without_leading_zero()),
                    URL_SAFE_NO_PAD.encode(public.exponent().big_endian_without_leading_zero()),
                ]
            }
            Algorithm::ES256 => {
                use p256::pkcs8::DecodePrivateKey as _;
                let secret =
                    p256::SecretKey::from_pkcs8_der(private_der).expect("generated EC key parses");
                let point = p256::elliptic_curve::sec1::ToSec1Point::to_sec1_point(
                    &secret.public_key(),
                    false,
                );
                vec![
                    URL_SAFE_NO_PAD.encode(point.x().unwrap()),
                    URL_SAFE_NO_PAD.encode(point.y().unwrap()),
                ]
            }
            _ => unreachable!(),
        }
    }

    /// Public-key DecodingKey built directly through the jsonwebtoken oracle.
    fn native_decoding_key(algorithm: Algorithm, private_der: &[u8]) -> jsonwebtoken::DecodingKey {
        let parts = public_components(algorithm, private_der);
        match algorithm {
            Algorithm::EdDSA => jsonwebtoken::DecodingKey::from_ed_components(&parts[0]).unwrap(),
            Algorithm::RS256 | Algorithm::PS256 => {
                jsonwebtoken::DecodingKey::from_rsa_components(&parts[0], &parts[1]).unwrap()
            }
            Algorithm::ES256 => {
                jsonwebtoken::DecodingKey::from_ec_components(&parts[0], &parts[1]).unwrap()
            }
            _ => unreachable!(),
        }
    }

    fn native_encoding_key(algorithm: Algorithm, private_der: &[u8]) -> jsonwebtoken::EncodingKey {
        match algorithm {
            Algorithm::EdDSA => jsonwebtoken::EncodingKey::from_ed_der(private_der),
            Algorithm::RS256 | Algorithm::PS256 => {
                jsonwebtoken::EncodingKey::from_rsa_der(private_der)
            }
            Algorithm::ES256 => jsonwebtoken::EncodingKey::from_ec_der(private_der),
            _ => unreachable!(),
        }
    }

    /// The public-side VerificationKey matching a generated private key.
    fn verification_key(algorithm: Algorithm, private_der: &[u8]) -> VerificationKey {
        let parts = public_components(algorithm, private_der);
        match algorithm {
            Algorithm::EdDSA => VerificationKey::from_ed_components(&parts[0]).unwrap(),
            Algorithm::RS256 | Algorithm::PS256 => {
                VerificationKey::from_rsa_components(&parts[0], &parts[1]).unwrap()
            }
            Algorithm::ES256 => VerificationKey::from_ec_components(&parts[0], &parts[1]).unwrap(),
            _ => unreachable!(),
        }
    }

    /// Old AWS-LC RSA-OAEP-256 encrypt oracle, moved verbatim from the
    /// retired application crypto helper.
    fn aws_rsa_oaep256_encrypt(n: &[u8], e: &[u8], plaintext: &[u8]) -> Vec<u8> {
        use der::{
            Encode as _,
            asn1::{Any, BitString, UintRef},
        };
        use x509_cert::spki::{
            AlgorithmIdentifierOwned, ObjectIdentifier, SubjectPublicKeyInfoOwned,
        };

        #[derive(der::Sequence)]
        struct RsaPublicKey<'a> {
            modulus: UintRef<'a>,
            public_exponent: UintRef<'a>,
        }

        let pkcs1 = RsaPublicKey {
            modulus: UintRef::new(n).unwrap(),
            public_exponent: UintRef::new(e).unwrap(),
        }
        .to_der()
        .unwrap();
        let spki = SubjectPublicKeyInfoOwned {
            algorithm: AlgorithmIdentifierOwned {
                oid: ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1"),
                parameters: Some(Any::null()),
            },
            subject_public_key: BitString::from_bytes(&pkcs1).unwrap(),
        }
        .to_der()
        .unwrap();
        let public = PublicEncryptingKey::from_der(&spki).unwrap();
        let public = OaepPublicEncryptingKey::new(public).unwrap();
        let mut ciphertext = vec![0; public.ciphertext_size()];
        public
            .encrypt(&OAEP_SHA256_MGF1SHA256, plaintext, &mut ciphertext, None)
            .unwrap()
            .to_vec()
    }

    #[test]
    fn jws_matches_existing_implementation() {
        for algorithm in [
            Algorithm::EdDSA,
            Algorithm::RS256,
            Algorithm::PS256,
            Algorithm::ES256,
        ] {
            let private_der = signature::generate_private_key(algorithm).unwrap();
            let decoding = native_decoding_key(algorithm, &private_der);
            let key = verification_key(algorithm, &private_der);
            let message = b"eyJhbGci.test-claims";

            let raw = sign_raw(algorithm, &private_der, message);
            if algorithm == Algorithm::ES256 {
                assert_eq!(raw.len(), 64, "ES256 stays JOSE fixed-width r||s");
            }
            let encoded = URL_SAFE_NO_PAD.encode(&raw);
            assert!(matches!(
                jsonwebtoken::crypto::verify(&encoded, message, &decoding, algorithm),
                Ok(true)
            ));
            assert!(signature::verify(algorithm, &key, message, &raw).is_ok());

            let native = jsonwebtoken::crypto::sign(
                message,
                &native_encoding_key(algorithm, &private_der),
                algorithm,
            )
            .unwrap();
            let native_raw = URL_SAFE_NO_PAD.decode(native).unwrap();
            assert!(signature::verify(algorithm, &key, message, &native_raw).is_ok());
            if algorithm == Algorithm::ES256 {
                assert_eq!(native_raw.len(), 64);
            }

            // Wrong message and tampered signatures must not verify.
            assert!(matches!(
                signature::verify(algorithm, &key, b"other", &raw),
                Err(CryptoError::InvalidSignature)
            ));
            let mut tampered = raw.clone();
            tampered[0] ^= 0x01;
            assert!(signature::verify(algorithm, &key, message, &tampered).is_err());

            // A signature from a different key must not verify.
            let other_der = signature::generate_private_key(algorithm).unwrap();
            let other_raw = sign_raw(algorithm, &other_der, message);
            assert!(signature::verify(algorithm, &key, message, &other_raw).is_err());
        }
    }

    #[test]
    fn jws_error_categories_preserve_dpop_semantics() {
        let private_der = signature::generate_private_key(Algorithm::EdDSA).unwrap();
        let key = verification_key(Algorithm::EdDSA, &private_der);
        let message = b"proof.signing-input";
        let raw = sign_raw(Algorithm::EdDSA, &private_der, message);

        // Mismatched content: native verify returns Ok(false); the boundary
        // must surface InvalidSignature, not a generic failure.
        let wrong = sign_raw(Algorithm::EdDSA, &private_der, b"other");
        assert!(matches!(
            signature::verify(Algorithm::EdDSA, &key, message, &wrong),
            Err(CryptoError::InvalidSignature)
        ));

        // A key/algorithm family combination the native verifier factory
        // rejects outright maps to InvalidInput, preserving the DPoP
        // malformed-proof category.
        let rsa_der = signature::generate_private_key(Algorithm::RS256).unwrap();
        let rsa_key = verification_key(Algorithm::RS256, &rsa_der);
        let encoded = URL_SAFE_NO_PAD.encode(&raw);
        assert!(
            jsonwebtoken::crypto::verify(
                &encoded,
                message,
                &native_decoding_key(Algorithm::RS256, &rsa_der),
                Algorithm::ES256,
            )
            .is_err()
        );
        assert!(matches!(
            signature::verify(Algorithm::ES256, &rsa_key, message, &raw),
            Err(CryptoError::InvalidInput)
        ));

        // Non-supported algorithms are rejected before touching the backend.
        assert!(matches!(
            signature::PreparedSigningKey::new(Algorithm::HS256, &private_der),
            Err(CryptoError::UnsupportedAlgorithm)
        ));
        assert!(matches!(
            signature::verify(Algorithm::HS256, &key, message, &raw),
            Err(CryptoError::UnsupportedAlgorithm)
        ));
        assert!(matches!(
            signature::generate_private_key(Algorithm::HS256),
            Err(CryptoError::UnsupportedAlgorithm)
        ));
    }

    #[derive(Deserialize)]
    #[allow(dead_code)]
    struct TestClaims {
        iss: String,
        aud: String,
        exp: i64,
    }

    #[test]
    fn jwt_decoding_preserves_claim_policy() {
        let private_der = signature::generate_private_key(Algorithm::EdDSA).unwrap();
        let key = verification_key(Algorithm::EdDSA, &private_der);
        let native_encoding = native_encoding_key(Algorithm::EdDSA, &private_der);

        let mut validation = jsonwebtoken::Validation::new(Algorithm::EdDSA);
        validation.set_issuer(&["https://issuer.example"]);
        validation.set_audience(&["https://audience.example"]);
        validation.required_spec_claims.insert("exp".to_owned());

        let make_token = |iss: &str, aud: &str, exp: i64| {
            jsonwebtoken::encode(
                &jsonwebtoken::Header::new(Algorithm::EdDSA),
                &serde_json::json!({"iss": iss, "aud": aud, "exp": exp}),
                &native_encoding,
            )
            .unwrap()
        };

        let valid = make_token(
            "https://issuer.example",
            "https://audience.example",
            4_000_000_000,
        );
        let decoded = jwt::decode::<TestClaims>(&valid, &key, &validation).unwrap();
        assert_eq!(decoded.claims.iss, "https://issuer.example");

        let expired = make_token("https://issuer.example", "https://audience.example", 1);
        assert!(matches!(
            jwt::decode::<TestClaims>(&expired, &key, &validation),
            Err(CryptoError::InvalidToken)
        ));

        let wrong_iss = make_token(
            "https://other.example",
            "https://audience.example",
            4_000_000_000,
        );
        assert!(matches!(
            jwt::decode::<TestClaims>(&wrong_iss, &key, &validation),
            Err(CryptoError::InvalidToken)
        ));

        let wrong_aud = make_token(
            "https://issuer.example",
            "https://other.example",
            4_000_000_000,
        );
        assert!(matches!(
            jwt::decode::<TestClaims>(&wrong_aud, &key, &validation),
            Err(CryptoError::InvalidToken)
        ));

        // A token signed by another key keeps the InvalidSignature category.
        let other_der = signature::generate_private_key(Algorithm::EdDSA).unwrap();
        let forged = jsonwebtoken::encode(
            &jsonwebtoken::Header::new(Algorithm::EdDSA),
            &serde_json::json!({"iss": "https://issuer.example", "aud": "https://audience.example", "exp": 4_000_000_000_i64}),
            &native_encoding_key(Algorithm::EdDSA, &other_der),
        )
        .unwrap();
        assert!(matches!(
            jwt::decode::<TestClaims>(&forged, &key, &validation),
            Err(CryptoError::InvalidSignature)
        ));

        // Header decoding and insecure decode keep parse-only semantics.
        let header = jwt::decode_header(&valid).unwrap();
        assert_eq!(header.alg, Algorithm::EdDSA);
        let insecure = jwt::dangerous::insecure_decode::<TestClaims>(&forged).unwrap();
        assert_eq!(insecure.claims.iss, "https://issuer.example");
        assert!(jwt::decode_header("not-a-jwt").is_err());
        assert!(jwt::dangerous::insecure_decode::<TestClaims>("not-a-jwt").is_err());

        // JWK component constructors reject malformed material as InvalidKey.
        assert!(matches!(
            VerificationKey::from_rsa_components("!!!", "AQAB"),
            Err(CryptoError::InvalidKey)
        ));
        assert!(matches!(
            VerificationKey::from_ec_components("!!!", "!!!"),
            Err(CryptoError::InvalidKey)
        ));
        assert!(matches!(
            VerificationKey::from_ed_components("!!!"),
            Err(CryptoError::InvalidKey)
        ));

        // The SEC1 constructor feeds SD-JWT leaf keys; it must produce a key
        // that verifies ES256 signatures.
        let es_der = signature::generate_private_key(Algorithm::ES256).unwrap();
        let es_raw = sign_raw(Algorithm::ES256, &es_der, b"input");
        use p256::pkcs8::DecodePrivateKey as _;
        let secret = p256::SecretKey::from_pkcs8_der(&es_der).unwrap();
        let point =
            p256::elliptic_curve::sec1::ToSec1Point::to_sec1_point(&secret.public_key(), false);
        let sec1_key = VerificationKey::from_ec_sec1(point.as_bytes());
        assert!(signature::verify(Algorithm::ES256, &sec1_key, b"input", &es_raw).is_ok());
    }

    #[test]
    fn stored_key_bytes_and_public_projection_are_compatible() {
        // Ed25519 material keeps the 16-byte prefix + 32-byte seed layout.
        let ed_der = signature::generate_private_key(Algorithm::EdDSA).unwrap();
        assert_eq!(ed_der.len(), 48);
        assert!(ed_der.starts_with(ED25519_PKCS8_PREFIX));
        let _usable = jsonwebtoken::EncodingKey::from_ed_der(&ed_der);

        // RSA signing material stays PKCS#1 usable by the old encoding key.
        let rsa_der = signature::generate_private_key(Algorithm::RS256).unwrap();
        let _usable = jsonwebtoken::EncodingKey::from_rsa_der(&rsa_der);

        // ES256 material stays PKCS#8 usable by the old encoding key.
        let es_der = signature::generate_private_key(Algorithm::ES256).unwrap();
        let _usable = jsonwebtoken::EncodingKey::from_ec_der(&es_der);

        // public_jwk returns only mathematical members matching the old
        // Jwk::from_encoding_key projection.
        for (algorithm, der, members) in [
            (Algorithm::RS256, &rsa_der, ["kty", "n", "e"].as_slice()),
            (
                Algorithm::ES256,
                &es_der,
                ["kty", "crv", "x", "y"].as_slice(),
            ),
        ] {
            let jwk = signature::public_jwk(algorithm, der).unwrap();
            let object = jwk.as_object().unwrap();
            assert_eq!(object.len(), members.len());
            for member in members {
                assert!(object.contains_key(*member), "missing {member}");
            }
            let native = jsonwebtoken::jwk::Jwk::from_encoding_key(
                &native_encoding_key(algorithm, der),
                algorithm,
            )
            .unwrap();
            let native_value = serde_json::to_value(native).unwrap();
            for member in members {
                assert_eq!(object[*member], native_value[*member]);
            }
        }
        let ed_jwk = signature::public_jwk(Algorithm::EdDSA, &ed_der).unwrap();
        assert_eq!(ed_jwk["kty"], "OKP");
        assert_eq!(ed_jwk["crv"], "Ed25519");
        let seed: [u8; 32] = ed_der[ED25519_PKCS8_PREFIX.len()..].try_into().unwrap();
        let native_public = ed25519_dalek::SigningKey::from_bytes(&seed)
            .verifying_key()
            .to_bytes();
        assert_eq!(ed_jwk["x"], URL_SAFE_NO_PAD.encode(native_public));

        // Request-object keys keep PKCS#8 storage sizes and the exact
        // AsDer(public) bytes used for kid derivation.
        for bits in [2048, 3072, 4096] {
            let pkcs8 = key_wrap::generate_rsa_pkcs8_der(bits).unwrap();
            let pair = aws_lc_rs::rsa::KeyPair::from_pkcs8(&pkcs8).unwrap();
            let (n, e, public_der) = key_wrap::rsa_public_components(&pkcs8).unwrap();
            let expected_der = AsDer::<PublicKeyX509Der<'static>>::as_der(pair.public_key())
                .unwrap()
                .as_ref()
                .to_vec();
            assert_eq!(public_der, expected_der);
            assert_eq!(
                n,
                pair.public_key()
                    .modulus()
                    .big_endian_without_leading_zero()
                    .to_vec()
            );
            assert_eq!(
                e,
                pair.public_key()
                    .exponent()
                    .big_endian_without_leading_zero()
                    .to_vec()
            );
        }
        assert!(matches!(
            key_wrap::generate_rsa_pkcs8_der(1024),
            Err(CryptoError::InvalidInput)
        ));
        assert!(matches!(
            key_wrap::validate_rsa_pkcs8(b"not der"),
            Err(CryptoError::InvalidKey)
        ));
    }

    #[test]
    fn rsa_oaep_and_key_wrap_interoperate() {
        let private_der = key_wrap::generate_rsa_pkcs8_der(2048).unwrap();
        let (n, e, _public_der) = key_wrap::rsa_public_components(&private_der).unwrap();
        let message = b"content-encryption-key";

        // New encrypt -> old AWS-LC decrypt.
        let ciphertext = key_wrap::rsa_oaep256_encrypt(&n, &e, message).unwrap();
        let private = PrivateDecryptingKey::from_pkcs8(&private_der).unwrap();
        let private = OaepPrivateDecryptingKey::new(private).unwrap();
        let mut plaintext = vec![0; private.min_output_size()];
        let decrypted = private
            .decrypt(&OAEP_SHA256_MGF1SHA256, &ciphertext, &mut plaintext, None)
            .unwrap();
        assert_eq!(decrypted, message);

        // Old AWS-LC encrypt -> new decrypt.
        let ciphertext = aws_rsa_oaep256_encrypt(&n, &e, message);
        let decrypted = key_wrap::rsa_oaep256_decrypt(&private_der, &ciphertext).unwrap();
        assert_eq!(decrypted, message);

        // Tampering fails authentication; malformed key material is InvalidKey.
        let mut tampered = ciphertext.clone();
        tampered[0] ^= 0x01;
        assert!(matches!(
            key_wrap::rsa_oaep256_decrypt(&private_der, &tampered),
            Err(CryptoError::AuthenticationFailed)
        ));
        assert!(matches!(
            key_wrap::rsa_oaep256_decrypt(b"garbage", &ciphertext),
            Err(CryptoError::InvalidKey)
        ));
        assert!(matches!(
            key_wrap::rsa_oaep256_encrypt(b"bad-n", b"bad-e", message),
            Err(CryptoError::InvalidKey)
        ));

        // RFC 3394 wrap output unwraps under the old AWS-LC oracle.
        for kek_len in [16_usize, 32] {
            let kek = vec![0x42_u8; kek_len];
            let cek = vec![0x07_u8; 32];
            let wrapped = key_wrap::aes_wrap(&kek, &cek).unwrap();
            assert_eq!(wrapped.len(), cek.len() + 8);
            let cipher = if kek_len == 16 { &AES_128 } else { &AES_256 };
            let kek_ref = AesKek::new(cipher, &kek).unwrap();
            let mut output = vec![0_u8; cek.len()];
            let unwrapped = kek_ref.unwrap(&wrapped, &mut output).unwrap();
            assert_eq!(unwrapped, cek.as_slice());
        }
        assert!(matches!(
            key_wrap::aes_wrap(&[0_u8; 24], &[0_u8; 32]),
            Err(CryptoError::InvalidKey)
        ));
        assert!(matches!(
            key_wrap::aes_wrap(&[0_u8; 16], &[0_u8; 8]),
            Err(CryptoError::InvalidInput)
        ));
        assert!(matches!(
            key_wrap::aes_wrap(&[0_u8; 16], &[0_u8; 20]),
            Err(CryptoError::InvalidInput)
        ));
    }
}

#[cfg(all(feature = "aead", feature = "jose"))]
mod aead_aws_oracle {
    use aws_lc_rs::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};

    pub fn aws_aes_256_gcm_encrypt(
        key: &[u8],
        nonce: &[u8],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Vec<u8> {
        let key = LessSafeKey::new(UnboundKey::new(&AES_256_GCM, key).unwrap());
        let nonce = Nonce::try_assume_unique_for_key(nonce).unwrap();
        let mut protected = plaintext.to_vec();
        key.seal_in_place_append_tag(nonce, Aad::from(aad), &mut protected)
            .unwrap();
        protected
    }
}

#[cfg(feature = "aead")]
mod aead {
    use aes_gcm::{
        Aes128Gcm, Aes256Gcm, KeyInit as _,
        aead::{Aead as _, Payload},
    };
    use nazo_crypto::{CryptoError, aead as crypto_aead};

    #[test]
    fn aead_ciphertexts_match_existing_layouts() {
        for key_len in [16_usize, 32] {
            let key = vec![0xAB_u8; key_len];
            let nonce = [0x11_u8; 12];
            for (aad, plaintext) in [
                (&b""[..], &b""[..]),
                (&b"aad"[..], &b"hello world"[..]),
                (&b""[..], &b"data"[..]),
            ] {
                let out = crypto_aead::encrypt(&key, &nonce, aad, plaintext).unwrap();
                assert_eq!(out.len(), plaintext.len() + 16);
                let payload = Payload {
                    msg: plaintext,
                    aad,
                };
                let expected = if key_len == 16 {
                    Aes128Gcm::new_from_slice(&key)
                        .unwrap()
                        .encrypt((&nonce).into(), payload)
                } else {
                    Aes256Gcm::new_from_slice(&key)
                        .unwrap()
                        .encrypt((&nonce).into(), payload)
                }
                .unwrap();
                assert_eq!(out, expected, "ct||tag layout must match aes-gcm");
                let back = crypto_aead::decrypt(&key, &nonce, aad, &out).unwrap();
                assert_eq!(back, plaintext);
            }
        }

        // Tampering never returns plaintext.
        let key = [0x5A_u8; 32];
        let nonce = [0x22_u8; 12];
        let aad = b"context";
        let out = crypto_aead::encrypt(&key, &nonce, aad, b"secret").unwrap();
        for mutated in [
            {
                let mut value = out.clone();
                value[0] ^= 0x01;
                value
            },
            {
                let mut value = out.clone();
                *value.last_mut().unwrap() ^= 0x01;
                value
            },
        ] {
            assert!(matches!(
                crypto_aead::decrypt(&key, &nonce, aad, &mutated),
                Err(CryptoError::AuthenticationFailed)
            ));
        }
        assert!(matches!(
            crypto_aead::decrypt(&key, &nonce, b"other", &out),
            Err(CryptoError::AuthenticationFailed)
        ));
        assert!(matches!(
            crypto_aead::decrypt(&[0x5A_u8; 16], &nonce, aad, &out),
            Err(CryptoError::AuthenticationFailed)
        ));
        assert!(matches!(
            crypto_aead::decrypt(&key, &[0x22_u8; 12].map(|b| b ^ 1), aad, &out),
            Err(CryptoError::AuthenticationFailed)
        ));

        // Input length categories.
        assert!(matches!(
            crypto_aead::encrypt(&key, &[0_u8; 11], aad, b"x"),
            Err(CryptoError::InvalidInput)
        ));
        assert!(matches!(
            crypto_aead::decrypt(&key, &nonce, aad, &[0_u8; 15]),
            Err(CryptoError::InvalidInput)
        ));
        assert!(matches!(
            crypto_aead::encrypt(&[0_u8; 24], &nonce, aad, b"x"),
            Err(CryptoError::InvalidKey)
        ));
        let empty = crypto_aead::encrypt(&key, &nonce, aad, b"").unwrap();
        assert_eq!(empty.len(), 16);

        // The retired AWS-LC A256GCM path produced identical bytes.
        #[cfg(feature = "jose")]
        {
            let aws = super::aead_aws_oracle::aws_aes_256_gcm_encrypt(&key, &nonce, aad, b"secret");
            assert_eq!(
                crypto_aead::encrypt(&key, &nonce, aad, b"secret").unwrap(),
                aws
            );
        }
    }
}

#[cfg(feature = "ecdh")]
mod ecdh {
    use nazo_crypto::{CryptoError, ec};

    #[test]
    fn p256_shared_secret_matches_existing_curve() {
        let mut scalar_a = [0_u8; 32];
        scalar_a[31] = 1;
        let mut scalar_b = [0_u8; 32];
        scalar_b[31] = 2;
        let a = ec::P256SecretKey::from_secret_bytes(&scalar_a).unwrap();
        let b = ec::P256SecretKey::from_secret_bytes(&scalar_b).unwrap();

        let public_a = a.public_key();
        let public_b = b.public_key();
        assert_eq!(public_a.len(), 65);
        assert_eq!(public_a[0], 0x04);
        assert_eq!(public_b[0], 0x04);

        let shared_ab = a.agree(&public_b).unwrap();
        let shared_ba = b.agree(&public_a).unwrap();
        assert_eq!(&shared_ab[..], &shared_ba[..]);

        // Native p256 oracle proves identical shared-secret bytes.
        let native_a = p256::SecretKey::from_slice(&scalar_a).unwrap();
        let native_b = p256::PublicKey::from_sec1_bytes(&public_b).unwrap();
        let expected =
            p256::ecdh::diffie_hellman(native_a.to_nonzero_scalar(), native_b.as_affine());
        assert_eq!(&shared_ab[..], expected.raw_secret_bytes().as_slice());

        // Scalar zero and malformed points are InvalidKey.
        assert!(matches!(
            ec::P256SecretKey::from_secret_bytes(&[0_u8; 32]),
            Err(CryptoError::InvalidKey)
        ));
        assert!(matches!(a.agree(&[0x04; 65]), Err(CryptoError::InvalidKey)));
        assert!(matches!(a.agree(&[0x04; 32]), Err(CryptoError::InvalidKey)));
        assert!(matches!(
            ec::normalize_p256_public_key(&[0x04; 65]),
            Err(CryptoError::InvalidKey)
        ));
        let normalized = ec::normalize_p256_public_key(&public_a).unwrap();
        assert_eq!(normalized, public_a);
        assert_eq!(a.secret_bytes(), scalar_a);
        assert_eq!(format!("{:?}", a), "P256SecretKey(..)");
    }
}

#[cfg(feature = "ed25519")]
mod ed25519 {
    use nazo_crypto::{CryptoError, ed25519};

    #[test]
    fn ed25519_matches_existing_dalek() {
        let seed = [7_u8; 32];
        let signing = ed25519::SigningKey::from_bytes(&seed);
        let message = b"operator statement";

        // Identical raw signature to the old Dalek path.
        let native = ed25519_dalek::SigningKey::from_bytes(&seed);
        let expected = ed25519_dalek::Signer::sign(&native, message).to_bytes();
        let signature = signing.sign(message);
        assert_eq!(signature, expected);
        assert_eq!(signature.len(), 64);

        let verifying = signing.verifying_key();
        assert_eq!(verifying.to_bytes(), native.verifying_key().to_bytes());
        assert!(verifying.verify(message, &signature).is_ok());
        ed25519_dalek::Verifier::verify(
            &native.verifying_key(),
            message,
            &ed25519_dalek::Signature::from_slice(&signature).unwrap(),
        )
        .unwrap();

        // Non-64-byte signature, wrong message, malformed public key.
        assert!(matches!(
            verifying.verify(message, &signature[..32]),
            Err(CryptoError::InvalidSignature)
        ));
        assert!(matches!(
            verifying.verify(b"other", &signature),
            Err(CryptoError::InvalidSignature)
        ));
        let mut bad_public = [0_u8; 32];
        bad_public[0] = 2; // y=2 has no curve point: decompression fails
        assert!(matches!(
            ed25519::VerifyingKey::from_bytes(&bad_public),
            Err(CryptoError::InvalidKey)
        ));

        assert_eq!(format!("{:?}", signing), "SigningKey(..)");
        assert_eq!(format!("{:?}", verifying), "VerifyingKey(..)");
        assert_eq!(signing.to_bytes(), seed);
    }
}

#[cfg(feature = "password")]
mod password {
    use argon2::{Argon2, PasswordHash, PasswordHasher as _, PasswordVerifier as _};
    use nazo_crypto::{CryptoError, password};

    const LEGACY_PHC: &str =
        "$argon2id$v=19$m=256,t=2,p=1$c29tZXNhbHQ$nf65EOgLrQMR/uIPnA4rEsF5h7TKyQwu9U1bMCHGi/4";

    #[test]
    fn argon2_accepts_stored_phc() {
        // Fixed Argon2id v19 vector from argon2 0.5.3 kat tests.
        assert!(password::verify_argon2_phc(LEGACY_PHC, b"password"));
        assert!(!password::verify_argon2_phc(LEGACY_PHC, b"wrong password"));
        assert!(!password::verify_argon2_phc("not a phc", b"password"));
        assert!(!password::verify_argon2_phc(
            "$argon2id$v=19$m=8",
            b"password"
        ));

        let produced = password::hash_argon2id(b"correct horse battery staple", 256, 2, 1).unwrap();
        assert!(produced.starts_with("$argon2id$v=19$m=256,t=2,p=1$"));
        let parsed = PasswordHash::new(&produced).unwrap();
        Argon2::default()
            .verify_password(b"correct horse battery staple", &parsed)
            .unwrap();

        let native = Argon2::default()
            .hash_password_with_salt(b"native secret", b"saltsalt")
            .unwrap()
            .to_string();
        assert!(password::verify_argon2_phc(&native, b"native secret"));

        assert!(matches!(
            password::hash_argon2id(b"x", 0, 2, 1),
            Err(CryptoError::InvalidInput)
        ));
        assert!(matches!(
            password::hash_argon2id(b"x", 256, 0, 1),
            Err(CryptoError::InvalidInput)
        ));
    }
}

#[cfg(feature = "x509")]
mod certificate {
    use nazo_crypto::{CryptoError, certificate as certs};
    use x509_parser::extensions::ParsedExtension;

    const NOW: i64 = 1_760_000_000;
    const CA_SECONDS: i64 = 3650 * 86_400;
    const LEAF_SECONDS: i64 = 457 * 86_400;
    const CA_SKI: [u8; 20] = [0xAA; 20];
    const LEAF_SKI: [u8; 20] = [0xBB; 20];

    fn at(seconds: i64) -> x509_parser::time::ASN1Time {
        x509_parser::time::ASN1Time::from_timestamp(seconds).unwrap()
    }

    fn to_pem(der: &[u8]) -> String {
        const ALPHABET: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut body = String::new();
        let mut chunk = 0_u32;
        let mut bits = 0_u32;
        for byte in der {
            chunk = (chunk << 8) | u32::from(*byte);
            bits += 8;
            while bits >= 6 {
                bits -= 6;
                body.push(ALPHABET[((chunk >> bits) & 0x3F) as usize] as char);
            }
        }
        if bits > 0 {
            body.push(ALPHABET[((chunk << (6 - bits)) & 0x3F) as usize] as char);
        }
        while !body.len().is_multiple_of(4) {
            body.push('=');
        }
        let mut wrapped = String::new();
        for part in body.as_bytes().chunks(64) {
            wrapped.push_str(std::str::from_utf8(part).unwrap());
            wrapped.push('\n');
        }
        format!("-----BEGIN CERTIFICATE-----\n{wrapped}-----END CERTIFICATE-----\n")
    }

    fn country() -> certs::DnValue {
        certs::DnValue::PrintableString(certs::PrintableString::try_from("DE").unwrap())
    }

    // Mirrors build_openid4vc_certificate_bundle's mdoc profile in keyctl.rs.
    fn ca_params() -> certs::CertificateParams {
        let mut params = certs::CertificateParams::default();
        params.distinguished_name = certs::DistinguishedName::new();
        params
            .distinguished_name
            .push(certs::DnType::CommonName, "NazoAuth OpenID4VC Local CA");
        params
            .distinguished_name
            .push(certs::DnType::CountryName, country());
        params.is_ca = certs::IsCa::Ca(certs::BasicConstraints::Constrained(0));
        params.key_usages = vec![
            certs::KeyUsagePurpose::KeyCertSign,
            certs::KeyUsagePurpose::CrlSign,
        ];
        params.not_before = at(NOW).to_datetime();
        params.not_after = at(NOW + CA_SECONDS).to_datetime();
        params.serial_number = Some(certs::SerialNumber::from(vec![0x42; 19]));
        params.key_identifier_method = certs::KeyIdMethod::PreSpecified(CA_SKI.to_vec());
        params
    }

    fn leaf_params(leaf_ski: &[u8]) -> certs::CertificateParams {
        let mut params = certs::CertificateParams::new(vec!["client.example".to_owned()]).unwrap();
        params.distinguished_name = certs::DistinguishedName::new();
        params
            .distinguished_name
            .push(certs::DnType::CommonName, "client.example");
        params
            .distinguished_name
            .push(certs::DnType::CountryName, country());
        params.is_ca = certs::IsCa::NoCa;
        params.key_usages = vec![certs::KeyUsagePurpose::DigitalSignature];
        params.not_before = at(NOW).to_datetime();
        params.not_after = at(NOW + LEAF_SECONDS).to_datetime();
        params.serial_number = Some(certs::SerialNumber::from(vec![0x7B; 19]));
        params.use_authority_key_identifier_extension = true;
        params
            .custom_extensions
            .push(subject_key_identifier(leaf_ski));
        params
    }

    // DER OCTET STRING wrapping, matching keyctl's yasna write_bytes.
    fn subject_key_identifier(key_id: &[u8]) -> certs::CustomExtension {
        let mut content = vec![0x04, key_id.len() as u8];
        content.extend_from_slice(key_id);
        certs::CustomExtension::from_oid_content(&[2, 5, 29, 14], content)
    }

    fn subject_key_id(
        certificate: &x509_parser::certificate::X509Certificate<'_>,
    ) -> Option<Vec<u8>> {
        certificate
            .extensions()
            .iter()
            .find_map(|extension| match extension.parsed_extension() {
                ParsedExtension::SubjectKeyIdentifier(identifier) => Some(identifier.0.to_vec()),
                _ => None,
            })
    }

    fn authority_key_id(
        certificate: &x509_parser::certificate::X509Certificate<'_>,
    ) -> Option<Vec<u8>> {
        certificate
            .extensions()
            .iter()
            .find_map(|extension| match extension.parsed_extension() {
                ParsedExtension::AuthorityKeyIdentifier(identifier) => {
                    identifier.key_identifier.as_ref().map(|key| key.0.to_vec())
                }
                _ => None,
            })
    }

    #[test]
    fn certificate_signatures_and_profiles_interoperate() {
        let this_update = at(NOW).to_datetime();
        let next_update = at(NOW + 86_400).to_datetime();

        // CA generation and public projection match the old rcgen path.
        let ca_key_pem = certs::generate_p256_private_key_pem().unwrap();
        let ca_der = certs::self_signed(ca_params(), &ca_key_pem).unwrap();
        let native_public = rcgen::KeyPair::from_pem(&ca_key_pem).unwrap();
        assert_eq!(
            certs::public_key_from_pem(&ca_key_pem).unwrap(),
            native_public.public_key_raw()
        );

        let (_, ca) = x509_parser::parse_x509_certificate(&ca_der).unwrap();
        assert_eq!(
            ca.subject()
                .iter_common_name()
                .next()
                .unwrap()
                .as_str()
                .unwrap(),
            "NazoAuth OpenID4VC Local CA"
        );
        assert_eq!(
            ca.subject()
                .iter_country()
                .next()
                .unwrap()
                .as_str()
                .unwrap(),
            "DE"
        );
        let ca_constraints = ca.basic_constraints().unwrap().unwrap();
        assert!(ca_constraints.value.ca);
        assert_eq!(ca_constraints.value.path_len_constraint, Some(0));
        assert_eq!(subject_key_id(&ca).as_deref(), Some(&CA_SKI[..]));
        assert!(ca.raw_serial().len() <= 20);
        assert_eq!(
            ca.validity().not_after.timestamp() - ca.validity().not_before.timestamp(),
            CA_SECONDS
        );
        assert!(certs::verify_signature(&ca, ca.public_key()).is_ok());
        ca.verify_signature(Some(ca.public_key())).unwrap();

        // Leaf issuance through the rebuilt issuer keeps DN/SKI/AKI/profile.
        let leaf_key_pem = certs::generate_p256_private_key_pem().unwrap();
        let leaf_der =
            certs::sign(leaf_params(&LEAF_SKI), &leaf_key_pem, &ca_der, &ca_key_pem).unwrap();
        let (_, leaf) = x509_parser::parse_x509_certificate(&leaf_der).unwrap();
        assert_eq!(
            leaf.subject()
                .iter_common_name()
                .next()
                .unwrap()
                .as_str()
                .unwrap(),
            "client.example"
        );
        assert_eq!(
            leaf.subject()
                .iter_country()
                .next()
                .unwrap()
                .as_str()
                .unwrap(),
            "DE"
        );
        assert_eq!(
            leaf.issuer(),
            ca.subject(),
            "leaf issuer must be the CA subject"
        );
        assert!(certs::verify_signature(&leaf, ca.public_key()).is_ok());
        leaf.verify_signature(Some(ca.public_key())).unwrap();
        assert!(matches!(
            certs::verify_signature(&leaf, leaf.public_key()),
            Err(CryptoError::InvalidSignature)
        ));
        assert!(
            !leaf
                .basic_constraints()
                .unwrap()
                .map(|constraints| constraints.value.ca)
                .unwrap_or_default()
        );
        assert_eq!(subject_key_id(&leaf).as_deref(), Some(&LEAF_SKI[..]));
        assert_eq!(authority_key_id(&leaf).as_deref(), Some(&CA_SKI[..]));
        assert!(leaf.raw_serial().len() <= 20);
        assert_eq!(
            leaf.validity().not_after.timestamp() - leaf.validity().not_before.timestamp(),
            LEAF_SECONDS
        );

        // CRL issuance through the rebuilt issuer keeps dates and serials.
        let crl = certs::CertificateRevocationListParams {
            this_update,
            next_update,
            crl_number: certs::SerialNumber::from(7_u64),
            issuing_distribution_point: None,
            revoked_certs: vec![certs::RevokedCertParams {
                serial_number: certs::SerialNumber::from(leaf.raw_serial().to_vec()),
                revocation_time: this_update,
                reason_code: None,
                invalidity_date: None,
            }],
            key_identifier_method: certs::KeyIdMethod::PreSpecified(CA_SKI.to_vec()),
        };
        let crl_der = certs::sign_crl(crl, &ca_der, &ca_key_pem).unwrap();
        let (_, parsed_crl) = x509_parser::parse_x509_crl(&crl_der).unwrap();
        assert_eq!(
            parsed_crl.issuer(),
            ca.subject(),
            "CRL issuer must be the CA subject"
        );
        assert_eq!(parsed_crl.last_update().timestamp(), NOW);
        assert_eq!(parsed_crl.next_update().unwrap().timestamp(), NOW + 86_400);
        assert_eq!(
            parsed_crl.crl_number().map(|number| number.to_string()),
            Some("7".to_owned())
        );
        let revoked = parsed_crl.iter_revoked_certificates().next().unwrap();
        assert_eq!(revoked.raw_serial(), leaf.raw_serial());
        assert_eq!(revoked.revocation_date.timestamp(), NOW);
        assert_eq!(parsed_crl.iter_revoked_certificates().count(), 1);
        assert!(parsed_crl.verify_signature(ca.public_key()).is_ok());

        // Standard client-chain verification against the anchor at a fixed time.
        let anchors = to_pem(&ca_der);
        assert!(
            certs::verify_client_chain_at(std::slice::from_ref(&leaf_der), &anchors, NOW as u64)
                .is_ok()
        );

        // Wrong trust root, expired, not-yet-valid, tampered or empty chain fail.
        let other_key_pem = certs::generate_p256_private_key_pem().unwrap();
        let other_der = certs::self_signed(ca_params(), &other_key_pem).unwrap();
        assert!(
            certs::verify_client_chain_at(
                std::slice::from_ref(&leaf_der),
                &to_pem(&other_der),
                NOW as u64
            )
            .is_err()
        );
        // Actual expiry: one second past the leaf's not_after.
        assert!(matches!(
            certs::verify_client_chain_at(
                std::slice::from_ref(&leaf_der),
                &anchors,
                (NOW + LEAF_SECONDS + 1) as u64
            ),
            Err(CryptoError::InvalidSignature)
        ));
        // Not yet valid: one second before the leaf's not_before.
        assert!(matches!(
            certs::verify_client_chain_at(
                std::slice::from_ref(&leaf_der),
                &anchors,
                (NOW - 1) as u64
            ),
            Err(CryptoError::InvalidSignature)
        ));
        let mut tampered = leaf_der.clone();
        *tampered.last_mut().unwrap() ^= 0x01;
        assert!(certs::verify_client_chain_at(&[tampered], &anchors, NOW as u64).is_err());
        assert!(matches!(
            certs::verify_client_chain_at(&[], &anchors, NOW as u64),
            Err(CryptoError::InvalidInput)
        ));
        assert!(matches!(
            certs::verify_client_chain_at(&[leaf_der], "not pem", NOW as u64),
            Err(CryptoError::InvalidInput)
        ));
        assert!(matches!(
            certs::public_key_from_pem("not a key"),
            Err(CryptoError::InvalidKey)
        ));
    }
}
