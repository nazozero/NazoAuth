use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::json;

use crate::KeySettings;

fn settings() -> KeySettings {
    KeySettings {
        rotation_interval: chrono::Duration::days(90),
        prepublish_window: chrono::Duration::days(1),
        verification_grace: chrono::Duration::minutes(10),
    }
}

#[tokio::test]
async fn dedicated_request_object_key_decrypts_authenticated_nested_jwt() {
    let manager = crate::test_support::key_manager(settings()).await.unwrap();
    let jwk = manager.snapshot().request_object_encryption_jwk.clone();
    let nested = "header.claims.signature";
    let compact = encrypt(&jwk, nested.as_bytes());

    assert_eq!(
        manager
            .decrypt_request_object(&compact)
            .expect("request object decrypts"),
        nested
    );
}

#[tokio::test]
async fn authenticated_request_object_rejects_unimplemented_critical_headers() {
    let manager = crate::test_support::key_manager(settings()).await.unwrap();
    let jwk = manager.snapshot().request_object_encryption_jwk.clone();
    for critical in [json!(["unknown"]), json!([]), serde_json::Value::Null] {
        let compact = encrypt_with_header(
            &jwk,
            b"header.claims.signature",
            json!({
                "alg": "RSA-OAEP-256", "enc": "A256GCM", "kid": jwk["kid"],
                "cty": "JWT", "crit": critical, "unknown": true
            }),
        );
        assert!(
            manager
                .decrypt_request_object(&compact)
                .unwrap_err()
                .to_string()
                .contains("unsupported request object JWE header")
        );
    }
}

#[tokio::test]
async fn request_object_decryption_uses_the_current_generation_recipient_key() {
    let manager = crate::test_support::key_manager(settings()).await.unwrap();
    let old_jwk = manager.snapshot().request_object_encryption_jwk.clone();
    let old_compact = encrypt(&old_jwk, b"old.claims.signature");
    assert_eq!(
        manager.decrypt_request_object(&old_compact).unwrap(),
        "old.claims.signature"
    );
    let replacement = crate::test_support::key_manager(settings()).await.unwrap();
    let new_jwk = replacement.snapshot().request_object_encryption_jwk.clone();
    assert_ne!(old_jwk["kid"], new_jwk["kid"]);
    manager
        .inner
        .generation
        .store(replacement.inner.generation.load_full());
    assert!(manager.decrypt_request_object(&old_compact).is_err());
    assert_eq!(
        manager
            .decrypt_request_object(&encrypt(&new_jwk, b"new.claims.signature"))
            .unwrap(),
        "new.claims.signature",
    );
}

#[tokio::test]
async fn request_object_decryption_rejects_tampered_ciphertext() {
    let manager = crate::test_support::key_manager(settings()).await.unwrap();
    let jwk = manager.snapshot().request_object_encryption_jwk.clone();
    let mut compact = encrypt(&jwk, b"header.claims.signature");
    for (segment, lengths) in [(2, [0, 11, 13]), (4, [0, 15, 17])] {
        for length in lengths {
            let encoded = URL_SAFE_NO_PAD.encode(vec![0_u8; length]);
            let mut segments: Vec<_> = compact.split('.').collect();
            segments[segment] = &encoded;
            assert!(manager.decrypt_request_object(&segments.join(".")).is_err());
        }
    }
    let replacement = if compact.ends_with('A') { 'B' } else { 'A' };
    compact.pop();
    compact.push(replacement);

    assert!(manager.decrypt_request_object(&compact).is_err());
}

#[tokio::test]
async fn request_object_decryption_rejects_invalid_encrypted_key_before_aead() {
    let manager = crate::test_support::key_manager(settings()).await.unwrap();
    let jwk = manager.snapshot().request_object_encryption_jwk.clone();
    let protected = URL_SAFE_NO_PAD.encode(
        serde_json::to_vec(&json!({
            "alg": "RSA-OAEP-256",
            "enc": "A256GCM",
            "kid": jwk["kid"],
            "cty": "JWT"
        }))
        .expect("header"),
    );
    let compact = format!(
        "{}.{}.{}.{}.{}",
        protected,
        URL_SAFE_NO_PAD.encode([1_u8, 2, 3]),
        URL_SAFE_NO_PAD.encode([0_u8; 12]),
        URL_SAFE_NO_PAD.encode([0_u8; 1]),
        URL_SAFE_NO_PAD.encode([0_u8; 16])
    );

    let error = manager
        .decrypt_request_object(&compact)
        .expect_err("invalid RSA ciphertext must fail before AEAD");
    assert!(format!("{error:#}").contains("RSA") || format!("{error:#}").contains("decrypt"));
}

fn encrypt(jwk: &serde_json::Value, plaintext: &[u8]) -> String {
    let kid = jwk["kid"].as_str().expect("kid");
    encrypt_with_header(
        jwk,
        plaintext,
        json!({
            "alg": "RSA-OAEP-256", "enc": "A256GCM", "kid": kid, "cty": "JWT"
        }),
    )
}

fn encrypt_with_header(
    jwk: &serde_json::Value,
    plaintext: &[u8],
    header: serde_json::Value,
) -> String {
    let protected = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).expect("header"));
    let cek = rand::random::<[u8; 32]>();
    let encrypted_key = crate::crypto_test_support::rsa_oaep_sha256_encrypt(
        &URL_SAFE_NO_PAD
            .decode(jwk["n"].as_str().expect("n"))
            .expect("n encoding"),
        &URL_SAFE_NO_PAD
            .decode(jwk["e"].as_str().expect("e"))
            .expect("e encoding"),
        &cek,
    )
    .expect("encrypt key");

    let iv = rand::random::<[u8; 12]>();
    let (ciphertext, tag) =
        crate::crypto_test_support::aes_256_gcm_encrypt(&cek, &iv, protected.as_bytes(), plaintext)
            .expect("encrypt payload");
    format!(
        "{}.{}.{}.{}.{}",
        protected,
        URL_SAFE_NO_PAD.encode(encrypted_key),
        URL_SAFE_NO_PAD.encode(iv),
        URL_SAFE_NO_PAD.encode(ciphertext),
        URL_SAFE_NO_PAD.encode(tag)
    )
}
