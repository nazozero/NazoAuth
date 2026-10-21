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
async fn unique_request_object_recipient_accepts_omitted_kid_but_rejects_wrong_kid() {
    let manager = crate::test_support::key_manager(settings()).await.unwrap();
    let jwk = manager.snapshot().request_object_encryption_jwk.clone();
    let header = json!({"alg":"RSA-OAEP-256", "enc":"A256GCM", "cty":"JWT"});
    let compact = encrypt_with_header(&jwk, b"header.claims.signature", header.clone());
    assert_eq!(
        manager.decrypt_request_object(&compact).unwrap(),
        "header.claims.signature"
    );
    let mut wrong = header;
    wrong["kid"] = json!("unavailable-key");
    assert!(
        manager
            .decrypt_request_object(&encrypt_with_header(
                &jwk,
                b"header.claims.signature",
                wrong
            ))
            .is_err()
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

#[tokio::test]
async fn protocol_and_encryption_rotation_prepublishes_switches_and_retires_in_one_generation() {
    use crate::{SigningKeyRepository, SigningKeyWrappingKeyRing};
    use std::sync::Arc;
    let repository = Arc::new(crate::test_support::MemorySigningKeyRepository::default());
    let tenant = uuid::Uuid::now_v7();
    let wrapping = SigningKeyWrappingKeyRing::new("wrapping", [42; 32], None).unwrap();
    let manager = crate::KeyManager::load_or_create_database(
        settings(),
        None,
        tenant,
        repository.clone(),
        wrapping.clone(),
    )
    .await
    .unwrap();
    let old_jwk = manager.snapshot().request_object_encryption_jwk.clone();
    let old_compact = encrypt(&old_jwk, b"old.claims.signature");
    let old_ps = manager
        .snapshot()
        .signing_verification_key(
            nazo_auth::SigningPurpose::AccessToken,
            nazo_crypto::jwt::Algorithm::PS256,
        )
        .unwrap()
        .kid
        .clone();
    let mut record = repository.load().await.unwrap().unwrap();
    let mut payload: serde_json::Value =
        serde_json::from_slice(wrapping.open_generation(tenant, &mut record).unwrap()).unwrap();
    let aged = (chrono::Utc::now() - settings().rotation_interval - chrono::Duration::seconds(1))
        .to_rfc3339();
    payload["request_object_created_at"] = json!(aged);
    for key in payload["keys"].as_array_mut().unwrap() {
        if key["kid"] == old_ps {
            key["created_at"] = json!(aged);
        }
    }
    repository.replace(Some(
        crate::database::persist_payload(tenant, record.revision + 1, payload, &wrapping).unwrap(),
    ));
    manager.refresh().await.unwrap();
    assert_eq!(manager.snapshot().request_object_encryption_jwk, old_jwk);
    assert_eq!(
        manager
            .snapshot()
            .signing_verification_key(
                nazo_auth::SigningPurpose::AccessToken,
                nazo_crypto::jwt::Algorithm::PS256
            )
            .unwrap()
            .kid,
        old_ps
    );
    let mut record = repository.load().await.unwrap().unwrap();
    assert!(
        !serde_json::to_string(&record.public_metadata)
            .unwrap()
            .contains("private_pem")
    );
    let mut payload: serde_json::Value =
        serde_json::from_slice(wrapping.open_generation(tenant, &mut record).unwrap()).unwrap();
    let candidate = &payload["request_object_retained_keys"][0];
    let candidate_der = super::private_key(&candidate["private_pem"]).unwrap();
    let next_jwk = super::request_object_encryption_jwk(&candidate_der).unwrap();
    let new_compact = encrypt(&next_jwk, b"new.claims.signature");
    assert_eq!(
        manager.decrypt_request_object(&new_compact).unwrap(),
        "new.claims.signature",
        "next recipient is loaded before it is advertised"
    );
    assert!(
        manager.snapshot().jwks()["keys"]
            .as_array()
            .unwrap()
            .iter()
            .all(|key| key["kid"] != next_jwk["kid"])
    );
    let next_ps = payload["keys"]
        .as_array()
        .unwrap()
        .iter()
        .find(|key| key["prepublished"] == true)
        .unwrap()["kid"]
        .as_str()
        .unwrap()
        .to_owned();
    assert!(
        !manager
            .snapshot()
            .verification_key(&next_ps)
            .unwrap()
            .can_sign(nazo_auth::SigningPurpose::AccessToken)
    );
    let ready = (chrono::Utc::now() - settings().prepublish_window - chrono::Duration::seconds(1))
        .to_rfc3339();
    payload["request_object_retained_keys"][0]["created_at"] = json!(ready);
    for key in payload["keys"].as_array_mut().unwrap() {
        if key["kid"] == next_ps {
            key["created_at"] = json!(ready);
        }
    }
    repository.replace(Some(
        crate::database::persist_payload(tenant, record.revision + 1, payload, &wrapping).unwrap(),
    ));
    manager.refresh().await.unwrap();
    assert_eq!(manager.snapshot().request_object_encryption_jwk, next_jwk);
    assert_eq!(
        manager.decrypt_request_object(&old_compact).unwrap(),
        "old.claims.signature"
    );
    assert_eq!(
        manager.decrypt_request_object(&new_compact).unwrap(),
        "new.claims.signature"
    );
    assert_eq!(
        manager
            .snapshot()
            .signing_verification_key(
                nazo_auth::SigningPurpose::AccessToken,
                nazo_crypto::jwt::Algorithm::PS256
            )
            .unwrap()
            .kid,
        next_ps
    );
    assert!(
        !manager
            .snapshot()
            .verification_key(&old_ps)
            .unwrap()
            .can_sign(nazo_auth::SigningPurpose::AccessToken)
    );
    let mut record = repository.load().await.unwrap().unwrap();
    let mut payload: serde_json::Value =
        serde_json::from_slice(wrapping.open_generation(tenant, &mut record).unwrap()).unwrap();
    let expired = (chrono::Utc::now() - chrono::Duration::seconds(1)).to_rfc3339();
    payload["request_object_retained_keys"][0]["retire_at"] = json!(expired);
    for key in payload["keys"].as_array_mut().unwrap() {
        if key["kid"] == old_ps {
            key["retire_at"] = json!(expired);
        }
    }
    repository.replace(Some(
        crate::database::persist_payload(tenant, record.revision + 1, payload, &wrapping).unwrap(),
    ));
    manager.refresh().await.unwrap();
    assert!(manager.decrypt_request_object(&old_compact).is_err());
    assert!(manager.snapshot().verification_key(&old_ps).is_none());
    let mut record = repository.load().await.unwrap().unwrap();
    let payload: serde_json::Value =
        serde_json::from_slice(wrapping.open_generation(tenant, &mut record).unwrap()).unwrap();
    assert!(
        payload["request_object_retained_keys"][0]
            .get("private_pem")
            .is_none()
    );
    assert!(
        payload["keys"]
            .as_array()
            .unwrap()
            .iter()
            .find(|key| key["kid"] == old_ps)
            .unwrap()
            .get("private_pkcs8_der")
            .is_none()
    );
}
