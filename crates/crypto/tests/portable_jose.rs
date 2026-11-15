//! The same independent vectors and production operations run on native and WASM.
#![cfg(feature = "jose")]

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use nazo_crypto::jwt::{Algorithm, Validation, VerificationKey};
use nazo_crypto::{CryptoError, jwt, key_wrap, signature};
use serde_json::Value;

fn vectors() -> Value {
    serde_json::from_str(include_str!("fixtures/portable-jose.json")).unwrap()
}

fn bytes(value: &Value) -> Vec<u8> {
    URL_SAFE_NO_PAD.decode(value.as_str().unwrap()).unwrap()
}

fn algorithm(vector: &Value) -> Algorithm {
    serde_json::from_value(vector["algorithm"].clone()).unwrap()
}

fn verification_key(jwk: &Value) -> VerificationKey {
    match jwk["kty"].as_str().unwrap() {
        "RSA" => VerificationKey::from_rsa_components(
            jwk["n"].as_str().unwrap(),
            jwk["e"].as_str().unwrap(),
        )
        .unwrap(),
        "EC" => VerificationKey::from_ec_components(
            jwk["x"].as_str().unwrap(),
            jwk["y"].as_str().unwrap(),
        )
        .unwrap(),
        "OKP" => VerificationKey::from_ed_components(jwk["x"].as_str().unwrap()).unwrap(),
        _ => unreachable!(),
    }
}

fn validation(algorithm: Algorithm) -> Validation {
    let mut validation = Validation::new(algorithm);
    validation.set_audience(&["https://audience.example"]);
    validation.set_issuer(&["https://issuer.example"]);
    validation
}

#[cfg_attr(
    all(target_arch = "wasm32", target_os = "unknown"),
    wasm_bindgen_test::wasm_bindgen_test
)]
#[cfg_attr(not(all(target_arch = "wasm32", target_os = "unknown")), test)]
fn all_jose_algorithms_interoperate_with_independent_vectors() {
    let fixture = vectors();
    let message = bytes(&fixture["message"]);
    for vector in fixture["signatures"].as_array().unwrap() {
        let algorithm = algorithm(vector);
        let private = bytes(&vector["private_der"]);
        let key = verification_key(&vector["public_jwk"]);
        let expected = bytes(&vector["signature"]);
        signature::verify(algorithm, &key, &message, &expected).unwrap();
        assert_eq!(
            signature::public_jwk(algorithm, &private).unwrap(),
            vector["public_jwk"]
        );

        let prepared = signature::PreparedSigningKey::new(algorithm, &private).unwrap();
        let signed = prepared.sign(&message).unwrap();
        signature::verify(algorithm, &key, &message, &signed).unwrap();
        if matches!(algorithm, Algorithm::EdDSA | Algorithm::RS256) {
            assert_eq!(signed, expected);
        }
        let mut tampered = expected;
        tampered[0] ^= 1;
        assert_eq!(
            signature::verify(algorithm, &key, &message, &tampered),
            Err(CryptoError::InvalidSignature)
        );

        let token = vector["token"].as_str().unwrap();
        let claims = jwt::decode::<Value>(token, &key, &validation(algorithm))
            .unwrap()
            .claims;
        assert_eq!(claims["sub"], "subject");
        let mut wrong_audience = validation(algorithm);
        wrong_audience.set_audience(&["https://wrong.example"]);
        assert!(jwt::decode::<Value>(token, &key, &wrong_audience).is_err());

        let header = URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&serde_json::json!({"alg": algorithm})).unwrap());
        let expired = URL_SAFE_NO_PAD.encode(
            br#"{"iss":"https://issuer.example","aud":"https://audience.example","exp":1}"#,
        );
        let input = format!("{header}.{expired}");
        let expired = format!(
            "{input}.{}",
            URL_SAFE_NO_PAD.encode(prepared.sign(input.as_bytes()).unwrap())
        );
        assert!(jwt::decode::<Value>(&expired, &key, &validation(algorithm)).is_err());
    }
}

#[cfg_attr(
    all(target_arch = "wasm32", target_os = "unknown"),
    wasm_bindgen_test::wasm_bindgen_test
)]
#[cfg_attr(not(all(target_arch = "wasm32", target_os = "unknown")), test)]
fn rsa_oaep_preserves_key_format_and_authenticated_decryption() {
    let fixture = vectors();
    let vector = &fixture["rsa_oaep"];
    let private = bytes(&vector["private_pkcs8"]);
    let plaintext = bytes(&vector["plaintext"]);
    let ciphertext = bytes(&vector["ciphertext"]);
    let (n, e, spki) = key_wrap::rsa_public_components(&private).unwrap();
    assert_eq!(spki, bytes(&vector["public_spki"]));
    let prepared = key_wrap::RsaOaep256PrivateKey::from_pkcs8(&private).unwrap();
    assert_eq!(prepared.decrypt(&ciphertext).unwrap(), plaintext);
    let encrypted = key_wrap::rsa_oaep256_encrypt(&n, &e, &plaintext).unwrap();
    assert_eq!(prepared.decrypt(&encrypted).unwrap(), plaintext);
    assert_ne!(ciphertext, encrypted);
    let mut tampered = ciphertext.clone();
    tampered[0] ^= 1;
    assert_eq!(
        prepared.decrypt(&tampered),
        Err(CryptoError::AuthenticationFailed)
    );
}

#[cfg_attr(
    all(target_arch = "wasm32", target_os = "unknown"),
    wasm_bindgen_test::wasm_bindgen_test
)]
#[cfg_attr(not(all(target_arch = "wasm32", target_os = "unknown")), test)]
fn rsa_import_rejects_inconsistent_crt_coefficients() {
    let fixture = vectors();
    let vector = &fixture["signatures"][1];
    let mut pkcs1 = bytes(&vector["private_der"]);
    *pkcs1.last_mut().unwrap() ^= 1;
    assert!(signature::PreparedSigningKey::new(Algorithm::RS256, &pkcs1).is_err());

    let mut pkcs8 = bytes(&fixture["rsa_oaep"]["private_pkcs8"]);
    *pkcs8.last_mut().unwrap() ^= 1;
    assert!(key_wrap::RsaOaep256PrivateKey::from_pkcs8(&pkcs8).is_err());
}

#[cfg_attr(
    all(target_arch = "wasm32", target_os = "unknown"),
    wasm_bindgen_test::wasm_bindgen_test
)]
#[cfg_attr(not(all(target_arch = "wasm32", target_os = "unknown")), test)]
fn rsa_verification_rejects_undersized_and_noncanonical_keys() {
    let fixture = vectors();
    let weak = &fixture["undersized_rsa"];
    let key = VerificationKey::from_rsa_components(
        weak["n"].as_str().unwrap(),
        weak["e"].as_str().unwrap(),
    )
    .unwrap();
    assert!(
        signature::verify(
            Algorithm::RS256,
            &key,
            &bytes(&fixture["message"]),
            &bytes(&weak["signature"])
        )
        .is_err()
    );
    assert!(
        jwt::decode::<Value>(
            weak["token"].as_str().unwrap(),
            &key,
            &validation(Algorithm::RS256)
        )
        .is_err()
    );

    let vector = &fixture["signatures"][1];
    let n = bytes(&vector["public_jwk"]["n"]);
    let e = bytes(&vector["public_jwk"]["e"]);
    for (n, e) in [
        (
            vec![0].into_iter().chain(n.clone()).collect::<Vec<_>>(),
            e.clone(),
        ),
        (n, vec![0].into_iter().chain(e).collect()),
    ] {
        let key = VerificationKey::from_rsa_raw_components(&n, &e);
        assert!(
            signature::verify(
                Algorithm::RS256,
                &key,
                &bytes(&fixture["message"]),
                &bytes(&vector["signature"])
            )
            .is_err()
        );
        assert!(
            jwt::decode::<Value>(
                vector["token"].as_str().unwrap(),
                &key,
                &validation(Algorithm::RS256)
            )
            .is_err()
        );
    }
}

#[cfg_attr(
    all(target_arch = "wasm32", target_os = "unknown"),
    wasm_bindgen_test::wasm_bindgen_test
)]
#[cfg_attr(not(all(target_arch = "wasm32", target_os = "unknown")), test)]
fn malformed_ed25519_keys_return_errors() {
    let fixture = vectors();
    let vector = &fixture["signatures"][0];
    for len in [0, 1, 31, 33] {
        let key =
            VerificationKey::from_ed_components(&URL_SAFE_NO_PAD.encode(vec![7; len])).unwrap();
        assert!(
            signature::verify(
                Algorithm::EdDSA,
                &key,
                &bytes(&fixture["message"]),
                &bytes(&vector["signature"])
            )
            .is_err()
        );
        assert!(
            jwt::decode::<Value>(
                vector["token"].as_str().unwrap(),
                &key,
                &validation(Algorithm::EdDSA)
            )
            .is_err()
        );
    }
}

#[cfg_attr(
    all(target_arch = "wasm32", target_os = "unknown"),
    wasm_bindgen_test::wasm_bindgen_test
)]
#[cfg_attr(not(all(target_arch = "wasm32", target_os = "unknown")), test)]
fn aes_wrap_matches_independent_rfc3394_vectors() {
    let fixture = vectors();
    let key: [u8; 32] = bytes(&fixture["rsa_oaep"]["plaintext"]).try_into().unwrap();
    for vector in fixture["aes_wrap"].as_array().unwrap() {
        let kek = bytes(&vector["kek"]);
        assert_eq!(
            key_wrap::aes_wrap(&kek, &key).unwrap().as_slice(),
            bytes(&vector["wrapped"])
        );
    }
    assert_eq!(
        key_wrap::aes_wrap(&[0; 24], &key),
        Err(CryptoError::InvalidKey)
    );
}

#[cfg_attr(
    all(target_arch = "wasm32", target_os = "unknown"),
    wasm_bindgen_test::wasm_bindgen_test
)]
#[cfg_attr(not(all(target_arch = "wasm32", target_os = "unknown")), test)]
fn generated_rsa_keys_support_real_private_operations() {
    let private = key_wrap::generate_rsa_pkcs8_der(2048).unwrap();
    let (n, e, _) = key_wrap::rsa_public_components(&private).unwrap();
    assert_eq!(n.len(), 256);
    assert_eq!(e, [1, 0, 1]);
    let encrypted = key_wrap::rsa_oaep256_encrypt(&n, &e, b"generated key").unwrap();
    let prepared = key_wrap::RsaOaep256PrivateKey::from_pkcs8(&private).unwrap();
    assert_eq!(prepared.decrypt(&encrypted).unwrap(), b"generated key");
    assert_eq!(
        key_wrap::generate_rsa_pkcs8_der(1024),
        Err(CryptoError::InvalidInput)
    );
}
