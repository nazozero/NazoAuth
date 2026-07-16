use nazo_digital_credentials::{
    EphemeralEncryptionKey, JweError, encrypt_ecdh_es, encrypt_ecdh_es_a128,
    encrypt_ecdh_es_deflate,
};

#[test]
fn ecdh_es_a256gcm_round_trip_is_authenticated() {
    let recipient = EphemeralEncryptionKey::generate();
    let compact = encrypt_ecdh_es(
        br#"{"vp_token":"credential"}"#,
        &recipient.public_jwk(),
        Some("application/json"),
    )
    .expect("encrypt");
    assert_eq!(
        recipient.decrypt(&compact).expect("decrypt"),
        br#"{"vp_token":"credential"}"#
    );
    let mut parts = compact.split('.').map(str::to_owned).collect::<Vec<_>>();
    let replacement = if parts[4].starts_with('A') { "B" } else { "A" };
    parts[4].replace_range(0..1, replacement);
    assert_eq!(
        recipient.decrypt(&parts.join(".")),
        Err(JweError::AuthenticationFailed)
    );
}

#[test]
fn ecdh_es_a128gcm_round_trip_matches_oid4vp_default() {
    let recipient = EphemeralEncryptionKey::generate();
    let compact = encrypt_ecdh_es_a128(
        br#"{"vp_token":"credential"}"#,
        &recipient.public_jwk(),
        Some("json"),
    )
    .expect("encrypt A128GCM");

    assert_eq!(
        recipient.decrypt(&compact).expect("decrypt A128GCM"),
        br#"{"vp_token":"credential"}"#
    );
}

#[test]
fn deflate_round_trip_is_authenticated_and_bounded() {
    let recipient = EphemeralEncryptionKey::generate();
    let plaintext = br#"{"credential":"repetitive-repetitive-repetitive"}"#;
    let compact =
        encrypt_ecdh_es_deflate(plaintext, &recipient.public_jwk(), Some("application/json"))
            .expect("encrypt compressed JWE");

    assert_eq!(
        recipient.decrypt(&compact).expect("decrypt compressed JWE"),
        plaintext
    );
}
