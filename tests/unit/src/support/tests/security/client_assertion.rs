use super::*;

#[test]
fn par_client_assertion_accepts_only_issuer_audience() {
    let expected = client_assertion_audience_candidates("https://issuer.example", "/par", false);

    assert!(audience_matches(
        &json!("https://issuer.example"),
        &expected,
        false
    ));
    assert!(!audience_matches(
        &json!("https://issuer.example/par"),
        &expected,
        false
    ));
    assert!(!audience_matches(
        &json!("https://issuer.example/token"),
        &expected,
        false
    ));
    assert!(!audience_matches(
        &json!(["https://issuer.example", "https://unexpected.example"]),
        &expected,
        false
    ));
    assert!(!audience_matches(
        &json!("https://issuer.example/authorize"),
        &expected,
        false
    ));
    assert!(!audience_matches(
        &json!(["https://unexpected.example"]),
        &expected,
        false
    ));
}

#[test]
fn par_client_assertion_endpoint_audiences_require_client_policy() {
    let expected = client_assertion_audience_candidates("https://issuer.example", "/par", true);

    assert!(audience_matches(
        &json!("https://issuer.example"),
        &expected,
        false
    ));
    assert!(audience_matches(
        &json!("https://issuer.example/par"),
        &expected,
        false
    ));
    assert!(audience_matches(
        &json!("https://issuer.example/token"),
        &expected,
        false
    ));
    assert!(!audience_matches(
        &json!("https://issuer.example/authorize"),
        &expected,
        false
    ));
}

#[test]
fn client_assertion_audience_arrays_require_explicit_client_policy() {
    let expected = client_assertion_audience_candidates("https://issuer.example", "/par", false);

    assert!(audience_matches(
        &json!(["https://issuer.example", "https://unexpected.example"]),
        &expected,
        true
    ));
    assert!(!audience_matches(
        &json!(["https://issuer.example", "https://unexpected.example"]),
        &expected,
        false
    ));
}

#[test]
fn token_client_assertion_accepts_issuer_and_token_endpoint_audience() {
    let expected = client_assertion_audience_candidates("https://issuer.example", "/token", false);

    assert!(audience_matches(
        &json!("https://issuer.example"),
        &expected,
        false
    ));
    assert!(audience_matches(
        &json!("https://issuer.example/token"),
        &expected,
        false
    ));
    assert!(!audience_matches(
        &json!("https://issuer.example/par"),
        &expected,
        false
    ));
    assert!(!audience_matches(
        &json!(["https://issuer.example", "https://unexpected.example"]),
        &expected,
        false
    ));
    assert!(audience_matches(
        &json!(["https://issuer.example", "https://unexpected.example"]),
        &expected,
        true
    ));
    assert!(!audience_matches(
        &json!(["https://unexpected.example"]),
        &expected,
        true
    ));
}

#[test]
fn private_key_jwt_accepts_current_and_previous_jwks_during_rotation() {
    let first = generate_key_material(jsonwebtoken::Algorithm::RS256)
        .expect("first key should generate")
        .private_pkcs8_der;
    let second = generate_key_material(jsonwebtoken::Algorithm::RS256)
        .expect("second key should generate")
        .private_pkcs8_der;
    let first_jwk = public_jwk_from_private_der("kid-1", jsonwebtoken::Algorithm::RS256, &first)
        .expect("first jwk should derive");
    let second_jwk = public_jwk_from_private_der("kid-2", jsonwebtoken::Algorithm::RS256, &second)
        .expect("second jwk should derive");
    let client = private_key_jwt_client(json!({"keys": [first_jwk, second_jwk]}));
    let settings = test_settings();
    let req = TestRequest::post().uri("/token").to_http_request();
    let first_assertion = signed_client_assertion(
        &client.client_id,
        &settings.issuer,
        "kid-1",
        &first,
        "jti-first",
    );
    let second_assertion = signed_client_assertion(
        &client.client_id,
        &settings.issuer,
        "kid-2",
        &second,
        "jti-second",
    );

    assert!(
        verify_private_key_jwt_claims_with_settings(&settings, &req, &client, &first_assertion)
            .is_ok()
    );
    assert!(
        verify_private_key_jwt_claims_with_settings(&settings, &req, &client, &second_assertion)
            .is_ok()
    );
}

#[test]
fn private_key_jwt_rejects_assertions_after_key_retirement() {
    let retired = generate_key_material(jsonwebtoken::Algorithm::RS256)
        .expect("retired key should generate")
        .private_pkcs8_der;
    let active = generate_key_material(jsonwebtoken::Algorithm::RS256)
        .expect("active key should generate")
        .private_pkcs8_der;
    let active_jwk =
        public_jwk_from_private_der("active-kid", jsonwebtoken::Algorithm::RS256, &active)
            .expect("active jwk should derive");
    let client = private_key_jwt_client(json!({"keys": [active_jwk]}));
    let settings = test_settings();
    let req = TestRequest::post().uri("/token").to_http_request();
    let retired_assertion = signed_client_assertion(
        &client.client_id,
        &settings.issuer,
        "retired-kid",
        &retired,
        "jti-retired",
    );

    let result =
        verify_private_key_jwt_claims_with_settings(&settings, &req, &client, &retired_assertion);

    assert!(matches!(result, Err(ClientAssertionError::Invalid)));
}

#[test]
fn private_key_jwt_replay_key_is_client_scoped_and_hashed() {
    let first = client_assertion_replay_key("client-1", "assertion-jti");
    let same = client_assertion_replay_key("client-1", "assertion-jti");
    let other_client = client_assertion_replay_key("client-2", "assertion-jti");
    let other_jti = client_assertion_replay_key("client-1", "other-jti");

    assert_eq!(first, same);
    assert!(first.starts_with("oauth:client_assertion:jti:"));
    assert!(!first.contains("client-1"));
    assert!(!first.contains("assertion-jti"));
    assert_ne!(first, other_client);
    assert_ne!(first, other_jti);
}

#[test]
fn private_key_jwt_replay_ttl_is_bounded_to_assertion_window() {
    let assertion = ValidatedClientAssertion {
        jti: "jti-1".to_owned(),
        exp: 1_000,
        kid: "kid-1".to_owned(),
    };

    assert_eq!(assertion.replay_ttl_seconds(900), 100);
    assert_eq!(
        assertion.replay_ttl_seconds(1_000 - CLIENT_ASSERTION_MAX_TTL_SECONDS - 1),
        CLIENT_ASSERTION_MAX_TTL_SECONDS as u64
    );
    assert_eq!(assertion.replay_ttl_seconds(1_001), 1);
}
