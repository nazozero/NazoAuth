use super::*;
use crate::config::ConfigSource;
use crate::db::create_pool;
use crate::domain::{ActiveSigningKey, Keyset};
use ed25519_dalek::{Signer, SigningKey};
use proptest::prelude::*;
use std::sync::Arc;

fn dpop_state(nonce_policy: DpopNoncePolicy) -> AppState {
    let mut settings =
        Settings::from_config(&ConfigSource::default()).expect("default settings should load");
    settings.issuer = "https://issuer.example".to_owned();
    settings.mtls_endpoint_base_url = "https://mtls.example".to_owned();
    settings.dpop_nonce_policy = nonce_policy;

    AppState {
        diesel_db: create_pool(
            "postgres://nazo_dpop_test_invalid:nazo_dpop_test_invalid@127.0.0.1:1/nazo".to_owned(),
            1,
        )
        .expect("pool construction should not connect"),
        valkey: fred::prelude::Builder::default_centralized()
            .build()
            .expect("valkey client construction should not connect"),
        settings: Arc::new(settings),
        keyset: Arc::new(Keyset {
            active_kid: "test-kid".to_owned(),
            active_alg: jsonwebtoken::Algorithm::EdDSA,
            active_signing_key: ActiveSigningKey::LocalPkcs8Der(Vec::new()),
            verification_keys: Vec::new(),
        }),
    }
}

#[test]
fn authorization_scheme_is_case_insensitive() {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::AUTHORIZATION,
        HeaderValue::from_static("dpop abc.def"),
    );

    let Some((scheme, token)) = authorization_access_token(&headers) else {
        panic!("authorization header should parse");
    };

    assert!(matches!(scheme, AccessTokenAuthScheme::DPoP));
    assert_eq!(token, "abc.def");
}

#[test]
fn bearer_scheme_is_case_insensitive() {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::AUTHORIZATION,
        HeaderValue::from_static("bearer token"),
    );

    let Some((scheme, token)) = authorization_access_token(&headers) else {
        panic!("authorization header should parse");
    };

    assert!(matches!(scheme, AccessTokenAuthScheme::Bearer));
    assert_eq!(token, "token");
}

#[test]
fn token_endpoint_nonce_challenge_uses_bad_request() {
    let response = dpop_error_response(
        DpopError::UseNonce("nonce-1".to_owned()),
        DpopErrorContext::TokenEndpoint,
    );

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        response.headers().get("dpop-nonce").unwrap(),
        HeaderValue::from_static("nonce-1")
    );
}

#[test]
fn protected_resource_nonce_challenge_uses_unauthorized() {
    let response = dpop_error_response(
        DpopError::UseNonce("nonce-1".to_owned()),
        DpopErrorContext::ProtectedResource,
    );

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        response.headers().get(header::WWW_AUTHENTICATE).unwrap(),
        HeaderValue::from_static(r#"DPoP error="use_dpop_nonce""#)
    );
}

#[test]
fn dpop_error_response_maps_reject_reasons_without_secret_material() {
    let cases = [
        (
            DpopError::MalformedProof,
            StatusCode::BAD_REQUEST,
            r#"DPoP error="invalid_dpop_proof""#,
        ),
        (
            DpopError::InvalidProof,
            StatusCode::BAD_REQUEST,
            r#"DPoP error="invalid_dpop_proof""#,
        ),
        (
            DpopError::ReplayDetected,
            StatusCode::BAD_REQUEST,
            r#"DPoP error="invalid_dpop_proof""#,
        ),
        (
            DpopError::BindingMismatch,
            StatusCode::BAD_REQUEST,
            r#"DPoP error="invalid_dpop_proof""#,
        ),
        (
            DpopError::TokenNotBound,
            StatusCode::BAD_REQUEST,
            r#"DPoP error="invalid_dpop_proof""#,
        ),
        (
            DpopError::NonceStoreUnavailable,
            StatusCode::SERVICE_UNAVAILABLE,
            r#"DPoP error="server_error""#,
        ),
    ];

    for (error, status, authenticate) in cases {
        let response = dpop_error_response(error, DpopErrorContext::TokenEndpoint);
        assert_eq!(response.status(), status);
        assert_eq!(
            response.headers().get(header::CACHE_CONTROL).unwrap(),
            HeaderValue::from_static("no-store")
        );
        assert_eq!(
            response.headers().get(header::WWW_AUTHENTICATE).unwrap(),
            HeaderValue::from_static(authenticate)
        );
    }
}

#[test]
fn token_endpoint_missing_proof_uses_bad_request() {
    let response = dpop_error_response(DpopError::MissingProof, DpopErrorContext::TokenEndpoint);

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        response.headers().get(header::WWW_AUTHENTICATE).unwrap(),
        HeaderValue::from_static(r#"DPoP error="invalid_dpop_proof""#)
    );
}

#[test]
fn authorization_header_rejects_empty_multi_token_and_unknown_schemes() {
    let mut headers = HeaderMap::new();
    headers.insert(header::AUTHORIZATION, HeaderValue::from_static("DPoP"));
    assert!(authorization_access_token(&headers).is_none());

    headers.insert(
        header::AUTHORIZATION,
        HeaderValue::from_static("DPoP one two"),
    );
    assert!(authorization_access_token(&headers).is_none());

    headers.insert(
        header::AUTHORIZATION,
        HeaderValue::from_static("PoP abc.def"),
    );
    assert!(authorization_access_token(&headers).is_none());
}

#[test]
fn dpop_iat_rejects_extreme_past_without_overflow() {
    assert!(!dpop_iat_within_window(i64::MIN, 1_000));
}

#[test]
fn dpop_iat_allows_clock_skew_but_not_far_future() {
    let now = 1_000;

    assert!(dpop_iat_within_window(now + DPOP_CLOCK_SKEW_SECONDS, now));
    assert!(!dpop_iat_within_window(
        now + DPOP_CLOCK_SKEW_SECONDS + 1,
        now
    ));
}

#[test]
fn dpop_jkt_uses_base64url_sha256_thumbprint_shape() {
    assert!(is_valid_dpop_jkt(
        "w7JAoU_gJbZJvV-zCOvU9yFJq0FNC_edCMRM78P8eQQ"
    ));
    assert!(!is_valid_dpop_jkt("short"));
    assert!(!is_valid_dpop_jkt(
        "w7JAoU/gJbZJvV+zCOvU9yFJq0FNC+edCMRM78P8eQQ"
    ));
}

#[test]
fn dpop_replay_key_is_scoped_to_jwk_thumbprint_and_jti_hash() {
    let first = dpop_replay_key("jkt-1", "proof-jti");
    let same = dpop_replay_key("jkt-1", "proof-jti");
    let other_key = dpop_replay_key("jkt-2", "proof-jti");
    let other_jti = dpop_replay_key("jkt-1", "other-proof-jti");

    assert_eq!(first, same);
    assert!(first.starts_with("oauth:dpop:jti:jkt-1:"));
    assert!(!first.contains("proof-jti"));
    assert_ne!(first, other_key);
    assert_ne!(first, other_jti);
}

#[test]
fn dpop_nonce_policy_controls_missing_nonce_requirement() {
    assert!(dpop_nonce_required(DpopNoncePolicy::Required));
    assert!(!dpop_nonce_required(DpopNoncePolicy::Optional));
}

#[test]
fn dpop_header_rejects_multiple_proofs() {
    let req = actix_web::test::TestRequest::get()
        .insert_header(("DPoP", "proof-1"))
        .append_header(("DPoP", "proof-2"))
        .to_http_request();

    assert!(matches!(
        dpop_proof_header(&req),
        Err(DpopError::MalformedProof)
    ));
}

#[test]
fn signed_dpop_proof_verifies_signature_thumbprint_and_claims() {
    let signing_key = SigningKey::from_bytes(&[7u8; 32]);
    let access_token = "access.token.value";
    let proof = signed_test_proof(
        &signing_key,
        "POST",
        "https://issuer.example/token?ignored=true",
        Utc::now().timestamp(),
        "proof-1",
        Some(access_token),
        Some("nonce-1"),
    );

    let (header, claims, signing_input, signature) = decode_proof(&proof).unwrap();
    let algorithm = client_jwt_algorithm_from_name(&header.alg).unwrap();
    verify_signature(&header.jwk, algorithm, signing_input.as_bytes(), &signature).unwrap();
    assert!(!jwk_thumbprint(&header.jwk).unwrap().is_empty());
    validate_dpop_claims(
        &["https://issuer.example"],
        "POST",
        "/token",
        &claims,
        Some(access_token),
    )
    .unwrap();
}

#[actix_web::test]
async fn dpop_proof_rejects_non_dpop_typ_before_nonce_or_replay_state() {
    let signing_key = SigningKey::from_bytes(&[13u8; 32]);
    let proof = signed_test_proof_with_typ(
        &signing_key,
        "jwt",
        "GET",
        "https://issuer.example/userinfo",
        Utc::now().timestamp(),
        "proof-wrong-typ",
        None,
        None,
    );
    let state = dpop_state(DpopNoncePolicy::Optional);
    let req = actix_web::test::TestRequest::get()
        .uri("/userinfo")
        .insert_header(("DPoP", proof))
        .to_http_request();

    assert!(matches!(
        validate_dpop_proof(&state, &req, None, None).await,
        Err(DpopError::InvalidProof)
    ));
}

#[actix_web::test]
async fn optional_dpop_nonce_policy_accepts_missing_nonce_without_store_access() {
    let state = dpop_state(DpopNoncePolicy::Optional);

    validate_dpop_nonce(&state, None)
        .await
        .expect("optional nonce policy must not require valkey access for absent nonce");
}

#[test]
fn dpop_claim_validation_rejects_wrong_method_htu_and_ath() {
    let signing_key = SigningKey::from_bytes(&[9u8; 32]);
    let proof = signed_test_proof(
        &signing_key,
        "POST",
        "https://issuer.example/token",
        Utc::now().timestamp(),
        "proof-2",
        Some("bound-token"),
        Some("nonce-2"),
    );
    let (_, claims, _, _) = decode_proof(&proof).unwrap();

    assert!(matches!(
        validate_dpop_claims(&["https://issuer.example"], "GET", "/token", &claims, None),
        Err(DpopError::InvalidProof)
    ));
    assert!(matches!(
        validate_dpop_claims(
            &["https://issuer.example"],
            "POST",
            "/userinfo",
            &claims,
            None
        ),
        Err(DpopError::InvalidProof)
    ));
    assert!(matches!(
        validate_dpop_claims(
            &["https://issuer.example"],
            "POST",
            "/token",
            &claims,
            Some("other-token")
        ),
        Err(DpopError::InvalidProof)
    ));
}

#[test]
fn dpop_claim_validation_rejects_stale_iat_and_blank_jti() {
    let claims = DpopClaims {
        htm: "GET".to_owned(),
        htu: "https://issuer.example/userinfo".to_owned(),
        iat: Utc::now().timestamp() - DPOP_TTL_SECONDS - 1,
        jti: "proof-stale".to_owned(),
        ath: None,
        nonce: None,
    };
    assert!(matches!(
        validate_dpop_claims(
            &["https://issuer.example"],
            "GET",
            "/userinfo",
            &claims,
            None
        ),
        Err(DpopError::InvalidProof)
    ));

    let claims = DpopClaims {
        iat: Utc::now().timestamp(),
        jti: "   ".to_owned(),
        ..claims
    };
    assert!(matches!(
        validate_dpop_claims(
            &["https://issuer.example"],
            "GET",
            "/userinfo",
            &claims,
            None
        ),
        Err(DpopError::InvalidProof)
    ));
}

#[test]
fn dpop_decode_rejects_extra_jwt_segments() {
    let proof = signed_test_proof(
        &SigningKey::from_bytes(&[15u8; 32]),
        "GET",
        "https://issuer.example/userinfo",
        Utc::now().timestamp(),
        "proof-extra-segment",
        None,
        None,
    );

    assert!(matches!(
        decode_proof(&format!("{proof}.extra")),
        Err(DpopError::MalformedProof)
    ));
}

#[test]
fn dpop_thumbprint_rejects_wrong_curve_and_unknown_key_type() {
    assert!(matches!(
        jwk_thumbprint(&json!({"kty": "OKP", "crv": "X25519", "x": "abc"})),
        Err(DpopError::InvalidProof)
    ));
    assert!(matches!(
        jwk_thumbprint(&json!({"kty": "EC", "crv": "P-384", "x": "abc", "y": "def"})),
        Err(DpopError::InvalidProof)
    ));
    assert!(matches!(
        jwk_thumbprint(&json!({"kty": "oct", "k": "abc"})),
        Err(DpopError::InvalidProof)
    ));
}

#[test]
fn dpop_signature_rejects_wrong_signature_bytes() {
    let proof = signed_test_proof(
        &SigningKey::from_bytes(&[17u8; 32]),
        "GET",
        "https://issuer.example/userinfo",
        Utc::now().timestamp(),
        "proof-invalid-signature",
        None,
        None,
    );
    let (header, _, signing_input, _) = decode_proof(&proof).unwrap();
    let invalid_signature = URL_SAFE_NO_PAD.encode([0u8; 64]);
    let algorithm = client_jwt_algorithm_from_name(&header.alg).unwrap();

    assert!(matches!(
        verify_signature(
            &header.jwk,
            algorithm,
            signing_input.as_bytes(),
            &invalid_signature
        ),
        Err(DpopError::InvalidProof)
    ));
}

#[test]
fn dpop_claim_validation_accepts_mtls_endpoint_base() {
    let signing_key = SigningKey::from_bytes(&[11u8; 32]);
    let proof = signed_test_proof(
        &signing_key,
        "POST",
        "https://mtls.example/token",
        Utc::now().timestamp(),
        "proof-mtls",
        None,
        Some("nonce-mtls"),
    );
    let (_, claims, _, _) = decode_proof(&proof).unwrap();

    validate_dpop_claims(
        &["https://issuer.example", "https://mtls.example"],
        "POST",
        "/token",
        &claims,
        None,
    )
    .unwrap();
}

proptest! {
    #[test]
    fn dpop_iat_window_accepts_only_configured_past_and_future_skew(
        age in 0i64..=DPOP_TTL_SECONDS,
        future_skew in 0i64..=DPOP_CLOCK_SKEW_SECONDS
    ) {
        let now = 1_700_000_000;

        prop_assert!(dpop_iat_within_window(now - age, now));
        prop_assert!(dpop_iat_within_window(now + future_skew, now));
        prop_assert!(!dpop_iat_within_window(now - DPOP_TTL_SECONDS - 1, now));
        prop_assert!(!dpop_iat_within_window(now + DPOP_CLOCK_SKEW_SECONDS + 1, now));
    }

    #[test]
    fn dpop_jti_accepts_non_empty_values_within_byte_limit(
        valid in "[A-Za-z0-9._~-]{1,128}",
        oversized in "[A-Za-z0-9._~-]{129,160}"
    ) {
        prop_assert!(valid_jti(&valid));
        prop_assert!(!valid_jti(&oversized));
        prop_assert!(!valid_jti(""));
        prop_assert!(!valid_jti("   "));
    }

    #[test]
    fn dpop_htu_normalization_removes_query_and_fragment(
        path in "[a-zA-Z0-9/_-]{0,32}",
        query in "[a-zA-Z0-9_=&-]{1,32}",
        fragment in "[a-zA-Z0-9_-]{1,16}"
    ) {
        let normalized_path = format!("/{}", path.trim_start_matches('/'));
        let htu = format!("https://issuer.example{normalized_path}?{query}#{fragment}");

        prop_assert_eq!(
            normalize_htu(&htu).unwrap(),
            format!("https://issuer.example{normalized_path}")
        );
    }
}

fn signed_test_proof(
    signing_key: &SigningKey,
    method: &str,
    htu: &str,
    iat: i64,
    jti: &str,
    token_for_ath: Option<&str>,
    nonce: Option<&str>,
) -> String {
    signed_test_proof_with_typ(
        signing_key,
        "dpop+jwt",
        method,
        htu,
        iat,
        jti,
        token_for_ath,
        nonce,
    )
}

#[allow(clippy::too_many_arguments)]
fn signed_test_proof_with_typ(
    signing_key: &SigningKey,
    typ: &str,
    method: &str,
    htu: &str,
    iat: i64,
    jti: &str,
    token_for_ath: Option<&str>,
    nonce: Option<&str>,
) -> String {
    let public_key = URL_SAFE_NO_PAD.encode(signing_key.verifying_key().to_bytes());
    let header = json!({
        "typ": typ,
        "alg": "EdDSA",
        "jwk": {
            "kty": "OKP",
            "crv": "Ed25519",
            "x": public_key
        }
    });
    let mut claims = json!({
        "htm": method,
        "htu": htu,
        "iat": iat,
        "jti": jti
    });
    if let Some(token) = token_for_ath {
        claims["ath"] = json!(URL_SAFE_NO_PAD.encode(Sha256::digest(token.as_bytes())));
    }
    if let Some(nonce) = nonce {
        claims["nonce"] = json!(nonce);
    }

    let encoded_header = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
    let encoded_claims = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap());
    let signing_input = format!("{encoded_header}.{encoded_claims}");
    let signature = signing_key.sign(signing_input.as_bytes());

    format!(
        "{}.{}",
        signing_input,
        URL_SAFE_NO_PAD.encode(signature.to_bytes())
    )
}
