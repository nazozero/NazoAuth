use super::tokens::*;
use super::*;
use crate::config::ConfigSource;
use crate::support::{generate_key_material, public_jwk_from_private_der};
use actix_web::test::TestRequest;

fn test_settings() -> Settings {
    Settings::from_config(&ConfigSource::default()).expect("default settings should load")
}

fn private_key_jwt_client(jwks: Value) -> ClientRow {
    ClientRow {
        id: Uuid::now_v7(),
        tenant_id: DEFAULT_TENANT_ID,
        realm_id: DEFAULT_REALM_ID,
        organization_id: DEFAULT_ORGANIZATION_ID,
        client_id: "client-1".to_owned(),
        client_name: "Client".to_owned(),
        client_type: "confidential".to_owned(),
        client_secret_argon2_hash: None,
        redirect_uris: json!(["https://client.example/callback"]),
        scopes: json!(["openid"]),
        allowed_audiences: json!(["resource://default"]),
        grant_types: json!(["authorization_code"]),
        token_endpoint_auth_method: "private_key_jwt".to_owned(),
        require_dpop_bound_tokens: false,
        require_mtls_bound_tokens: false,
        tls_client_auth_subject_dn: None,
        tls_client_auth_cert_sha256: None,
        tls_client_auth_san_dns: json!([]),
        tls_client_auth_san_uri: json!([]),
        tls_client_auth_san_ip: json!([]),
        tls_client_auth_san_email: json!([]),
        allow_client_assertion_audience_array: false,
        allow_client_assertion_endpoint_audience: false,
        require_par_request_object: false,
        allow_authorization_code_without_pkce: false,
        is_active: true,
        jwks: Some(jwks),
        post_logout_redirect_uris: json!([]),
        backchannel_logout_uri: None,
        backchannel_logout_session_required: true,
    }
}

fn signed_client_assertion(
    client_id: &str,
    audience: &str,
    kid: &str,
    private_pkcs8_der: &[u8],
    jti: &str,
) -> String {
    let now = Utc::now().timestamp();
    let claims = json!({
        "iss": client_id,
        "sub": client_id,
        "aud": audience,
        "iat": now,
        "nbf": now,
        "exp": now + 120,
        "jti": jti
    });
    let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
    header.kid = Some(kid.to_owned());
    jsonwebtoken::encode(
        &header,
        &claims,
        &jsonwebtoken::EncodingKey::from_rsa_der(private_pkcs8_der),
    )
    .expect("client assertion should sign")
}

#[test]
fn numeric_code_is_six_ascii_digits() {
    let code = random_numeric_code();

    assert_eq!(code.len(), 6);
    assert!(code.chars().all(|value| value.is_ascii_digit()));
}

#[test]
fn password_hash_policy_is_explicit_argon2id_v19() {
    let hash = hash_password("correct horse battery staple").expect("password should hash");

    assert!(hash.starts_with("$argon2id$v=19$m=19456,t=2,p=1$"));
    assert!(verify_password("correct horse battery staple", &hash));
    assert!(!verify_password("wrong password", &hash));
}

#[test]
fn random_urlsafe_token_is_256_bit_opaque_value() {
    let token = random_urlsafe_token();

    assert_eq!(token.len(), 43);
    assert!(
        token
            .chars()
            .all(|value| value.is_ascii_alphanumeric() || value == '-' || value == '_')
    );
}

#[test]
fn authorization_response_jwt_preserves_explicit_empty_state() {
    let input = AuthorizationResponseJwtInput {
        client_id: "client-1",
        code: Some("code-1"),
        error: None,
        state: Some(""),
        ttl: 60,
    };
    let claims = authorization_response_jwt_claims("https://issuer.example", &input, 123);

    assert_eq!(claims.get("state"), Some(&json!("")));
    assert_eq!(claims.get("code"), Some(&json!("code-1")));
    assert!(!claims.contains_key("error"));
}

#[test]
fn authorization_response_jwt_omits_absent_state_and_inapplicable_result() {
    let input = AuthorizationResponseJwtInput {
        client_id: "client-1",
        code: None,
        error: Some("invalid_request"),
        state: None,
        ttl: 60,
    };
    let claims = authorization_response_jwt_claims("https://issuer.example", &input, 123);

    assert!(!claims.contains_key("state"));
    assert!(!claims.contains_key("code"));
    assert_eq!(claims.get("error"), Some(&json!("invalid_request")));
}

#[test]
fn id_token_claims_include_independent_sid_and_protect_reserved_claims() {
    let amr = vec!["password".to_owned()];
    let extra_claims = json!({
        "sid": "attacker-controlled-sid",
        "azp": "attacker-controlled-azp",
        "email": "alice@example.com"
    });
    let input = IdTokenInput {
        subject: "subject-1",
        client_id: "client-1",
        nonce: Some("nonce-1".to_owned()),
        auth_time: Some(1_000),
        amr: &amr,
        sid: Some("server-session-sid"),
        acr: Some("urn:acr:1"),
        extra_claims: Some(&extra_claims),
        ttl: 600,
    };

    let claims = id_token_claims("https://issuer.example", &input, 2_000);

    assert_eq!(claims.get("sid"), Some(&json!("server-session-sid")));
    assert!(!claims.contains_key("azp"));
    assert_eq!(claims.get("email"), Some(&json!("alice@example.com")));
    assert_eq!(claims.get("nonce"), Some(&json!("nonce-1")));
    assert_eq!(claims.get("auth_time"), Some(&json!(1_000)));
    assert_eq!(claims.get("amr"), Some(&json!(["password"])));
    assert_eq!(claims.get("acr"), Some(&json!("urn:acr:1")));
}

#[test]
fn id_token_extra_claims_cannot_override_registered_claims() {
    let extra_claims = json!({
        "iss": "https://attacker.example",
        "sub": "attacker-subject",
        "aud": "attacker-client",
        "exp": 9_999_999,
        "email": "alice@example.com"
    });
    let input = IdTokenInput {
        subject: "subject-1",
        client_id: "client-1",
        nonce: None,
        auth_time: None,
        amr: &[],
        sid: None,
        acr: None,
        extra_claims: Some(&extra_claims),
        ttl: 600,
    };

    let claims = id_token_claims("https://issuer.example", &input, 2_000);

    assert_eq!(claims.get("iss"), Some(&json!("https://issuer.example")));
    assert_eq!(claims.get("sub"), Some(&json!("subject-1")));
    assert_eq!(claims.get("aud"), Some(&json!("client-1")));
    assert_eq!(claims.get("exp"), Some(&json!(2_600)));
    assert_eq!(claims.get("email"), Some(&json!("alice@example.com")));
}

#[test]
fn backchannel_logout_token_claims_follow_oidc_shape_without_nonce() {
    let input = BackchannelLogoutTokenInput {
        client_id: "client-1",
        subject: Some("user-1"),
        sid: Some("sid-1"),
        ttl: 120,
    };

    let claims = backchannel_logout_token_claims("https://issuer.example", &input, 2_000);

    assert_eq!(claims.get("iss"), Some(&json!("https://issuer.example")));
    assert_eq!(claims.get("aud"), Some(&json!("client-1")));
    assert_eq!(claims.get("sub"), Some(&json!("user-1")));
    assert_eq!(claims.get("sid"), Some(&json!("sid-1")));
    assert_eq!(
        claims.get("events").and_then(|events| {
            events.get("http://schemas.openid.net/event/backchannel-logout")
        }),
        Some(&json!({}))
    );
    assert!(claims.get("nonce").is_none());
    assert!(claims.get("jti").and_then(Value::as_str).is_some());
}

#[test]
fn access_token_header_uses_active_alg_kid_and_at_jwt_type() {
    let header = access_token_header(jsonwebtoken::Algorithm::PS256, "active-kid");

    assert_eq!(header.alg, jsonwebtoken::Algorithm::PS256);
    assert_eq!(header.kid.as_deref(), Some("active-kid"));
    assert_eq!(header.typ.as_deref(), Some("at+jwt"));
}

#[test]
fn access_token_claims_follow_jwt_profile_for_user_subjects() {
    let user_id = Uuid::now_v7();
    let scopes = vec!["profile".to_owned(), "openid".to_owned()];
    let claims = access_token_claims(
        "https://issuer.example",
        AccessTokenJwtInput {
            tenant_id: DEFAULT_TENANT_ID,
            subject: "pairwise-subject",
            user_id: Some(user_id),
            subject_type: "user",
            client_id: "client-1",
            audiences: &["https://issuer.example/userinfo".to_owned()],
            scopes: &scopes,
            authorization_details: &json!([]),
            userinfo_claims: &["email".to_owned()],
            userinfo_claim_requests: &[],
            ttl: 300,
            dpop_jkt: Some("thumbprint-jkt"),
            mtls_x5t_s256: None,
        },
        1_000,
        "jti-1",
    );

    assert_eq!(claims.iss, "https://issuer.example");
    assert_eq!(claims.aud, json!("https://issuer.example/userinfo"));
    assert_eq!(claims.exp, 1_300);
    assert_eq!(claims.iat, 1_000);
    assert_eq!(claims.nbf, 1_000);
    assert_eq!(claims.client_id, "client-1");
    assert_eq!(claims.tenant_id, DEFAULT_TENANT_ID.to_string());
    assert_eq!(claims.sub, "pairwise-subject");
    assert_eq!(
        claims.user_id.as_deref(),
        Some(user_id.to_string().as_str())
    );
    assert_eq!(claims.subject_type, "user");
    assert_eq!(claims.scope, "openid profile");
    assert_eq!(claims.token_use, "access");
    assert_eq!(claims.jti, "jti-1");
    assert_eq!(claims.userinfo_claims, vec!["email"]);
    let cnf = claims.cnf.expect("DPoP-bound token should carry cnf");
    assert_eq!(cnf.jkt.as_deref(), Some("thumbprint-jkt"));
    assert!(cnf.x5t_s256.is_none());
}

#[test]
fn access_token_claims_keep_client_credentials_subject_separate() {
    let scopes = vec!["write".to_owned(), "read".to_owned()];
    let claims = access_token_claims(
        "https://issuer.example",
        AccessTokenJwtInput {
            tenant_id: DEFAULT_TENANT_ID,
            subject: "service-client",
            user_id: None,
            subject_type: "client",
            client_id: "service-client",
            audiences: &[
                "resource://default".to_owned(),
                "https://api.example".to_owned(),
            ],
            scopes: &scopes,
            authorization_details: &json!([{"type":"payment_initiation","actions":["write"]}]),
            userinfo_claims: &[],
            userinfo_claim_requests: &[],
            ttl: 120,
            dpop_jkt: None,
            mtls_x5t_s256: Some("certificate-thumbprint"),
        },
        2_000,
        "jti-2",
    );

    assert_eq!(claims.sub, "service-client");
    assert!(claims.user_id.is_none());
    assert_eq!(claims.subject_type, "client");
    assert_eq!(claims.client_id, "service-client");
    assert_eq!(
        claims.aud,
        json!(["resource://default", "https://api.example"])
    );
    assert_eq!(claims.scope, "read write");
    assert_eq!(
        claims.authorization_details,
        json!([{"type":"payment_initiation","actions":["write"]}])
    );
    let cnf = claims.cnf.expect("mTLS-bound token should carry cnf");
    assert!(cnf.jkt.is_none());
    assert_eq!(cnf.x5t_s256.as_deref(), Some("certificate-thumbprint"));
}

#[test]
fn basic_client_credentials_scheme_is_case_insensitive() {
    let encoded = STANDARD.encode("client-1:secret-1");
    let req = TestRequest::default()
        .insert_header((
            header::AUTHORIZATION,
            HeaderValue::from_str(&format!("basic {encoded}")).unwrap(),
        ))
        .to_http_request();
    let settings = test_settings();

    assert!(has_basic_authorization_scheme(req.headers()));
    let credentials = extract_client_credentials(&req, &settings, None, None, None, None);

    assert_eq!(credentials.method, "client_secret_basic");
    assert_eq!(credentials.client_id.as_deref(), Some("client-1"));
    assert_eq!(credentials.client_secret.as_deref(), Some("secret-1"));
}

#[test]
fn malformed_basic_authorization_scheme_is_detected() {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::AUTHORIZATION,
        HeaderValue::from_static("Basic not-base64 with-space"),
    );

    assert!(has_basic_authorization_scheme(&headers));
}

#[test]
fn malformed_basic_authorization_is_not_decoded_as_basic_credentials() {
    let req = TestRequest::default()
        .insert_header((header::AUTHORIZATION, "Basic not-base64 with-space"))
        .to_http_request();
    let settings = test_settings();

    let credentials = extract_client_credentials(&req, &settings, None, None, None, None);

    assert_eq!(credentials.method, "none");
    assert!(credentials.client_id.is_none());
    assert!(credentials.client_secret.is_none());
}

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

#[test]
fn non_utf8_basic_authorization_scheme_is_detected() {
    let req = TestRequest::default()
        .insert_header((
            header::AUTHORIZATION,
            HeaderValue::from_bytes(b"Basic \xff").unwrap(),
        ))
        .to_http_request();
    let settings = test_settings();

    assert!(has_basic_authorization_scheme(req.headers()));
    let credentials = extract_client_credentials(&req, &settings, None, None, None, None);
    assert_eq!(credentials.method, "none");
}
