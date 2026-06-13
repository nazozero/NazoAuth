use super::*;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use proptest::prelude::*;
use serde_json::json;

fn request_object(payload: Value, alg: &str, signature: &str) -> String {
    let header = if alg == "none" {
        json!({"alg": "none"})
    } else {
        json!({"alg": alg, "kid": "kid-1"})
    };
    format!(
        "{}.{}.{}",
        URL_SAFE_NO_PAD.encode(header.to_string()),
        URL_SAFE_NO_PAD.encode(payload.to_string()),
        signature
    )
}

#[test]
fn unverified_client_id_allows_basic_unsigned_request_object_claims() {
    let token = request_object(
        json!({
            "client_id": "client-a",
            "redirect_uri": "https://client.example/callback",
            "response_type": "code",
            "scope": "openid",
            "state": "state-1",
            "nonce": "nonce-1"
        }),
        "none",
        "",
    );
    assert_eq!(
        unverified_request_object_client_id(&token).as_deref(),
        Some("client-a")
    );
}

#[test]
fn unverified_client_id_rejects_mismatched_party_claims() {
    let token = request_object(
        json!({
            "iss": "client-a",
            "sub": "client-a",
            "client_id": "client-a",
            "aud": "https://issuer.example",
            "exp": 4102444800i64,
            "jti": "jar-1"
        }),
        "EdDSA",
        &URL_SAFE_NO_PAD.encode("signature"),
    );
    assert_eq!(
        unverified_request_object_client_id(&token).as_deref(),
        Some("client-a")
    );

    let mismatched = request_object(
        json!({
            "iss": "client-a",
            "sub": "client-a",
            "client_id": "client-b",
            "aud": "https://issuer.example",
            "exp": 4102444800i64,
            "jti": "jar-2"
        }),
        "EdDSA",
        &URL_SAFE_NO_PAD.encode("signature"),
    );
    assert!(unverified_request_object_client_id(&mismatched).is_none());
}

#[test]
fn unverified_client_id_rejects_invalid_compact_signatures() {
    let payload = json!({"client_id": "client-a"});
    let unsigned_with_signature = request_object(
        payload.clone(),
        "none",
        &URL_SAFE_NO_PAD.encode("signature"),
    );
    assert!(unverified_request_object_client_id(&unsigned_with_signature).is_none());

    let signed_without_signature = request_object(payload, "EdDSA", "");
    assert!(unverified_request_object_client_id(&signed_without_signature).is_none());
}

#[test]
fn request_object_jti_is_optional_but_validated_when_present() {
    assert!(is_valid_request_object_jti("abc"));
    assert!(!is_valid_request_object_jti(""));
    assert!(!is_valid_request_object_jti(&"a".repeat(129)));

    let basic = RequestObjectClaims {
        client_id: "client-a".to_owned(),
        iss: None,
        sub: None,
        aud: None,
        exp: None,
        nbf: None,
        iat: None,
        jti: None,
        params: HashMap::new(),
    };
    assert!(request_object_jti_valid(
        &basic,
        RequestObjectMode::BasicOidc,
        RequestObjectJtiPolicy::RequiredForSignedJar
    ));
    assert!(request_object_jti_valid(
        &basic,
        RequestObjectMode::SignedJar,
        RequestObjectJtiPolicy::Optional
    ));
    assert!(!request_object_jti_valid(
        &basic,
        RequestObjectMode::SignedJar,
        RequestObjectJtiPolicy::RequiredForSignedJar
    ));

    let invalid = RequestObjectClaims {
        jti: Some(String::new()),
        ..basic
    };
    assert!(!request_object_jti_valid(
        &invalid,
        RequestObjectMode::SignedJar,
        RequestObjectJtiPolicy::RequiredForSignedJar
    ));
}

#[test]
fn request_object_params_rejects_request_uri_claim() {
    let mut claims = RequestObjectClaims {
        client_id: "client-a".to_owned(),
        iss: None,
        sub: None,
        aud: None,
        exp: None,
        nbf: None,
        iat: None,
        jti: None,
        params: HashMap::from([
            (
                "redirect_uri".to_owned(),
                json!("https://client.example/callback"),
            ),
            ("request_uri".to_owned(), json!("urn:example:bad")),
        ]),
    };
    assert!(request_object_params(&claims).is_err());

    claims.params.remove("request_uri");
    let params = request_object_params(&claims).expect("valid request object params");
    assert_eq!(
        params.get("redirect_uri").map(String::as_str),
        Some("https://client.example/callback")
    );
}

fn time_claims(exp: Option<i64>, nbf: Option<i64>, iat: Option<i64>) -> RequestObjectClaims {
    RequestObjectClaims {
        client_id: "client-a".to_owned(),
        iss: None,
        sub: None,
        aud: None,
        exp,
        nbf,
        iat,
        jti: None,
        params: HashMap::new(),
    }
}

#[test]
fn signed_request_object_requires_exp_and_nbf() {
    let now = 1_700_000_000;

    assert!(!request_object_times_valid(
        &time_claims(None, Some(now), None),
        now,
        RequestObjectMode::SignedJar
    ));
    assert!(!request_object_times_valid(
        &time_claims(Some(now + 60), None, None),
        now,
        RequestObjectMode::SignedJar
    ));
    assert!(request_object_times_valid(
        &time_claims(Some(now + 60), Some(now), None),
        now,
        RequestObjectMode::SignedJar
    ));
}

#[test]
fn signed_request_object_rejects_invalid_nbf_window() {
    let now = 1_700_000_000;

    assert!(request_object_times_valid(
        &time_claims(Some(now + 300), Some(now + 8), None),
        now,
        RequestObjectMode::SignedJar
    ));
    assert!(!request_object_times_valid(
        &time_claims(Some(now + 300), Some(now + 31), None),
        now,
        RequestObjectMode::SignedJar
    ));
    assert!(!request_object_times_valid(
        &time_claims(Some(now + 60), Some(now - 301), None),
        now,
        RequestObjectMode::SignedJar
    ));
}

#[test]
fn signed_request_object_rejects_invalid_exp_window() {
    let now = 1_700_000_000;

    assert!(!request_object_times_valid(
        &time_claims(Some(now), Some(now), None),
        now,
        RequestObjectMode::SignedJar
    ));
    assert!(request_object_times_valid(
        &time_claims(Some(now + 301), Some(now), None),
        now,
        RequestObjectMode::SignedJar
    ));
    assert!(!request_object_times_valid(
        &time_claims(Some(now + 331), Some(now), None),
        now,
        RequestObjectMode::SignedJar
    ));
    assert!(!request_object_times_valid(
        &time_claims(Some(now + 60), Some(now + 60), None),
        now,
        RequestObjectMode::SignedJar
    ));
}

#[test]
fn dpop_bound_client_rejects_unsigned_request_objects() {
    let mut client = ClientRow {
        id: Uuid::now_v7(),
        tenant_id: DEFAULT_TENANT_ID,
        realm_id: DEFAULT_REALM_ID,
        organization_id: DEFAULT_ORGANIZATION_ID,
        client_id: "client-a".to_owned(),
        client_name: "Client A".to_owned(),
        client_type: "confidential".to_owned(),
        client_secret_argon2_hash: None,
        redirect_uris: json!([]),
        scopes: json!([]),
        allowed_audiences: json!([]),
        grant_types: json!([]),
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
        jwks: None,
        post_logout_redirect_uris: json!([]),
        backchannel_logout_uri: None,
        backchannel_logout_session_required: true,
    };

    assert!(request_object_mode_allowed(
        &client,
        RequestObjectMode::BasicOidc
    ));
    assert!(request_object_mode_allowed(
        &client,
        RequestObjectMode::SignedJar
    ));

    client.require_dpop_bound_tokens = true;
    assert!(!request_object_mode_allowed(
        &client,
        RequestObjectMode::BasicOidc
    ));
    assert!(request_object_mode_allowed(
        &client,
        RequestObjectMode::SignedJar
    ));
}

#[test]
fn par_request_object_policy_rejects_unsigned_request_objects() {
    let mut client = ClientRow {
        id: Uuid::now_v7(),
        tenant_id: DEFAULT_TENANT_ID,
        realm_id: DEFAULT_REALM_ID,
        organization_id: DEFAULT_ORGANIZATION_ID,
        client_id: "client-a".to_owned(),
        client_name: "Client A".to_owned(),
        client_type: "confidential".to_owned(),
        client_secret_argon2_hash: None,
        redirect_uris: json!([]),
        scopes: json!([]),
        allowed_audiences: json!([]),
        grant_types: json!([]),
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
        jwks: None,
        post_logout_redirect_uris: json!([]),
        backchannel_logout_uri: None,
        backchannel_logout_session_required: true,
    };

    assert!(request_object_mode_allowed(
        &client,
        RequestObjectMode::BasicOidc
    ));

    client.require_par_request_object = true;
    assert!(!request_object_mode_allowed(
        &client,
        RequestObjectMode::BasicOidc
    ));
    assert!(request_object_mode_allowed(
        &client,
        RequestObjectMode::SignedJar
    ));
}

#[test]
fn signed_request_object_sub_is_optional_but_must_match_when_present() {
    let mut claims = RequestObjectClaims {
        client_id: "client-a".to_owned(),
        iss: Some("client-a".to_owned()),
        sub: None,
        aud: None,
        exp: None,
        nbf: None,
        iat: None,
        jti: None,
        params: HashMap::new(),
    };
    let client = ClientRow {
        id: Uuid::now_v7(),
        tenant_id: DEFAULT_TENANT_ID,
        realm_id: DEFAULT_REALM_ID,
        organization_id: DEFAULT_ORGANIZATION_ID,
        client_id: "client-a".to_owned(),
        client_name: "Client A".to_owned(),
        client_type: "confidential".to_owned(),
        client_secret_argon2_hash: None,
        redirect_uris: json!([]),
        scopes: json!([]),
        allowed_audiences: json!([]),
        grant_types: json!([]),
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
        jwks: None,
        post_logout_redirect_uris: json!([]),
        backchannel_logout_uri: None,
        backchannel_logout_session_required: true,
    };

    assert!(request_object_party_claims_valid(
        &claims,
        &client,
        RequestObjectMode::SignedJar
    ));

    claims.sub = Some("client-a".to_owned());
    assert!(request_object_party_claims_valid(
        &claims,
        &client,
        RequestObjectMode::SignedJar
    ));

    claims.sub = Some("client-b".to_owned());
    assert!(!request_object_party_claims_valid(
        &claims,
        &client,
        RequestObjectMode::SignedJar
    ));
}

proptest! {
    #[test]
    fn request_object_params_accept_supported_string_number_and_claims_object_values(
        state in "[A-Za-z0-9._~-]{1,32}",
        max_age in 0i64..=3_600
    ) {
        let claims = RequestObjectClaims {
            client_id: "client-a".to_owned(),
            iss: None,
            sub: None,
            aud: None,
            exp: None,
            nbf: None,
            iat: None,
            jti: None,
            params: HashMap::from([
                ("state".to_owned(), json!(state)),
                ("max_age".to_owned(), json!(max_age)),
                ("claims".to_owned(), json!({"id_token": {"auth_time": {"essential": true}}})),
                ("unknown".to_owned(), json!("ignored")),
            ]),
        };

        let params = request_object_params(&claims).unwrap();
        let expected_max_age = max_age.to_string();

        prop_assert_eq!(params.get("state").map(String::as_str), Some(state.as_str()));
        prop_assert_eq!(params.get("max_age").map(String::as_str), Some(expected_max_age.as_str()));
        prop_assert!(params.get("claims").is_some_and(|value| value.contains("auth_time")));
        prop_assert!(!params.contains_key("unknown"));
    }

    #[test]
    fn request_object_params_reject_invalid_supported_value_types(
        state in "[A-Za-z0-9._~-]{1,32}"
    ) {
        let claims = RequestObjectClaims {
            client_id: "client-a".to_owned(),
            iss: None,
            sub: None,
            aud: None,
            exp: None,
            nbf: None,
            iat: None,
            jti: None,
            params: HashMap::from([
                ("state".to_owned(), json!([state])),
            ]),
        };

        prop_assert!(request_object_params(&claims).is_err());
    }

    #[test]
    fn signed_request_object_time_window_accepts_only_profile_bounds(
        lifetime in 1i64..=REQUEST_OBJECT_MAX_TTL_SECONDS + REQUEST_OBJECT_CLOCK_SKEW_SECONDS,
        nbf_skew in 0i64..=REQUEST_OBJECT_CLOCK_SKEW_SECONDS
    ) {
        let now = 1_700_000_000;
        let nbf = now + nbf_skew;

        prop_assert!(request_object_times_valid(
            &time_claims(Some(nbf + lifetime), Some(nbf), None),
            now,
            RequestObjectMode::SignedJar
        ));
        prop_assert!(!request_object_times_valid(
            &time_claims(
                Some(nbf + REQUEST_OBJECT_MAX_TTL_SECONDS + REQUEST_OBJECT_CLOCK_SKEW_SECONDS + 1),
                Some(nbf),
                None
            ),
            now,
            RequestObjectMode::SignedJar
        ));
    }
}
