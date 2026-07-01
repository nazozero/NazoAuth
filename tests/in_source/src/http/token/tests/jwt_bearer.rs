use super::*;
use crate::config::ConfigSource;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

fn jwt_bearer_client(client_id: &str, kid: &str, private_pkcs8_der: &[u8]) -> ClientRow {
    let public_jwk =
        public_jwk_from_private_der(kid, jsonwebtoken::Algorithm::RS256, private_pkcs8_der)
            .expect("public jwk should derive");
    ClientRow {
        id: Uuid::now_v7(),
        tenant_id: DEFAULT_TENANT_ID,
        realm_id: DEFAULT_REALM_ID,
        organization_id: DEFAULT_ORGANIZATION_ID,
        client_id: client_id.to_owned(),
        client_name: "JWT Bearer Client".to_owned(),
        client_type: "confidential".to_owned(),
        client_secret_argon2_hash: None,
        redirect_uris: json!([]),
        scopes: json!(["accounts", "payments"]),
        allowed_audiences: json!(["resource://default"]),
        grant_types: json!([JWT_BEARER_GRANT_TYPE]),
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
        jwks: Some(json!({"keys": [public_jwk]})),
        post_logout_redirect_uris: json!([]),
        backchannel_logout_uri: None,
        backchannel_logout_session_required: true,
        subject_type: "public".to_owned(),
        sector_identifier_uri: None,
        sector_identifier_host: None,
    }
}

fn signed_jwt_bearer_assertion(
    client_id: &str,
    kid: &str,
    private_pkcs8_der: &[u8],
    extra: Value,
) -> String {
    let now = Utc::now().timestamp();
    let mut claims = json!({
        "iss": client_id,
        "sub": client_id,
        "aud": "https://issuer.example",
        "exp": now + 120,
        "nbf": now,
        "iat": now,
        "jti": format!("jwt-bearer-{}", Uuid::now_v7())
    });
    let target = claims.as_object_mut().expect("claims must be an object");
    for (key, value) in extra.as_object().expect("extra must be an object") {
        target.insert(key.clone(), value.clone());
    }
    let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
    header.kid = Some(kid.to_owned());
    jsonwebtoken::encode(
        &header,
        &claims,
        &jsonwebtoken::EncodingKey::from_rsa_der(private_pkcs8_der),
    )
    .expect("JWT bearer assertion should sign")
}

#[test]
fn jwt_bearer_assertion_validation_binds_client_issuer_audience_and_times() {
    let private_key = generate_key_material(jsonwebtoken::Algorithm::RS256)
        .expect("JWT bearer test key should generate")
        .private_pkcs8_der;
    let client = jwt_bearer_client("client-a", "jwt-bearer-kid", &private_key);
    let settings = Settings::from_config(&ConfigSource::from_pairs_for_test([
        ("ISSUER", "https://issuer.example"),
        ("PUBLIC_BASE_URL", "https://issuer.example"),
        ("FRONTEND_BASE_URL", "https://app.example"),
        ("COOKIE_SECURE", "true"),
    ]))
    .expect("JWT bearer test settings should load");
    let assertion =
        signed_jwt_bearer_assertion("client-a", "jwt-bearer-kid", &private_key, json!({}));

    let claims = validate_jwt_bearer_assertion(&settings, &client, &assertion)
        .expect("valid client-bound JWT bearer assertion should validate");

    assert_eq!(claims.subject, "client-a");
    assert!(valid_jwt_bearer_jti(&claims.jti));

    let wrong_audience = signed_jwt_bearer_assertion(
        "client-a",
        "jwt-bearer-kid",
        &private_key,
        json!({"aud": "https://issuer.example/token"}),
    );
    assert!(validate_jwt_bearer_assertion(&settings, &client, &wrong_audience).is_err());

    let wrong_subject = signed_jwt_bearer_assertion(
        "client-a",
        "jwt-bearer-kid",
        &private_key,
        json!({"sub": "user-1"}),
    );
    assert!(validate_jwt_bearer_assertion(&settings, &client, &wrong_subject).is_err());

    let alg_none = format!(
        "{}.{}.",
        URL_SAFE_NO_PAD.encode(r#"{"alg":"none"}"#),
        URL_SAFE_NO_PAD.encode(json!({"iss":"client-a","sub":"client-a"}).to_string())
    );
    assert!(validate_jwt_bearer_assertion(&settings, &client, &alg_none).is_err());
}
