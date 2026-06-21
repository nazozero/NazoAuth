use super::*;
use std::sync::Arc;

use crate::config::ConfigSource;
use crate::db::create_pool;
use crate::domain::{ActiveSigningKey, Keyset};
use crate::support::{IpCidr, generate_key_material, public_jwk_from_private_der};
use actix_web::test::TestRequest;
use fred::prelude::{
    Builder as ValkeyBuilder, Config as ValkeyConfig, ConnectionConfig, PerformanceConfig,
};
use std::time::Duration as StdDuration;

fn token_management_state() -> AppState {
    token_management_state_with_settings(
        Settings::from_config(&ConfigSource::default()).expect("default settings should load"),
    )
}

fn token_management_state_with_settings(settings: Settings) -> AppState {
    AppState {
        diesel_db: create_pool(
            "postgres://nazo_client_auth_test_invalid:nazo_client_auth_test_invalid@127.0.0.1:1/nazo"
                .to_owned(),
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

fn token_management_state_with_trusted_proxy() -> AppState {
    let mut settings =
        Settings::from_config(&ConfigSource::default()).expect("default settings should load");
    settings.trusted_proxy_cidrs =
        vec![IpCidr::parse("127.0.0.1/32").expect("trusted proxy CIDR should parse")];
    token_management_state_with_settings(settings)
}

fn unavailable_valkey_client() -> fred::prelude::Client {
    let mut builder = ValkeyBuilder::from_config(
        ValkeyConfig::from_url("redis://127.0.0.1:1").expect("unavailable Valkey URL should parse"),
    );
    builder.with_performance_config(|performance: &mut PerformanceConfig| {
        performance.default_command_timeout = StdDuration::from_millis(200);
    });
    builder.with_connection_config(|connection: &mut ConnectionConfig| {
        connection.connection_timeout = StdDuration::from_millis(200);
        connection.internal_command_timeout = StdDuration::from_millis(200);
        connection.max_command_attempts = 1;
    });
    builder
        .build()
        .expect("unavailable valkey client construction should not connect")
}

fn confidential_client_with_secret(secret: &str) -> ClientRow {
    ClientRow {
        id: Uuid::now_v7(),
        tenant_id: DEFAULT_TENANT_ID,
        realm_id: DEFAULT_REALM_ID,
        organization_id: DEFAULT_ORGANIZATION_ID,
        client_id: "client-1".to_owned(),
        client_name: "Client 1".to_owned(),
        client_type: "confidential".to_owned(),
        client_secret_argon2_hash: Some(hash_password(secret).expect("secret should hash")),
        redirect_uris: json!(["https://client.example/callback"]),
        scopes: json!(["openid"]),
        allowed_audiences: json!(["resource://default"]),
        grant_types: json!(["authorization_code"]),
        token_endpoint_auth_method: "client_secret_basic".to_owned(),
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
    }
}

fn client_credentials(method: &str) -> ClientCredentials {
    ClientCredentials {
        client_id: Some("client-1".to_owned()),
        client_secret: None,
        client_assertion: None,
        method: method.to_owned(),
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
fn token_management_basic_client_auth_failure_has_basic_challenge() {
    let response =
        token_management_client_auth_error(TokenManagementClientAuthError::InvalidClient, true);

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        response.headers().get(header::WWW_AUTHENTICATE).unwrap(),
        HeaderValue::from_static(r#"Basic realm="nazo-oauth""#)
    );
    assert_eq!(
        response.headers().get(header::CACHE_CONTROL).unwrap(),
        HeaderValue::from_static("no-store")
    );
    assert_eq!(
        response.headers().get(header::PRAGMA).unwrap(),
        HeaderValue::from_static("no-cache")
    );
}

#[test]
fn public_revocation_client_accepts_only_none_without_secret_material() {
    let credentials = client_credentials("none");
    assert!(
        revocation_public_client_allows_credentials(&credentials),
        "public revocation may identify the client without authenticating as confidential"
    );

    let mut with_secret = client_credentials("none");
    with_secret.client_secret = Some("secret".to_owned());
    assert!(
        !revocation_public_client_allows_credentials(&with_secret),
        "public revocation must not accept confidential-client secret material"
    );

    let mut with_assertion = client_credentials("none");
    with_assertion.client_assertion = Some("jwt".to_owned());
    assert!(
        !revocation_public_client_allows_credentials(&with_assertion),
        "public revocation must not accept private_key_jwt assertion material"
    );

    let basic = client_credentials("client_secret_basic");
    assert!(
        !revocation_public_client_allows_credentials(&basic),
        "public revocation must not upgrade itself into a confidential auth method"
    );
}

#[test]
fn token_management_non_basic_client_auth_failure_has_no_basic_challenge() {
    let response =
        token_management_client_auth_error(TokenManagementClientAuthError::InvalidClient, false);

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert!(response.headers().get(header::WWW_AUTHENTICATE).is_none());
    assert_eq!(
        response.headers().get(header::CACHE_CONTROL).unwrap(),
        HeaderValue::from_static("no-store")
    );
}

#[test]
fn token_management_store_failure_has_no_basic_challenge() {
    let response =
        token_management_client_auth_error(TokenManagementClientAuthError::StoreUnavailable, true);

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(response.headers().get(header::WWW_AUTHENTICATE).is_none());
    assert_eq!(
        response.headers().get(header::CACHE_CONTROL).unwrap(),
        HeaderValue::from_static("no-store")
    );
}

#[test]
fn token_management_auth_error_maps_store_unavailable_to_server_error() {
    let response = token_management_auth_error(TokenManagementClientAuthError::StoreUnavailable);

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        response
            .extensions()
            .get::<OAuthJsonErrorFields>()
            .map(|fields| fields.error.as_str()),
        Some("server_error")
    );
}

#[test]
fn client_assertion_replay_maps_to_invalid_client_not_server_error() {
    let error = token_management_client_assertion_error(ClientAssertionError::ReplayDetected);
    let response = token_management_client_auth_error(error, false);

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert!(response.headers().get(header::WWW_AUTHENTICATE).is_none());
    assert_eq!(
        response.headers().get(header::CACHE_CONTROL).unwrap(),
        HeaderValue::from_static("no-store")
    );
    assert_eq!(
        response
            .extensions()
            .get::<OAuthJsonErrorFields>()
            .map(|fields| fields.error.as_str()),
        Some("invalid_client")
    );
}

#[test]
fn client_assertion_store_failure_maps_to_server_error_without_challenge() {
    let error = token_management_client_assertion_error(ClientAssertionError::StoreUnavailable);
    let response = token_management_client_auth_error(error, true);

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(response.headers().get(header::WWW_AUTHENTICATE).is_none());
    assert_eq!(
        response.headers().get(header::CACHE_CONTROL).unwrap(),
        HeaderValue::from_static("no-store")
    );
    assert_eq!(
        response
            .extensions()
            .get::<OAuthJsonErrorFields>()
            .map(|fields| fields.error.as_str()),
        Some("server_error")
    );
}

#[actix_web::test]
async fn token_client_assertion_store_failure_fails_token_grant_as_server_error() {
    let mut state = token_management_state();
    state.valkey = unavailable_valkey_client();
    let key = generate_key_material(jsonwebtoken::Algorithm::RS256)
        .expect("test client key should generate")
        .private_pkcs8_der;
    let public_jwk =
        public_jwk_from_private_der("client-kid", jsonwebtoken::Algorithm::RS256, &key)
            .expect("test client jwk should derive");
    let mut client = confidential_client_with_secret("unused-secret");
    client.token_endpoint_auth_method = "private_key_jwt".to_owned();
    client.client_secret_argon2_hash = None;
    client.jwks = Some(json!({"keys": [public_jwk]}));
    let req = TestRequest::post().uri("/token").to_http_request();
    let assertion = signed_client_assertion(
        &client.client_id,
        &state.settings.issuer,
        "client-kid",
        &key,
        "token-store-unavailable-jti",
    );
    let mut credentials = client_credentials("private_key_jwt");
    credentials.client_assertion = Some(assertion);
    let assertion = match verify_confidential_client(&state, &req, &client, &credentials) {
        Ok(Some(assertion)) => assertion,
        Ok(None) => panic!("private_key_jwt verification should return replay material"),
        Err(_) => panic!("signed private_key_jwt assertion should verify"),
    };

    let response = consume_token_client_assertion(&state, &client, Some(&assertion))
        .await
        .expect_err("unavailable replay store must fail the token grant");

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        response
            .extensions()
            .get::<OAuthJsonErrorFields>()
            .map(|fields| fields.error.as_str()),
        Some("server_error")
    );
}

#[test]
fn confidential_client_secret_auth_accepts_only_registered_method_and_secret() {
    let state = token_management_state();
    let req = TestRequest::default().to_http_request();
    let client = confidential_client_with_secret("correct-secret");
    let mut credentials = client_credentials("client_secret_basic");
    credentials.client_secret = Some("correct-secret".to_owned());

    assert!(
        verify_confidential_client(&state, &req, &client, &credentials).is_ok(),
        "registered confidential client with the correct auth method and secret may authenticate"
    );

    let mut wrong_secret = client_credentials("client_secret_basic");
    wrong_secret.client_secret = Some("wrong-secret".to_owned());
    assert!(matches!(
        verify_confidential_client(&state, &req, &client, &wrong_secret),
        Err(TokenManagementClientAuthError::InvalidClient)
    ));

    let mut wrong_method = client_credentials("client_secret_post");
    wrong_method.client_secret = Some("correct-secret".to_owned());
    assert!(matches!(
        verify_confidential_client(&state, &req, &client, &wrong_method),
        Err(TokenManagementClientAuthError::InvalidClient)
    ));
}

#[test]
fn confidential_client_auth_rejects_public_or_unknown_auth_method_even_with_secret() {
    let state = token_management_state();
    let req = TestRequest::default().to_http_request();
    let mut client = confidential_client_with_secret("correct-secret");
    let mut credentials = client_credentials("client_secret_basic");
    credentials.client_secret = Some("correct-secret".to_owned());

    client.client_type = "public".to_owned();
    assert!(matches!(
        verify_confidential_client(&state, &req, &client, &credentials),
        Err(TokenManagementClientAuthError::InvalidClient)
    ));

    client.client_type = "confidential".to_owned();
    client.token_endpoint_auth_method = "unsupported_method".to_owned();
    credentials.method = "unsupported_method".to_owned();
    assert!(matches!(
        verify_confidential_client(&state, &req, &client, &credentials),
        Err(TokenManagementClientAuthError::InvalidClient)
    ));
}

#[test]
fn private_key_jwt_requires_present_and_well_formed_assertion() {
    let state = token_management_state();
    let req = TestRequest::default().to_http_request();
    let mut client = confidential_client_with_secret("unused-secret");
    client.token_endpoint_auth_method = "private_key_jwt".to_owned();
    client.client_secret_argon2_hash = None;

    let mut missing_assertion = client_credentials("private_key_jwt");
    assert!(matches!(
        verify_confidential_client(&state, &req, &client, &missing_assertion),
        Err(TokenManagementClientAuthError::InvalidClient)
    ));

    missing_assertion.client_assertion = Some("not-a-jwt".to_owned());
    assert!(matches!(
        verify_confidential_client(&state, &req, &client, &missing_assertion),
        Err(TokenManagementClientAuthError::InvalidClient)
    ));
}

#[test]
fn mtls_client_auth_requires_certificate_from_trusted_request_context() {
    let state = token_management_state();
    let req = TestRequest::default()
        .insert_header(("x-ssl-client-verify", "SUCCESS"))
        .insert_header((
            "x-forwarded-tls-client-cert-sha256",
            "ABEiM0RVZneImaq7zN3u_wARIjNEVWZ3iJmqu8zd7v8",
        ))
        .to_http_request();
    let mut client = confidential_client_with_secret("unused-secret");
    client.token_endpoint_auth_method = "tls_client_auth".to_owned();
    client.client_secret_argon2_hash = None;
    let credentials = client_credentials("tls_client_auth");

    assert!(matches!(
        verify_confidential_client(&state, &req, &client, &credentials),
        Err(TokenManagementClientAuthError::InvalidClient)
    ));
}

#[test]
fn mtls_client_auth_accepts_matching_certificate_from_trusted_proxy() {
    let state = token_management_state_with_trusted_proxy();
    let thumbprint = "ABEiM0RVZneImaq7zN3u_wARIjNEVWZ3iJmqu8zd7v8";
    let req = TestRequest::default()
        .peer_addr("127.0.0.1:443".parse().unwrap())
        .insert_header(("x-ssl-client-verify", "SUCCESS"))
        .insert_header(("x-forwarded-tls-client-cert-sha256", thumbprint))
        .to_http_request();
    let mut client = confidential_client_with_secret("unused-secret");
    client.token_endpoint_auth_method = "tls_client_auth".to_owned();
    client.client_secret_argon2_hash = None;
    client.tls_client_auth_cert_sha256 = Some(thumbprint.to_owned());
    let credentials = client_credentials("tls_client_auth");

    assert!(
        verify_confidential_client(&state, &req, &client, &credentials).is_ok(),
        "matching mTLS certificate from trusted proxy should authenticate the client"
    );
}
