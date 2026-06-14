use super::*;
use std::sync::Arc;

use crate::config::ConfigSource;
use crate::db::create_pool;
use crate::domain::{ActiveSigningKey, Keyset};

fn test_state() -> AppState {
    AppState {
        diesel_db: create_pool(
            "postgres://nazo_refresh_security_invalid:nazo_refresh_security_invalid@127.0.0.1:1/nazo"
                .to_owned(),
            1,
        )
        .expect("pool construction should not connect"),
        valkey: fred::prelude::Builder::default_centralized()
            .build()
            .expect("valkey client construction should not connect"),
        settings: Arc::new(
            Settings::from_config(&ConfigSource::default()).expect("default settings should load"),
        ),
        keyset: Arc::new(Keyset {
            active_kid: "test-kid".to_owned(),
            active_alg: jsonwebtoken::Algorithm::EdDSA,
            active_signing_key: ActiveSigningKey::LocalPkcs8Der(Vec::new()),
            verification_keys: Vec::new(),
        }),
    }
}

fn refresh_form_without_token() -> TokenForm {
    TokenForm {
        grant_type: "refresh_token".to_owned(),
        code: None,
        redirect_uri: None,
        code_verifier: None,
        refresh_token: None,
        scope: None,
        client_id: None,
        client_secret: None,
        client_assertion_type: None,
        client_assertion: None,
        audiences: Vec::new(),
    }
}

async fn response_json(response: HttpResponse) -> (StatusCode, Value) {
    let status = response.status();
    assert_eq!(
        response
            .headers()
            .get(header::CACHE_CONTROL)
            .and_then(|value| value.to_str().ok()),
        Some("no-store")
    );
    assert_eq!(
        response
            .headers()
            .get(header::PRAGMA)
            .and_then(|value| value.to_str().ok()),
        Some("no-cache")
    );
    let body = actix_web::body::to_bytes(response.into_body())
        .await
        .expect("response body should be readable");
    let json = serde_json::from_slice(&body).expect("response should be json");
    (status, json)
}

fn client_row() -> ClientRow {
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
        scopes: json!(["openid", "offline_access"]),
        allowed_audiences: json!(["resource://default"]),
        grant_types: json!(["authorization_code", "refresh_token"]),
        token_endpoint_auth_method: "private_key_jwt".to_owned(),
        require_dpop_bound_tokens: true,
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

fn token_row() -> TokenRow {
    TokenRow {
        id: Uuid::now_v7(),
        tenant_id: DEFAULT_TENANT_ID,
        token_family_id: Uuid::now_v7(),
        client_id: Uuid::now_v7(),
        user_id: Some(Uuid::now_v7()),
        scopes: json!(["openid", "offline_access"]),
        authorization_details: json!([]),
        issued_at: Utc::now(),
        expires_at: Utc::now() + Duration::days(30),
        revoked_at: None,
        subject: "subject-1".to_owned(),
        dpop_jkt: Some("dpop-jkt".to_owned()),
        mtls_x5t_s256: None,
    }
}

#[test]
fn refresh_scope_narrowing_is_case_sensitive_and_does_not_add_privilege() {
    let original = vec![
        "openid".to_owned(),
        "offline_access".to_owned(),
        "payments:read".to_owned(),
    ];

    assert_eq!(
        refresh_token_scopes(&original, Some("openid payments:read")).unwrap(),
        vec!["openid".to_owned(), "payments:read".to_owned()]
    );

    for requested in ["OpenID", "payments:write", "offline_access payments:write"] {
        assert!(
            refresh_token_scopes(&original, Some(requested)).is_err(),
            "refresh scope narrowing must be exact and reject privilege expansion: {requested}"
        );
    }
}

#[test]
fn confidential_holder_of_key_client_auth_preserves_mtls_refresh_tokens() {
    let mut token = token_row();
    token.dpop_jkt = None;
    token.mtls_x5t_s256 = Some("thumb-1".to_owned());

    for method in [
        "tls_client_auth",
        "self_signed_tls_client_auth",
        "private_key_jwt",
    ] {
        let mut client = client_row();
        client.require_dpop_bound_tokens = false;
        client.require_mtls_bound_tokens = false;
        client.token_endpoint_auth_method = method.to_owned();

        assert!(
            confidential_client_has_sender_constrained_refresh_token(&client, &token),
            "holder-of-key confidential auth should preserve sender-constrained refresh tokens"
        );
        assert_eq!(
            refresh_token_policy_for_authorization_server_profile(
                AuthorizationServerProfile::Oauth2Baseline,
                &client,
                &token,
            ),
            RefreshTokenPolicy::PreserveExisting
        );
    }
}

#[test]
fn secret_authenticated_or_public_clients_do_not_preserve_refresh_tokens_by_cnf_alone() {
    let mut token = token_row();
    token.dpop_jkt = None;
    token.mtls_x5t_s256 = Some("thumb-1".to_owned());

    let mut secret_client = client_row();
    secret_client.token_endpoint_auth_method = "client_secret_basic".to_owned();
    secret_client.require_dpop_bound_tokens = false;
    secret_client.require_mtls_bound_tokens = false;
    assert!(!confidential_client_has_sender_constrained_refresh_token(
        &secret_client,
        &token
    ));
    assert_eq!(
        refresh_token_policy_for_authorization_server_profile(
            AuthorizationServerProfile::Oauth2Baseline,
            &secret_client,
            &token,
        ),
        RefreshTokenPolicy::Rotate {
            family_id: token.token_family_id,
            rotated_from_id: token.id,
        }
    );

    let mut public_client = client_row();
    public_client.client_type = "public".to_owned();
    public_client.token_endpoint_auth_method = "none".to_owned();
    public_client.require_dpop_bound_tokens = true;
    assert!(!confidential_client_has_sender_constrained_refresh_token(
        &public_client,
        &token
    ));
}

#[actix_web::test]
async fn refresh_grant_without_token_does_not_report_client_credentials_challenge() {
    let state = test_state();
    let req = actix_web::test::TestRequest::post()
        .uri("/oauth/token")
        .to_http_request();
    let client = client_row();
    let form = refresh_form_without_token();

    let response = token_refresh(&state, &req, &client, &form, None).await;

    assert!(
        response.headers().get(header::WWW_AUTHENTICATE).is_none(),
        "invalid refresh grant syntax must not be turned into a client credentials challenge"
    );
    let (status, body) = response_json(response).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_request");
    assert!(body.get("access_token").is_none());
    assert!(body.get("refresh_token").is_none());
}
