use super::*;
use std::sync::Arc;

use crate::config::ConfigSource;
use crate::db::{create_pool, get_conn};
use crate::domain::ConfirmationClaims;
use crate::domain::{ActiveSigningKey, Claims, Keyset, VerificationKey};
use crate::support::{generate_key_material, public_jwk_from_private_der};
use actix_web::test::TestRequest;
use diesel::sql_query;
use diesel::sql_types::{Bool, Jsonb, Nullable, Text, Timestamptz, Uuid as SqlUuid};
use diesel_async::RunQueryDsl;

fn introspection_state() -> Data<AppState> {
    Data::new(AppState {
        diesel_db: create_pool(
            "postgres://nazo_introspect_test_invalid:nazo_introspect_test_invalid@127.0.0.1:1/nazo"
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
    })
}

fn live_introspection_state() -> Option<Data<AppState>> {
    let database_url = std::env::var("DATABASE_URL").ok()?;
    let key_material =
        generate_key_material(jsonwebtoken::Algorithm::EdDSA).expect("test key should generate");
    let public_jwk = public_jwk_from_private_der(
        "introspect-test-kid",
        jsonwebtoken::Algorithm::EdDSA,
        &key_material.private_pkcs8_der,
    )
    .expect("test public JWK should derive");
    let mut settings =
        Settings::from_config(&ConfigSource::default()).expect("default settings should load");
    settings.issuer = "https://issuer.example".to_owned();
    settings.default_audience = "resource://default".to_owned();

    Some(Data::new(AppState {
        diesel_db: create_pool(database_url, 1).expect("database pool should build"),
        valkey: fred::prelude::Builder::default_centralized()
            .build()
            .expect("valkey client construction should not connect"),
        settings: Arc::new(settings),
        keyset: Arc::new(Keyset {
            active_kid: "introspect-test-kid".to_owned(),
            active_alg: jsonwebtoken::Algorithm::EdDSA,
            active_signing_key: ActiveSigningKey::LocalPkcs8Der(key_material.private_pkcs8_der),
            verification_keys: vec![VerificationKey {
                kid: "introspect-test-kid".to_owned(),
                public_jwk,
            }],
        }),
    }))
}

async fn insert_introspection_client(
    state: &Data<AppState>,
    client_id: &str,
    secret: &str,
) -> ClientRow {
    let row = ClientRow {
        id: Uuid::now_v7(),
        tenant_id: DEFAULT_TENANT_ID,
        realm_id: DEFAULT_REALM_ID,
        organization_id: DEFAULT_ORGANIZATION_ID,
        client_id: client_id.to_owned(),
        client_name: "Introspection Test Client".to_owned(),
        client_type: "confidential".to_owned(),
        client_secret_argon2_hash: Some(hash_password(secret).expect("secret should hash")),
        redirect_uris: json!(["https://client.example/callback"]),
        scopes: json!(["openid", "offline_access"]),
        allowed_audiences: json!(["resource://default"]),
        grant_types: json!(["authorization_code", "refresh_token"]),
        token_endpoint_auth_method: "client_secret_post".to_owned(),
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
    let mut conn = get_conn(&state.diesel_db)
        .await
        .expect("database connection should be available");
    sql_query(
        r#"
        DELETE FROM access_token_revocations
        USING oauth_clients
        WHERE access_token_revocations.client_id = oauth_clients.id
          AND oauth_clients.tenant_id = $1
          AND oauth_clients.client_id = $2
        "#,
    )
    .bind::<SqlUuid, _>(row.tenant_id)
    .bind::<Text, _>(row.client_id.as_str())
    .execute(&mut conn)
    .await
    .expect("introspection access token revocation cleanup should succeed");
    sql_query(
        r#"
        DELETE FROM oauth_tokens
        USING oauth_clients
        WHERE oauth_tokens.client_id = oauth_clients.id
          AND oauth_clients.tenant_id = $1
          AND oauth_clients.client_id = $2
        "#,
    )
    .bind::<SqlUuid, _>(row.tenant_id)
    .bind::<Text, _>(row.client_id.as_str())
    .execute(&mut conn)
    .await
    .expect("introspection refresh token cleanup should succeed");
    sql_query("DELETE FROM oauth_clients WHERE tenant_id = $1 AND client_id = $2")
        .bind::<SqlUuid, _>(row.tenant_id)
        .bind::<Text, _>(row.client_id.as_str())
        .execute(&mut conn)
        .await
        .expect("introspection test client cleanup should succeed");
    sql_query(
        r#"
        INSERT INTO oauth_clients (
            id, tenant_id, realm_id, organization_id, client_id, client_name, client_type,
            client_secret_argon2_hash, redirect_uris, scopes, allowed_audiences,
            grant_types, token_endpoint_auth_method, require_dpop_bound_tokens,
            require_mtls_bound_tokens, tls_client_auth_san_dns, tls_client_auth_san_uri,
            tls_client_auth_san_ip, tls_client_auth_san_email,
            allow_client_assertion_audience_array,
            allow_client_assertion_endpoint_audience, require_par_request_object,
            allow_authorization_code_without_pkce, is_active,
            post_logout_redirect_uris, backchannel_logout_session_required
        )
        VALUES (
            $1, $2, $3, $4, $5, $6, $7,
            $8, $9, $10, $11,
            $12, $13, $14,
            $15, '[]'::jsonb, '[]'::jsonb,
            '[]'::jsonb, '[]'::jsonb,
            false, false, false,
            false, true,
            '[]'::jsonb, true
        )
        "#,
    )
    .bind::<SqlUuid, _>(row.id)
    .bind::<SqlUuid, _>(row.tenant_id)
    .bind::<SqlUuid, _>(row.realm_id)
    .bind::<SqlUuid, _>(row.organization_id)
    .bind::<Text, _>(row.client_id.as_str())
    .bind::<Text, _>(row.client_name.as_str())
    .bind::<Text, _>(row.client_type.as_str())
    .bind::<Nullable<Text>, _>(row.client_secret_argon2_hash.as_deref())
    .bind::<Jsonb, _>(row.redirect_uris.clone())
    .bind::<Jsonb, _>(row.scopes.clone())
    .bind::<Jsonb, _>(row.allowed_audiences.clone())
    .bind::<Jsonb, _>(row.grant_types.clone())
    .bind::<Text, _>(row.token_endpoint_auth_method.as_str())
    .bind::<Bool, _>(row.require_dpop_bound_tokens)
    .bind::<Bool, _>(row.require_mtls_bound_tokens)
    .execute(&mut conn)
    .await
    .expect("introspection test client insert should succeed");
    row
}

async fn sign_access_token(
    state: &Data<AppState>,
    tenant_id: Uuid,
    client_id: &str,
    audience: Value,
) -> IssuedAccessToken {
    make_jwt(
        state,
        AccessTokenJwtInput {
            tenant_id,
            subject: client_id,
            user_id: None,
            subject_type: "client",
            client_id,
            audiences: &json_array_to_strings(&audience),
            scopes: &["openid".to_owned()],
            authorization_details: &json!([]),
            userinfo_claims: &[],
            userinfo_claim_requests: &[],
            ttl: 300,
            dpop_jkt: None,
            mtls_x5t_s256: None,
        },
    )
    .await
    .expect("access token should sign")
}

async fn insert_access_token_revocation(
    state: &Data<AppState>,
    client: &ClientRow,
    access_token_jti: &str,
) {
    let mut conn = get_conn(&state.diesel_db)
        .await
        .expect("database connection should be available");
    sql_query(
        r#"
        INSERT INTO access_token_revocations (
            tenant_id, client_id, access_token_jti_blake3, revoked_at, expires_at
        )
        VALUES ($1, $2, $3, now(), $4)
        "#,
    )
    .bind::<SqlUuid, _>(client.tenant_id)
    .bind::<SqlUuid, _>(client.id)
    .bind::<Text, _>(blake3_hex(access_token_jti))
    .bind::<Timestamptz, _>(Utc::now() + Duration::minutes(5))
    .execute(&mut conn)
    .await
    .expect("introspection test access token revocation insert should succeed");
}

async fn insert_refresh_token_for_client(
    state: &Data<AppState>,
    client_id: Uuid,
    raw_refresh_token: &str,
    revoked_at: Option<DateTime<Utc>>,
    expires_at: DateTime<Utc>,
) {
    let mut conn = get_conn(&state.diesel_db)
        .await
        .expect("database connection should be available");
    sql_query("DELETE FROM oauth_tokens WHERE tenant_id = $1 AND refresh_token_blake3 = $2")
        .bind::<SqlUuid, _>(DEFAULT_TENANT_ID)
        .bind::<Text, _>(blake3_hex(raw_refresh_token))
        .execute(&mut conn)
        .await
        .expect("refresh token cleanup should succeed");
    sql_query(
        r#"
        INSERT INTO oauth_tokens (
            id, tenant_id, refresh_token_blake3, token_family_id, rotated_from_id,
            client_id, user_id, scopes, authorization_details, issued_at, expires_at,
            revoked_at, reuse_detected_at, subject, dpop_jkt, mtls_x5t_s256
        )
        VALUES (
            $1, $2, $3, $4, NULL,
            $5, NULL, '["openid","offline_access"]'::jsonb, '[]'::jsonb, now(), $6,
            $7, NULL, 'subject-1', NULL, NULL
        )
        "#,
    )
    .bind::<SqlUuid, _>(Uuid::now_v7())
    .bind::<SqlUuid, _>(DEFAULT_TENANT_ID)
    .bind::<Text, _>(blake3_hex(raw_refresh_token))
    .bind::<SqlUuid, _>(Uuid::now_v7())
    .bind::<SqlUuid, _>(client_id)
    .bind::<Timestamptz, _>(expires_at)
    .bind::<Nullable<Timestamptz>, _>(revoked_at)
    .execute(&mut conn)
    .await
    .expect("refresh token insert should succeed");
}

async fn introspect_with_client(
    state: Data<AppState>,
    client_id: &str,
    client_secret: &str,
    token: &str,
) -> (StatusCode, Value) {
    let body = Bytes::from(format!(
        "token={}&client_id={}&client_secret={}",
        urlencoding::encode(token),
        urlencoding::encode(client_id),
        urlencoding::encode(client_secret)
    ));
    json_body(introspect_after_rate_limit(state, form_request(), body).await).await
}

fn form_request() -> HttpRequest {
    TestRequest::default()
        .insert_header((header::CONTENT_TYPE, "application/x-www-form-urlencoded"))
        .to_http_request()
}

async fn introspect_form(body: &'static [u8]) -> HttpResponse {
    introspect_after_rate_limit(
        introspection_state(),
        form_request(),
        Bytes::from_static(body),
    )
    .await
}

async fn json_body(response: HttpResponse) -> (StatusCode, Value) {
    let status = response.status();
    assert_eq!(
        response.headers().get(header::CACHE_CONTROL).unwrap(),
        HeaderValue::from_static("no-store")
    );
    assert_eq!(
        response.headers().get(header::PRAGMA).unwrap(),
        HeaderValue::from_static("no-cache")
    );
    let body = actix_web::body::to_bytes(response.into_body())
        .await
        .expect("response body should collect");
    let value = serde_json::from_slice(&body).expect("response body should be JSON");
    (status, value)
}

fn access_claims(cnf: Option<ConfirmationClaims>) -> Claims {
    Claims {
        iss: "https://as.example".to_owned(),
        sub: "subject".to_owned(),
        tenant_id: DEFAULT_TENANT_ID.to_string(),
        user_id: None,
        subject_type: "client".to_owned(),
        aud: json!("resource://default"),
        client_id: "client-1".to_owned(),
        scope: "openid".to_owned(),
        authorization_details: json!([]),
        token_use: "access".to_owned(),
        jti: "jti-1".to_owned(),
        iat: 1,
        nbf: 1,
        exp: 2,
        cnf,
        userinfo_claims: Vec::new(),
        userinfo_claim_requests: Vec::new(),
    }
}

#[test]
fn access_token_introspection_type_matches_issued_bearer_token_type() {
    assert_eq!(
        introspection_access_token_type(&access_claims(None)),
        "Bearer"
    );
}

#[test]
fn access_token_introspection_type_matches_issued_dpop_token_type() {
    let claims = access_claims(Some(ConfirmationClaims {
        jkt: Some("thumbprint".to_owned()),
        x5t_s256: None,
    }));

    assert_eq!(introspection_access_token_type(&claims), "DPoP");
}

#[test]
fn mtls_bound_access_token_introspection_type_remains_bearer() {
    let claims = access_claims(Some(ConfirmationClaims {
        jkt: None,
        x5t_s256: Some("certificate-thumbprint".to_owned()),
    }));

    assert_eq!(introspection_access_token_type(&claims), "Bearer");
}

#[test]
fn refresh_token_introspection_metadata_omits_access_token_type() {
    let issued_at = DateTime::<Utc>::from_timestamp(1_700_000_000, 0).unwrap();
    let token = TokenRow {
        id: Uuid::now_v7(),
        tenant_id: DEFAULT_TENANT_ID,
        token_family_id: Uuid::now_v7(),
        client_id: Uuid::now_v7(),
        user_id: None,
        scopes: json!(["openid", "offline_access"]),
        authorization_details: json!([]),
        issued_at,
        expires_at: issued_at + Duration::days(30),
        revoked_at: None,
        subject: "subject".to_owned(),
        dpop_jkt: None,
        mtls_x5t_s256: None,
    };

    let body = active_refresh_token_introspection_body(&token, "client-1");

    assert_eq!(body.get("active"), Some(&json!(true)));
    assert_eq!(body.get("client_id"), Some(&json!("client-1")));
    assert_eq!(body.get("scope"), Some(&json!("openid offline_access")));
    assert_eq!(
        body.get("exp"),
        Some(&json!(issued_at.timestamp() + 30 * 24 * 60 * 60))
    );
    assert_eq!(body.get("iat"), Some(&json!(issued_at.timestamp())));
    assert_eq!(body.get("sub"), Some(&json!("subject")));
    assert!(!body.as_object().unwrap().contains_key("token_type"));
    assert!(!body.as_object().unwrap().contains_key("jti"));
}

#[actix_web::test]
async fn inactive_introspection_response_is_minimal_and_not_cacheable() {
    let response = json_response_no_store(json!({"active": false}));

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get(header::CACHE_CONTROL).unwrap(),
        HeaderValue::from_static("no-store")
    );
    assert_eq!(
        response.headers().get(header::PRAGMA).unwrap(),
        HeaderValue::from_static("no-cache")
    );
    assert!(response.headers().get(header::WWW_AUTHENTICATE).is_none());

    let body = actix_web::body::to_bytes(response.into_body())
        .await
        .expect("response body should collect");
    let value: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(value, json!({"active": false}));
    assert!(
        value.get("client_id").is_none() && value.get("sub").is_none(),
        "inactive introspection must not leak token metadata"
    );
}

#[test]
fn token_management_server_errors_are_oauth_json_without_auth_challenge() {
    let response = token_management_oauth_error(
        StatusCode::SERVICE_UNAVAILABLE,
        "server_error",
        "token 状态查询失败.",
    );

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        response
            .extensions()
            .get::<OAuthJsonErrorFields>()
            .map(|fields| fields.error.as_str()),
        Some("server_error")
    );
    assert_eq!(
        response.headers().get(header::CACHE_CONTROL).unwrap(),
        HeaderValue::from_static("no-store")
    );
    assert_eq!(
        response.headers().get(header::PRAGMA).unwrap(),
        HeaderValue::from_static("no-cache")
    );
    assert!(
        response.headers().get(header::WWW_AUTHENTICATE).is_none(),
        "backend failures must not be exposed as client-auth challenges"
    );
}

#[actix_web::test]
async fn introspection_rejects_malformed_form_before_token_lookup() {
    let cases = [
        introspect_after_rate_limit(
            introspection_state(),
            TestRequest::default()
                .insert_header((header::CONTENT_TYPE, "application/json"))
                .to_http_request(),
            Bytes::from_static(br#"{"token":"secret"}"#),
        )
        .await,
        introspect_form(b"token=\xff").await,
        introspect_form(b"token=token-1&token=token-2").await,
        introspect_form(b"token=%20%20").await,
    ];

    for response in cases {
        assert!(
            response.headers().get(header::WWW_AUTHENTICATE).is_none(),
            "malformed introspection input is invalid_request, not a client-auth challenge"
        );
        let (status, body) = json_body(response).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body.get("error"), Some(&json!("invalid_request")));
        assert_eq!(
            body.get("error_description"),
            Some(&json!("Request failed."))
        );
        assert!(body.get("active").is_none());
        assert!(body.get("client_id").is_none());
        assert!(body.get("sub").is_none());
    }
}

#[actix_web::test]
async fn introspection_rejects_conflicting_client_auth_without_token_lookup() {
    let response = introspect_after_rate_limit(
        introspection_state(),
        TestRequest::default()
            .insert_header((header::CONTENT_TYPE, "application/x-www-form-urlencoded"))
            .insert_header((header::AUTHORIZATION, "Basic Y2xpZW50LTE6c2VjcmV0"))
            .to_http_request(),
        Bytes::from_static(b"token=token-1&client_assertion=jwt"),
    )
    .await;

    let (status, body) = json_body(response).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body.get("error"), Some(&json!("invalid_request")));
    assert_eq!(
        body.get("error_description"),
        Some(&json!("Request failed."))
    );
    assert!(body.get("active").is_none());
    assert!(body.get("client_id").is_none());
    assert!(body.get("sub").is_none());
}

#[actix_web::test]
async fn introspection_requires_client_authentication_before_token_lookup() {
    let response = introspect_after_rate_limit(
        introspection_state(),
        form_request(),
        Bytes::from_static(b"token=token-1"),
    )
    .await;

    assert!(
        response.headers().get(header::WWW_AUTHENTICATE).is_none(),
        "introspection must not invent a Basic challenge unless the client attempted Basic auth"
    );
    let (status, body) = json_body(response).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body.get("error"), Some(&json!("invalid_client")));
    assert_eq!(
        body.get("error_description"),
        Some(&json!("Request failed."))
    );
    assert!(body.get("active").is_none());
    assert!(body.get("client_id").is_none());
    assert!(body.get("sub").is_none());
}

#[actix_web::test]
async fn introspection_client_lookup_failures_return_server_error() {
    let response = introspect_after_rate_limit(
        introspection_state(),
        form_request(),
        Bytes::from_static(b"token=token-1&client_id=introspect-lookup-error&client_secret=secret"),
    )
    .await;

    let (status, body) = json_body(response).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body.get("error"), Some(&json!("server_error")));
    assert!(body.get("active").is_none());
    assert!(body.get("client_id").is_none());
    assert!(body.get("sub").is_none());
}

#[actix_web::test]
async fn introspection_returns_inactive_for_access_tokens_outside_client_or_tenant_binding() {
    let Some(state) = live_introspection_state() else {
        return;
    };
    let client = insert_introspection_client(&state, "introspect-client", "correct-secret").await;

    let foreign_audience_token = sign_access_token(
        &state,
        DEFAULT_TENANT_ID,
        "other-client",
        json!("resource://other"),
    )
    .await;
    let (status, body) = introspect_with_client(
        state.clone(),
        &client.client_id,
        "correct-secret",
        &foreign_audience_token.token,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, json!({"active": false}));

    let foreign_tenant_token = sign_access_token(
        &state,
        Uuid::now_v7(),
        &client.client_id,
        json!("resource://default"),
    )
    .await;
    let (status, body) = introspect_with_client(
        state,
        &client.client_id,
        "correct-secret",
        &foreign_tenant_token.token,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, json!({"active": false}));
}

#[actix_web::test]
async fn introspection_respects_access_token_revocation_state() {
    let Some(state) = live_introspection_state() else {
        return;
    };
    let client =
        insert_introspection_client(&state, "introspect-client-access", "correct-secret").await;
    let access_token = sign_access_token(
        &state,
        client.tenant_id,
        &client.client_id,
        json!("resource://default"),
    )
    .await;
    insert_access_token_revocation(&state, &client, &access_token.jti).await;

    let (status, body) = introspect_with_client(
        state,
        &client.client_id,
        "correct-secret",
        &access_token.token,
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, json!({"active": false}));
}

#[actix_web::test]
async fn introspection_reports_refresh_token_activity_and_client_binding() {
    let Some(state) = live_introspection_state() else {
        return;
    };
    let client =
        insert_introspection_client(&state, "introspect-client-refresh", "correct-secret").await;

    let active_refresh = "active-refresh-token";
    insert_refresh_token_for_client(
        &state,
        client.id,
        active_refresh,
        None,
        Utc::now() + Duration::minutes(30),
    )
    .await;
    let (status, body) = introspect_with_client(
        state.clone(),
        &client.client_id,
        "correct-secret",
        active_refresh,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body.get("active"), Some(&json!(true)));
    assert_eq!(
        body.get("client_id"),
        Some(&json!(client.client_id.clone()))
    );
    assert_eq!(body.get("scope"), Some(&json!("openid offline_access")));
    assert!(body.get("token_type").is_none());

    let revoked_refresh = "revoked-refresh-token";
    insert_refresh_token_for_client(
        &state,
        client.id,
        revoked_refresh,
        Some(Utc::now()),
        Utc::now() + Duration::minutes(30),
    )
    .await;
    let (status, body) = introspect_with_client(
        state.clone(),
        &client.client_id,
        "correct-secret",
        revoked_refresh,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, json!({"active": false}));

    let other_client =
        insert_introspection_client(&state, "introspect-client-refresh-other", "correct-secret")
            .await;
    let mismatched_refresh = "mismatched-refresh-token";
    insert_refresh_token_for_client(
        &state,
        other_client.id,
        mismatched_refresh,
        None,
        Utc::now() + Duration::minutes(30),
    )
    .await;
    let (status, body) = introspect_with_client(
        state,
        &client.client_id,
        "correct-secret",
        mismatched_refresh,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, json!({"active": false}));
}

#[actix_web::test]
async fn introspection_returns_minimal_inactive_for_unknown_tokens() {
    let Some(state) = live_introspection_state() else {
        return;
    };
    let client = insert_introspection_client(
        &state,
        &format!("introspect-client-missing-{}", Uuid::now_v7()),
        "correct-secret",
    )
    .await;

    let (status, body) = introspect_with_client(
        state,
        &client.client_id,
        "correct-secret",
        &format!("missing-refresh-{}", Uuid::now_v7()),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, json!({"active": false}));
}
