use super::*;
use std::sync::Arc;

use crate::config::ConfigSource;
use crate::db::create_pool;
use crate::domain::ConfirmationClaims;
use crate::domain::{ActiveSigningKey, Keyset};
use actix_web::test::TestRequest;

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
