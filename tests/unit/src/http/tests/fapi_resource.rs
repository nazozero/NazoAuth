use super::*;
use std::sync::Arc;

use crate::config::ConfigSource;
use crate::db::create_pool;
use crate::domain::{ActiveSigningKey, ConfirmationClaims, Keyset};

fn fapi_test_state() -> AppState {
    fapi_test_state_with_settings(
        Settings::from_config(&ConfigSource::default()).expect("default settings should load"),
    )
}

fn fapi_test_state_with_settings(settings: Settings) -> AppState {
    AppState {
        diesel_db: create_pool(
            "postgres://nazo_fapi_test_invalid:nazo_fapi_test_invalid@127.0.0.1:1/nazo".to_owned(),
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

fn fapi_trusted_proxy_state() -> AppState {
    let mut settings =
        Settings::from_config(&ConfigSource::default()).expect("default settings should load");
    settings.client_ip_header_mode = ClientIpHeaderMode::None;
    settings.trusted_proxy_cidrs =
        parse_trusted_proxy_cidrs(Some("192.0.2.0/24".to_owned())).unwrap();
    fapi_test_state_with_settings(settings)
}

fn access_claims(cnf: Option<ConfirmationClaims>) -> Claims {
    Claims {
        iss: "https://issuer.example".to_owned(),
        sub: "subject-1".to_owned(),
        tenant_id: DEFAULT_TENANT_ID.to_string(),
        user_id: None,
        subject_type: "public".to_owned(),
        aud: json!("resource://default"),
        client_id: "client-1".to_owned(),
        scope: "openid".to_owned(),
        authorization_details: json!([]),
        token_use: "access".to_owned(),
        jti: "jti-1".to_owned(),
        iat: Utc::now().timestamp(),
        nbf: Utc::now().timestamp(),
        exp: Utc::now().timestamp() + 300,
        cnf,
        userinfo_claims: Vec::new(),
        userinfo_claim_requests: Vec::new(),
    }
}

fn oauth_error_code(response: &HttpResponse) -> Option<String> {
    response
        .extensions()
        .get::<OAuthJsonErrorFields>()
        .map(|fields| fields.error.clone())
}

#[actix_web::test]
async fn fapi_resource_rejects_missing_or_conflicting_access_token_transport() {
    let state = Data::new(fapi_test_state());
    let missing_req = actix_web::test::TestRequest::get()
        .uri("/fapi/resource")
        .to_http_request();

    let missing = fapi_resource(state.clone(), missing_req, Bytes::new()).await;
    assert_eq!(missing.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(oauth_error_code(&missing).as_deref(), Some("invalid_token"));

    let duplicate_req = actix_web::test::TestRequest::post()
        .uri("/fapi/resource")
        .insert_header((header::AUTHORIZATION, "Bearer header-token"))
        .insert_header((header::CONTENT_TYPE, "application/x-www-form-urlencoded"))
        .to_http_request();
    let duplicate = fapi_resource(
        state,
        duplicate_req,
        Bytes::from_static(b"access_token=body-token"),
    )
    .await;
    assert_eq!(duplicate.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        oauth_error_code(&duplicate).as_deref(),
        Some("invalid_request")
    );
}

#[actix_web::test]
async fn fapi_resource_rejects_unverifiable_access_token_before_revocation_lookup() {
    let state = Data::new(fapi_test_state());
    let req = actix_web::test::TestRequest::get()
        .uri("/fapi/resource")
        .insert_header((header::AUTHORIZATION, "Bearer not-a-jwt"))
        .to_http_request();

    let response = fapi_resource(state, req, Bytes::new()).await;

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        oauth_error_code(&response).as_deref(),
        Some("invalid_token")
    );
}

#[test]
fn post_body_access_token_accepts_single_form_value() {
    let req = actix_web::test::TestRequest::post()
        .insert_header((header::CONTENT_TYPE, "application/x-www-form-urlencoded"))
        .to_http_request();
    let token = resource_access_token(&req, &Bytes::from_static(b"access_token=token-1"));

    let ResourceAccessToken::Present(AccessTokenAuthScheme::Bearer, token) = token else {
        panic!("expected bearer token from form body");
    };
    assert_eq!(token, "token-1");
}

#[test]
fn post_body_access_token_rejects_missing_content_type() {
    let req = actix_web::test::TestRequest::post().to_http_request();
    let token = resource_access_token(&req, &Bytes::from_static(b"access_token=token-1"));

    assert!(matches!(token, ResourceAccessToken::Missing));
}

#[test]
fn post_body_access_token_rejects_duplicate_value() {
    let req = actix_web::test::TestRequest::post()
        .insert_header((header::CONTENT_TYPE, "application/x-www-form-urlencoded"))
        .to_http_request();
    let token = resource_access_token(
        &req,
        &Bytes::from_static(b"access_token=token-1&access_token=token-2"),
    );

    assert!(matches!(token, ResourceAccessToken::InvalidRequest));
}

#[test]
fn query_access_token_is_not_accepted() {
    let req = actix_web::test::TestRequest::get()
        .uri("/fapi/resource?access_token=query-token")
        .to_http_request();
    let token = resource_access_token(&req, &Bytes::new());

    assert!(matches!(token, ResourceAccessToken::Missing));
}

#[test]
fn authorization_header_access_token_accepts_single_value() {
    let req = actix_web::test::TestRequest::get()
        .insert_header((header::AUTHORIZATION, "DPoP header-token"))
        .to_http_request();
    let token = resource_access_token(&req, &Bytes::new());

    let ResourceAccessToken::Present(AccessTokenAuthScheme::DPoP, token) = token else {
        panic!("expected dpop token from authorization header");
    };
    assert_eq!(token, "header-token");
}

#[test]
fn access_token_rejects_multiple_transport_methods() {
    let req = actix_web::test::TestRequest::post()
        .insert_header((header::AUTHORIZATION, "Bearer header-token"))
        .insert_header((header::CONTENT_TYPE, "application/x-www-form-urlencoded"))
        .to_http_request();
    let token = resource_access_token(&req, &Bytes::from_static(b"access_token=body-token"));

    assert!(matches!(token, ResourceAccessToken::InvalidRequest));
}

#[test]
fn fapi_resource_accepts_only_bound_resource_audiences() {
    let mut settings = Settings::from_config(&crate::config::ConfigSource::default())
        .expect("default settings should load");
    settings.issuer = "https://issuer.example".to_owned();
    settings.default_audience = "resource://default".to_owned();

    assert!(fapi_resource_audience_allowed(
        &settings,
        &json!("resource://default")
    ));
    assert!(fapi_resource_audience_allowed(
        &settings,
        &json!("https://issuer.example/fapi/resource")
    ));
    assert!(fapi_resource_audience_allowed(
        &settings,
        &json!(["resource://other", "https://issuer.example/fapi/resource"])
    ));
    assert!(!fapi_resource_audience_allowed(
        &settings,
        &json!("https://issuer.example/userinfo")
    ));
    assert!(!fapi_resource_audience_allowed(
        &settings,
        &json!(["resource://other", "https://issuer.example/userinfo"])
    ));
}

#[actix_web::test]
async fn sender_constrained_resource_rejects_wrong_transport_without_backend_lookup() {
    let state = fapi_test_state();
    let req = actix_web::test::TestRequest::get().to_http_request();

    let bearer_with_dpop_cnf = validate_access_token_binding(
        &state,
        &req,
        "access-token",
        AccessTokenAuthScheme::Bearer,
        &access_claims(Some(ConfirmationClaims {
            jkt: Some("dpop-jkt".to_owned()),
            x5t_s256: None,
        })),
    )
    .await
    .expect_err("Bearer transport must not accept a DPoP-bound access token");
    assert_eq!(bearer_with_dpop_cnf.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        oauth_error_code(&bearer_with_dpop_cnf).as_deref(),
        Some("invalid_dpop_proof")
    );

    let dpop_without_cnf = validate_access_token_binding(
        &state,
        &req,
        "access-token",
        AccessTokenAuthScheme::DPoP,
        &access_claims(None),
    )
    .await
    .expect_err("DPoP transport must require a DPoP-bound access token");
    assert_eq!(dpop_without_cnf.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        oauth_error_code(&dpop_without_cnf).as_deref(),
        Some("invalid_dpop_proof")
    );
}

#[actix_web::test]
async fn mtls_bound_resource_token_requires_verified_certificate() {
    let state = fapi_test_state();
    let req = actix_web::test::TestRequest::get().to_http_request();

    let response = validate_access_token_binding(
        &state,
        &req,
        "access-token",
        AccessTokenAuthScheme::Bearer,
        &access_claims(Some(ConfirmationClaims {
            jkt: None,
            x5t_s256: Some("thumbprint".to_owned()),
        })),
    )
    .await
    .expect_err("mTLS-bound access token must require a verified certificate");

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        oauth_error_code(&response).as_deref(),
        Some("invalid_token")
    );
}

#[actix_web::test]
async fn mtls_bound_resource_token_rejects_certificate_thumbprint_mismatch() {
    let state = fapi_trusted_proxy_state();
    let req = actix_web::test::TestRequest::get()
        .peer_addr("192.0.2.10:443".parse().unwrap())
        .insert_header(("x-ssl-client-verify", "SUCCESS"))
        .insert_header((
            "x-forwarded-tls-client-cert-sha256",
            "ABEiM0RVZneImaq7zN3u_wARIjNEVWZ3iJmqu8zd7v8",
        ))
        .to_http_request();

    let response = validate_access_token_binding(
        &state,
        &req,
        "access-token",
        AccessTokenAuthScheme::Bearer,
        &access_claims(Some(ConfirmationClaims {
            jkt: None,
            x5t_s256: Some("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned()),
        })),
    )
    .await
    .expect_err("mTLS-bound access token must reject the wrong client certificate");

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        oauth_error_code(&response).as_deref(),
        Some("invalid_token")
    );
}

#[actix_web::test]
async fn mtls_bound_resource_token_accepts_matching_verified_certificate() {
    let state = fapi_trusted_proxy_state();
    let thumbprint = "ABEiM0RVZneImaq7zN3u_wARIjNEVWZ3iJmqu8zd7v8";
    let req = actix_web::test::TestRequest::get()
        .peer_addr("192.0.2.10:443".parse().unwrap())
        .insert_header(("x-ssl-client-verify", "SUCCESS"))
        .insert_header(("x-forwarded-tls-client-cert-sha256", thumbprint))
        .to_http_request();

    validate_access_token_binding(
        &state,
        &req,
        "access-token",
        AccessTokenAuthScheme::Bearer,
        &access_claims(Some(ConfirmationClaims {
            jkt: None,
            x5t_s256: Some(thumbprint.to_owned()),
        })),
    )
    .await
    .expect("matching verified mTLS certificate should satisfy token binding");
}
