use super::*;
use std::sync::Arc;

use actix_web::{cookie::Cookie, http::header};
use chrono::Duration;

use crate::config::ConfigSource;
use crate::db::create_pool;
use crate::domain::{ActiveSigningKey, Keyset};

fn test_state() -> AppState {
    AppState {
        diesel_db: create_pool(
            "postgres://nazo_mfa_test_invalid:nazo_mfa_test_invalid@127.0.0.1:1/nazo".to_owned(),
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

fn request_with_session_but_no_csrf(state: &AppState) -> HttpRequest {
    actix_web::test::TestRequest::default()
        .cookie(Cookie::new(
            state.settings.session_cookie_name.clone(),
            "active-session",
        ))
        .to_http_request()
}

async fn response_json(response: HttpResponse) -> (StatusCode, Value, bool) {
    let status = response.status();
    let has_set_cookie = response.headers().contains_key(header::SET_COOKIE);
    let body = actix_web::body::to_bytes(response.into_body())
        .await
        .expect("response body should be readable");
    let json = serde_json::from_slice(&body).expect("response should be json");
    (status, json, has_set_cookie)
}

async fn assert_mfa_endpoint_rejects_missing_csrf(response: HttpResponse) {
    let (status, body, has_set_cookie) = response_json(response).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_request");
    assert_eq!(body["error_description"], "Request failed.");
    assert!(body.get("secret_base32").is_none());
    assert!(body.get("otpauth_uri").is_none());
    assert!(body.get("backup_codes").is_none());
    assert!(body.get("success").is_none());
    assert!(body.get("mfa_enabled").is_none());
    assert!(
        !has_set_cookie,
        "CSRF failure must not create, replace, remember, or clear session cookies"
    );
}

#[test]
fn protected_mfa_request_requires_code() {
    let payload = serde_json::from_value::<MfaProtectedRequest>(json!({"code": "123456"}));

    assert!(payload.is_ok());
}

#[test]
fn remembered_mfa_cookie_ttl_is_bounded_to_thirty_days() {
    assert_eq!(
        Duration::seconds(MFA_REMEMBERED_TTL_SECONDS as i64).num_days(),
        30
    );
}

#[actix_web::test]
async fn mfa_totp_begin_rejects_session_request_without_csrf_before_enrollment_secret() {
    let state = Data::new(test_state());
    let req = request_with_session_but_no_csrf(&state);

    assert_mfa_endpoint_rejects_missing_csrf(mfa_totp_begin(state, req).await).await;
}

#[actix_web::test]
async fn mfa_totp_confirm_rejects_session_request_without_csrf_before_backup_codes() {
    let state = Data::new(test_state());
    let req = request_with_session_but_no_csrf(&state);

    assert_mfa_endpoint_rejects_missing_csrf(
        mfa_totp_confirm(
            state,
            req,
            Json(ConfirmTotpRequest {
                code: "123456".into(),
            }),
        )
        .await,
    )
    .await;
}

#[actix_web::test]
async fn mfa_verify_rejects_session_request_without_csrf_before_completing_challenge() {
    let state = Data::new(test_state());
    let req = request_with_session_but_no_csrf(&state);

    assert_mfa_endpoint_rejects_missing_csrf(
        mfa_verify(
            state,
            req,
            Json(MfaChallengeRequest {
                code: "123456".into(),
                remember_device: Some(true),
            }),
        )
        .await,
    )
    .await;
}

#[actix_web::test]
async fn mfa_backup_codes_regenerate_rejects_session_request_without_csrf_before_rotation() {
    let state = Data::new(test_state());
    let req = request_with_session_but_no_csrf(&state);

    assert_mfa_endpoint_rejects_missing_csrf(
        mfa_backup_codes_regenerate(
            state,
            req,
            Json(MfaProtectedRequest {
                code: "123456".into(),
            }),
        )
        .await,
    )
    .await;
}

#[actix_web::test]
async fn mfa_disable_rejects_session_request_without_csrf_before_clearing_mfa_state() {
    let state = Data::new(test_state());
    let req = request_with_session_but_no_csrf(&state);

    assert_mfa_endpoint_rejects_missing_csrf(
        mfa_disable(
            state,
            req,
            Json(MfaProtectedRequest {
                code: "123456".into(),
            }),
        )
        .await,
    )
    .await;
}
