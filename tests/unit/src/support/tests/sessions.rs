use super::*;
use std::sync::Arc;

use crate::config::ConfigSource;
use crate::db::create_pool;
use crate::domain::{ActiveSigningKey, Keyset};
use crate::support::OAuthJsonErrorFields;
use actix_web::test::TestRequest;

fn valid_payload() -> SessionPayload {
    SessionPayload {
        user_id: Uuid::now_v7(),
        auth_time: 1_000,
        amr: vec!["password".to_owned()],
        pending_mfa: false,
        oidc_sid: Some("sid-1".to_owned()),
    }
}

fn session_state() -> AppState {
    AppState {
        diesel_db: create_pool(
            "postgres://nazo_session_test_invalid:nazo_session_test_invalid@127.0.0.1:1/nazo"
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

#[test]
fn session_payload_requires_authentication_metadata_and_oidc_sid() {
    let valid = valid_payload();

    assert!(valid_session_payload(&valid, 1_001));
    assert!(!valid_session_payload(
        &SessionPayload {
            oidc_sid: None,
            ..valid.clone()
        },
        1_001
    ));
    assert!(!valid_session_payload(
        &SessionPayload {
            oidc_sid: Some(" ".to_owned()),
            ..valid.clone()
        },
        1_001
    ));
    assert!(!valid_session_payload(
        &SessionPayload {
            auth_time: 0,
            ..valid.clone()
        },
        1_001
    ));
    assert!(!valid_session_payload(
        &SessionPayload {
            auth_time: 2_000,
            ..valid.clone()
        },
        1_001
    ));
    assert!(!valid_session_payload(
        &SessionPayload {
            amr: Vec::new(),
            ..valid
        },
        1_001
    ));
}

#[test]
fn session_payload_allows_only_small_clock_skew_for_auth_time() {
    let mut payload = valid_payload();

    payload.auth_time = 1_030;
    assert!(valid_session_payload(&payload, 1_000));

    payload.auth_time = 1_031;
    assert!(!valid_session_payload(&payload, 1_000));
}

#[test]
fn session_payload_preserves_pending_mfa_as_metadata_not_validity() {
    let mut payload = valid_payload();
    payload.pending_mfa = true;

    assert!(valid_session_payload(&payload, 1_001));
}

#[test]
fn session_payload_requires_non_blank_oidc_sid_after_trimming() {
    for sid in ["", " ", "\t\n"] {
        let mut payload = valid_payload();
        payload.oidc_sid = Some(sid.to_owned());

        assert!(
            !valid_session_payload(&payload, 1_001),
            "blank sid {sid:?} must not produce an OIDC session"
        );
    }
}

#[test]
fn add_amr_deduplicates_methods() {
    let mut amr = vec!["password".to_owned()];

    add_amr(&mut amr, "otp");
    add_amr(&mut amr, "otp");

    assert_eq!(amr, vec!["password", "otp"]);
}

#[test]
fn add_amr_preserves_original_order_for_oidc_amr_claims() {
    let mut amr = vec!["pwd".to_owned(), "otp".to_owned()];

    add_amr(&mut amr, "mfa");
    add_amr(&mut amr, "pwd");

    assert_eq!(amr, vec!["pwd", "otp", "mfa"]);
}

fn oauth_error_code(response: &HttpResponse) -> String {
    response
        .extensions()
        .get::<OAuthJsonErrorFields>()
        .map(|fields| fields.error.clone())
        .expect("OAuth error response should record its error code")
}

#[test]
fn session_lookup_failures_are_server_errors_without_auth_material() {
    let response = session_lookup_error_response(anyhow::anyhow!("database unavailable"));

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(oauth_error_code(&response), "server_error");
    assert!(
        response.headers().get(header::WWW_AUTHENTICATE).is_none(),
        "backend session failures must not be exposed as client credentials challenges"
    );
}

#[actix_web::test]
async fn missing_session_cookie_is_anonymous_without_backend_lookup() {
    let state = session_state();
    let req = TestRequest::default().to_http_request();

    assert!(
        current_session(&state, &req)
            .await
            .expect("missing cookie should not hit storage")
            .is_none()
    );
    assert!(
        current_user(&state, &req)
            .await
            .expect("missing cookie should not hit storage")
            .is_none()
    );
    assert!(
        current_pending_mfa_session(&state, &req)
            .await
            .expect("missing cookie should not hit storage")
            .is_none()
    );
}

#[actix_web::test]
async fn missing_session_cookie_cannot_complete_or_step_up_mfa() {
    let state = session_state();
    let req = TestRequest::default().to_http_request();

    assert!(
        !complete_mfa_session(&state, &req, "otp")
            .await
            .expect("missing cookie should not hit storage")
    );
    assert!(
        !step_up_current_session(&state, &req, "otp")
            .await
            .expect("missing cookie should not hit storage")
    );
}

#[actix_web::test]
async fn missing_session_cookie_requires_login_or_admin_denial_without_storage_lookup() {
    let state = session_state();
    let req = TestRequest::default().to_http_request();

    let login = current_user_or_login_required(&state, &req)
        .await
        .expect_err("anonymous user must be challenged to log in");
    assert_eq!(login.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(oauth_error_code(&login), "login_required");
    assert!(
        login.headers().get(header::SET_COOKIE).is_some(),
        "login-required response must clear stale session cookies"
    );
    assert!(login.headers().get(header::WWW_AUTHENTICATE).is_none());

    let forbidden = require_admin_or_forbidden(&state, &req)
        .await
        .expect_err("anonymous user must not receive admin access");
    assert_eq!(forbidden.status(), StatusCode::FORBIDDEN);
    assert!(forbidden.headers().get(header::WWW_AUTHENTICATE).is_none());
    let body = actix_web::body::to_bytes(forbidden.into_body())
        .await
        .expect("forbidden response body should collect");
    let value: Value = serde_json::from_slice(&body).expect("OAuth error body should be JSON");
    assert_eq!(value.get("error"), Some(&json!("access_denied")));
}
