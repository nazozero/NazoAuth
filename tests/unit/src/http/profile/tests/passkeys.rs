use super::*;
use std::sync::Arc;

use actix_web::{cookie::Cookie, http::header};

use crate::config::ConfigSource;
use crate::db::create_pool;
use crate::domain::{ActiveSigningKey, Keyset};

fn test_state() -> AppState {
    AppState {
        diesel_db: create_pool(
            "postgres://nazo_profile_passkey_test_invalid:nazo_profile_passkey_test_invalid@127.0.0.1:1/nazo".to_owned(),
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

fn passkey_row(id: Uuid, tenant_id: Uuid, user_id: Uuid, label: &str) -> PasskeyCredentialRow {
    let now = Utc::now();
    PasskeyCredentialRow {
        id,
        tenant_id,
        user_id,
        credential_id: "credential-public-id".to_owned(),
        credential: json!({
            "id": [1, 2, 3, 4],
            "public_key_cose": [5, 6, 7],
            "counter": 9,
            "transports": ["internal"],
            "aaguid": [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        }),
        label: label.to_owned(),
        sign_count: 9,
        last_used_at: Some(now),
        created_at: now,
        updated_at: now,
    }
}

fn uuid_fixture(value: u128) -> Uuid {
    Uuid::from_u128(value)
}

async fn response_json(response: HttpResponse) -> (StatusCode, Value) {
    let status = response.status();
    let body = actix_web::body::to_bytes(response.into_body())
        .await
        .expect("response body should be readable");
    let json = serde_json::from_slice(&body).expect("response should be json");
    (status, json)
}

async fn response_json_with_cookie_state(response: HttpResponse) -> (StatusCode, Value, bool) {
    let status = response.status();
    let has_set_cookie = response.headers().contains_key(header::SET_COOKIE);
    let body = actix_web::body::to_bytes(response.into_body())
        .await
        .expect("response body should be readable");
    let json = serde_json::from_slice(&body).expect("response should be json");
    (status, json, has_set_cookie)
}

async fn assert_passkey_write_rejects_missing_csrf(response: HttpResponse) {
    let (status, body, has_set_cookie) = response_json_with_cookie_state(response).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_request");
    assert_eq!(body["error_description"], "Request failed.");
    assert!(body.get("ceremony_id").is_none());
    assert!(body.get("publicKey").is_none());
    assert!(body.get("credential_id").is_none());
    assert!(body.get("credential").is_none());
    assert!(!has_set_cookie);
}

#[actix_web::test]
async fn passkey_list_response_exposes_only_public_credential_projection() {
    let row = passkey_row(
        uuid_fixture(0x11111111111111111111111111111111),
        uuid_fixture(0x22222222222222222222222222222222),
        uuid_fixture(0x33333333333333333333333333333333),
        "Laptop",
    );

    let (status, body) = response_json(passkey_list_response(std::slice::from_ref(&row))).await;

    assert_eq!(status, StatusCode::OK);
    let passkeys = body["passkeys"]
        .as_array()
        .expect("passkeys must be an array");
    assert_eq!(passkeys.len(), 1);
    let public = passkeys[0]
        .as_object()
        .expect("passkey projection must be an object");
    assert_eq!(public["id"], json!(row.id));
    assert_eq!(public["label"], "Laptop");
    assert_eq!(public["credential_id"], "credential-public-id");
    assert_eq!(public["sign_count"], 9);
    assert!(public.get("last_used_at").is_some());
    assert!(public.get("created_at").is_some());
    assert!(public.get("updated_at").is_some());
    assert_eq!(public.len(), 7);
    for forbidden in ["tenant_id", "user_id", "credential"] {
        assert!(
            public.get(forbidden).is_none(),
            "{forbidden} must not be exposed in passkey profile responses"
        );
    }
}

#[actix_web::test]
async fn passkey_created_response_uses_created_status_and_public_projection_only() {
    let row = passkey_row(
        uuid_fixture(0x44444444444444444444444444444444),
        uuid_fixture(0x55555555555555555555555555555555),
        uuid_fixture(0x66666666666666666666666666666666),
        "Security key",
    );

    let (status, body) = response_json(passkey_created_response(&row)).await;

    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(body["id"], json!(row.id));
    assert_eq!(body["label"], "Security key");
    assert!(body.get("tenant_id").is_none());
    assert!(body.get("user_id").is_none());
    assert!(body.get("credential").is_none());
}

#[actix_web::test]
async fn duplicate_passkey_registration_returns_conflict_without_credential_data() {
    let (status, body) = response_json(passkey_already_registered_response()).await;

    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["error"], "invalid_request");
    assert_eq!(body["error_description"], "passkey already registered.");
    assert!(body.get("credential").is_none());
    assert!(body.get("credential_id").is_none());
}

#[actix_web::test]
async fn delete_missing_passkey_returns_not_found_without_cross_user_context() {
    let (status, body) = response_json(passkey_delete_response(0)).await;

    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["error"], "invalid_request");
    assert_eq!(body["error_description"], "passkey not found.");
    assert!(body.get("tenant_id").is_none());
    assert!(body.get("user_id").is_none());
    assert!(body.get("credential_id").is_none());
}

#[actix_web::test]
async fn delete_existing_passkey_returns_empty_no_content_response() {
    let response = passkey_delete_response(1);
    let status = response.status();
    let body = actix_web::body::to_bytes(response.into_body())
        .await
        .expect("response body should be readable");

    assert_eq!(status, StatusCode::NO_CONTENT);
    assert!(body.is_empty());
}

#[actix_web::test]
async fn registration_begin_rejects_session_request_without_csrf_before_ceremony_creation() {
    let state = Data::new(test_state());
    let req = request_with_session_but_no_csrf(&state);

    assert_passkey_write_rejects_missing_csrf(
        passkey_registration_begin(state, req, Json(PasskeyBeginRequest { label: None })).await,
    )
    .await;
}

#[actix_web::test]
async fn delete_passkey_rejects_session_request_without_csrf_before_credential_delete() {
    let state = Data::new(test_state());
    let req = request_with_session_but_no_csrf(&state);
    let credential_id = uuid_fixture(0x77777777777777777777777777777777);

    assert_passkey_write_rejects_missing_csrf(
        passkey_delete(state, req, actix_web::web::Path::from(credential_id)).await,
    )
    .await;
}
