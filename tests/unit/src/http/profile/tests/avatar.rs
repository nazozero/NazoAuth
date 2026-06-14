use super::*;
use std::sync::Arc;

use actix_web::error::PayloadError;
use actix_web::{
    cookie::Cookie,
    http::{header, header::HeaderMap},
};
use futures_util::stream;

use crate::config::ConfigSource;
use crate::db::create_pool;
use crate::domain::{ActiveSigningKey, Keyset};

fn test_state() -> AppState {
    AppState {
        diesel_db: create_pool(
            "postgres://nazo_avatar_test_invalid:nazo_avatar_test_invalid@127.0.0.1:1/nazo"
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

async fn assert_avatar_write_rejects_missing_csrf(response: HttpResponse) {
    let (status, body, has_set_cookie) = response_json(response).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_request");
    assert_eq!(body["error_description"], "Request failed.");
    assert!(body.get("avatar_url").is_none());
    assert!(body.get("email").is_none());
    assert!(body.get("sub").is_none());
    assert!(!has_set_cookie);
}

#[tokio::test]
async fn avatar_promotion_can_restore_previous_files() {
    let dir = temp_avatar_dir("rollback");
    tokio::fs::create_dir_all(&dir).await.unwrap();
    let avatar = dir.join("avatar.bin");
    let meta = dir.join("meta.json");
    let avatar_tmp = dir.join("avatar-new.tmp");
    let meta_tmp = dir.join("meta-new.tmp");
    tokio::fs::write(&avatar, b"old-avatar").await.unwrap();
    tokio::fs::write(&meta, b"old-meta").await.unwrap();
    tokio::fs::write(&avatar_tmp, b"new-avatar").await.unwrap();
    tokio::fs::write(&meta_tmp, b"new-meta").await.unwrap();

    let promotion =
        promote_avatar_files(&avatar_tmp, &meta_tmp, avatar.clone(), meta.clone(), "v1")
            .await
            .unwrap();
    assert_eq!(tokio::fs::read(&avatar).await.unwrap(), b"new-avatar");
    assert_eq!(tokio::fs::read(&meta).await.unwrap(), b"new-meta");

    rollback_avatar_promotion(&promotion).await;
    assert_eq!(tokio::fs::read(&avatar).await.unwrap(), b"old-avatar");
    assert_eq!(tokio::fs::read(&meta).await.unwrap(), b"old-meta");
    let _ = tokio::fs::remove_dir_all(&dir).await;
}

#[tokio::test]
async fn avatar_promotion_finish_removes_backup_files() {
    let dir = temp_avatar_dir("finish");
    tokio::fs::create_dir_all(&dir).await.unwrap();
    let avatar = dir.join("avatar.bin");
    let meta = dir.join("meta.json");
    let avatar_tmp = dir.join("avatar-new.tmp");
    let meta_tmp = dir.join("meta-new.tmp");
    tokio::fs::write(&avatar, b"old-avatar").await.unwrap();
    tokio::fs::write(&meta, b"old-meta").await.unwrap();
    tokio::fs::write(&avatar_tmp, b"new-avatar").await.unwrap();
    tokio::fs::write(&meta_tmp, b"new-meta").await.unwrap();

    let promotion =
        promote_avatar_files(&avatar_tmp, &meta_tmp, avatar.clone(), meta.clone(), "v1")
            .await
            .unwrap();
    finish_avatar_promotion(&promotion).await;
    let avatar_backup_exists = tokio::fs::try_exists(&promotion.avatar_backup_path)
        .await
        .unwrap();
    let meta_backup_exists = tokio::fs::try_exists(&promotion.avatar_meta_backup_path)
        .await
        .unwrap();
    let _ = tokio::fs::remove_dir_all(&dir).await;

    assert!(!avatar_backup_exists);
    assert!(!meta_backup_exists);
}

fn temp_avatar_dir(label: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "nazo_avatar_{label}_{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ))
}

#[actix_web::test]
async fn upload_avatar_rejects_session_request_without_csrf_before_file_or_profile_write() {
    let state = Data::new(test_state());
    let req = request_with_session_but_no_csrf(&state);
    let headers = HeaderMap::new();
    let payload =
        actix_multipart::Multipart::new(&headers, stream::empty::<Result<Bytes, PayloadError>>());

    assert_avatar_write_rejects_missing_csrf(upload_avatar(state, req, payload).await).await;
}

#[actix_web::test]
async fn delete_avatar_rejects_session_request_without_csrf_before_profile_write() {
    let state = Data::new(test_state());
    let req = request_with_session_but_no_csrf(&state);

    assert_avatar_write_rejects_missing_csrf(delete_avatar(state, req).await).await;
}
