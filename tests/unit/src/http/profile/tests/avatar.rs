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

fn build_test_state(settings: Settings) -> AppState {
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
        settings: Arc::new(settings),
        keyset: Arc::new(Keyset {
            active_kid: "test-kid".to_owned(),
            active_alg: jsonwebtoken::Algorithm::EdDSA,
            active_signing_key: ActiveSigningKey::LocalPkcs8Der(Vec::new()),
            verification_keys: Vec::new(),
        }),
    }
}

fn test_state() -> AppState {
    build_test_state(
        Settings::from_config(&ConfigSource::default()).expect("default settings should load"),
    )
}

fn test_state_with_avatar_dir(avatar_storage_dir: PathBuf) -> AppState {
    let mut settings =
        Settings::from_config(&ConfigSource::default()).expect("default settings should load");
    settings.avatar_storage_dir = avatar_storage_dir;
    build_test_state(settings)
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

#[test]
fn avatar_url_version_accepts_only_expected_query_shape() {
    assert_eq!(
        avatar_url_version("/auth/me/avatar?v=019789ad-1f5a-7c0d-b9b5-d9d74376d6fc"),
        Some("019789ad-1f5a-7c0d-b9b5-d9d74376d6fc")
    );

    for invalid_url in [
        "",
        "/auth/me/avatar",
        "/auth/me/avatar?v=",
        "/auth/me/avatar?version=abc",
        "/profile/avatar?v=abc",
    ] {
        assert_eq!(
            avatar_url_version(invalid_url),
            None,
            "unexpected avatar URL shape should not be parsed as a version"
        );
    }
}

#[tokio::test]
async fn remove_avatar_file_if_exists_removes_existing_file_and_ignores_missing_path() {
    let dir = temp_avatar_dir("remove");
    let avatar = dir.join("avatar.bin");
    tokio::fs::create_dir_all(&dir).await.unwrap();
    tokio::fs::write(&avatar, b"avatar-bytes").await.unwrap();

    remove_avatar_file_if_exists(avatar.clone()).await.unwrap();
    assert!(!tokio::fs::try_exists(&avatar).await.unwrap());

    remove_avatar_file_if_exists(avatar.clone()).await.unwrap();
    assert!(!tokio::fs::try_exists(&avatar).await.unwrap());

    let _ = tokio::fs::remove_dir_all(&dir).await;
}

#[tokio::test]
async fn rename_avatar_file_if_exists_moves_existing_file_and_reports_missing_source() {
    let dir = temp_avatar_dir("rename");
    let source = dir.join("avatar.tmp");
    let target = dir.join("avatar.bin");
    let missing_source = dir.join("missing.tmp");
    let missing_target = dir.join("missing.bin");
    tokio::fs::create_dir_all(&dir).await.unwrap();
    tokio::fs::write(&source, b"new-avatar").await.unwrap();

    assert!(
        rename_avatar_file_if_exists(&source, &target)
            .await
            .unwrap()
    );
    assert!(!tokio::fs::try_exists(&source).await.unwrap());
    assert_eq!(tokio::fs::read(&target).await.unwrap(), b"new-avatar");

    assert!(
        !rename_avatar_file_if_exists(&missing_source, &missing_target)
            .await
            .unwrap()
    );
    assert!(!tokio::fs::try_exists(&missing_target).await.unwrap());

    let _ = tokio::fs::remove_dir_all(&dir).await;
}

#[tokio::test]
async fn cleanup_avatar_temps_removes_existing_files_and_is_idempotent() {
    let dir = temp_avatar_dir("cleanup");
    let avatar_tmp = dir.join("avatar.tmp");
    let avatar_meta_tmp = dir.join("meta.tmp");
    tokio::fs::create_dir_all(&dir).await.unwrap();
    tokio::fs::write(&avatar_tmp, b"new-avatar").await.unwrap();
    tokio::fs::write(&avatar_meta_tmp, b"new-meta")
        .await
        .unwrap();

    cleanup_avatar_temps(&avatar_tmp, &avatar_meta_tmp).await;
    cleanup_avatar_temps(&avatar_tmp, &avatar_meta_tmp).await;

    assert!(!tokio::fs::try_exists(&avatar_tmp).await.unwrap());
    assert!(!tokio::fs::try_exists(&avatar_meta_tmp).await.unwrap());

    let _ = tokio::fs::remove_dir_all(&dir).await;
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

#[tokio::test]
async fn avatar_promotion_without_previous_files_can_roll_back_to_empty_state() {
    let dir = temp_avatar_dir("rollback-empty");
    tokio::fs::create_dir_all(&dir).await.unwrap();
    let avatar = dir.join("avatar.bin");
    let meta = dir.join("meta.json");
    let avatar_tmp = dir.join("avatar-new.tmp");
    let meta_tmp = dir.join("meta-new.tmp");
    tokio::fs::write(&avatar_tmp, b"new-avatar").await.unwrap();
    tokio::fs::write(&meta_tmp, b"{\"content_type\":\"image/png\"}")
        .await
        .unwrap();

    let promotion =
        promote_avatar_files(&avatar_tmp, &meta_tmp, avatar.clone(), meta.clone(), "v1")
            .await
            .unwrap();
    assert!(!promotion.avatar_backup_exists);
    assert!(!promotion.avatar_meta_backup_exists);
    assert_eq!(tokio::fs::read(&avatar).await.unwrap(), b"new-avatar");
    assert_eq!(
        tokio::fs::read(&meta).await.unwrap(),
        b"{\"content_type\":\"image/png\"}"
    );

    rollback_avatar_promotion(&promotion).await;

    assert!(!tokio::fs::try_exists(&avatar).await.unwrap());
    assert!(!tokio::fs::try_exists(&meta).await.unwrap());
    assert!(
        !tokio::fs::try_exists(&promotion.avatar_backup_path)
            .await
            .unwrap()
    );
    assert!(
        !tokio::fs::try_exists(&promotion.avatar_meta_backup_path)
            .await
            .unwrap()
    );

    let _ = tokio::fs::remove_dir_all(&dir).await;
}

#[tokio::test]
async fn avatar_promotion_restores_previous_files_when_avatar_temp_is_missing() {
    let dir = temp_avatar_dir("rollback-missing-avatar-tmp");
    tokio::fs::create_dir_all(&dir).await.unwrap();
    let avatar = dir.join("avatar.bin");
    let meta = dir.join("meta.json");
    let avatar_tmp = dir.join("avatar-new.tmp");
    let meta_tmp = dir.join("meta-new.tmp");
    tokio::fs::write(&avatar, b"old-avatar").await.unwrap();
    tokio::fs::write(&meta, b"old-meta").await.unwrap();
    tokio::fs::write(&meta_tmp, b"new-meta").await.unwrap();

    let error = match promote_avatar_files(
        &avatar_tmp,
        &meta_tmp,
        avatar.clone(),
        meta.clone(),
        "v1",
    )
    .await
    {
        Ok(_) => panic!("missing avatar temp should fail promotion"),
        Err(error) => error,
    };

    assert_eq!(error.kind(), io::ErrorKind::NotFound);
    assert_eq!(tokio::fs::read(&avatar).await.unwrap(), b"old-avatar");
    assert_eq!(tokio::fs::read(&meta).await.unwrap(), b"old-meta");
    assert!(!tokio::fs::try_exists(&avatar_tmp).await.unwrap());
    assert!(!tokio::fs::try_exists(&meta_tmp).await.unwrap());
    assert!(
        !tokio::fs::try_exists(dir.join("avatar-v1.bak"))
            .await
            .unwrap()
    );
    assert!(
        !tokio::fs::try_exists(dir.join("meta-v1.bak"))
            .await
            .unwrap()
    );

    let _ = tokio::fs::remove_dir_all(&dir).await;
}

#[tokio::test]
async fn avatar_promotion_restores_previous_files_when_metadata_temp_is_missing_after_avatar_move()
{
    let dir = temp_avatar_dir("rollback-missing-meta-tmp");
    tokio::fs::create_dir_all(&dir).await.unwrap();
    let avatar = dir.join("avatar.bin");
    let meta = dir.join("meta.json");
    let avatar_tmp = dir.join("avatar-new.tmp");
    let meta_tmp = dir.join("meta-new.tmp");
    tokio::fs::write(&avatar, b"old-avatar").await.unwrap();
    tokio::fs::write(&meta, b"old-meta").await.unwrap();
    tokio::fs::write(&avatar_tmp, b"new-avatar").await.unwrap();

    let error = match promote_avatar_files(
        &avatar_tmp,
        &meta_tmp,
        avatar.clone(),
        meta.clone(),
        "v1",
    )
    .await
    {
        Ok(_) => panic!("missing metadata temp should fail promotion"),
        Err(error) => error,
    };

    assert_eq!(error.kind(), io::ErrorKind::NotFound);
    assert_eq!(tokio::fs::read(&avatar).await.unwrap(), b"old-avatar");
    assert_eq!(tokio::fs::read(&meta).await.unwrap(), b"old-meta");
    assert!(!tokio::fs::try_exists(&avatar_tmp).await.unwrap());
    assert!(!tokio::fs::try_exists(&meta_tmp).await.unwrap());
    assert!(
        !tokio::fs::try_exists(dir.join("avatar-v1.bak"))
            .await
            .unwrap()
    );
    assert!(
        !tokio::fs::try_exists(dir.join("meta-v1.bak"))
            .await
            .unwrap()
    );

    let _ = tokio::fs::remove_dir_all(&dir).await;
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

#[tokio::test]
async fn read_avatar_meta_distinguishes_missing_valid_and_invalid_metadata() {
    let dir = temp_avatar_dir("read-meta");
    let state = test_state_with_avatar_dir(dir.clone());
    let user_id = Uuid::now_v7();

    assert!(read_avatar_meta(&state, user_id).await.unwrap().is_none());

    let user_dir = avatar_user_dir(&state, user_id);
    tokio::fs::create_dir_all(&user_dir).await.unwrap();
    tokio::fs::write(
        avatar_meta_path(&state, user_id),
        r#"{"content_type":"image/webp","version":"v1"}"#,
    )
    .await
    .unwrap();

    let meta = read_avatar_meta(&state, user_id)
        .await
        .unwrap()
        .expect("metadata should be present after write");
    assert_eq!(meta["content_type"], "image/webp");
    assert_eq!(meta["version"], "v1");

    tokio::fs::write(avatar_meta_path(&state, user_id), b"{not-json")
        .await
        .unwrap();
    let error = read_avatar_meta(&state, user_id)
        .await
        .expect_err("invalid metadata JSON should fail");
    assert!(error.downcast_ref::<serde_json::Error>().is_some());

    let _ = tokio::fs::remove_dir_all(&dir).await;
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
