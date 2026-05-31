//! 当前用户头像接口。
// 只处理头像上传、读取和删除的 HTTP 细节。
use std::{
    io,
    path::{Path, PathBuf},
};

use crate::http::prelude::*;

struct AvatarPromotion {
    avatar_file_path: PathBuf,
    avatar_meta_file_path: PathBuf,
    avatar_backup_path: PathBuf,
    avatar_meta_backup_path: PathBuf,
    avatar_backup_exists: bool,
    avatar_meta_backup_exists: bool,
}

async fn remove_avatar_file_if_exists(path: PathBuf) -> io::Result<()> {
    match tokio::fs::remove_file(path).await {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

async fn rename_avatar_file_if_exists(source: &Path, target: &Path) -> io::Result<bool> {
    match tokio::fs::rename(source, target).await {
        Ok(()) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
    }
}

async fn cleanup_avatar_temps(avatar_tmp_path: &Path, avatar_meta_tmp_path: &Path) {
    let _ = tokio::fs::remove_file(avatar_tmp_path).await;
    let _ = tokio::fs::remove_file(avatar_meta_tmp_path).await;
}

async fn restore_avatar_backup(backup_path: &Path, final_path: &Path, backup_exists: bool) {
    if backup_exists
        && let Err(error) = tokio::fs::rename(backup_path, final_path).await
        && error.kind() != io::ErrorKind::NotFound
    {
        tracing::warn!(%error, "failed to restore previous avatar file");
    }
}

async fn rollback_avatar_promotion(promotion: &AvatarPromotion) {
    let _ = tokio::fs::remove_file(&promotion.avatar_file_path).await;
    let _ = tokio::fs::remove_file(&promotion.avatar_meta_file_path).await;
    restore_avatar_backup(
        &promotion.avatar_backup_path,
        &promotion.avatar_file_path,
        promotion.avatar_backup_exists,
    )
    .await;
    restore_avatar_backup(
        &promotion.avatar_meta_backup_path,
        &promotion.avatar_meta_file_path,
        promotion.avatar_meta_backup_exists,
    )
    .await;
}

async fn finish_avatar_promotion(promotion: &AvatarPromotion) {
    let _ = tokio::fs::remove_file(&promotion.avatar_backup_path).await;
    let _ = tokio::fs::remove_file(&promotion.avatar_meta_backup_path).await;
}

async fn rollback_avatar_promotion_attempt(
    avatar_tmp_path: &Path,
    avatar_meta_tmp_path: &Path,
    promotion: &AvatarPromotion,
) {
    cleanup_avatar_temps(avatar_tmp_path, avatar_meta_tmp_path).await;
    rollback_avatar_promotion(promotion).await;
}

async fn promote_avatar_files(
    avatar_tmp_path: &Path,
    avatar_meta_tmp_path: &Path,
    avatar_file_path: PathBuf,
    avatar_meta_file_path: PathBuf,
    version: &str,
) -> io::Result<AvatarPromotion> {
    let avatar_backup_path = avatar_file_path.with_file_name(format!("avatar-{version}.bak"));
    let avatar_meta_backup_path =
        avatar_meta_file_path.with_file_name(format!("meta-{version}.bak"));
    let avatar_backup_exists =
        rename_avatar_file_if_exists(&avatar_file_path, &avatar_backup_path).await?;
    let avatar_meta_backup_exists = match rename_avatar_file_if_exists(
        &avatar_meta_file_path,
        &avatar_meta_backup_path,
    )
    .await
    {
        Ok(value) => value,
        Err(error) => {
            restore_avatar_backup(&avatar_backup_path, &avatar_file_path, avatar_backup_exists)
                .await;
            cleanup_avatar_temps(avatar_tmp_path, avatar_meta_tmp_path).await;
            return Err(error);
        }
    };
    let promotion = AvatarPromotion {
        avatar_file_path,
        avatar_meta_file_path,
        avatar_backup_path,
        avatar_meta_backup_path,
        avatar_backup_exists,
        avatar_meta_backup_exists,
    };
    if let Err(error) = tokio::fs::rename(avatar_tmp_path, &promotion.avatar_file_path).await {
        rollback_avatar_promotion_attempt(avatar_tmp_path, avatar_meta_tmp_path, &promotion).await;
        return Err(error);
    }
    if let Err(error) =
        tokio::fs::rename(avatar_meta_tmp_path, &promotion.avatar_meta_file_path).await
    {
        rollback_avatar_promotion_attempt(avatar_tmp_path, avatar_meta_tmp_path, &promotion).await;
        return Err(error);
    }
    Ok(promotion)
}

fn avatar_url_version(avatar_url: &str) -> Option<&str> {
    avatar_url
        .strip_prefix("/auth/me/avatar?v=")
        .filter(|version| !version.is_empty())
}

pub(crate) async fn upload_avatar(
    state: Data<AppState>,
    req: HttpRequest,
    mut multipart: Multipart,
) -> HttpResponse {
    if !has_valid_csrf_token(&state, &req, None) {
        return csrf_error();
    }
    let user = match current_user_or_login_required(&state, &req).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    while let Some(field) = multipart.next().await {
        let mut field = match field {
            Ok(field) => field,
            Err(_) => {
                return oauth_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_request",
                    "头像文件读取失败.",
                );
            }
        };
        if field.name() != Some("avatar") {
            continue;
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = field.next().await {
            let chunk = match chunk {
                Ok(chunk) => chunk,
                Err(_) => {
                    return oauth_error(
                        StatusCode::BAD_REQUEST,
                        "invalid_request",
                        "头像文件读取失败.",
                    );
                }
            };
            bytes.extend_from_slice(&chunk);
            if bytes.len() > state.settings.avatar_max_bytes {
                return oauth_error(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "invalid_request",
                    "头像文件过大.",
                );
            }
        }
        let Some(content_type) = detect_avatar_content_type(&bytes) else {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "头像仅支持 PNG、JPEG、WEBP 格式.",
            );
        };
        let version = Uuid::now_v7().to_string();
        let user_dir = avatar_user_dir(&state, user.id);
        let avatar_file_path = avatar_path(&state, user.id);
        let avatar_meta_file_path = avatar_meta_path(&state, user.id);
        let avatar_tmp_path = user_dir.join(format!("avatar-{version}.tmp"));
        let avatar_meta_tmp_path = user_dir.join(format!("meta-{version}.tmp"));
        if tokio::fs::create_dir_all(&user_dir).await.is_err() {
            return oauth_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "头像保存失败.",
            );
        }
        if tokio::fs::write(&avatar_tmp_path, &bytes).await.is_err()
            || tokio::fs::write(
                &avatar_meta_tmp_path,
                json!({"content_type": content_type, "version": version}).to_string(),
            )
            .await
            .is_err()
        {
            cleanup_avatar_temps(&avatar_tmp_path, &avatar_meta_tmp_path).await;
            return oauth_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "头像保存失败.",
            );
        }
        let mut conn = match get_conn(&state.diesel_db).await {
            Ok(conn) => conn,
            Err(error) => {
                tracing::warn!(%error, "failed to get database connection for avatar upload");
                let _ = tokio::fs::remove_file(&avatar_tmp_path).await;
                let _ = tokio::fs::remove_file(&avatar_meta_tmp_path).await;
                return oauth_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "server_error",
                    "头像保存失败.",
                );
            }
        };
        let promotion = match promote_avatar_files(
            &avatar_tmp_path,
            &avatar_meta_tmp_path,
            avatar_file_path,
            avatar_meta_file_path,
            &version,
        )
        .await
        {
            Ok(promotion) => promotion,
            Err(error) => {
                tracing::warn!(%error, "failed to promote uploaded avatar files");
                return oauth_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "server_error",
                    "头像保存失败.",
                );
            }
        };
        let user = match diesel::update(users::table.find(user.id))
            .set((
                users::avatar_url.eq(Some(format!("/auth/me/avatar?v={version}"))),
                users::updated_at.eq(diesel_now),
            ))
            .returning(UserRow::as_returning())
            .get_result::<UserRow>(&mut conn)
            .await
        {
            Ok(user) => user,
            Err(error) => {
                tracing::warn!(%error, "failed to persist avatar metadata");
                rollback_avatar_promotion(&promotion).await;
                return oauth_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "server_error",
                    "头像保存失败.",
                );
            }
        };
        finish_avatar_promotion(&promotion).await;
        return match auth_me_json(&state, &user).await {
            Ok(body) => json_response(body),
            Err(error) => {
                tracing::warn!(%error, "failed to build auth me response after avatar upload");
                oauth_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "server_error",
                    "当前用户资料查询失败.",
                )
            }
        };
    }
    oauth_error(
        StatusCode::BAD_REQUEST,
        "invalid_request",
        "缺少 avatar 文件.",
    )
}

pub(crate) async fn get_avatar(state: Data<AppState>, req: HttpRequest) -> HttpResponse {
    let user = match current_user_or_login_required(&state, &req).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    if is_cross_site_fetch(req.headers()) {
        return oauth_error(
            StatusCode::FORBIDDEN,
            "access_denied",
            "跨站请求头像资源被拒绝.",
        );
    };
    let Some(avatar_url) = user.avatar_url.as_deref() else {
        return oauth_error(
            StatusCode::NOT_FOUND,
            "invalid_request",
            "当前用户尚未上传头像.",
        );
    };
    let Some(expected_version) = avatar_url_version(avatar_url) else {
        tracing::warn!("stored avatar_url has invalid shape");
        return oauth_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "头像读取失败.",
        );
    };
    let meta = match read_avatar_meta(&state, user.id).await {
        Ok(Some(meta)) => meta,
        Ok(None) => {
            tracing::warn!("avatar metadata file is missing while user avatar_url is set");
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "头像读取失败.",
            );
        }
        Err(error) => {
            tracing::warn!(%error, "failed to read avatar metadata");
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "头像读取失败.",
            );
        }
    };
    if meta.get("version").and_then(Value::as_str) != Some(expected_version) {
        tracing::warn!("avatar metadata version does not match user avatar_url");
        return oauth_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "头像读取失败.",
        );
    }
    match tokio::fs::read(avatar_path(&state, user.id)).await {
        Ok(bytes) => {
            let content_type = match meta.get("content_type").and_then(Value::as_str) {
                Some("image/png") => "image/png",
                Some("image/jpeg") => "image/jpeg",
                Some("image/webp") => "image/webp",
                _ => match detect_avatar_content_type(&bytes) {
                    Some(content_type) => content_type,
                    None => {
                        tracing::warn!("avatar file has unsupported content type");
                        return oauth_error(
                            StatusCode::SERVICE_UNAVAILABLE,
                            "server_error",
                            "头像读取失败.",
                        );
                    }
                },
            };
            let mut resp = bytes_response(bytes);
            if let Ok(value) = HeaderValue::from_str(content_type) {
                resp.headers_mut().insert(header::CONTENT_TYPE, value);
            }
            resp.headers_mut().insert(
                header::CACHE_CONTROL,
                HeaderValue::from_static("private, no-store, no-cache, must-revalidate"),
            );
            resp.headers_mut()
                .insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
            resp.headers_mut().insert(
                header::X_CONTENT_TYPE_OPTIONS,
                HeaderValue::from_static("nosniff"),
            );
            resp.headers_mut().insert(
                header::CONTENT_SECURITY_POLICY,
                HeaderValue::from_static("default-src 'none'"),
            );
            resp
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            tracing::warn!("avatar file is missing while user avatar_url is set");
            oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "头像读取失败.",
            )
        }
        Err(error) => {
            tracing::warn!(%error, "failed to read avatar file");
            oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "头像读取失败.",
            )
        }
    }
}

pub(crate) async fn delete_avatar(state: Data<AppState>, req: HttpRequest) -> HttpResponse {
    if !has_valid_csrf_token(&state, &req, None) {
        return csrf_error();
    }
    let user = match current_user_or_login_required(&state, &req).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    let mut conn = match get_conn(&state.diesel_db).await {
        Ok(conn) => conn,
        Err(error) => {
            tracing::warn!(%error, "failed to get database connection for avatar delete");
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "头像删除失败.",
            );
        }
    };
    let user_id = user.id;
    let user = match diesel::update(users::table.find(user_id))
        .set((
            users::avatar_url.eq(Option::<String>::None),
            users::updated_at.eq(diesel_now),
        ))
        .returning(UserRow::as_returning())
        .get_result::<UserRow>(&mut conn)
        .await
    {
        Ok(user) => user,
        Err(error) => {
            tracing::warn!(%error, "failed to clear avatar metadata");
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "头像删除失败.",
            );
        }
    };
    if let Err(error) = remove_avatar_file_if_exists(avatar_path(&state, user_id)).await {
        tracing::warn!(%error, "failed to remove avatar file");
        return oauth_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "头像删除失败.",
        );
    }
    if let Err(error) = remove_avatar_file_if_exists(avatar_meta_path(&state, user_id)).await {
        tracing::warn!(%error, "failed to remove avatar metadata file");
        return oauth_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "头像删除失败.",
        );
    }
    if let Err(error) = tokio::fs::remove_dir(avatar_user_dir(&state, user_id)).await
        && error.kind() != std::io::ErrorKind::NotFound
    {
        tracing::warn!(%error, "failed to remove avatar user directory");
    }
    match auth_me_json(&state, &user).await {
        Ok(body) => json_response(body),
        Err(error) => {
            tracing::warn!(%error, "failed to build auth me response after avatar delete");
            oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "当前用户资料查询失败.",
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
