//! 管理端用户账户接口。
// 只处理用户列表与用户状态更新，不包含客户端或授权关系逻辑。
use crate::http::prelude::*;

pub(crate) async fn admin_users(
    state: Data<AppState>,
    req: HttpRequest,
    Query(q): Query<HashMap<String, String>>,
) -> HttpResponse {
    if let Err(response) = require_admin_or_forbidden(&state, &req).await {
        return response;
    }
    let (page, page_size, offset) = pagination(&q);
    let (total, user_rows) = match nazo_postgres::UserRepository::new(state.diesel_db.clone())
        .page(page_size as i64, offset as i64)
        .await
    {
        Ok(page) => (page.total, page.users),
        Err(error) => {
            tracing::warn!(%error, "failed to get database connection for user list");
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "用户列表查询失败.",
            );
        }
    };
    admin_users_list_response(page, page_size, total, user_rows)
}

fn admin_users_list_response(
    page: i32,
    page_size: i32,
    total: i64,
    user_rows: Vec<PublicAccount>,
) -> HttpResponse {
    let items: Vec<Value> = user_rows.into_iter().map(admin_user_json).collect();
    json_response(json!({"total": total, "page": page, "page_size": page_size, "items": items}))
}

#[derive(Deserialize)]
pub(crate) struct PatchUserRequest {
    role: Option<String>,
    admin_level: Option<i32>,
    is_active: Option<bool>,
}

pub(crate) async fn admin_patch_user(
    state: Data<AppState>,
    req: HttpRequest,
    path: actix_web::web::Path<Uuid>,
    Json(payload): Json<PatchUserRequest>,
) -> HttpResponse {
    let user_id = path.into_inner();
    if !has_valid_csrf_token(&state, &req, None) {
        return csrf_error();
    }
    if let Err(response) = require_admin_or_forbidden(&state, &req).await {
        return response;
    }
    if let Some(response) = patch_user_validation_error(&payload) {
        return response;
    }
    let user_id = match nazo_identity::UserId::new(user_id) {
        Ok(user_id) => user_id,
        Err(_) => {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "user_id 格式无效.",
            );
        }
    };
    let updated = match nazo_postgres::UserRepository::new(state.diesel_db.clone())
        .admin_update(
            user_id,
            nazo_identity::ports::AdminUserUpdate {
                role: payload.role,
                admin_level: payload.admin_level,
                active: payload.is_active,
            },
        )
        .await
    {
        Ok(updated) => updated,
        Err(nazo_identity::ports::RepositoryError::Conflict) => {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "role 与 admin_level 组合无效.",
            );
        }
        Err(error) => {
            tracing::warn!(%error, "failed to update user");
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "用户更新失败.",
            );
        }
    };
    match updated {
        Some(user) => {
            audit_event(
                "admin_user_updated",
                audit_fields(&[
                    ("user_id", json!(user.id())),
                    (
                        "source_ip_hash",
                        json!(blake3_hex(&client_ip(&req, &state.settings))),
                    ),
                ]),
            );
            json_response(admin_user_json(user))
        }
        None => oauth_error(StatusCode::NOT_FOUND, "invalid_request", "未找到该用户."),
    }
}

fn patch_user_validation_error(payload: &PatchUserRequest) -> Option<HttpResponse> {
    if payload.admin_level.is_some_and(|level| level < 0) {
        return Some(oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "admin_level 不能为负数.",
        ));
    }
    if let Some(role) = payload.role.as_deref() {
        match role {
            "admin" | "user" => {}
            _ => {
                return Some(oauth_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_request",
                    "用户角色无效.",
                ));
            }
        }
    }
    None
}

#[cfg(test)]
#[path = "../../../tests/in_source/src/http/admin/tests/users.rs"]
mod tests;
