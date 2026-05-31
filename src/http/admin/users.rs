//! 管理端用户账户接口。
// 只处理用户列表与用户状态更新，不包含客户端或授权关系逻辑。
use crate::http::prelude::*;
use diesel_async::AsyncConnection;

pub(crate) async fn admin_users(
    state: Data<AppState>,
    req: HttpRequest,
    Query(q): Query<HashMap<String, String>>,
) -> HttpResponse {
    if let Err(response) = require_admin_or_forbidden(&state, &req).await {
        return response;
    }
    let (page, page_size, offset) = pagination(&q);
    let (total, user_rows) = match get_conn(&state.diesel_db).await {
        Ok(mut conn) => {
            let total = match users::table
                .select(count_star())
                .first::<i64>(&mut conn)
                .await
            {
                Ok(total) => total,
                Err(error) => {
                    tracing::warn!(%error, "failed to count users");
                    return oauth_error(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "server_error",
                        "用户列表查询失败.",
                    );
                }
            };
            let rows = match users::table
                .select(UserRow::as_select())
                .order(users::created_at.desc())
                .limit(page_size as i64)
                .offset(offset as i64)
                .load::<UserRow>(&mut conn)
                .await
            {
                Ok(rows) => rows,
                Err(error) => {
                    tracing::warn!(%error, "failed to load users");
                    return oauth_error(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "server_error",
                        "用户列表查询失败.",
                    );
                }
            };
            (total, rows)
        }
        Err(error) => {
            tracing::warn!(%error, "failed to get database connection for user list");
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "用户列表查询失败.",
            );
        }
    };
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
    if payload.admin_level.is_some_and(|level| level < 0) {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "admin_level 不能为负数.",
        );
    }
    if let Some(role) = payload.role.as_deref() {
        match role {
            "admin" | "user" => {}
            _ => {
                return oauth_error(StatusCode::BAD_REQUEST, "invalid_request", "用户角色无效.");
            }
        }
    }
    let mut conn = match get_conn(&state.diesel_db).await {
        Ok(conn) => conn,
        Err(error) => {
            tracing::warn!(%error, "failed to get database connection for user update");
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "用户更新失败.",
            );
        }
    };
    let updated = match conn
        .transaction::<Option<UserRow>, diesel::result::Error, _>(async |conn| {
            if let Some(role) = payload.role.as_deref()
                && diesel::update(users::table.find(user_id))
                    .set((users::role.eq(role), users::updated_at.eq(diesel_now)))
                    .execute(conn)
                    .await?
                    == 0
            {
                return Ok(None);
            }
            if let Some(admin_level) = payload.admin_level
                && diesel::update(users::table.find(user_id))
                    .set((
                        users::admin_level.eq(admin_level),
                        users::updated_at.eq(diesel_now),
                    ))
                    .execute(conn)
                    .await?
                    == 0
            {
                return Ok(None);
            }
            if let Some(is_active) = payload.is_active
                && diesel::update(users::table.find(user_id))
                    .set((
                        users::is_active.eq(is_active),
                        users::updated_at.eq(diesel_now),
                    ))
                    .execute(conn)
                    .await?
                    == 0
            {
                return Ok(None);
            }
            users::table
                .find(user_id)
                .select(UserRow::as_select())
                .first::<UserRow>(conn)
                .await
                .optional()
        })
        .await
    {
        Ok(updated) => updated,
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
        Some(user) => json_response(admin_user_json(user)),
        None => oauth_error(StatusCode::NOT_FOUND, "invalid_request", "未找到该用户."),
    }
}
