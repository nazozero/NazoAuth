//! 当前用户资料接口。
// 只处理 /auth/me 的读取和基础资料更新。
use crate::http::prelude::*;

pub(crate) async fn me(state: Data<AppState>, req: HttpRequest) -> HttpResponse {
    let user = match current_user_or_login_required(&state, &req).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    match auth_me_json(&state, &user).await {
        Ok(body) => json_response(body),
        Err(error) => {
            tracing::warn!(%error, "failed to build auth me response");
            oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "当前用户资料查询失败.",
            )
        }
    }
}

#[derive(Deserialize)]
pub(crate) struct UpdateProfileRequest {
    display_name: Option<String>,
}

pub(crate) async fn update_me(
    state: Data<AppState>,
    req: HttpRequest,
    Json(payload): Json<UpdateProfileRequest>,
) -> HttpResponse {
    if !has_valid_csrf_token(&state, &req, None) {
        return csrf_error();
    }
    let user = match current_user_or_login_required(&state, &req).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    let display_name = payload
        .display_name
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty());
    let mut conn = match get_conn(&state.diesel_db).await {
        Ok(conn) => conn,
        Err(_) => {
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "数据库连接失败.",
            );
        }
    };
    let updated = diesel::update(users::table.find(user.id))
        .set((
            users::display_name.eq(display_name),
            users::updated_at.eq(diesel_now),
        ))
        .returning(UserRow::as_returning())
        .get_result::<UserRow>(&mut conn)
        .await;
    match updated {
        Ok(user) => match auth_me_json(&state, &user).await {
            Ok(body) => json_response(body),
            Err(error) => {
                tracing::warn!(%error, "failed to build updated auth me response");
                oauth_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "server_error",
                    "当前用户资料查询失败.",
                )
            }
        },
        Err(error) => {
            tracing::warn!(%error, "failed to update profile");
            oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "资料更新失败.",
            )
        }
    }
}
