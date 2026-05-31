//! 管理端客户端详情端点。
// 根据公开 client_id 查找客户端，响应中不暴露 secret hash。
use crate::http::prelude::*;

/// 返回单个 OAuth 客户端详情。
pub(crate) async fn admin_get_client(
    state: Data<AppState>,
    req: HttpRequest,
    path: actix_web::web::Path<String>,
) -> HttpResponse {
    let client_id = path.into_inner();
    if let Err(response) = require_admin_or_forbidden(&state, &req).await {
        return response;
    }

    match find_client(&state.diesel_db, &client_id).await {
        Ok(Some(client)) => json_response(client_json(client)),
        Ok(None) => oauth_error(StatusCode::NOT_FOUND, "invalid_request", "未找到该客户端."),
        Err(error) => {
            tracing::warn!(%error, "failed to query oauth client detail");
            oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "客户端查询失败.",
            )
        }
    }
}
