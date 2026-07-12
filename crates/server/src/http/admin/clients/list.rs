//! 管理端客户端列表端点。
// 只负责分页读取和响应组装，不处理创建或更新逻辑。
use crate::http::prelude::*;

/// 返回 OAuth 客户端分页列表。
pub(crate) async fn admin_clients(
    state: Data<AppState>,
    req: HttpRequest,
    Query(q): Query<HashMap<String, String>>,
) -> HttpResponse {
    if let Err(response) = require_admin_or_forbidden(&state, &req).await {
        return response;
    }

    let (page, page_size, offset) = pagination(&q);
    let (clients, total) = match nazo_postgres::OAuthClientRepository::new(state.diesel_db.clone())
        .page(offset as i64, page_size as i64)
        .await
    {
        Ok(page) => page,
        Err(error) => {
            tracing::warn!(%error, "failed to load oauth clients");
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "客户端列表查询失败.",
            );
        }
    };
    clients_list_response(total, page, page_size, clients)
}

fn clients_list_response(
    total: i64,
    page: i32,
    page_size: i32,
    clients: Vec<ClientRow>,
) -> HttpResponse {
    let items: Vec<Value> = clients.into_iter().map(client_json).collect();
    json_response(json!({"total": total, "page": page, "page_size": page_size, "items": items}))
}

#[cfg(test)]
#[path = "../../../../tests/in_source/src/http/admin/clients/tests/list.rs"]
mod tests;
