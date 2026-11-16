//! 管理端客户端详情端点。
use super::ServerAdminClientService;
use crate::endpoints::sessions::{AdminSessionHandles, require_admin_or_forbidden_with_handles};
use crate::endpoints::views::client_json;
use crate::http::Request as HttpRequest;
use crate::http::Response as HttpResponse;
use http::StatusCode;

use crate::http::{json_response, oauth_error};
use nazo_auth::AdminClientError;

pub async fn admin_get_client(
    admin_sessions: &AdminSessionHandles,
    service: &ServerAdminClientService,
    req: &HttpRequest,
    path: String,
) -> HttpResponse {
    let client_id = path;
    if let Err(response) = require_admin_or_forbidden_with_handles(admin_sessions, req).await {
        return response;
    }
    match service.detail(&client_id).await {
        Ok(client) => client_detail_response(client),
        Err(AdminClientError::NotFound) => client_detail_not_found_response(),
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

pub fn client_detail_response(client: nazo_auth::OAuthClient) -> HttpResponse {
    json_response(client_json(&client))
}

pub fn client_detail_not_found_response() -> HttpResponse {
    oauth_error(StatusCode::NOT_FOUND, "invalid_request", "未找到该客户端.")
}
