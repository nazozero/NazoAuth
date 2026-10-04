//! 管理端客户端更新端点。
use super::{AdminClientConfig, ServerAdminClientService};
use crate::http::admin::require_transactional_audit_or_unavailable;
use crate::http::sessions::{
    AdminSessionHandles, require_admin_with_recent_mfa_or_forbidden_with_handles,
};
use crate::http::views::client_json;
use actix_web::http::StatusCode;
use actix_web::web::{Data, Json};
use actix_web::{HttpRequest, HttpResponse};
use nazo_auth::{AdminClientError, PatchClientRequest};
use nazo_http_actix::client_ip_with_config;
use nazo_http_actix::{csrf_error, has_valid_csrf_token_for_cookies};
use nazo_http_actix::{json_response, oauth_error};
use nazo_oauth_server::crypto::blake3_hex;

pub(crate) async fn admin_patch_client(
    admin_sessions: Data<AdminSessionHandles>,
    service: Data<ServerAdminClientService>,
    config: Data<AdminClientConfig>,
    req: HttpRequest,
    path: actix_web::web::Path<String>,
    Json(payload): Json<PatchClientRequest>,
) -> HttpResponse {
    let client_id = path.into_inner();
    let session_http = admin_sessions.http_config();
    if !has_valid_csrf_token_for_cookies(
        &req,
        None,
        session_http.session_cookie_name(),
        session_http.csrf_cookie_name(),
    ) {
        return csrf_error();
    }
    let admin = match require_admin_with_recent_mfa_or_forbidden_with_handles(&admin_sessions, &req).await {
        Ok(admin) => admin,
        Err(response) => return response,
    };
    if let Err(response) = require_transactional_audit_or_unavailable().await {
        return response;
    }
    let source_ip_hash = blake3_hex(&client_ip_with_config(&req, config.client_ip()));
    match service.update_with_required_audit(&client_id, payload, admin.id(), &source_ip_hash).await {
        Ok(client) => {
            json_response(client_json(&client))
        }
        Err(AdminClientError::NotFound) => {
            oauth_error(StatusCode::NOT_FOUND, "invalid_request", "未找到该客户端.")
        }
        Err(AdminClientError::InvalidRequest(message)) => oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            &format!("客户端更新失败: {message}"),
        ),
        Err(AdminClientError::Write(nazo_auth::AdminClientPortError::Conflict)) => oauth_error(
            StatusCode::CONFLICT,
            "invalid_request",
            "Client metadata changed while preparing this update. Reload and retry.",
        ),
        Err(AdminClientError::Lookup(error)) => {
            tracing::warn!(%error, "failed to query oauth client for admin update");
            oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "客户端查询失败.",
            )
        }
        Err(error) => {
            tracing::warn!(%error, "failed to update oauth client");
            oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "客户端更新失败.",
            )
        }
    }
}

#[cfg(test)]
#[path = "../../../../tests/unit/http/admin/clients/update.rs"]
mod tests;
