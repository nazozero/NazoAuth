//! 管理端客户端创建端点。
use super::{AdminClientConfig, ServerAdminClientService};
use crate::endpoints::admin::require_transactional_audit_or_unavailable;
use crate::endpoints::sessions::{
    AdminSessionHandles, require_admin_with_recent_mfa_or_forbidden_with_handles,
};
use crate::endpoints::views::{ClientView, client_json};
use crate::http::Request as HttpRequest;
use crate::http::Response as HttpResponse;
use http::StatusCode;

use crate::http::client_ip_with_config;
use crate::http::{csrf_error, has_valid_csrf_token_for_cookies};
use crate::http::{json_response_status, oauth_error};
use nazo_auth::{AdminClientError, CreateClientRequest};
use nazo_oauth_server::crypto::blake3_hex;
use serde::Serialize;

#[derive(Serialize)]
pub struct CreatedClientResponse<'a> {
    #[serde(flatten)]
    pub client: ClientView<'a>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_secret: Option<&'a str>,
}

pub async fn admin_create_client(
    audit: &dyn nazo_oauth_server::ports::audit::SecurityAudit,
    admin_sessions: &AdminSessionHandles,
    service: &ServerAdminClientService,
    config: &AdminClientConfig,
    req: &HttpRequest,
    payload: CreateClientRequest,
) -> HttpResponse {
    let session_http = admin_sessions.http_config();
    if !has_valid_csrf_token_for_cookies(
        req,
        None,
        session_http.session_cookie_name(),
        session_http.csrf_cookie_name(),
    ) {
        return csrf_error();
    }
    let admin =
        match require_admin_with_recent_mfa_or_forbidden_with_handles(admin_sessions, req).await {
            Ok(admin) => admin,
            Err(response) => return response,
        };
    if let Err(response) = require_transactional_audit_or_unavailable(audit).await {
        return response;
    }

    let source_ip_hash = blake3_hex(&client_ip_with_config(req, config.client_ip()));
    match service
        .create_with_required_audit(payload, admin.id(), &source_ip_hash)
        .await
    {
        Ok(created) => json_response_status(
            StatusCode::CREATED,
            CreatedClientResponse {
                client: client_json(&created.client),
                client_secret: created.issued_secret.as_deref(),
            },
        ),
        Err(error) => create_error_response(error),
    }
}

pub fn create_error_response(error: AdminClientError) -> HttpResponse {
    match error {
        AdminClientError::InvalidRequest(message) => oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            &format!("客户端创建失败: {message}"),
        ),
        error => {
            tracing::warn!(%error, "failed to create oauth client");
            oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "客户端创建失败.",
            )
        }
    }
}
