//! 管理端客户端详情端点。
#[cfg(test)]
use super::test_dependencies;
use crate::domain::ClientRow;
#[cfg(test)]
use crate::domain::{AppState, DatabaseUserFixture};
#[cfg(test)]
use crate::settings::Settings;
use crate::support::sessions::{AdminSessionHandles, require_admin_or_forbidden_with_handles};
#[cfg(test)]
use crate::support::{DEFAULT_ORGANIZATION_ID, DEFAULT_REALM_ID, SessionPayload, valkey_set_ex};
use crate::support::{DEFAULT_TENANT_ID, client_json};
use actix_web::http::StatusCode;
use actix_web::web::Data;
use actix_web::{HttpRequest, HttpResponse};
#[cfg(test)]
use chrono::Utc;
#[cfg(test)]
use nazo_http_actix::OAuthJsonErrorFields;
use nazo_http_actix::{json_response, oauth_error};
use nazo_postgres::OAuthClientRepository;
#[cfg(test)]
use serde_json::{Value, json};
#[cfg(test)]
use uuid::Uuid;
// 根据公开 client_id 查找客户端，响应中不暴露 secret hash。

/// 返回单个 OAuth 客户端详情。
pub(crate) async fn admin_get_client(
    admin_sessions: Data<AdminSessionHandles>,
    clients: Data<OAuthClientRepository>,
    req: HttpRequest,
    path: actix_web::web::Path<String>,
) -> HttpResponse {
    let client_id = path.into_inner();
    if let Err(response) = require_admin_or_forbidden_with_handles(&admin_sessions, &req).await {
        return response;
    }

    match clients.by_client_id(DEFAULT_TENANT_ID, &client_id).await {
        Ok(Some(client)) => client_detail_response(client),
        Ok(None) => client_detail_not_found_response(),
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

fn client_detail_response(client: ClientRow) -> HttpResponse {
    json_response(client_json(client))
}

fn client_detail_not_found_response() -> HttpResponse {
    oauth_error(StatusCode::NOT_FOUND, "invalid_request", "未找到该客户端.")
}

#[cfg(test)]
#[path = "../../../../tests/in_source/src/http/admin/clients/tests/detail.rs"]
mod tests;
