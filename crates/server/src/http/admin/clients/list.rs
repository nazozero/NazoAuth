//! 管理端客户端列表端点。
#[cfg(test)]
use super::test_dependencies;
use crate::domain::ClientRow;
#[cfg(test)]
use crate::domain::{AppState, DatabaseUserFixture};
#[cfg(test)]
use crate::settings::Settings;
use crate::support::sessions::{AdminSessionHandles, require_admin_or_forbidden_with_handles};
#[cfg(test)]
use crate::support::{
    DEFAULT_ORGANIZATION_ID, DEFAULT_REALM_ID, DEFAULT_TENANT_ID, SessionPayload, valkey_set_ex,
};
use crate::support::{client_json, pagination};
use actix_web::http::StatusCode;
use actix_web::web::{Data, Query};
use actix_web::{HttpRequest, HttpResponse};
#[cfg(test)]
use chrono::Utc;
#[cfg(test)]
use nazo_http_actix::OAuthJsonErrorFields;
use nazo_http_actix::{json_response, oauth_error};
use nazo_postgres::OAuthClientRepository;
use serde_json::{Value, json};
use std::collections::HashMap;
#[cfg(test)]
use uuid::Uuid;
// 只负责分页读取和响应组装，不处理创建或更新逻辑。

/// 返回 OAuth 客户端分页列表。
pub(crate) async fn admin_clients(
    admin_sessions: Data<AdminSessionHandles>,
    clients: Data<OAuthClientRepository>,
    req: HttpRequest,
    Query(q): Query<HashMap<String, String>>,
) -> HttpResponse {
    if let Err(response) = require_admin_or_forbidden_with_handles(&admin_sessions, &req).await {
        return response;
    }

    let (page, page_size, offset) = pagination(&q);
    let (clients, total) = match clients.page(offset as i64, page_size as i64).await {
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
