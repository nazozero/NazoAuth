//! 管理端客户端列表端点。
use super::ServerAdminClientService;
use crate::endpoints::sessions::{AdminSessionHandles, require_admin_or_forbidden_with_handles};
use crate::endpoints::views::{client_json, pagination};
use crate::http::Request as HttpRequest;
use crate::http::Response as HttpResponse;
use http::StatusCode;

use crate::http::{json_response, oauth_error};
use serde::{Serialize, Serializer};

#[derive(Serialize)]
pub struct ClientsListResponse<'a> {
    pub total: i64,
    pub page: i32,
    pub page_size: i32,
    #[serde(serialize_with = "serialize_clients")]
    pub items: &'a [nazo_auth::OAuthClient],
}

pub fn serialize_clients<S: Serializer>(
    clients: &[nazo_auth::OAuthClient],
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serializer.collect_seq(clients.iter().map(client_json))
}
use std::collections::HashMap;

pub async fn admin_clients(
    admin_sessions: &AdminSessionHandles,
    service: &ServerAdminClientService,
    req: &HttpRequest,
    query: HashMap<String, String>,
) -> HttpResponse {
    if let Err(response) = require_admin_or_forbidden_with_handles(admin_sessions, req).await {
        return response;
    }
    let (page, page_size, offset) = pagination(&query);
    match service.page(offset, page_size as i64).await {
        Ok((clients, total)) => clients_list_response(total, page, page_size, clients),
        Err(error) => {
            tracing::warn!(%error, "failed to load oauth clients");
            oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "客户端列表查询失败.",
            )
        }
    }
}

pub fn clients_list_response(
    total: i64,
    page: i32,
    page_size: i32,
    clients: Vec<nazo_auth::OAuthClient>,
) -> HttpResponse {
    json_response(ClientsListResponse {
        total,
        page,
        page_size,
        items: &clients,
    })
}
