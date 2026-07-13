//! 管理端用户授权关系接口。
use crate::domain::AppState;
#[cfg(test)]
use crate::domain::ClientRow;
#[cfg(test)]
use crate::domain::DatabaseUserFixture;
#[cfg(test)]
use crate::settings::Settings;
#[cfg(test)]
use crate::support::{
    DEFAULT_ORGANIZATION_ID, DEFAULT_REALM_ID, OAuthJsonErrorFields, SessionPayload, valkey_set_ex,
};
use crate::support::{
    DEFAULT_TENANT_ID, csrf_error, has_valid_csrf_token, json_array_to_strings, json_response,
    oauth_error, pagination, require_admin_or_forbidden,
};
use actix_web::http::StatusCode;
use actix_web::web::{Data, Json, Query};
use actix_web::{HttpRequest, HttpResponse};
#[cfg(test)]
use chrono::Utc;
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::HashMap;
use uuid::Uuid;
// 授权列表与撤销逻辑只依赖授权表和 refresh token 撤销。

pub(crate) async fn admin_grants(
    state: Data<AppState>,
    req: HttpRequest,
    Query(q): Query<HashMap<String, String>>,
) -> HttpResponse {
    if let Err(response) = require_admin_or_forbidden(&state, &req).await {
        return response;
    }
    let (page, page_size, offset) = pagination(&q);
    let page_result = match nazo_postgres::GrantRepository::new(state.diesel_db.clone())
        .page(i64::from(page_size), i64::from(offset))
        .await
    {
        Ok(page) => page,
        Err(error) => {
            tracing::warn!(%error, "failed to load user client grants");
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "授权记录查询失败.",
            );
        }
    };
    grants_list_response(page, page_size, page_result.total, page_result.grants)
}

fn grants_list_response(
    page: i32,
    page_size: i32,
    total: i64,
    rows: Vec<nazo_postgres::GrantProjection>,
) -> HttpResponse {
    let items: Vec<Value> = rows.into_iter().map(grant_json).collect();
    json_response(json!({"total": total, "page": page, "page_size": page_size, "items": items}))
}

fn grant_json(row: nazo_postgres::GrantProjection) -> Value {
    json!({
        "user_id": row.user_id,
        "email": row.email,
        "client_id": row.client_id,
        "client_name": row.client_name,
        "last_authorized_at": row.last_authorized_at,
        "authorization_count": row.authorization_count,
        "last_scopes": json_array_to_strings(&row.last_scopes),
        "last_authorization_details": row.last_authorization_details
    })
}

#[derive(Deserialize)]
pub(crate) struct GrantRevokeRequest {
    user_id: String,
    client_id: String,
}

pub(crate) async fn admin_revoke_grant(
    state: Data<AppState>,
    req: HttpRequest,
    Json(payload): Json<GrantRevokeRequest>,
) -> HttpResponse {
    if !has_valid_csrf_token(&state, &req, None) {
        return csrf_error();
    }
    if let Err(response) = require_admin_or_forbidden(&state, &req).await {
        return response;
    }
    let Ok(user_id) = Uuid::parse_str(&payload.user_id) else {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "user_id 格式无效.",
        );
    };
    let client = match nazo_postgres::OAuthClientRepository::new(state.diesel_db.clone())
        .by_client_id(DEFAULT_TENANT_ID, &payload.client_id)
        .await
    {
        Ok(Some(client)) => client,
        Ok(None) => {
            return oauth_error(StatusCode::NOT_FOUND, "invalid_request", "未找到该客户端.");
        }
        Err(error) => {
            tracing::warn!(%error, "failed to query oauth client for grant revocation");
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "客户端查询失败.",
            );
        }
    };
    let revoked = match nazo_postgres::GrantRepository::new(state.diesel_db.clone())
        .revoke(user_id, client.id)
        .await
    {
        Ok(result) => result,
        Err(error) => {
            tracing::warn!(%error, "failed to get database connection for grant revocation");
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "授权记录撤销失败.",
            );
        }
    };
    grant_revocation_response(revoked.revoked_refresh_tokens, revoked.removed_grants)
}

fn grant_revocation_response(revoked_refresh_tokens: usize, removed_grants: usize) -> HttpResponse {
    json_response(json!({
        "revoked_refresh_tokens": revoked_refresh_tokens,
        "removed_grants": removed_grants
    }))
}

#[cfg(test)]
#[path = "../../../tests/in_source/src/http/admin/tests/grants.rs"]
mod tests;
