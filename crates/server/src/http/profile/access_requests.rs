//! 当前用户客户端接入申请接口。
// 只处理用户侧申请列表和新建申请。
use crate::http::prelude::*;

pub(crate) async fn my_access_requests(state: Data<AppState>, req: HttpRequest) -> HttpResponse {
    let user = match current_user_or_login_required(&state, &req).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    let rows = match nazo_postgres::AccessRequestRepository::new(state.diesel_db.clone())
        .list_for_user(user.principal.tenant.tenant_id, user.user_id())
        .await
    {
        Ok(rows) => rows,
        Err(error) => {
            tracing::warn!(%error, "failed to load user access requests");
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "接入申请查询失败.",
            );
        }
    };
    my_access_requests_response(rows)
}

fn my_access_requests_response(rows: Vec<nazo_identity::AccessRequest>) -> HttpResponse {
    let items: Vec<Value> = rows.into_iter().map(user_access_request_json).collect();
    let pending_count = items
        .iter()
        .filter(|item| {
            item.get("status").and_then(Value::as_i64)
                == Some(nazo_identity::AccessRequestStatus::Pending.code() as i64)
        })
        .count();
    json_response(json!({"total": items.len(), "pending_count": pending_count, "items": items}))
}

fn user_access_request_json(row: nazo_identity::AccessRequest) -> Value {
    json!({
        "id": row.id,
        "site_name": row.site_name,
        "site_url": row.site_url,
        "request_description": row.request_description,
        "status": row.status.code(),
        "admin_note": row.admin_note,
        "approved_client_id": row.approved_client_id,
        "created_at": row.created_at,
        "resolved_at": row.resolved_at
    })
}

#[derive(Deserialize)]
pub(crate) struct CreateAccessRequest {
    site_name: String,
    site_url: String,
    request_description: String,
}

pub(crate) async fn create_access_request(
    state: Data<AppState>,
    req: HttpRequest,
    Json(payload): Json<CreateAccessRequest>,
) -> HttpResponse {
    if !has_valid_csrf_token(&state, &req, None) {
        return csrf_error();
    }
    let user = match current_user_or_login_required(&state, &req).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    let row = nazo_postgres::AccessRequestRepository::new(state.diesel_db.clone())
        .create(nazo_identity::NewAccessRequest {
            tenant_id: user.principal.tenant.tenant_id,
            user_id: user.user_id(),
            site_name: payload.site_name,
            site_url: payload.site_url,
            request_description: payload.request_description,
        })
        .await;
    match row {
        Ok(r) => create_access_request_response(r),
        Err(nazo_identity::ports::RepositoryError::Conflict) => {
            oauth_error(StatusCode::CONFLICT, "invalid_request", "已有待处理申请.")
        }
        Err(error) => {
            tracing::warn!(%error, "failed to create access request");
            oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "接入申请创建失败.",
            )
        }
    }
}

fn create_access_request_response(row: nazo_identity::AccessRequest) -> HttpResponse {
    json_response_status(StatusCode::CREATED, user_access_request_json(row))
}

#[cfg(test)]
#[path = "../../../tests/in_source/src/http/profile/tests/access_requests.rs"]
mod tests;
