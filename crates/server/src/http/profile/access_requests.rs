//! 当前用户客户端接入申请接口。
// 只处理用户侧申请列表和新建申请。
use crate::http::prelude::*;

pub(crate) async fn my_access_requests(state: Data<AppState>, req: HttpRequest) -> HttpResponse {
    let user = match current_user_or_login_required(&state, &req).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    let rows = match get_conn(&state.diesel_db).await {
        Ok(mut conn) => match client_access_requests::table
            .filter(client_access_requests::user_id.eq(user.id))
            .select((
                client_access_requests::id,
                client_access_requests::site_name,
                client_access_requests::site_url,
                client_access_requests::request_description,
                client_access_requests::status,
                client_access_requests::admin_note,
                client_access_requests::approved_client_id,
                client_access_requests::created_at,
                client_access_requests::resolved_at,
            ))
            .order(client_access_requests::created_at.desc())
            .load::<UserAccessRequestRow>(&mut conn)
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
        },
        Err(error) => {
            tracing::warn!(%error, "failed to get database connection for user access requests");
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "接入申请查询失败.",
            );
        }
    };
    my_access_requests_response(rows)
}

fn my_access_requests_response(rows: Vec<UserAccessRequestRow>) -> HttpResponse {
    let items: Vec<Value> = rows.into_iter().map(user_access_request_json).collect();
    let pending_count = items
        .iter()
        .filter(|item| {
            item.get("status").and_then(Value::as_i64)
                == Some(AccessRequestStatus::Pending.code() as i64)
        })
        .count();
    json_response(json!({"total": items.len(), "pending_count": pending_count, "items": items}))
}

fn user_access_request_json(row: UserAccessRequestRow) -> Value {
    json!({
        "id": row.id,
        "site_name": row.site_name,
        "site_url": row.site_url,
        "request_description": row.request_description,
        "status": row.status,
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
    let mut conn = match get_conn(&state.diesel_db).await {
        Ok(conn) => conn,
        Err(_) => {
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "数据库连接失败.",
            );
        }
    };
    let row = diesel::insert_into(client_access_requests::table)
        .values((
            client_access_requests::user_id.eq(user.id),
            client_access_requests::site_name.eq(payload.site_name),
            client_access_requests::site_url.eq(payload.site_url),
            client_access_requests::request_description.eq(payload.request_description),
            client_access_requests::status.eq(AccessRequestStatus::Pending.code()),
        ))
        .returning((
            client_access_requests::id,
            client_access_requests::site_name,
            client_access_requests::site_url,
            client_access_requests::request_description,
            client_access_requests::status,
            client_access_requests::admin_note,
            client_access_requests::approved_client_id,
            client_access_requests::created_at,
            client_access_requests::resolved_at,
        ))
        .get_result::<UserAccessRequestRow>(&mut conn)
        .await;
    match row {
        Ok(r) => create_access_request_response(r),
        Err(diesel::result::Error::DatabaseError(
            diesel::result::DatabaseErrorKind::UniqueViolation,
            _,
        )) => oauth_error(StatusCode::CONFLICT, "invalid_request", "已有待处理申请."),
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

fn create_access_request_response(row: UserAccessRequestRow) -> HttpResponse {
    json_response_status(StatusCode::CREATED, user_access_request_json(row))
}

#[cfg(test)]
#[path = "../../../tests/in_source/src/http/profile/tests/access_requests.rs"]
mod tests;
