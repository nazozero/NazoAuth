//! 管理端用户授权关系接口。
// 授权列表与撤销逻辑只依赖授权表和 refresh token 撤销。
use crate::http::prelude::*;
use diesel_async::AsyncConnection;

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
    let client = match find_client(&state.diesel_db, &payload.client_id).await {
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
    let (revoked, removed) = match get_conn(&state.diesel_db).await {
        Ok(mut conn) => match conn
            .transaction::<(usize, usize), diesel::result::Error, _>(async |conn| {
                let revoked = diesel::update(
                    oauth_tokens::table
                        .filter(oauth_tokens::user_id.eq(user_id))
                        .filter(oauth_tokens::client_id.eq(client.id))
                        .filter(oauth_tokens::revoked_at.is_null()),
                )
                .set(oauth_tokens::revoked_at.eq(diesel_now))
                .execute(conn)
                .await?;
                let removed = diesel::delete(
                    user_client_grants::table
                        .filter(user_client_grants::user_id.eq(user_id))
                        .filter(user_client_grants::client_id.eq(client.id)),
                )
                .execute(conn)
                .await?;
                Ok((revoked, removed))
            })
            .await
        {
            Ok(result) => result,
            Err(error) => {
                tracing::warn!(%error, "failed to revoke user client grant");
                return oauth_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "server_error",
                    "授权记录撤销失败.",
                );
            }
        },
        Err(error) => {
            tracing::warn!(%error, "failed to get database connection for grant revocation");
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "授权记录撤销失败.",
            );
        }
    };
    grant_revocation_response(revoked, removed)
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
