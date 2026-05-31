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
    let (total, rows) = match get_conn(&state.diesel_db).await {
        Ok(mut conn) => {
            let total = match user_client_grants::table
                .select(count_star())
                .first::<i64>(&mut conn)
                .await
            {
                Ok(total) => total,
                Err(error) => {
                    tracing::warn!(%error, "failed to count user client grants");
                    return oauth_error(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "server_error",
                        "授权记录查询失败.",
                    );
                }
            };
            let rows = match user_client_grants::table
                .inner_join(users::table.on(users::id.eq(user_client_grants::user_id)))
                .inner_join(
                    oauth_clients::table.on(oauth_clients::id.eq(user_client_grants::client_id)),
                )
                .select((
                    user_client_grants::user_id,
                    users::email,
                    oauth_clients::client_id,
                    oauth_clients::client_name,
                    user_client_grants::last_authorized_at,
                    user_client_grants::authorization_count,
                    user_client_grants::last_scopes,
                ))
                .order(user_client_grants::last_authorized_at.desc())
                .limit(page_size as i64)
                .offset(offset as i64)
                .load::<GrantRow>(&mut conn)
                .await
            {
                Ok(rows) => rows,
                Err(error) => {
                    tracing::warn!(%error, "failed to load user client grants");
                    return oauth_error(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "server_error",
                        "授权记录查询失败.",
                    );
                }
            };
            (total, rows)
        }
        Err(error) => {
            tracing::warn!(%error, "failed to get database connection for grant list");
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "授权记录查询失败.",
            );
        }
    };
    let items: Vec<Value> = rows.into_iter().map(|r| json!({"user_id": r.user_id, "email": r.email, "client_id": r.client_id, "client_name": r.client_name, "last_authorized_at": r.last_authorized_at, "authorization_count": r.authorization_count, "last_scopes": json_array_to_strings(&r.last_scopes)})).collect();
    json_response(json!({"total": total, "page": page, "page_size": page_size, "items": items}))
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
    json_response(json!({"revoked_refresh_tokens": revoked, "removed_grants": removed}))
}
