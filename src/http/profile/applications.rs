//! 当前用户已授权应用接口。
// 只读取当前用户的 OAuth 授权关系。
use crate::http::prelude::*;

pub(crate) async fn my_applications(state: Data<AppState>, req: HttpRequest) -> HttpResponse {
    let user = match current_user_or_login_required(&state, &req).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    let rows = match get_conn(&state.diesel_db).await {
        Ok(mut conn) => match user_client_grants::table
            .inner_join(
                oauth_clients::table.on(oauth_clients::id.eq(user_client_grants::client_id)),
            )
            .filter(user_client_grants::user_id.eq(user.id))
            .select((
                oauth_clients::client_id,
                oauth_clients::client_name,
                user_client_grants::last_scopes,
                user_client_grants::last_authorized_at,
                user_client_grants::authorization_count,
            ))
            .order(user_client_grants::last_authorized_at.desc())
            .load::<MyApplicationRow>(&mut conn)
            .await
        {
            Ok(rows) => rows,
            Err(error) => {
                tracing::warn!(%error, "failed to load user applications");
                return oauth_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "server_error",
                    "授权应用查询失败.",
                );
            }
        },
        Err(error) => {
            tracing::warn!(%error, "failed to get database connection for user applications");
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "授权应用查询失败.",
            );
        }
    };
    let items: Vec<Value> = rows.into_iter().map(my_application_json).collect();
    json_response(json!({"total": items.len(), "items": items}))
}

fn my_application_json(row: MyApplicationRow) -> Value {
    json!({
        "client_id": row.client_id,
        "client_name": row.client_name,
        "last_scopes": json_array_to_strings(&row.last_scopes),
        "last_authorized_at": row.last_authorized_at,
        "authorization_count": row.authorization_count
    })
}

#[cfg(test)]
#[path = "../../../tests/unit/src/http/profile/tests/applications.rs"]
mod tests;
