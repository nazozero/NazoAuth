//! 当前用户已授权应用接口。
// 只读取当前用户的 OAuth 授权关系。
use crate::http::prelude::*;

pub(crate) async fn my_applications(state: Data<AppState>, req: HttpRequest) -> HttpResponse {
    let user = match current_user_or_login_required(&state, &req).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    let rows = match nazo_postgres::OAuthClientRepository::new(state.diesel_db.clone())
        .applications_for_user(user.id())
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
    };
    let items: Vec<Value> = rows.into_iter().map(my_application_json).collect();
    json_response(json!({"total": items.len(), "items": items}))
}

fn my_application_json(row: nazo_postgres::OAuthClientApplication) -> Value {
    json!({
        "client_id": row.client_id,
        "client_name": row.client_name,
        "last_scopes": json_array_to_strings(&row.last_scopes),
        "last_authorized_at": row.last_authorized_at,
        "authorization_count": row.authorization_count
    })
}

#[cfg(test)]
#[path = "../../../tests/in_source/src/http/profile/tests/applications.rs"]
mod tests;
