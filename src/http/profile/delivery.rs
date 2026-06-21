//! 一次性客户端凭据领取接口。
// 只处理审批后临时凭据的只读领取。
use crate::http::prelude::*;

pub(crate) async fn access_delivery(
    state: Data<AppState>,
    req: HttpRequest,
    Query(q): Query<HashMap<String, String>>,
) -> HttpResponse {
    let user = match current_user_or_login_required(&state, &req).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    let Some(token) = q.get("token") else {
        return oauth_error(StatusCode::BAD_REQUEST, "invalid_request", "缺少 token.");
    };
    let key = format!("oauth:client_delivery:{}:{token}", user.id);
    let raw = match valkey_getdel(&state.valkey, &key).await {
        Ok(value) => value,
        Err(error) => {
            tracing::warn!(%error, "failed to read client delivery payload");
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "凭据读取失败.",
            );
        }
    };
    let Some(raw) = raw else {
        return oauth_error(
            StatusCode::NOT_FOUND,
            "invalid_request",
            "凭据链接无效、已过期或已被读取.",
        );
    };
    delivery_payload_response(&raw)
}

fn delivery_payload_response(raw: &str) -> HttpResponse {
    match serde_json::from_str::<Value>(raw) {
        Ok(mut v) => {
            v["read_once_notice"] = json!("此凭据链接已完成一次性读取并销毁，请立即保存敏感信息。");
            json_response(v)
        }
        Err(_) => oauth_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            "凭据内容无效.",
        ),
    }
}

#[cfg(test)]
#[path = "../../../tests/in_source/src/http/profile/tests/delivery.rs"]
mod tests;
