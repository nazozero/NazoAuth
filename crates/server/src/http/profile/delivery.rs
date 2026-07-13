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
    let store = nazo_valkey::DeliveryStore::new(&state.valkey_connection());
    let stored = match nazo_valkey::DeliveryStore::load(&store, user.user_id(), token).await {
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
    let Some(stored) = stored else {
        return oauth_error(
            StatusCode::NOT_FOUND,
            "invalid_request",
            "凭据链接无效、已过期或已被读取.",
        );
    };
    let Some(claim) = delivery_claim(stored.value()) else {
        let _ = store.delete(user.user_id(), token).await;
        return invalid_delivery_link_response();
    };
    let repository = nazo_postgres::AccessRequestRepository::new(state.diesel_db.clone());
    let linked = repository
        .approved_delivery_matches(
            user.tenant().tenant_id,
            user.user_id(),
            claim.request_id,
            claim.approved_client_id,
            &claim.client_id,
        )
        .await;
    match linked {
        Ok(true) => {}
        Ok(false) => {
            let _ = store.delete(user.user_id(), token).await;
            return invalid_delivery_link_response();
        }
        Err(error) => {
            tracing::warn!(%error, "failed to validate client delivery linkage");
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "凭据读取失败.",
            );
        }
    }
    let claimed = match store.consume(user.user_id(), token, &stored).await {
        Ok(nazo_valkey::DeliveryConsume::Consumed(claimed)) => claimed,
        Ok(nazo_valkey::DeliveryConsume::MissingOrChanged) => {
            return invalid_delivery_link_response();
        }
        Err(error) => {
            tracing::warn!(%error, "failed to consume client delivery payload");
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "凭据读取失败.",
            );
        }
    };
    delivery_value_response(claimed)
}

struct DeliveryClaim {
    request_id: Uuid,
    approved_client_id: Uuid,
    client_id: String,
}

fn delivery_claim(value: &Value) -> Option<DeliveryClaim> {
    if value.get("delivery_state")?.as_str()? != "committed" {
        return None;
    }
    Some(DeliveryClaim {
        request_id: serde_json::from_value(value.get("request_id")?.clone()).ok()?,
        approved_client_id: serde_json::from_value(value.get("approved_client_id")?.clone())
            .ok()?,
        client_id: value.get("client_id")?.as_str()?.to_owned(),
    })
}

fn invalid_delivery_link_response() -> HttpResponse {
    oauth_error(
        StatusCode::NOT_FOUND,
        "invalid_request",
        "凭据链接无效、已过期或已被读取.",
    )
}

fn delivery_value_response(mut value: Value) -> HttpResponse {
    if delivery_claim(&value).is_some() {
        value
            .as_object_mut()
            .expect("validated delivery payload is an object")
            .remove("delivery_state");
        value
            .as_object_mut()
            .expect("validated delivery payload is an object")
            .remove("approved_client_id");
        value["read_once_notice"] = json!("此凭据链接已完成一次性读取并销毁，请立即保存敏感信息。");
        json_response(value)
    } else {
        invalid_delivery_link_response()
    }
}

#[cfg(test)]
fn delivery_payload_response(raw: &str) -> HttpResponse {
    match serde_json::from_str(raw) {
        Ok(value) => delivery_value_response(value),
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
