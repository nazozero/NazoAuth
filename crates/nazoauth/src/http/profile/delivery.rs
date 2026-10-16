//! 一次性客户端凭据领取接口。
use crate::http::sessions::SessionProfileHandles;
use actix_web::http::StatusCode;
use actix_web::web::{Data, Json};
use actix_web::{HttpRequest, HttpResponse};
use nazo_http_actix::{authorization_error_response, csrf_error, json_response_no_store};
use serde::Deserialize;
use serde_json::Value;
use uuid::Uuid;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AccessDeliveryRequest {
    pub(crate) request_id: Uuid,
}

pub(crate) async fn access_delivery(
    sessions: Data<SessionProfileHandles>,
    service: Data<nazo_oauth_server::services::ClientAccessProfileService>,
    req: HttpRequest,
    Json(payload): Json<AccessDeliveryRequest>,
) -> HttpResponse {
    if !sessions.has_valid_csrf_token(&req, None) {
        return csrf_error();
    }
    let user = match sessions.current_session_or_login_required(&req).await {
        Ok(session) => session.user,
        Err(response) => return response,
    };
    let claimed = match service.claim_delivery(&user, payload.request_id).await {
        Ok(claimed) => claimed,
        Err(nazo_identity::DeliveryReadError::Invalid) => {
            return invalid_delivery_response();
        }
        Err(
            nazo_identity::DeliveryReadError::Repository(error)
            | nazo_identity::DeliveryReadError::DeliveryStore(error),
        ) => {
            tracing::warn!(%error, "failed to read or consume client delivery payload");
            return authorization_error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "凭据读取失败.",
            );
        }
    };
    delivery_value_response(claimed)
}

fn invalid_delivery_response() -> HttpResponse {
    authorization_error_response(
        StatusCode::NOT_FOUND,
        "invalid_request",
        "凭据不存在、已过期或已被读取.",
    )
}

fn delivery_value_response(mut value: Value) -> HttpResponse {
    let payload = value
        .as_object_mut()
        .expect("claimed delivery is a validated object");
    payload.remove("delivery_state");
    payload.remove("approved_client_id");
    payload.insert(
        "read_once_notice".to_owned(),
        "此凭据已完成一次性读取并销毁，请立即保存敏感信息。".into(),
    );
    json_response_no_store(value)
}

#[cfg(test)]
#[path = "../../../tests/unit/http/profile/delivery.rs"]
mod tests;
