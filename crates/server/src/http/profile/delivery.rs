//! 一次性客户端凭据领取接口。
use crate::support::sessions::SessionProfileHandles;
use actix_web::http::StatusCode;
use actix_web::web::{Data, Query};
use actix_web::{HttpRequest, HttpResponse};
use nazo_http_actix::{json_response, oauth_error};
use serde_json::{Value, json};
use std::collections::HashMap;
use uuid::Uuid;
// 只处理审批后临时凭据的只读领取。

#[derive(Clone)]
pub(crate) struct DeliveryProfileService {
    requests: nazo_postgres::AccessRequestRepository,
    deliveries: nazo_valkey::DeliveryStore,
}

impl DeliveryProfileService {
    pub(crate) fn new(
        requests: nazo_postgres::AccessRequestRepository,
        deliveries: nazo_valkey::DeliveryStore,
    ) -> Self {
        Self {
            requests,
            deliveries,
        }
    }

    async fn claim(
        &self,
        user: &nazo_identity::PublicAccount,
        token: &str,
    ) -> Result<Value, DeliveryReadError> {
        let stored = self
            .deliveries
            .load(user.user_id(), token)
            .await
            .map_err(|error| DeliveryReadError::Unavailable(error.into()))?
            .ok_or(DeliveryReadError::Invalid)?;
        let Some(claim) = delivery_claim(stored.value()) else {
            let _ = self.deliveries.delete(user.user_id(), token).await;
            return Err(DeliveryReadError::Invalid);
        };
        match self
            .requests
            .approved_delivery_matches(
                user.tenant().tenant_id,
                user.user_id(),
                claim.request_id,
                claim.approved_client_id,
                &claim.client_id,
            )
            .await
        {
            Ok(true) => {}
            Ok(false) => {
                let _ = self.deliveries.delete(user.user_id(), token).await;
                return Err(DeliveryReadError::Invalid);
            }
            Err(error) => return Err(DeliveryReadError::Unavailable(error.into())),
        }
        match self
            .deliveries
            .consume(user.user_id(), token, &stored)
            .await
        {
            Ok(nazo_valkey::DeliveryConsume::Consumed(value)) => Ok(value),
            Ok(nazo_valkey::DeliveryConsume::MissingOrChanged) => Err(DeliveryReadError::Invalid),
            Err(error) => Err(DeliveryReadError::Unavailable(error.into())),
        }
    }
}

enum DeliveryReadError {
    Invalid,
    Unavailable(anyhow::Error),
}

pub(crate) async fn access_delivery(
    sessions: Data<SessionProfileHandles>,
    service: Data<DeliveryProfileService>,
    req: HttpRequest,
    Query(q): Query<HashMap<String, String>>,
) -> HttpResponse {
    let user = match sessions.current_user_or_login_required(&req).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    let Some(token) = q.get("token") else {
        return oauth_error(StatusCode::BAD_REQUEST, "invalid_request", "缺少 token.");
    };
    let claimed = match service.claim(&user, token).await {
        Ok(claimed) => claimed,
        Err(DeliveryReadError::Invalid) => return invalid_delivery_link_response(),
        Err(DeliveryReadError::Unavailable(error)) => {
            tracing::warn!(%error, "failed to read or consume client delivery payload");
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
