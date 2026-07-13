//! 当前用户客户端接入申请接口。
#[cfg(test)]
use crate::domain::DatabaseUserFixture;
#[cfg(test)]
use crate::settings::Settings;
use crate::support::access_delivery_token;
use crate::support::sessions::SessionProfileHandles;
#[cfg(test)]
use crate::support::{
    DEFAULT_ORGANIZATION_ID, DEFAULT_REALM_ID, DEFAULT_TENANT_ID, SessionPayload, valkey_set_ex,
};
use actix_web::http::StatusCode;
#[cfg(test)]
use actix_web::http::header;
use actix_web::web::{Data, Json};
use actix_web::{HttpRequest, HttpResponse};
#[cfg(test)]
use chrono::Utc;
#[cfg(test)]
use diesel_async::RunQueryDsl;
use nazo_http_actix::csrf_error;
use nazo_http_actix::{json_response, json_response_status, oauth_error};
#[cfg(test)]
use nazo_identity::AccessRequestStatus;
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::HashMap;
use uuid::Uuid;
// 只处理用户侧申请列表和新建申请。

#[derive(Clone)]
pub(crate) struct AccessRequestProfileService {
    requests: nazo_postgres::AccessRequestRepository,
    deliveries: nazo_valkey::DeliveryStore,
    client_secret_pepper: Box<str>,
    frontend_base_url: Box<str>,
}

impl AccessRequestProfileService {
    pub(crate) fn new(
        requests: nazo_postgres::AccessRequestRepository,
        deliveries: nazo_valkey::DeliveryStore,
        client_secret_pepper: &str,
        frontend_base_url: &str,
    ) -> Self {
        Self {
            requests,
            deliveries,
            client_secret_pepper: client_secret_pepper.into(),
            frontend_base_url: frontend_base_url.trim_end_matches('/').into(),
        }
    }

    async fn list_with_deliveries(
        &self,
        user: &nazo_identity::PublicAccount,
    ) -> Result<
        Vec<(nazo_identity::AccessRequest, Option<AvailableDelivery>)>,
        AccessRequestListError,
    > {
        const DELIVERY_LOOKUP_BATCH_SIZE: usize = 128;
        let rows = self
            .requests
            .list_for_user(user.tenant().tenant_id, user.user_id())
            .await
            .map_err(|error| AccessRequestListError::Repository(error.into()))?;
        let candidates = rows
            .iter()
            .filter_map(|row| delivery_candidate(self, row))
            .collect::<Vec<_>>();
        let mut deliveries = HashMap::with_capacity(candidates.len());
        for batch in candidates.chunks(DELIVERY_LOOKUP_BATCH_SIZE) {
            let lookups = batch
                .iter()
                .map(|candidate| (candidate.user_id, candidate.token.as_str()))
                .collect::<Vec<_>>();
            let payloads = self
                .deliveries
                .load_many(&lookups)
                .await
                .map_err(|error| AccessRequestListError::Delivery(error.into()))?;
            for (candidate, stored) in batch.iter().zip(payloads) {
                if let Some(stored) = stored
                    && delivery_payload_matches(candidate, stored.value())
                {
                    deliveries.insert(
                        candidate.request_id,
                        AvailableDelivery {
                            token: candidate.token.clone(),
                            url: format!(
                                "{}/delivery?token={}",
                                self.frontend_base_url, candidate.token
                            ),
                        },
                    );
                }
            }
        }
        Ok(rows
            .into_iter()
            .map(|row| {
                let delivery = deliveries.remove(&row.id);
                (row, delivery)
            })
            .collect())
    }

    async fn create(
        &self,
        user: &nazo_identity::PublicAccount,
        payload: CreateAccessRequest,
    ) -> Result<nazo_identity::AccessRequest, nazo_identity::ports::RepositoryError> {
        self.requests
            .create(nazo_identity::NewAccessRequest {
                tenant_id: user.principal.tenant.tenant_id,
                user_id: user.user_id(),
                site_name: payload.site_name,
                site_url: payload.site_url,
                request_description: payload.request_description,
            })
            .await
    }
}

enum AccessRequestListError {
    Repository(anyhow::Error),
    Delivery(anyhow::Error),
}

pub(crate) async fn my_access_requests(
    sessions: Data<SessionProfileHandles>,
    service: Data<AccessRequestProfileService>,
    req: HttpRequest,
) -> HttpResponse {
    let user = match sessions.current_user_or_login_required(&req).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    match service.list_with_deliveries(&user).await {
        Ok(items) => access_request_items_response(
            items
                .into_iter()
                .map(|(row, delivery)| user_access_request_json(row, delivery))
                .collect(),
        ),
        Err(AccessRequestListError::Repository(error)) => {
            tracing::warn!(%error, "failed to load user access requests");
            oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "接入申请查询失败.",
            )
        }
        Err(AccessRequestListError::Delivery(error)) => {
            tracing::warn!(%error, "failed to resolve access-request delivery link");
            oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "接入申请交付状态查询失败.",
            )
        }
    }
}

#[cfg(test)]
fn my_access_requests_response(rows: Vec<nazo_identity::AccessRequest>) -> HttpResponse {
    let items: Vec<Value> = rows
        .into_iter()
        .map(|row| user_access_request_json(row, None))
        .collect();
    access_request_items_response(items)
}

fn access_request_items_response(items: Vec<Value>) -> HttpResponse {
    let pending_count = items
        .iter()
        .filter(|item| {
            item.get("status").and_then(Value::as_i64)
                == Some(nazo_identity::AccessRequestStatus::Pending.code() as i64)
        })
        .count();
    json_response(json!({"total": items.len(), "pending_count": pending_count, "items": items}))
}

struct AvailableDelivery {
    token: String,
    url: String,
}

struct DeliveryCandidate {
    request_id: Uuid,
    user_id: nazo_identity::UserId,
    approved_client_id: Uuid,
    token: String,
}

fn delivery_candidate(
    service: &AccessRequestProfileService,
    row: &nazo_identity::AccessRequest,
) -> Option<DeliveryCandidate> {
    let approved_client_id = row.approved_client_id?;
    if row.status != nazo_identity::AccessRequestStatus::Approved {
        return None;
    }
    let user_id = row.user_id;
    let token = access_delivery_token(&service.client_secret_pepper, user_id.as_uuid(), row.id);
    Some(DeliveryCandidate {
        request_id: row.id,
        user_id,
        approved_client_id,
        token,
    })
}

fn delivery_payload_matches(candidate: &DeliveryCandidate, payload: &Value) -> bool {
    if payload["delivery_state"] != "committed"
        || payload["request_id"] != json!(candidate.request_id)
        || payload["user_id"] != json!(candidate.user_id.as_uuid())
        || payload["approved_client_id"] != json!(candidate.approved_client_id)
    {
        return false;
    }
    true
}

fn user_access_request_json(
    row: nazo_identity::AccessRequest,
    delivery: Option<AvailableDelivery>,
) -> Value {
    let mut value = json!({
        "id": row.id,
        "site_name": row.site_name,
        "site_url": row.site_url,
        "request_description": row.request_description,
        "status": row.status.code(),
        "admin_note": row.admin_note,
        "approved_client_id": row.approved_client_id,
        "created_at": row.created_at,
        "resolved_at": row.resolved_at,
    });
    if let Some(delivery) = delivery {
        value["delivery_token"] = json!(delivery.token);
        value["delivery_url"] = json!(delivery.url);
    }
    value
}

#[derive(Deserialize)]
pub(crate) struct CreateAccessRequest {
    site_name: String,
    site_url: String,
    request_description: String,
}

pub(crate) async fn create_access_request(
    sessions: Data<SessionProfileHandles>,
    service: Data<AccessRequestProfileService>,
    req: HttpRequest,
    Json(payload): Json<CreateAccessRequest>,
) -> HttpResponse {
    if !sessions.has_valid_csrf_token(&req, None) {
        return csrf_error();
    }
    let user = match sessions.current_user_or_login_required(&req).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    let row = service.create(&user, payload).await;
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
    json_response_status(StatusCode::CREATED, user_access_request_json(row, None))
}

#[cfg(test)]
#[path = "../../../tests/in_source/src/http/profile/tests/access_requests.rs"]
mod tests;
