//! 当前用户客户端接入申请接口。
// 只处理用户侧申请列表和新建申请。
use crate::http::prelude::*;

pub(crate) async fn my_access_requests(state: Data<AppState>, req: HttpRequest) -> HttpResponse {
    let user = match current_user_or_login_required(&state, &req).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    let rows = match nazo_postgres::AccessRequestRepository::new(state.diesel_db.clone())
        .list_for_user(user.principal.tenant.tenant_id, user.user_id())
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
    };
    match my_access_requests_response_with_delivery(&state, rows).await {
        Ok(response) => response,
        Err(error) => {
            tracing::warn!(%error, "failed to resolve access-request delivery link");
            oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "接入申请交付状态查询失败.",
            )
        }
    }
}

async fn my_access_requests_response_with_delivery(
    state: &AppState,
    rows: Vec<nazo_identity::AccessRequest>,
) -> anyhow::Result<HttpResponse> {
    const DELIVERY_LOOKUP_BATCH_SIZE: usize = 128;
    let candidates = rows
        .iter()
        .filter_map(|row| delivery_candidate(state, row))
        .collect::<Vec<_>>();
    let mut deliveries = HashMap::with_capacity(candidates.len());
    for batch in candidates.chunks(DELIVERY_LOOKUP_BATCH_SIZE) {
        let lookups = batch
            .iter()
            .map(|candidate| (candidate.user_id, candidate.token.as_str()))
            .collect::<Vec<_>>();
        let payloads = nazo_valkey::DeliveryStore::new(&state.valkey_connection())
            .load_many(&lookups)
            .await?;
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
                            state.settings.frontend_base_url.trim_end_matches('/'),
                            candidate.token
                        ),
                    },
                );
            }
        }
    }
    let items = rows
        .into_iter()
        .map(|row| {
            let delivery = deliveries.remove(&row.id);
            user_access_request_json(row, delivery)
        })
        .collect();
    Ok(access_request_items_response(items))
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
    state: &AppState,
    row: &nazo_identity::AccessRequest,
) -> Option<DeliveryCandidate> {
    let approved_client_id = row.approved_client_id?;
    if row.status != nazo_identity::AccessRequestStatus::Approved {
        return None;
    }
    let user_id = row.user_id;
    let token = access_delivery_token(
        state.settings.protocol().client_secret_pepper,
        user_id.as_uuid(),
        row.id,
    );
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
    let row = nazo_postgres::AccessRequestRepository::new(state.diesel_db.clone())
        .create(nazo_identity::NewAccessRequest {
            tenant_id: user.principal.tenant.tenant_id,
            user_id: user.user_id(),
            site_name: payload.site_name,
            site_url: payload.site_url,
            request_description: payload.request_description,
        })
        .await;
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
