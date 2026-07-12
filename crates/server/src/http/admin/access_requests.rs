//! 管理端客户端接入申请接口。
// 申请审批会创建客户端，因此显式依赖 clients 模块的创建逻辑。
use super::clients::{
    CreateClientRequest, insert_client_error_response, prepare_client_insert_with_secret_pepper,
};
use crate::http::prelude::*;

pub(crate) async fn admin_access_requests(
    state: Data<AppState>,
    req: HttpRequest,
    Query(q): Query<HashMap<String, String>>,
) -> HttpResponse {
    let admin = match require_admin_or_forbidden(&state, &req).await {
        Ok(admin) => admin,
        Err(response) => return response,
    };
    let (page, page_size, offset) = pagination(&q);
    let status = match parse_access_request_status(&q) {
        Ok(status) => status,
        Err(response) => return response,
    };
    let search = q.get("q").map(String::as_str);
    let result = nazo_postgres::AccessRequestRepository::new(state.diesel_db.clone())
        .page(
            admin.principal.tenant.tenant_id,
            i64::from(page_size),
            i64::from(offset),
            search,
            status,
        )
        .await;
    let result = match result {
        Ok(result) => result,
        Err(error) => {
            tracing::warn!(%error, "failed to load access requests");
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "接入申请查询失败.",
            );
        }
    };
    access_requests_response(page, page_size, result.total, result.items)
}

fn parse_access_request_status(
    q: &HashMap<String, String>,
) -> Result<Option<nazo_identity::AccessRequestStatus>, HttpResponse> {
    match q
        .get("status")
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
    {
        Some(value) => value
            .parse::<i16>()
            .ok()
            .and_then(nazo_identity::AccessRequestStatus::from_code)
            .map(Some)
            .ok_or_else(invalid_access_request_status_response),
        None => Ok(None),
    }
}

fn invalid_access_request_status_response() -> HttpResponse {
    oauth_error(
        StatusCode::BAD_REQUEST,
        "invalid_request",
        "status 参数仅支持 0/1/2.",
    )
}

fn access_requests_response(
    page: i32,
    page_size: i32,
    total: i64,
    rows: Vec<nazo_identity::AccessRequest>,
) -> HttpResponse {
    let rows = rows
        .into_iter()
        .map(access_request_json)
        .collect::<Vec<_>>();
    json_response(json!({"total": total, "page": page, "page_size": page_size, "items": rows}))
}

pub(crate) async fn admin_approve_access_request(
    state: Data<AppState>,
    req: HttpRequest,
    path: actix_web::web::Path<Uuid>,
    Json(payload): Json<CreateClientRequest>,
) -> HttpResponse {
    let request_id = path.into_inner();
    if !has_valid_csrf_token(&state, &req, None) {
        return csrf_error();
    }
    let admin = match require_admin_or_forbidden(&state, &req).await {
        Ok(admin) => admin,
        Err(response) => return response,
    };
    let repository = nazo_postgres::AccessRequestRepository::new(state.diesel_db.clone());
    let pending_request = match repository
        .by_id(admin.principal.tenant.tenant_id, request_id)
        .await
    {
        Ok(Some(row)) if row.status == nazo_identity::AccessRequestStatus::Pending => row,
        Ok(Some(row)) if row.status == nazo_identity::AccessRequestStatus::Approved => {
            match resume_staged_client_delivery(&state, &row).await {
                Ok(true) => return json_response(access_request_json(row)),
                Ok(false) => return access_request_already_approved_response(),
                Err(error) => {
                    tracing::warn!(%error, "failed to resume staged client delivery");
                    return oauth_error(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "server_error",
                        "客户端凭据交付恢复失败.",
                    );
                }
            }
        }
        Ok(_) => return access_request_already_approved_response(),
        Err(error) => {
            tracing::warn!(%error, "failed to query pending access request");
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "接入申请查询失败.",
            );
        }
    };
    let request_user_id = pending_request.user_id.as_uuid();
    let site_name = pending_request.site_name;
    let response_signing_algorithms = state
        .keyset
        .snapshot()
        .response_signing_alg_values_supported();
    let prepared = match prepare_client_insert_with_secret_pepper(
        payload,
        state.settings.pairwise_subject_secret.as_deref(),
        &state.settings.client_secret_pepper,
        &state.settings.issuer,
        &response_signing_algorithms,
    )
    .await
    {
        Ok(prepared) => prepared,
        Err(error) => return insert_client_error_response(error),
    };
    let token = access_delivery_token(&state, request_user_id, request_id);
    let delivery_key = format!("oauth:client_delivery:{request_user_id}:{token}");
    let expires_at =
        Utc::now() + Duration::seconds(state.settings.client_delivery_ttl_seconds as i64);
    let delivery_payload = json!({
        "delivery_state": "staged",
        "request_id": request_id,
        "user_id": request_user_id,
        "client_id": &prepared.client_id,
        "client_name": &prepared.client_name,
        "client_type": &prepared.client_type,
        "client_secret": prepared.issued_secret.as_deref(),
        "redirect_uris": &prepared.redirect_uris,
        "scopes": &prepared.scopes,
        "grant_types": &prepared.grant_types,
        "token_endpoint_auth_method": &prepared.token_endpoint_auth_method,
        "site_name": site_name,
        "created_at": Utc::now(),
        "expires_at": expires_at
    });
    if let Err(error) = valkey_set_ex(
        &state.valkey,
        &delivery_key,
        delivery_payload.to_string(),
        state.settings.client_delivery_ttl_seconds,
    )
    .await
    {
        tracing::warn!(%error, "failed to persist client delivery payload");
        return oauth_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "客户端凭据交付创建失败.",
        );
    }

    let approval = repository
        .approve(
            admin.principal.tenant,
            request_id,
            admin.user_id(),
            &prepared.registration,
            prepared.client_secret_hash.as_deref(),
            prepared.registration_access_token_blake3.as_deref(),
        )
        .await;
    let client = match approval {
        Ok(client) => client,
        Err(error) => {
            if let Err(cleanup_error) = valkey_del(&state.valkey, &delivery_key).await {
                tracing::warn!(%cleanup_error, "failed to remove client delivery payload");
            }
            if let Some(response) = access_request_approval_error_response(&error) {
                return response;
            }
            tracing::warn!(%error, "failed to approve access request");
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "接入申请审批失败.",
            );
        }
    };
    let mut committed_delivery_payload = delivery_payload;
    committed_delivery_payload["delivery_state"] = json!("committed");
    committed_delivery_payload["approved_client_id"] = json!(client.id);
    if let Err(error) = valkey_set_ex(
        &state.valkey,
        &delivery_key,
        committed_delivery_payload.to_string(),
        state.settings.client_delivery_ttl_seconds,
    )
    .await
    {
        tracing::warn!(%error, "failed to activate client delivery payload");
        return oauth_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "客户端凭据交付激活失败.",
        );
    }
    audit_event(
        "client_created",
        audit_fields(&[
            ("client_id", json!(client.client_id)),
            ("request_id", json!(request_id)),
            ("admin_user_id", json!(admin.id())),
            (
                "source_ip_hash",
                json!(blake3_hex(&client_ip(&req, &state.settings))),
            ),
        ]),
    );
    match repository
        .by_id(admin.principal.tenant.tenant_id, request_id)
        .await
    {
        Ok(Some(row)) => json_response(access_request_json(row)),
        Ok(None) => json_response(json!({"id": request_id})),
        Err(error) => {
            tracing::warn!(%error, "failed to load approved access request");
            oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "接入申请查询失败.",
            )
        }
    }
}

fn access_delivery_token(state: &AppState, user_id: Uuid, request_id: Uuid) -> String {
    let material = format!(
        "client-delivery-v1:{}:{user_id}:{request_id}",
        state.settings.client_secret_pepper
    );
    blake3_hex(&material)
}

async fn resume_staged_client_delivery(
    state: &AppState,
    request: &nazo_identity::AccessRequest,
) -> anyhow::Result<bool> {
    let Some(approved_client_id) = request.approved_client_id else {
        return Ok(false);
    };
    let user_id = request.user_id.as_uuid();
    let token = access_delivery_token(state, user_id, request.id);
    let key = format!("oauth:client_delivery:{user_id}:{token}");
    let Some(raw) = valkey_get(&state.valkey, &key).await? else {
        return Ok(false);
    };
    let mut payload: Value = serde_json::from_str(&raw)?;
    if payload["delivery_state"] != "staged"
        || payload["request_id"] != json!(request.id)
        || payload["user_id"] != json!(user_id)
    {
        return Ok(false);
    }
    payload["delivery_state"] = json!("committed");
    payload["approved_client_id"] = json!(approved_client_id);
    valkey_set_ex(
        &state.valkey,
        key,
        payload.to_string(),
        state.settings.client_delivery_ttl_seconds,
    )
    .await?;
    Ok(true)
}

#[derive(Deserialize)]
pub(crate) struct RejectAccessRequest {
    admin_note: String,
}

pub(crate) async fn admin_reject_access_request(
    state: Data<AppState>,
    req: HttpRequest,
    path: actix_web::web::Path<Uuid>,
    Json(payload): Json<RejectAccessRequest>,
) -> HttpResponse {
    let request_id = path.into_inner();
    if !has_valid_csrf_token(&state, &req, None) {
        return csrf_error();
    }
    let admin = match require_admin_or_forbidden(&state, &req).await {
        Ok(admin) => admin,
        Err(response) => return response,
    };
    let repository = nazo_postgres::AccessRequestRepository::new(state.diesel_db.clone());
    let updated = match repository
        .reject(
            admin.principal.tenant.tenant_id,
            request_id,
            admin.user_id(),
            payload.admin_note,
        )
        .await
    {
        Ok(()) => true,
        Err(nazo_identity::ports::RepositoryError::Conflict) => false,
        Err(error) => {
            tracing::warn!(%error, "failed to reject access request");
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "接入申请拒绝失败.",
            );
        }
    };
    if !updated {
        return access_request_already_rejected_response();
    }
    match repository
        .by_id(admin.principal.tenant.tenant_id, request_id)
        .await
    {
        Ok(Some(row)) => json_response(access_request_json(row)),
        Ok(None) => json_response(json!({"id": request_id})),
        Err(error) => {
            tracing::warn!(%error, "failed to load rejected access request");
            oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "接入申请查询失败.",
            )
        }
    }
}

fn access_request_json(row: nazo_identity::AccessRequest) -> Value {
    json!({
        "id": row.id,
        "user_id": row.user_id.as_uuid(),
        "user_email": row.requester_email,
        "site_name": row.site_name,
        "site_url": row.site_url,
        "request_description": row.request_description,
        "status": row.status.code(),
        "admin_note": row.admin_note,
        "approved_client_id": row.approved_client_id,
        "created_at": row.created_at,
        "resolved_at": row.resolved_at
    })
}

fn access_request_already_approved_response() -> HttpResponse {
    oauth_error(
        StatusCode::CONFLICT,
        "invalid_request",
        "该申请已处理,不可重复审批.",
    )
}

fn access_request_approval_error_response(
    error: &nazo_identity::ports::RepositoryError,
) -> Option<HttpResponse> {
    let (mut response, conflict_type) = match error {
        nazo_identity::ports::RepositoryError::AlreadyProcessed => {
            (access_request_already_approved_response(), "request_state")
        }
        nazo_identity::ports::RepositoryError::Conflict => (
            oauth_error(StatusCode::CONFLICT, "invalid_request", "客户端标识已存在."),
            "client_unique",
        ),
        _ => return None,
    };
    response.headers_mut().insert(
        header::HeaderName::from_static("x-nazo-conflict-type"),
        HeaderValue::from_static(conflict_type),
    );
    Some(response)
}

fn access_request_already_rejected_response() -> HttpResponse {
    oauth_error(
        StatusCode::CONFLICT,
        "invalid_request",
        "该申请已处理,不可重复拒绝.",
    )
}

#[cfg(test)]
#[path = "../../../tests/in_source/src/http/admin/tests/access_requests.rs"]
mod tests;
