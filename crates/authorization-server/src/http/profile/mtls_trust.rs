//! User-side application for deployment mTLS trust.

use actix_web::{
    HttpRequest, HttpResponse,
    http::StatusCode,
    web::{Data, Json},
};
use nazo_http_actix::{
    csrf_error, json_response_no_store, json_response_status_no_store, oauth_error,
};
use serde::Deserialize;

use crate::{
    adapters::audit::{audit_event, audit_fields},
    bootstrap::MtlsTrustAnchorService,
    http::sessions::SessionProfileHandles,
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CreateMtlsTrustRequest {
    client_id: String,
    certificate_pem: String,
}

pub(crate) async fn my_mtls_trust_requests(
    sessions: Data<SessionProfileHandles>,
    service: Data<MtlsTrustAnchorService>,
    req: HttpRequest,
) -> HttpResponse {
    let user = match sessions.current_user_or_login_required(&req).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    match service
        .list_for_user(user.tenant().tenant_id, user.user_id())
        .await
    {
        Ok(items) => {
            json_response_no_store(serde_json::json!({"total": items.len(), "items": items}))
        }
        Err(error) => {
            tracing::warn!(%error, "failed to load mTLS trust requests");
            oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "mTLS 信任申请查询失败.",
            )
        }
    }
}

pub(crate) async fn create_mtls_trust_request(
    sessions: Data<SessionProfileHandles>,
    service: Data<MtlsTrustAnchorService>,
    req: HttpRequest,
    Json(payload): Json<CreateMtlsTrustRequest>,
) -> HttpResponse {
    if !sessions.has_valid_csrf_token(&req, None) {
        return csrf_error();
    }
    let user = match sessions.current_user_or_login_required(&req).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    let client_id = payload.client_id.trim();
    if client_id.is_empty() || client_id.len() > 128 {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "client_id 不能为空且不得超过 128 字节.",
        );
    }
    let validated = match nazo_key_management::validate_mtls_trust_anchor(&payload.certificate_pem)
    {
        Ok(validated) => validated,
        Err(error) => {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                &format!("mTLS CA 证书不符合信任策略: {error}."),
            );
        }
    };
    let request = nazo_identity::NewMtlsTrustAnchorRequest {
        tenant_id: user.tenant().tenant_id,
        user_id: user.user_id(),
        client_id: client_id.to_owned(),
        certificate_pem: validated.certificate_pem,
        certificate_sha256: validated.certificate_sha256,
        subject_dn: validated.subject_dn,
        not_before: validated.not_before,
        not_after: validated.not_after,
    };
    match service.create_for_owned_client(request).await {
        Ok(created) => {
            audit_event(
                "mtls_trust_anchor_requested",
                audit_fields(&[
                    ("request_id", serde_json::json!(created.id)),
                    ("requester_user_id", serde_json::json!(user.id())),
                    ("client_id", serde_json::json!(&created.client_id)),
                    (
                        "certificate_sha256",
                        serde_json::json!(&created.certificate_sha256),
                    ),
                ]),
            );
            json_response_status_no_store(StatusCode::CREATED, created)
        }
        Err(nazo_identity::ports::RepositoryError::NotFound) => oauth_error(
            StatusCode::NOT_FOUND,
            "invalid_request",
            "客户端不存在、不属于当前申请人，或未满足 mTLS 信任申请的证书绑定策略.",
        ),
        Err(nazo_identity::ports::RepositoryError::Conflict) => oauth_error(
            StatusCode::CONFLICT,
            "invalid_request",
            "该客户端已经提交过相同的 CA 证书，或待审批信任申请已达到部署安全上限.",
        ),
        Err(error) => {
            tracing::warn!(%error, "failed to create mTLS trust request");
            oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "mTLS 信任申请创建失败.",
            )
        }
    }
}
