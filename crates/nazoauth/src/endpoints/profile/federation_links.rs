//! 当前用户外部身份绑定管理。
//! 用户只能查看和解绑自己的 provider subject 绑定，不能修改 provider 配置。
use crate::http::Request as HttpRequest;
use crate::http::Response as HttpResponse;
use crate::http::{csrf_error, empty_response_no_store, json_response_no_store, oauth_error};
use http::StatusCode;

use crate::endpoints::sessions::SessionProfileHandles;

use nazo_identity::ports::FederationLinkSummary;
use serde::Serialize;
use uuid::Uuid;

pub async fn my_federation_links(
    sessions: &SessionProfileHandles,
    federation: &nazo_oauth_server::services::FederationProfileService,
    req: &HttpRequest,
) -> HttpResponse {
    let user = match sessions.current_session_or_login_required(req).await {
        Ok(session) => session.user,
        Err(response) => return response,
    };
    let rows = match federation.list_summaries(&user).await {
        Ok(rows) => rows,
        Err(error) => {
            tracing::warn!(%error, user_id = %user.id(), "failed to load federation links");
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "外部身份绑定查询失败.",
            );
        }
    };
    #[derive(Serialize)]
    struct Links {
        total: usize,
        items: Vec<PublicFederationLink>,
    }
    json_response_no_store(Links {
        total: rows.len(),
        items: rows.into_iter().map(PublicFederationLink::from).collect(),
    })
}

pub async fn unlink_my_federation_link(
    sessions: &SessionProfileHandles,
    federation: &nazo_oauth_server::services::FederationProfileService,
    req: &HttpRequest,
    path: Uuid,
) -> HttpResponse {
    if !sessions.has_valid_csrf_token(req, None) {
        return csrf_error();
    }
    // link_id 来自路径参数，但后续删除仍必须叠加当前 user_id 约束。
    let link_id = path;
    let user = match sessions.current_session_or_login_required(req).await {
        Ok(session) => session.user,
        Err(response) => return response,
    };
    match federation.unlink(&user, link_id).await {
        Ok(Some(_)) => {}
        Ok(None) => {
            return oauth_error(
                StatusCode::NOT_FOUND,
                "invalid_request",
                "外部身份绑定不存在.",
            );
        }
        Err(error) => {
            tracing::warn!(%error, user_id = %user.id(), %link_id, "failed to load federation link for unlink");
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "外部身份解绑失败.",
            );
        }
    };
    empty_response_no_store(StatusCode::NO_CONTENT)
}

// Provider claims and internal tenant/user identifiers stay outside the HTTP document.
#[derive(Serialize)]
pub struct PublicFederationLink {
    pub id: Uuid,
    pub provider_type: String,
    pub provider_id: String,
    pub subject: String,
    pub email: String,
    pub created_at: jiff::Timestamp,
    pub updated_at: jiff::Timestamp,
    pub last_login_at: Option<jiff::Timestamp>,
}

impl From<FederationLinkSummary> for PublicFederationLink {
    fn from(link: FederationLinkSummary) -> Self {
        Self {
            id: link.id,
            provider_type: link.provider_type,
            provider_id: link.provider_id,
            subject: link.subject,
            email: link.email,
            created_at: link.created_at,
            updated_at: link.updated_at,
            last_login_at: link.last_login_at,
        }
    }
}
