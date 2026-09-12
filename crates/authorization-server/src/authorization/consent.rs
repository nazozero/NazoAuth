//! Authorization consent state and session ownership checks.

use http::StatusCode;
use nazo_auth::{AuthorizationPortError, ConsentPayload};
use nazo_identity::SessionId;
use uuid::Uuid;

use crate::contracts::oauth_error::OAuthEndpointError;

use super::AuthorizationRequestContext;

pub(crate) async fn consent_with_context(
    context: &AuthorizationRequestContext<'_>,
    session_id: Option<&SessionId>,
    request_id: Option<&str>,
) -> Result<ConsentPayload, OAuthEndpointError> {
    let Some(session_id) = session_id else {
        return Err(OAuthEndpointError::json(
            StatusCode::UNAUTHORIZED,
            "login_required",
            "授权前必须先登录.",
        ));
    };
    let user = match context
        .sessions
        .current_session_by_id(session_id.as_str())
        .await
    {
        Ok(Some(session)) => session.user,
        Ok(None) => {
            return Err(OAuthEndpointError::json(
                StatusCode::UNAUTHORIZED,
                "login_required",
                "授权前必须先登录.",
            ));
        }
        Err(error) => {
            tracing::warn!(%error, "failed to resolve authorization consent user");
            return Err(OAuthEndpointError::json(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "会话查询失败.",
            ));
        }
    };
    let Some(request_id) = request_id else {
        return Err(OAuthEndpointError::json(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "缺少 request_id.",
        ));
    };
    let payload = match context.service.load_consent(request_id).await {
        Ok(value) => value,
        Err(AuthorizationPortError::CorruptData) => {
            tracing::warn!("authorization consent state is malformed");
            return Err(malformed_or_missing_consent_error());
        }
        Err(error) => {
            tracing::warn!(%error, "failed to read authorization consent state");
            return Err(OAuthEndpointError::json(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "授权请求读取失败.",
            ));
        }
    };
    let Some(payload) = payload else {
        return Err(malformed_or_missing_consent_error());
    };
    validate_consent_payload_user(payload, user.id())
}

fn validate_consent_payload_user(
    payload: ConsentPayload,
    current_user_id: Uuid,
) -> Result<ConsentPayload, OAuthEndpointError> {
    if payload.user_id != current_user_id {
        return Err(OAuthEndpointError::json(
            StatusCode::FORBIDDEN,
            "access_denied",
            "当前会话与授权请求不匹配.",
        ));
    }
    Ok(payload)
}

fn malformed_or_missing_consent_error() -> OAuthEndpointError {
    OAuthEndpointError::json(
        StatusCode::BAD_REQUEST,
        "invalid_request",
        "授权请求不存在或已过期,请重新发起授权.",
    )
}

#[cfg(test)]
#[path = "../../tests/unit/authorization_consent.rs"]
mod tests;
