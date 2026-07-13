//! 授权确认页数据端点。
// 前端通过 request_id 读取待确认内容，服务端再次校验该请求属于当前用户。
use crate::http::prelude::*;

#[cfg(test)]
fn parse_consent_payload(raw: Option<String>) -> Option<ConsentPayload> {
    raw.and_then(|value| serde_json::from_str::<ConsentPayload>(&value).ok())
}

fn validate_consent_payload_user(
    payload: ConsentPayload,
    current_user_id: Uuid,
) -> Result<ConsentPayload, HttpResponse> {
    if payload.user_id != current_user_id {
        return Err(oauth_error(
            StatusCode::FORBIDDEN,
            "access_denied",
            "当前会话与授权请求不匹配.",
        ));
    }
    Ok(payload)
}

fn malformed_or_missing_consent_response() -> HttpResponse {
    oauth_error(
        StatusCode::BAD_REQUEST,
        "invalid_request",
        "授权请求不存在或已过期,请重新发起授权.",
    )
}

fn consent_page_response(payload: ConsentPayload, csrf_token: Option<String>) -> HttpResponse {
    json_response(json!({
        "request_id": payload.request_id,
        "client_id": payload.client_id,
        "client_name": payload.client_name,
        "redirect_uri": payload.redirect_uri,
        "scopes": payload.scopes,
        "userinfo_claims": payload.userinfo_claims,
        "id_token_claims": payload.id_token_claims,
        "authorization_details": payload.authorization_details,
        "csrf_token": csrf_token
    }))
}

/// 返回授权确认页所需的客户端、scope 和 CSRF 信息。
pub(crate) async fn authorize_consent(
    state: Data<AppState>,
    req: HttpRequest,
    Query(q): Query<HashMap<String, String>>,
) -> HttpResponse {
    let user = match current_user(&state, &req).await {
        Ok(Some(user)) => user,
        Ok(None) => {
            return oauth_error(
                StatusCode::UNAUTHORIZED,
                "login_required",
                "授权前必须先登录.",
            );
        }
        Err(error) => {
            tracing::warn!(%error, "failed to resolve authorization consent user");
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "会话查询失败.",
            );
        }
    };
    let Some(request_id) = q.get("request_id") else {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "缺少 request_id.",
        );
    };

    let store = nazo_valkey::AuthorizationStore::new(&state.valkey_connection());
    let payload = match store.load_consent(request_id).await {
        Ok(value) => value,
        Err(error) if error.kind() == nazo_valkey::ErrorKind::CorruptData => {
            tracing::warn!(%error, "authorization consent state is malformed");
            return malformed_or_missing_consent_response();
        }
        Err(error) => {
            tracing::warn!(%error, "failed to read authorization consent state");
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "授权请求读取失败.",
            );
        }
    };
    let Some(payload) = payload else {
        return malformed_or_missing_consent_response();
    };
    let payload = match validate_consent_payload_user(payload, user.id()) {
        Ok(payload) => payload,
        Err(response) => return response,
    };

    consent_page_response(
        payload,
        cookie_value(&req, &state.settings.csrf_cookie_name),
    )
}

#[cfg(test)]
#[path = "../../../tests/in_source/src/http/authorization/tests/consent.rs"]
mod tests;
