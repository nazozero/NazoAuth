//! 授权确认提交端点。
// 同意时签发一次性授权码；拒绝时按 OAuth 规范把错误回传 redirect_uri。
use super::{
    PushedAuthorizationRequestConsumeError, authorization_response_redirect,
    consume_pushed_authorization_request,
};
use crate::http::prelude::*;

#[derive(Deserialize)]
pub(crate) struct DecisionForm {
    request_id: String,
    decision: String,
    csrf_token: Option<String>,
}

enum AuthorizationDecision {
    Approve,
    Deny,
}

fn parse_authorization_decision(value: &str) -> Option<AuthorizationDecision> {
    match value {
        "approve" => Some(AuthorizationDecision::Approve),
        "deny" => Some(AuthorizationDecision::Deny),
        _ => None,
    }
}

fn parse_consent_payload(raw: Option<String>) -> Option<ConsentPayload> {
    raw.and_then(|value| serde_json::from_str::<ConsentPayload>(&value).ok())
}

async fn consume_pushed_request_uri_if_present(
    state: &AppState,
    payload: &ConsentPayload,
) -> Result<(), HttpResponse> {
    let Some(request_uri) = payload.pushed_request_uri.as_deref() else {
        return Ok(());
    };

    match consume_pushed_authorization_request(state, request_uri).await {
        Ok(()) => Ok(()),
        Err(PushedAuthorizationRequestConsumeError::Missing) => {
            Err(authorization_error_redirect(state, payload, "invalid_request_uri").await)
        }
        Err(PushedAuthorizationRequestConsumeError::ReadFailed)
        | Err(PushedAuthorizationRequestConsumeError::Malformed) => {
            Err(authorization_error_redirect(state, payload, "server_error").await)
        }
    }
}

async fn authorization_error_redirect(
    state: &AppState,
    payload: &ConsentPayload,
    error: &str,
) -> HttpResponse {
    authorization_response_redirect(
        state,
        &payload.redirect_uri,
        &payload.client_id,
        payload.response_mode.as_deref(),
        None,
        Some(error),
        payload.state.as_deref(),
    )
    .await
}

/// 处理用户对授权请求的同意或拒绝。
pub(crate) async fn authorize_decision(
    state: Data<AppState>,
    req: HttpRequest,
    Form(form): Form<DecisionForm>,
) -> HttpResponse {
    if !has_valid_csrf_token(&state, &req, form.csrf_token.as_deref()) {
        return csrf_error();
    }
    let Some(decision) = parse_authorization_decision(&form.decision) else {
        return oauth_error(StatusCode::BAD_REQUEST, "invalid_request", "授权决策无效.");
    };
    let user = match current_user_or_login_required(&state, &req).await {
        Ok(user) => user,
        Err(response) => return response,
    };

    let key = format!("oauth:consent:{}", form.request_id);
    let raw = match valkey_get(&state.valkey, &key).await {
        Ok(value) => value,
        Err(error) => {
            tracing::warn!(%error, "failed to read authorization consent state");
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "授权请求读取失败.",
            );
        }
    };
    let Some(payload) = parse_consent_payload(raw) else {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "授权请求不存在或已过期,请重新发起授权.",
        );
    };
    if payload.user_id != user.id {
        return oauth_error(
            StatusCode::FORBIDDEN,
            "access_denied",
            "当前会话与授权请求不匹配.",
        );
    }
    let raw = match valkey_getdel(&state.valkey, &key).await {
        Ok(value) => value,
        Err(error) => {
            tracing::warn!(%error, "failed to consume authorization consent state");
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "授权请求读取失败.",
            );
        }
    };
    let Some(payload) = parse_consent_payload(raw) else {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "授权请求不存在或已过期,请重新发起授权.",
        );
    };
    if payload.user_id != user.id {
        return oauth_error(
            StatusCode::FORBIDDEN,
            "access_denied",
            "当前会话与授权请求不匹配.",
        );
    }
    if let Err(response) = consume_pushed_request_uri_if_present(&state, &payload).await {
        return response;
    }

    match decision {
        AuthorizationDecision::Deny => {
            audit_event(
                "authorization_denied",
                audit_fields(&[
                    ("user_id", json!(payload.user_id)),
                    ("client_id", json!(payload.client_id)),
                    ("scope", json!(payload.scopes.join(" "))),
                    (
                        "source_ip_hash",
                        json!(blake3_hex(&client_ip(&req, &state.settings))),
                    ),
                ]),
            );
            return authorization_error_redirect(&state, &payload, "access_denied").await;
        }
        AuthorizationDecision::Approve => {}
    }

    let now = Utc::now();
    let code = random_urlsafe_token();
    let code_payload = CodePayload {
        code_id: Uuid::now_v7().to_string(),
        user_id: payload.user_id,
        client_id: payload.client_id.clone(),
        redirect_uri: payload.redirect_uri.clone(),
        redirect_uri_was_supplied: payload.redirect_uri_was_supplied,
        scopes: payload.scopes.clone(),
        resource_indicators: payload.resource_indicators.clone(),
        authorization_details: payload.authorization_details.clone(),
        nonce: payload.nonce,
        auth_time: payload.auth_time,
        amr: payload.amr,
        oidc_sid: payload.oidc_sid,
        acr: payload.acr,
        userinfo_claims: payload.userinfo_claims,
        userinfo_claim_requests: payload.userinfo_claim_requests,
        id_token_claims: payload.id_token_claims,
        id_token_claim_requests: payload.id_token_claim_requests,
        code_challenge: payload.code_challenge,
        code_challenge_method: payload.code_challenge_method,
        dpop_jkt: payload.dpop_jkt,
        mtls_x5t_s256: payload.mtls_x5t_s256,
        issued_at: now,
        expires_at: now + Duration::seconds(state.settings.auth_code_ttl_seconds as i64),
    };
    let body = serde_json::to_string(&AuthorizationCodeState::Pending {
        payload: code_payload,
    })
    .expect("authorization code state serialization must be infallible");
    let code_key = authorization_code_key(&code);
    if let Err(error) = valkey_set_ex(
        &state.valkey,
        code_key.clone(),
        body,
        state.settings.auth_code_ttl_seconds,
    )
    .await
    {
        tracing::warn!(%error, "failed to persist authorization code");
        return oauth_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "授权码创建失败.",
        );
    }
    if let Err(error) = upsert_grant(
        &state,
        payload.user_id,
        &payload.client_id,
        &payload.scopes,
        &payload.resource_indicators,
        &payload.authorization_details,
    )
    .await
    {
        tracing::warn!(%error, "failed to persist user client grant");
        if let Err(cleanup_error) = valkey_del(&state.valkey, &code_key).await {
            tracing::warn!(%cleanup_error, "failed to remove authorization code after grant failure");
        }
        return oauth_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "授权记录写入失败.",
        );
    }

    audit_event(
        "authorization_approved",
        audit_fields(&[
            ("user_id", json!(payload.user_id)),
            ("client_id", json!(payload.client_id)),
            ("scope", json!(payload.scopes.join(" "))),
            (
                "source_ip_hash",
                json!(blake3_hex(&client_ip(&req, &state.settings))),
            ),
        ]),
    );

    authorization_response_redirect(
        &state,
        &payload.redirect_uri,
        &payload.client_id,
        payload.response_mode.as_deref(),
        Some(&code),
        None,
        payload.state.as_deref(),
    )
    .await
}

#[cfg(test)]
#[path = "../../../tests/in_source/src/http/authorization/tests/decision.rs"]
mod tests;
