//! 授权确认提交端点。
// 同意时签发一次性授权码；拒绝时按 OAuth 规范把错误回传 redirect_uri。
use crate::http::prelude::*;

#[derive(Deserialize)]
pub(crate) struct DecisionForm {
    request_id: String,
    decision: String,
    csrf_token: Option<String>,
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
    let Some(user) = current_user(&state, &req).await else {
        return login_required_response(&state);
    };

    let key = format!("oauth:consent:{}", form.request_id);
    let raw = match valkey_getdel(&state.valkey, &key).await {
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
    let Some(payload) = raw.and_then(|v| serde_json::from_str::<ConsentPayload>(&v).ok()) else {
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

    if form.decision == "deny" {
        return redirect_found(append_query(
            &payload.redirect_uri,
            &[
                ("error", "access_denied"),
                ("state", payload.state.as_deref().unwrap_or("")),
                ("iss", state.settings.issuer.as_str()),
            ],
        ));
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
        nonce: payload.nonce,
        code_challenge: payload.code_challenge,
        code_challenge_method: payload.code_challenge_method,
        issued_at: now,
        expires_at: now + Duration::seconds(state.settings.auth_code_ttl_seconds as i64),
    };
    let body = serde_json::to_string(&code_payload).unwrap();
    let code_key = format!("oauth:auth_code:{code}");
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
    if let Err(error) =
        upsert_grant(&state, payload.user_id, &payload.client_id, &payload.scopes).await
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

    redirect_found(append_query(
        &payload.redirect_uri,
        &[
            ("code", &code),
            ("state", payload.state.as_deref().unwrap_or("")),
            ("iss", state.settings.issuer.as_str()),
        ],
    ))
}
