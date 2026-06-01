//! authorization_code grant 处理。
// 只消费授权码并转入统一令牌签发逻辑。
use super::{TokenForm, issue_token_response, revoke_issued_authorization_code_tokens};
use crate::http::prelude::*;

const BEGIN_AUTHORIZATION_CODE_CONSUMPTION_SCRIPT: &str = r#"
local raw = redis.call('GET', KEYS[1])
if not raw then
  return 'missing'
end
local ok, state = pcall(cjson.decode, raw)
if not ok or type(state) ~= 'table' or type(state.status) ~= 'string' then
  return 'malformed'
end
if state.status == 'pending' then
  if type(state.payload) ~= 'table' then
    return 'malformed'
  end
  state.status = 'consuming'
  state.consuming_at = ARGV[1]
  redis.call('SET', KEYS[1], cjson.encode(state), 'KEEPTTL')
  return 'consuming|' .. cjson.encode(state.payload)
end
if state.status == 'consuming' then
  return 'busy'
end
if state.status == 'consumed' then
  return 'consumed|' .. raw
end
if state.status == 'failed' then
  return 'failed'
end
return 'malformed'
"#;

enum AuthorizationCodeConsumption {
    Consuming(CodePayload),
    Busy,
    Consumed(ConsumedAuthorizationCode),
    Failed,
    Missing,
    Malformed,
}

fn redirect_uri_matches_authorization_request(
    payload: &CodePayload,
    token_redirect_uri: Option<&str>,
) -> bool {
    match (payload.redirect_uri_was_supplied, token_redirect_uri) {
        (true, Some(value)) => value == payload.redirect_uri.as_str(),
        (true, None) => false,
        (false, Some(value)) => value == payload.redirect_uri.as_str(),
        (false, None) => true,
    }
}

async fn begin_authorization_code_consumption(
    state: &AppState,
    code_hash: &str,
) -> Result<AuthorizationCodeConsumption, HttpResponse> {
    let response = match valkey_eval_string(
        &state.valkey,
        BEGIN_AUTHORIZATION_CODE_CONSUMPTION_SCRIPT,
        vec![authorization_code_key_from_hash(code_hash)],
        vec![Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)],
    )
    .await
    {
        Ok(response) => response,
        Err(error) => {
            tracing::warn!(%error, "failed to atomically consume authorization code");
            return Err(oauth_token_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "授权码校验失败.",
                false,
            ));
        }
    };
    if let Some(raw) = response.strip_prefix("consuming|") {
        return match serde_json::from_str::<CodePayload>(raw) {
            Ok(payload) => Ok(AuthorizationCodeConsumption::Consuming(payload)),
            Err(error) => {
                tracing::warn!(%error, "authorization code pending payload is malformed");
                Ok(AuthorizationCodeConsumption::Malformed)
            }
        };
    }
    if let Some(raw) = response.strip_prefix("consumed|") {
        return match serde_json::from_str::<AuthorizationCodeState>(raw) {
            Ok(AuthorizationCodeState::Consumed { marker }) => {
                Ok(AuthorizationCodeConsumption::Consumed(marker))
            }
            Ok(_) => Ok(AuthorizationCodeConsumption::Malformed),
            Err(error) => {
                tracing::warn!(%error, "consumed authorization code marker is malformed");
                Ok(AuthorizationCodeConsumption::Malformed)
            }
        };
    }
    match response.as_str() {
        "busy" => Ok(AuthorizationCodeConsumption::Busy),
        "failed" => Ok(AuthorizationCodeConsumption::Failed),
        "missing" => Ok(AuthorizationCodeConsumption::Missing),
        _ => Ok(AuthorizationCodeConsumption::Malformed),
    }
}

async fn revoke_replayed_authorization_code(
    state: &AppState,
    marker: ConsumedAuthorizationCode,
) -> Result<bool, HttpResponse> {
    if let Err(error) = revoke_issued_authorization_code_tokens(
        state,
        marker.client_id,
        &marker.access_token_jti,
        marker.access_token_expires_at,
        marker.refresh_token_family_id,
    )
    .await
    {
        tracing::warn!(%error, "failed to revoke tokens after authorization code replay");
        return Err(oauth_token_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "授权码重放撤销失败.",
            false,
        ));
    }
    Ok(true)
}

pub(crate) async fn token_authorization_code(
    state: &AppState,
    req: &HttpRequest,
    client: &ClientRow,
    form: &TokenForm,
) -> HttpResponse {
    let dpop_jkt = match validate_dpop_proof(state, req, None, None).await {
        Ok(value) => value,
        Err(error) => return dpop_error_response(error, DpopErrorContext::TokenEndpoint),
    };
    let Some(code) = &form.code else {
        return oauth_token_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "缺少 code.",
            false,
        );
    };
    let code_hash = blake3_hex(code);
    let payload = match begin_authorization_code_consumption(state, &code_hash).await {
        Ok(AuthorizationCodeConsumption::Consuming(payload)) => payload,
        Ok(AuthorizationCodeConsumption::Consumed(marker)) => {
            match revoke_replayed_authorization_code(state, marker).await {
                Ok(true) => {
                    return oauth_token_error(
                        StatusCode::BAD_REQUEST,
                        "invalid_grant",
                        "授权码已被使用，相关令牌已撤销.",
                        false,
                    );
                }
                Ok(false) => {}
                Err(response) => return response,
            }
            return oauth_token_error(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "授权码已被使用.",
                false,
            );
        }
        Ok(AuthorizationCodeConsumption::Busy) => {
            return oauth_token_error(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "授权码正在兑换.",
                false,
            );
        }
        Ok(AuthorizationCodeConsumption::Failed) => {
            return oauth_token_error(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "授权码兑换已失败.",
                false,
            );
        }
        Ok(AuthorizationCodeConsumption::Missing) => {
            return oauth_token_error(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "授权码无效或已过期.",
                false,
            );
        }
        Ok(AuthorizationCodeConsumption::Malformed) => {
            return oauth_token_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "授权码状态无效.",
                false,
            );
        }
        Err(response) => return response,
    };
    if payload.client_id != client.client_id
        || !redirect_uri_matches_authorization_request(&payload, form.redirect_uri.as_deref())
    {
        mark_failed_authorization_code(state, &code_hash, "client_or_redirect_uri_mismatch").await;
        return oauth_token_error(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "授权码与客户端或 redirect_uri 不匹配.",
            false,
        );
    }
    let Some(verifier) = &form.code_verifier else {
        mark_failed_authorization_code(state, &code_hash, "missing_code_verifier").await;
        return oauth_token_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "缺少 code_verifier.",
            false,
        );
    };
    if payload.code_challenge_method != "S256"
        || !is_valid_pkce_value(verifier)
        || pkce_s256(verifier) != payload.code_challenge
    {
        mark_failed_authorization_code(state, &code_hash, "pkce_failed").await;
        return oauth_token_error(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "PKCE 校验失败.",
            false,
        );
    }
    let audience = form
        .audience
        .clone()
        .unwrap_or_else(|| state.settings.default_audience.clone());
    if !audience_allowed(client, &audience) {
        mark_failed_authorization_code(state, &code_hash, "audience_not_allowed").await;
        return oauth_token_error(
            StatusCode::BAD_REQUEST,
            "invalid_target",
            "请求的 audience 不在客户端允许范围内.",
            false,
        );
    }
    issue_token_response(
        state,
        client,
        TokenIssue {
            user_id: Some(payload.user_id),
            subject: oidc_subject(&state.settings, payload.user_id, &payload.redirect_uri),
            scopes: payload.scopes,
            audience,
            nonce: payload.nonce,
            auth_time: Some(payload.auth_time),
            amr: payload.amr,
            include_refresh: true,
            rotation: None,
            dpop_jkt,
            authorization_code_hash: Some(code_hash),
        },
    )
    .await
}

async fn mark_failed_authorization_code(state: &AppState, code_hash: &str, error_code: &str) {
    if let Err(error) = super::mark_failed_authorization_code(state, code_hash, error_code).await {
        tracing::warn!(%error, "failed to mark authorization code exchange as failed");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn code_payload(redirect_uri_was_supplied: bool) -> CodePayload {
        let now = Utc::now();
        CodePayload {
            code_id: "code-1".to_owned(),
            user_id: Uuid::now_v7(),
            client_id: "client-1".to_owned(),
            redirect_uri: "https://client.example/callback".to_owned(),
            redirect_uri_was_supplied,
            scopes: vec!["openid".to_owned()],
            nonce: None,
            auth_time: now.timestamp(),
            amr: vec!["password".to_owned()],
            code_challenge: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ".to_owned(),
            code_challenge_method: "S256".to_owned(),
            issued_at: now,
            expires_at: now + Duration::seconds(300),
        }
    }

    #[test]
    fn token_redirect_uri_is_required_when_authorize_request_supplied_it() {
        let payload = code_payload(true);

        assert!(!redirect_uri_matches_authorization_request(&payload, None));
        assert!(redirect_uri_matches_authorization_request(
            &payload,
            Some("https://client.example/callback")
        ));
        assert!(!redirect_uri_matches_authorization_request(
            &payload,
            Some("https://client.example/callback/")
        ));
    }

    #[test]
    fn token_redirect_uri_may_be_omitted_when_authorize_request_used_single_registered_uri() {
        let payload = code_payload(false);

        assert!(redirect_uri_matches_authorization_request(&payload, None));
        assert!(redirect_uri_matches_authorization_request(
            &payload,
            Some("https://client.example/callback")
        ));
        assert!(!redirect_uri_matches_authorization_request(
            &payload,
            Some("https://client.example/callback/")
        ));
    }
}
