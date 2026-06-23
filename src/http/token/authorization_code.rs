//! authorization_code grant 处理。
// 只消费授权码并转入统一令牌签发逻辑。
use super::{
    TokenForm, consume_token_client_assertion, issue_token_response,
    revoke_issued_authorization_code_tokens,
};
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
    Consuming(Box<CodePayload>),
    Busy,
    Consumed(ConsumedAuthorizationCode),
    Failed,
    Missing,
    Malformed,
}

fn parse_authorization_code_consumption_response(response: &str) -> AuthorizationCodeConsumption {
    if let Some(raw) = response.strip_prefix("consuming|") {
        return match serde_json::from_str::<CodePayload>(raw) {
            Ok(payload) => AuthorizationCodeConsumption::Consuming(Box::new(payload)),
            Err(error) => {
                tracing::warn!(%error, "authorization code pending payload is malformed");
                AuthorizationCodeConsumption::Malformed
            }
        };
    }
    if let Some(raw) = response.strip_prefix("consumed|") {
        return match serde_json::from_str::<AuthorizationCodeState>(raw) {
            Ok(AuthorizationCodeState::Consumed { marker }) => {
                AuthorizationCodeConsumption::Consumed(marker)
            }
            Ok(_) => AuthorizationCodeConsumption::Malformed,
            Err(error) => {
                tracing::warn!(%error, "consumed authorization code marker is malformed");
                AuthorizationCodeConsumption::Malformed
            }
        };
    }
    match response {
        "busy" => AuthorizationCodeConsumption::Busy,
        "failed" => AuthorizationCodeConsumption::Failed,
        "missing" => AuthorizationCodeConsumption::Missing,
        _ => AuthorizationCodeConsumption::Malformed,
    }
}

async fn load_pending_authorization_code_payload(
    state: &AppState,
    code_hash: &str,
) -> Result<Option<Box<CodePayload>>, HttpResponse> {
    let raw = match valkey_get(&state.valkey, authorization_code_key_from_hash(code_hash)).await {
        Ok(raw) => raw,
        Err(error) => {
            tracing::warn!(%error, "failed to read authorization code before dpop validation");
            return Err(oauth_token_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "授权码校验失败.",
                false,
            ));
        }
    };
    let Some(raw) = raw else {
        return Ok(None);
    };
    match serde_json::from_str::<AuthorizationCodeState>(&raw) {
        Ok(AuthorizationCodeState::Pending { payload }) => Ok(Some(Box::new(payload))),
        Ok(_) => Ok(None),
        Err(error) => {
            tracing::warn!(%error, "authorization code state is malformed before dpop validation");
            Err(oauth_token_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "授权码状态无效.",
                false,
            ))
        }
    }
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

fn authorization_code_requires_pkce(client: &ClientRow, payload: &CodePayload) -> bool {
    client.client_type == "public"
        || client.require_dpop_bound_tokens
        || client.require_mtls_bound_tokens
        || payload.dpop_jkt.is_some()
        || payload.mtls_x5t_s256.is_some()
        || !client.allow_authorization_code_without_pkce
}

fn authorization_code_dpop_error_response(error: DpopError) -> HttpResponse {
    match error {
        DpopError::UseNonce(_) | DpopError::NonceStoreUnavailable => {
            dpop_error_response(error, DpopErrorContext::TokenEndpoint)
        }
        _ => oauth_token_error(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "authorization code proof of possession validation failed.",
            false,
        ),
    }
}

fn authorization_code_mtls_holder_error_response() -> HttpResponse {
    oauth_token_error(
        StatusCode::BAD_REQUEST,
        "invalid_request",
        "authorization code mTLS binding validation failed.",
        false,
    )
}

fn authorization_code_client_mismatch_response() -> HttpResponse {
    oauth_token_error(
        StatusCode::BAD_REQUEST,
        "invalid_grant",
        "授权码与客户端或 redirect_uri 不匹配.",
        false,
    )
}

struct AuthorizationCodeIssueInput {
    payload: CodePayload,
    subject: String,
    audiences: Vec<String>,
    dpop_jkt: Option<String>,
    mtls_x5t_s256: Option<String>,
    code_hash: String,
    refresh_token_dpop_jkt: Option<String>,
    refresh_token_mtls_x5t_s256: Option<String>,
}

fn token_issue_from_authorization_code(input: AuthorizationCodeIssueInput) -> TokenIssue {
    TokenIssue {
        user_id: Some(input.payload.user_id),
        subject: input.subject,
        scopes: input.payload.scopes,
        authorization_details: input.payload.authorization_details,
        audiences: input.audiences,
        nonce: input.payload.nonce,
        auth_time: Some(input.payload.auth_time),
        amr: input.payload.amr,
        oidc_sid: input.payload.oidc_sid,
        acr: input.payload.acr,
        userinfo_claims: input.payload.userinfo_claims,
        userinfo_claim_requests: input.payload.userinfo_claim_requests,
        id_token_claims: input.payload.id_token_claims,
        id_token_claim_requests: input.payload.id_token_claim_requests,
        include_refresh: true,
        refresh_token_policy: RefreshTokenPolicy::IssueNew,
        dpop_jkt: input.dpop_jkt,
        refresh_token_dpop_jkt: input.refresh_token_dpop_jkt,
        mtls_x5t_s256: input.mtls_x5t_s256,
        refresh_token_mtls_x5t_s256: input.refresh_token_mtls_x5t_s256,
        authorization_code_hash: Some(input.code_hash),
    }
}

fn refresh_token_dpop_binding(
    client: &ClientRow,
    _payload: &CodePayload,
    dpop_jkt: Option<String>,
) -> Option<String> {
    if client.client_type == "public" {
        dpop_jkt
    } else {
        None
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
    Ok(parse_authorization_code_consumption_response(&response))
}

async fn revoke_replayed_authorization_code(
    state: &AppState,
    marker: ConsumedAuthorizationCode,
) -> Result<bool, HttpResponse> {
    let client = match find_client_by_id(&state.diesel_db, marker.client_id).await {
        Ok(Some(client)) => client,
        Ok(None) => {
            return Ok(false);
        }
        Err(error) => {
            tracing::warn!(%error, "failed to load replayed authorization code client");
            return Err(oauth_token_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "授权码重放撤销失败.",
                false,
            ));
        }
    };
    if let Err(error) = revoke_issued_authorization_code_tokens(
        state,
        &client,
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
    client_assertion: Option<&ValidatedClientAssertion>,
) -> HttpResponse {
    let Some(code) = &form.code else {
        return oauth_token_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "缺少 code.",
            false,
        );
    };
    let code_hash = blake3_hex(code);
    let expected_payload = match load_pending_authorization_code_payload(state, &code_hash).await {
        Ok(value) => value,
        Err(response) => return response,
    };
    if expected_payload
        .as_ref()
        .is_some_and(|payload| payload.client_id != client.client_id)
    {
        return authorization_code_client_mismatch_response();
    }
    let expected_dpop_jkt = expected_payload
        .as_ref()
        .and_then(|payload| payload.dpop_jkt.clone());
    let expected_mtls_x5t_s256 = expected_payload
        .as_ref()
        .and_then(|payload| payload.mtls_x5t_s256.clone());
    let dpop_jkt = match validate_dpop_proof(state, req, None, expected_dpop_jkt.as_deref()).await {
        Ok(value) => value.or(expected_dpop_jkt),
        Err(error) => return authorization_code_dpop_error_response(error),
    };
    if client.require_dpop_bound_tokens && dpop_jkt.is_none() {
        return authorization_code_dpop_error_response(DpopError::MissingProof);
    }
    let request_mtls_x5t_s256 = request_mtls_thumbprint(req, &state.settings);
    let mtls_x5t_s256 = match (expected_mtls_x5t_s256, request_mtls_x5t_s256) {
        (Some(expected), Some(actual))
            if constant_time_eq(expected.as_bytes(), actual.as_bytes()) =>
        {
            Some(expected)
        }
        (Some(_), _) => {
            return authorization_code_mtls_holder_error_response();
        }
        (None, actual) if client.require_mtls_bound_tokens => {
            let Some(actual) = actual else {
                return authorization_code_mtls_holder_error_response();
            };
            Some(actual)
        }
        (None, _) => None,
    };
    if let Err(response) = consume_token_client_assertion(state, client, client_assertion).await {
        return response;
    }
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
    let payload = *payload;
    if payload.client_id != client.client_id
        || !redirect_uri_matches_authorization_request(&payload, form.redirect_uri.as_deref())
    {
        mark_failed_authorization_code(state, &code_hash, "client_or_redirect_uri_mismatch").await;
        return authorization_code_client_mismatch_response();
    }
    match (&payload.code_challenge, &payload.code_challenge_method) {
        (Some(code_challenge), Some(method)) if method == "S256" => {
            let Some(verifier) = &form.code_verifier else {
                mark_failed_authorization_code(state, &code_hash, "missing_code_verifier").await;
                return oauth_token_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_grant",
                    "缺少 code_verifier.",
                    false,
                );
            };
            if !is_valid_pkce_value(verifier) || pkce_s256(verifier) != *code_challenge {
                mark_failed_authorization_code(state, &code_hash, "pkce_failed").await;
                return oauth_token_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_grant",
                    "PKCE 校验失败.",
                    false,
                );
            }
        }
        (None, None) if !authorization_code_requires_pkce(client, &payload) => {}
        _ => {
            mark_failed_authorization_code(state, &code_hash, "pkce_state_invalid").await;
            return oauth_token_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "授权码 PKCE 状态无效.",
                false,
            );
        }
    }
    let audiences = if form.audiences.is_empty() {
        vec![state.settings.default_audience.clone()]
    } else {
        form.audiences.clone()
    };
    if !audiences_allowed(client, &audiences) {
        mark_failed_authorization_code(state, &code_hash, "audience_not_allowed").await;
        return oauth_token_error(
            StatusCode::BAD_REQUEST,
            "invalid_target",
            "请求的 audience 不在客户端允许范围内.",
            false,
        );
    }
    let refresh_token_dpop_jkt = refresh_token_dpop_binding(client, &payload, dpop_jkt.clone());
    let refresh_token_mtls_x5t_s256 = mtls_x5t_s256.clone();
    let subject = match authorization_code_subject(&state.settings, &payload, client) {
        Ok(subject) => subject,
        Err(_) => {
            mark_failed_authorization_code(state, &code_hash, "subject_policy_invalid").await;
            let status = StatusCode::SERVICE_UNAVAILABLE;
            let error = "server_error";
            let description = "subject invalid";
            return oauth_token_error(status, error, description, false);
        }
    };
    issue_token_response(
        state,
        client,
        token_issue_from_authorization_code(AuthorizationCodeIssueInput {
            payload,
            subject,
            audiences,
            dpop_jkt,
            mtls_x5t_s256,
            code_hash,
            refresh_token_dpop_jkt,
            refresh_token_mtls_x5t_s256,
        }),
    )
    .await
}

async fn mark_failed_authorization_code(state: &AppState, code_hash: &str, error_code: &str) {
    if let Err(error) = super::mark_failed_authorization_code(state, code_hash, error_code).await {
        tracing::warn!(%error, "failed to mark authorization code exchange as failed");
    }
}

fn authorization_code_subject(
    settings: &Settings,
    payload: &CodePayload,
    client: &ClientRow,
) -> anyhow::Result<String> {
    let subject_type = client.subject_type.as_str();
    let sector_host = client.sector_identifier_host.as_deref();
    let redirect_uri = payload.redirect_uri.as_str();
    let user_id = payload.user_id;
    compute_subject_for_client(settings, user_id, subject_type, sector_host, redirect_uri)
}

#[cfg(test)]
#[path = "../../../tests/in_source/src/http/token/tests/authorization_code.rs"]
mod tests;
