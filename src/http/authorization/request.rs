//! 授权请求入口端点。
// 该端点只创建 consent 临时状态，不签发授权码。
use super::{
    apply_request_object, pushed_authorization_request_key, unverified_request_object_client_id,
};
use crate::http::prelude::*;

mod form;
mod parameters;
mod prompt_none;

use form::*;
pub(crate) use parameters::AUTHORIZED_REQUEST_PARAMETERS;
use parameters::*;
use prompt_none::*;

/// 校验 OAuth authorize 参数并创建待确认授权请求。
pub(crate) async fn authorize_get(
    state: Data<AppState>,
    req: HttpRequest,
    Query(mut q): Query<HashMap<String, String>>,
) -> HttpResponse {
    authorize_request(state, req, &mut q).await
}

pub(crate) async fn authorize_post(
    state: Data<AppState>,
    req: HttpRequest,
    body: Bytes,
) -> HttpResponse {
    let query_parameters = authorization_duplicate_parameters();
    let mut q = match parse_authorization_post_form(&req, &body, &query_parameters) {
        Ok(q) => q,
        Err(response) => return response,
    };
    authorize_request(state, req, &mut q).await
}

async fn authorize_request(
    state: Data<AppState>,
    req: HttpRequest,
    q: &mut HashMap<String, String>,
) -> HttpResponse {
    let query_parameters = authorization_duplicate_parameters();
    if has_duplicate_oauth_parameter(req.query_string(), &query_parameters) {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "OAuth 参数不能重复.",
        );
    }

    let original_authorization_query = q.clone();
    let reauth_started_at = q
        .get(reauth_started_at_parameter())
        .and_then(|value| value.parse::<i64>().ok())
        .filter(|value| *value > 0);
    q.remove(reauth_started_at_parameter());
    let mut pushed_dpop_jkt = None;
    let mut pushed_mtls_x5t_s256 = None;
    let mut consumed_request_uri_error: Option<&'static str> = None;
    let mut used_pushed_authorization_request = false;
    let mut pending_pushed_request_uri = None;
    if let Some(request_uri) = q.get("request_uri").cloned() {
        let raw = match valkey_get(
            &state.valkey,
            pushed_authorization_request_key(&request_uri),
        )
        .await
        {
            Ok(Some(raw)) => raw,
            Ok(None) => {
                consumed_request_uri_error = Some("invalid_request_uri");
                String::new()
            }
            Err(error) => {
                tracing::warn!(%error, "failed to read PAR request_uri");
                return oauth_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "server_error",
                    "request_uri 读取失败.",
                );
            }
        };
        if consumed_request_uri_error.is_none() {
            let pushed = match serde_json::from_str::<PushedAuthorizationRequest>(&raw) {
                Ok(pushed) => pushed,
                Err(error) => {
                    tracing::warn!(%error, "PAR payload is malformed");
                    return oauth_error(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "server_error",
                        "request_uri 状态无效.",
                    );
                }
            };
            if q.get("client_id")
                .is_some_and(|client_id| client_id != &pushed.client_id)
            {
                consumed_request_uri_error = Some("invalid_request_uri");
            } else if !outer_request_uri_parameters_match_pushed(q, &pushed.params) {
                consumed_request_uri_error = Some("invalid_request");
                *q = pushed.params;
            } else {
                pushed_dpop_jkt = pushed.dpop_jkt;
                pushed_mtls_x5t_s256 = pushed.mtls_x5t_s256;
                used_pushed_authorization_request = true;
                pending_pushed_request_uri = Some(request_uri);
                *q = pushed.params;
            }
        }
    } else if state.settings.require_pushed_authorization_requests {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "该服务要求使用 pushed authorization request.",
        );
    }

    if !q.contains_key("client_id")
        && let Some(request_object) = q.get("request")
        && let Some(client_id) = unverified_request_object_client_id(request_object)
    {
        q.insert("client_id".to_owned(), client_id);
    }

    let Some(client_id) = q.get("client_id") else {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "缺少 client_id.",
        );
    };

    let client = match find_client(&state.diesel_db, client_id).await {
        Ok(Some(client)) => client,
        Ok(None) => {
            return oauth_error(
                StatusCode::UNAUTHORIZED,
                "unauthorized_client",
                "客户端不存在或已停用.",
            );
        }
        Err(error) => {
            tracing::warn!(%error, "failed to query oauth client");
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "客户端查询失败.",
            );
        }
    };
    if !client.is_active {
        return oauth_error(
            StatusCode::UNAUTHORIZED,
            "unauthorized_client",
            "客户端不存在或已停用.",
        );
    }
    if !client_supports_grant(&client, "authorization_code") {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "unauthorized_client",
            "该客户端未启用 authorization_code 授权类型.",
        );
    }
    let request_object_error = apply_request_object(&state, q, &client).await.err();
    let request_dpop_jkt = match q.get("dpop_jkt") {
        Some(value) if is_valid_dpop_jkt(value) => Some(value.clone()),
        Some(_) => {
            return oauth_error(StatusCode::BAD_REQUEST, "invalid_request", "dpop_jkt 无效.");
        }
        None => None,
    };
    let dpop_jkt = match (pushed_dpop_jkt, request_dpop_jkt) {
        (Some(pushed), Some(requested)) if pushed != requested => {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "dpop_jkt 与 PAR 绑定不匹配.",
            );
        }
        (Some(pushed), _) => Some(pushed),
        (None, requested) => requested,
    };
    preserve_verified_dpop_binding(q, dpop_jkt.as_deref());
    let mtls_x5t_s256 = pushed_mtls_x5t_s256;
    let redirect_uri =
        match registered_redirect_uri(&client, q.get("redirect_uri").map(String::as_str)) {
            Ok(value) => value,
            Err(RedirectUriError::Missing) => {
                return authorization_error_response(
                    StatusCode::BAD_REQUEST,
                    "invalid_request",
                    "redirect_uri is required for this authorization request.",
                );
            }
            Err(RedirectUriError::Invalid) => {
                return authorization_error_response(
                    StatusCode::BAD_REQUEST,
                    "invalid_request",
                    "redirect_uri is not registered for this client.",
                );
            }
        };

    if let Some(error) = consumed_request_uri_error {
        return authorization_oauth_error_redirect(&state, &redirect_uri, error, q).await;
    }
    if let Some(error_response) = request_object_error {
        if let Some(error) = oauth_json_error(&error_response) {
            return authorization_oauth_error_redirect(&state, &redirect_uri, &error, q).await;
        }
        return error_response;
    }
    if (client.require_dpop_bound_tokens || client.require_mtls_bound_tokens)
        && !used_pushed_authorization_request
        && !q.contains_key("request")
    {
        return authorization_oauth_error_redirect(&state, &redirect_uri, "invalid_request", q)
            .await;
    }
    if authorization_nonce_too_long(q) {
        return authorization_oauth_error_redirect(&state, &redirect_uri, "invalid_request", q)
            .await;
    }

    if q.get("response_type").map(String::as_str) != Some("code") {
        return authorization_oauth_error_redirect(
            &state,
            &redirect_uri,
            "unsupported_response_type",
            q,
        )
        .await;
    }
    let response_mode = match authorization_response_mode(q) {
        Ok(value) => value,
        Err(()) => {
            return authorization_oauth_error_redirect(&state, &redirect_uri, "invalid_request", q)
                .await;
        }
    };
    let (code_challenge, code_challenge_method) = match authorization_pkce(q) {
        Ok(value) => value,
        Err(()) => {
            return authorization_oauth_error_redirect(&state, &redirect_uri, "invalid_request", q)
                .await;
        }
    };
    if code_challenge.is_none() && authorization_request_requires_pkce(&client) {
        return authorization_oauth_error_redirect(&state, &redirect_uri, "invalid_request", q)
            .await;
    }

    let prompt = match requested_prompt(q) {
        Ok(prompt) => prompt,
        Err(()) => {
            return authorization_oauth_error_redirect(&state, &redirect_uri, "invalid_request", q)
                .await;
        }
    };
    let max_age = match q.get("max_age") {
        Some(value) => match value.parse::<i64>() {
            Ok(value) if value >= 0 => Some(value),
            _ => {
                return authorization_oauth_error_redirect(
                    &state,
                    &redirect_uri,
                    "invalid_request",
                    q,
                )
                .await;
            }
        },
        None => None,
    };
    let requested_claims = match requested_claims(q) {
        Ok(value) => value,
        Err(()) => {
            return authorization_oauth_error_redirect(&state, &redirect_uri, "invalid_request", q)
                .await;
        }
    };

    let session = match current_session(&state, &req).await {
        Ok(session) => session,
        Err(error) => {
            tracing::warn!(%error, "failed to resolve authorization request user");
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "会话查询失败.",
            );
        }
    };
    let Some(session) = session else {
        if prompt.none {
            return authorization_response_redirect(
                &state,
                &redirect_uri,
                q.get("client_id").map(String::as_str).unwrap_or(""),
                q.get("response_mode").map(String::as_str),
                None,
                Some("login_required"),
                q.get("state").map(String::as_str),
            )
            .await;
        }
        return redirect_found(authorization_login_url(
            &state,
            &authorization_login_query(
                q,
                &original_authorization_query,
                pending_pushed_request_uri.as_ref(),
            ),
            prompt.login || prompt.select_account,
            reauth_started_at,
        ));
    };
    if session_requires_reauthentication(
        prompt,
        max_age,
        session.auth_time,
        reauth_started_at,
        Utc::now().timestamp(),
    ) {
        if prompt.none {
            return authorization_response_redirect(
                &state,
                &redirect_uri,
                q.get("client_id").map(String::as_str).unwrap_or(""),
                q.get("response_mode").map(String::as_str),
                None,
                Some("login_required"),
                q.get("state").map(String::as_str),
            )
            .await;
        }
        return redirect_found(authorization_login_url(
            &state,
            &authorization_login_query(
                q,
                &original_authorization_query,
                pending_pushed_request_uri.as_ref(),
            ),
            prompt.login || prompt.select_account,
            reauth_started_at,
        ));
    }

    let requested_scopes = parse_scope(q.get("scope").map(String::as_str).unwrap_or(""));
    if !is_subset(&requested_scopes, &json_array_to_strings(&client.scopes)) {
        return authorization_oauth_error_redirect(&state, &redirect_uri, "invalid_scope", q).await;
    }
    let authorization_details =
        match parse_authorization_details(q.get("authorization_details").map(String::as_str)) {
            Ok(value) => value,
            Err(()) => {
                return authorization_oauth_error_redirect(
                    &state,
                    &redirect_uri,
                    "invalid_request",
                    q,
                )
                .await;
            }
        };
    let now = Utc::now();
    let request_id = Uuid::now_v7().to_string();
    let payload = ConsentPayload {
        request_id: request_id.clone(),
        user_id: session.user.id,
        client_id: client.client_id,
        client_name: client.client_name,
        redirect_uri: redirect_uri.clone(),
        redirect_uri_was_supplied: q.contains_key("redirect_uri"),
        scopes: requested_scopes,
        authorization_details,
        state: q.get("state").cloned(),
        response_mode,
        nonce: q.get("nonce").cloned(),
        auth_time: session.auth_time,
        amr: session.amr,
        oidc_sid: Some(session.oidc_sid),
        acr: requested_acr(q, requested_claims.acr),
        userinfo_claims: claim_request_names(&requested_claims.userinfo),
        userinfo_claim_requests: requested_claims.userinfo,
        id_token_claims: claim_request_names(&requested_claims.id_token),
        id_token_claim_requests: requested_claims.id_token,
        code_challenge,
        code_challenge_method,
        dpop_jkt,
        mtls_x5t_s256,
        pushed_request_uri: pending_pushed_request_uri,
        issued_at: now,
        expires_at: now + Duration::seconds(state.settings.auth_code_ttl_seconds as i64),
    };
    if prompt.none {
        match user_grant_covers_requested_scopes(
            &state,
            payload.user_id,
            client.id,
            &payload.scopes,
            &payload.authorization_details,
        )
        .await
        {
            Ok(true) => {
                return issue_authorization_code_without_interaction(&state, &req, payload).await;
            }
            Ok(false) => {
                return authorization_oauth_error_redirect(
                    &state,
                    &redirect_uri,
                    "consent_required",
                    q,
                )
                .await;
            }
            Err(response) => return response,
        }
    }
    let key = format!("oauth:consent:{request_id}");
    let body = match serde_json::to_string(&payload) {
        Ok(body) => body,
        Err(error) => {
            tracing::warn!(%error, "failed to serialize consent request");
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "授权请求创建失败.",
            );
        }
    };
    if let Err(error) = valkey_set_ex(
        &state.valkey,
        key,
        body,
        state.settings.auth_code_ttl_seconds,
    )
    .await
    {
        tracing::warn!(%error, "failed to persist consent request");
        return oauth_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "授权请求创建失败.",
        );
    }

    redirect_found(format!(
        "{}/consent?request_id={request_id}",
        state.settings.frontend_base_url.trim_end_matches('/')
    ))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PushedAuthorizationRequestConsumeError {
    Missing,
    ReadFailed,
    Malformed,
}

pub(crate) async fn consume_pushed_authorization_request(
    state: &AppState,
    request_uri: &str,
) -> Result<(), PushedAuthorizationRequestConsumeError> {
    let raw =
        match valkey_getdel(&state.valkey, pushed_authorization_request_key(request_uri)).await {
            Ok(Some(raw)) => raw,
            Ok(None) => {
                return Err(PushedAuthorizationRequestConsumeError::Missing);
            }
            Err(error) => {
                tracing::warn!(%error, "failed to consume PAR request_uri");
                return Err(PushedAuthorizationRequestConsumeError::ReadFailed);
            }
        };
    if let Err(error) = serde_json::from_str::<PushedAuthorizationRequest>(&raw) {
        tracing::warn!(%error, "PAR payload is malformed");
        return Err(PushedAuthorizationRequestConsumeError::Malformed);
    }
    Ok(())
}

pub(crate) async fn authorization_oauth_error_redirect(
    state: &AppState,
    redirect_uri: &str,
    error: &str,
    q: &HashMap<String, String>,
) -> HttpResponse {
    authorization_response_redirect(
        state,
        redirect_uri,
        q.get("client_id").map(String::as_str).unwrap_or(""),
        q.get("response_mode").map(String::as_str),
        None,
        Some(error),
        q.get("state").map(String::as_str),
    )
    .await
}

pub(crate) async fn authorization_response_redirect(
    state: &AppState,
    redirect_uri: &str,
    client_id: &str,
    response_mode: Option<&str>,
    code: Option<&str>,
    error: Option<&str>,
    state_value: Option<&str>,
) -> HttpResponse {
    if response_mode == Some("jwt") && !client_id.trim().is_empty() {
        return authorization_response_jwt_result(
            redirect_uri,
            make_authorization_response_jwt(
                state,
                AuthorizationResponseJwtInput {
                    client_id,
                    code,
                    error,
                    state: state_value,
                    ttl: state.settings.auth_code_ttl_seconds as i64,
                },
            )
            .await,
        );
    }
    redirect_found(append_authorization_response_query(
        redirect_uri,
        state.settings.issuer.as_str(),
        code,
        error,
        state_value,
    ))
}

fn authorization_response_jwt_result(
    redirect_uri: &str,
    result: jsonwebtoken::errors::Result<String>,
) -> HttpResponse {
    match result {
        Ok(response) => authorization_response_jwt_redirect(redirect_uri, &response),
        Err(signing_error) => {
            tracing::warn!(%signing_error, "failed to sign JARM authorization response");
            oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "authorization response signing failed.",
            )
        }
    }
}

fn authorization_response_jwt_redirect(redirect_uri: &str, response: &str) -> HttpResponse {
    redirect_found(append_query(redirect_uri, &[("response", response)]))
}

fn oauth_json_error(response: &HttpResponse) -> Option<String> {
    let extensions = response.extensions();
    extensions
        .get::<OAuthJsonErrorFields>()
        .map(|fields| fields.error.clone())
}

fn authorization_login_url(
    state: &AppState,
    q: &HashMap<String, String>,
    reauthentication_required: bool,
    reauth_started_at: Option<i64>,
) -> String {
    authorization_login_url_for_frontend(
        &state.settings.frontend_base_url,
        q,
        reauthentication_required,
        reauth_started_at,
    )
}

#[cfg(test)]
#[path = "tests/request.rs"]
mod tests;
