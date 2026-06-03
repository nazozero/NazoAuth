//! Pushed Authorization Request endpoint.

use super::{apply_request_object, unverified_request_object_client_id};
use crate::http::prelude::*;
use crate::http::{
    consume_token_management_client_assertion, token_management_auth_error,
    verify_confidential_client,
};

const PAR_AUTHORIZATION_PARAMETERS: &[&str] = &[
    "response_type",
    "client_id",
    "redirect_uri",
    "scope",
    "state",
    "code_challenge",
    "code_challenge_method",
    "nonce",
    "claims",
    "acr_values",
    "prompt",
    "max_age",
    "dpop_jkt",
    "request",
];

pub(crate) async fn par(state: Data<AppState>, req: HttpRequest, body: Bytes) -> HttpResponse {
    if let Err(response) = enforce_rate_limit(&state, &req, RateLimitPolicy::TokenManagement).await
    {
        return response;
    }
    let content_type = req
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");
    if !content_type.split(';').next().is_some_and(|value| {
        value
            .trim()
            .eq_ignore_ascii_case("application/x-www-form-urlencoded")
    }) {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "PAR 请求必须使用 application/x-www-form-urlencoded.",
        );
    }
    let raw = match std::str::from_utf8(&body) {
        Ok(raw) => raw,
        Err(_) => {
            return oauth_error(StatusCode::BAD_REQUEST, "invalid_request", "PAR 表单无效.");
        }
    };
    let mut params = HashMap::new();
    let mut seen = std::collections::HashSet::new();
    for (key, value) in url::form_urlencoded::parse(raw.as_bytes()) {
        let key = key.into_owned();
        if key == "request_uri" {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "PAR 请求不能包含 request_uri.",
            );
        }
        if !PAR_AUTHORIZATION_PARAMETERS.contains(&key.as_str())
            && !matches!(
                key.as_str(),
                "client_secret" | "client_assertion_type" | "client_assertion"
            )
        {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "PAR 请求包含不支持的参数.",
            );
        }
        if !seen.insert(key.clone()) {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "PAR 参数不能重复.",
            );
        }
        params.insert(key, value.into_owned());
    }
    if !params.contains_key("client_id")
        && let Some(request_object) = params.get("request")
        && let Some(client_id) = unverified_request_object_client_id(request_object)
    {
        params.insert("client_id".to_owned(), client_id);
    }
    let Some(client_id) = params.get("client_id").cloned() else {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "缺少 client_id.",
        );
    };
    let client = match find_client(&state.diesel_db, &client_id).await {
        Ok(Some(client)) if client.is_active => client,
        Ok(_) => {
            return oauth_error(
                StatusCode::UNAUTHORIZED,
                "invalid_client",
                "客户端认证失败.",
            );
        }
        Err(error) => {
            tracing::warn!(%error, "failed to query PAR client");
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "客户端查询失败.",
            );
        }
    };
    let credentials = extract_client_credentials(
        req.headers(),
        Some(&client_id),
        params.get("client_secret").map(String::as_str),
        params.get("client_assertion_type").map(String::as_str),
        params.get("client_assertion").map(String::as_str),
    );
    let client_assertion = if client.client_type == "public" {
        None
    } else {
        match verify_confidential_client(&state, &req, &client, &credentials) {
            Ok(assertion) => assertion,
            Err(error) => return token_management_auth_error(error),
        }
    };
    params.remove("client_secret");
    params.remove("client_assertion_type");
    params.remove("client_assertion");
    if let Err(response) = apply_request_object(&state, &mut params, &client).await {
        return response;
    }
    params.remove("request");
    if let Err(response) = validate_pushed_authorization_request(&client, &params) {
        return response;
    }
    let request_dpop_jkt = match params.get("dpop_jkt") {
        Some(value) if is_valid_dpop_jkt(value) => Some(value.clone()),
        Some(_) => {
            return oauth_error(StatusCode::BAD_REQUEST, "invalid_request", "dpop_jkt 无效.");
        }
        None => None,
    };
    let header_dpop_jkt = match validate_dpop_proof(&state, &req, None, None).await {
        Ok(value) => value,
        Err(error) => return dpop_error_response(error, DpopErrorContext::TokenEndpoint),
    };
    if let (Some(request_dpop_jkt), Some(header_dpop_jkt)) =
        (request_dpop_jkt.as_deref(), header_dpop_jkt.as_deref())
        && request_dpop_jkt != header_dpop_jkt
    {
        return dpop_error_response(DpopError::BindingMismatch, DpopErrorContext::TokenEndpoint);
    }
    if let Err(error) =
        consume_token_management_client_assertion(&state, &client, client_assertion.as_ref()).await
    {
        return token_management_auth_error(error);
    }
    let dpop_jkt = request_dpop_jkt.or(header_dpop_jkt);

    let now = Utc::now();
    let request_token = random_urlsafe_token();
    let request_uri = format!("urn:ietf:params:oauth:request_uri:{request_token}");
    let payload = PushedAuthorizationRequest {
        client_id,
        params,
        dpop_jkt,
        issued_at: now,
        expires_at: now + Duration::seconds(state.settings.par_ttl_seconds as i64),
    };
    let body = match serde_json::to_string(&payload) {
        Ok(body) => body,
        Err(error) => {
            tracing::warn!(%error, "failed to serialize PAR payload");
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "PAR 写入失败.",
            );
        }
    };
    if let Err(error) = valkey_set_ex(
        &state.valkey,
        pushed_authorization_request_key(&request_uri),
        body,
        state.settings.par_ttl_seconds.max(1),
    )
    .await
    {
        tracing::warn!(%error, "failed to persist PAR payload");
        return oauth_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "PAR 写入失败.",
        );
    }
    json_response_status(
        StatusCode::CREATED,
        json!({
            "request_uri": request_uri,
            "expires_in": state.settings.par_ttl_seconds
        }),
    )
}

pub(crate) fn pushed_authorization_request_key(request_uri: &str) -> String {
    format!("oauth:par:{}", blake3_hex(request_uri))
}

fn validate_pushed_authorization_request(
    client: &ClientRow,
    params: &HashMap<String, String>,
) -> Result<(), HttpResponse> {
    registered_redirect_uri(client, params.get("redirect_uri").map(String::as_str))
        .map(|_| ())
        .map_err(|error| match error {
            RedirectUriError::Missing => oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "PAR 请求缺少 redirect_uri.",
            ),
            RedirectUriError::Invalid => oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "PAR 请求 redirect_uri 未注册.",
            ),
        })
}
