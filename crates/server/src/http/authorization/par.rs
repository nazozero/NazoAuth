//! Pushed Authorization Request endpoint.

use super::{
    apply_request_object, request_object_uses_unsigned_algorithm,
    unverified_signed_request_object_client_id,
};
use crate::http::prelude::*;

pub(crate) const PUSHED_AUTHORIZATION_REQUEST_URI_PREFIX: &str =
    "urn:ietf:params:oauth:request_uri:";
use crate::http::{
    consume_token_management_client_assertion, token_management_auth_error,
    verify_confidential_client,
};

const PAR_AUTHORIZATION_PARAMETERS: &[&str] = &[
    "response_type",
    "client_id",
    "redirect_uri",
    "scope",
    "resource",
    "authorization_details",
    "state",
    "code_challenge",
    "code_challenge_method",
    "nonce",
    "claims",
    "acr_values",
    "prompt",
    "max_age",
    "dpop_jkt",
    "response_mode",
    "request",
];

pub(crate) async fn par(state: Data<AppState>, req: HttpRequest, body: Bytes) -> HttpResponse {
    if let Err(response) = enforce_rate_limit(&state, &req, RateLimitPolicy::TokenManagement).await
    {
        return response;
    }
    par_after_rate_limit(state, req, body).await
}

pub(crate) async fn par_after_rate_limit(
    state: Data<AppState>,
    req: HttpRequest,
    body: Bytes,
) -> HttpResponse {
    let response = par_after_rate_limit_inner(state, req, body).await;
    log_par_error_response(&response);
    response
}

async fn par_after_rate_limit_inner(
    state: Data<AppState>,
    req: HttpRequest,
    body: Bytes,
) -> HttpResponse {
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
    let mut resource_values = Vec::new();
    for (key, value) in url::form_urlencoded::parse(raw.as_bytes()) {
        let key = key.into_owned();
        let value = value.into_owned();
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
        if key == "resource" {
            resource_values.push(value);
            continue;
        }
        if !seen.insert(key.clone()) {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "PAR 参数不能重复.",
            );
        }
        params.insert(key, value);
    }
    if let Some(encoded) = encoded_resource_indicators(&resource_values) {
        params.insert("resource".to_owned(), encoded);
    }
    if !state.settings.enable_par_request_object
        && !state
            .settings
            .authorization_server_profile
            .requires_signed_request_object_at_par()
        && params.contains_key("request")
    {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "PAR request object 未启用.",
        );
    }
    if !state.settings.enable_authorization_details && params.contains_key("authorization_details")
    {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "authorization_details 未启用.",
        );
    }

    if params
        .get("request")
        .is_some_and(|request| request_object_uses_unsigned_algorithm(request))
    {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request_object",
            "PAR request object 必须签名.",
        );
    }
    if !params.contains_key("client_id")
        && let Some(request_object) = params.get("request")
        && let Some(client_id) = unverified_signed_request_object_client_id(request_object)
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
        &req,
        &state.settings,
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
    if let Err(response) =
        validate_pushed_authorization_request_profile(&state.settings, &client, &credentials.method)
    {
        return response;
    }
    if pushed_authorization_request_requires_request_object(&state.settings, &client)
        && !params.contains_key("request")
    {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "PAR 请求缺少 request object.",
        );
    }
    if let Err(response) = apply_request_object(&state, &mut params, &client).await {
        return response;
    }
    if !state.settings.enable_authorization_details && params.contains_key("authorization_details")
    {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "authorization_details 未启用.",
        );
    }
    params.remove("request");
    if pushed_authorization_request_contains_request_uri(&params) {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request_object",
            "PAR request object 不能包含 request_uri.",
        );
    }
    if let Err(response) =
        validate_pushed_authorization_request_profile_parameters(&state.settings, &params)
    {
        return response;
    }
    if let Err(response) = validate_pushed_authorization_request(&client, &params) {
        return response;
    }
    if let Err(response) = validate_pushed_authorization_request_resources(&client, &params) {
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
    let mtls_x5t_s256 = if client.require_mtls_bound_tokens {
        request_mtls_thumbprint(&req, &state.settings)
    } else {
        None
    };

    let now = Utc::now();
    let request_token = random_urlsafe_token();
    let request_uri = format!("{PUSHED_AUTHORIZATION_REQUEST_URI_PREFIX}{request_token}");
    let payload = PushedAuthorizationRequest {
        client_id,
        params,
        dpop_jkt,
        mtls_x5t_s256,
        issued_at: now,
        expires_at: now + Duration::seconds(state.settings.par_ttl_seconds as i64),
    };
    let body = serde_json::to_string(&payload)
        .expect("pushed authorization request serialization must be infallible");
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

fn log_par_error_response(response: &HttpResponse) {
    let Some((status, oauth_error)) = par_error_log_fields(response) else {
        return;
    };
    if let Some(oauth_error) = oauth_error {
        tracing::warn!("PAR request rejected http_status={status} oauth_error={oauth_error}");
    } else {
        tracing::warn!("PAR request rejected http_status={status}");
    }
}

fn par_error_log_fields(response: &HttpResponse) -> Option<(u16, Option<String>)> {
    if response.status() == StatusCode::CREATED || response.status().is_success() {
        return None;
    }

    Some((
        response.status().as_u16(),
        response
            .extensions()
            .get::<OAuthJsonErrorFields>()
            .map(|fields| fields.error.clone()),
    ))
}

pub(crate) fn pushed_authorization_request_key(request_uri: &str) -> String {
    format!("oauth:par:{}", blake3_hex(request_uri))
}

pub(crate) fn is_pushed_authorization_request_uri(request_uri: &str) -> bool {
    request_uri.starts_with(PUSHED_AUTHORIZATION_REQUEST_URI_PREFIX)
}

fn validate_pushed_authorization_request(
    client: &ClientRow,
    params: &HashMap<String, String>,
) -> Result<(), HttpResponse> {
    if pushed_authorization_request_has_unsupported_response_type(params) {
        return Err(oauth_error(
            StatusCode::BAD_REQUEST,
            "unsupported_response_type",
            "PAR response_type is not supported.",
        ));
    }
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

fn pushed_authorization_request_has_unsupported_response_type(
    params: &HashMap<String, String>,
) -> bool {
    params
        .get("response_type")
        .is_some_and(|response_type| response_type != "code")
}

fn pushed_authorization_request_contains_request_uri(params: &HashMap<String, String>) -> bool {
    params.contains_key("request_uri")
}

fn validate_pushed_authorization_request_resources(
    client: &ClientRow,
    params: &HashMap<String, String>,
) -> Result<(), HttpResponse> {
    let resources =
        resource_indicators_from_parameter_value(params.get("resource").map(String::as_str))
            .map_err(|_| {
                oauth_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_target",
                    "resource must be an absolute URI without a fragment.",
                )
            })?;
    if !resources.is_empty() && !audiences_allowed(client, &resources) {
        return Err(oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_target",
            "请求的 resource 不在客户端允许范围内.",
        ));
    }
    Ok(())
}

fn pushed_authorization_request_requires_request_object(
    settings: &Settings,
    client: &ClientRow,
) -> bool {
    client.require_par_request_object
        || settings
            .authorization_server_profile
            .requires_signed_authorization_request()
}

fn validate_pushed_authorization_request_profile(
    settings: &Settings,
    client: &ClientRow,
    auth_method: &str,
) -> Result<(), HttpResponse> {
    if !settings
        .authorization_server_profile
        .requires_fapi2_security()
    {
        return Ok(());
    }
    if client.client_type != "confidential" {
        return Err(oauth_error(
            StatusCode::BAD_REQUEST,
            "unauthorized_client",
            "FAPI2 profiles require confidential clients.",
        ));
    }
    if !matches!(
        auth_method,
        "private_key_jwt" | "tls_client_auth" | "self_signed_tls_client_auth"
    ) {
        return Err(oauth_error(
            StatusCode::UNAUTHORIZED,
            "invalid_client",
            "FAPI2 profiles require private_key_jwt or mTLS client authentication.",
        ));
    }
    if !(client.require_dpop_bound_tokens || client.require_mtls_bound_tokens) {
        return Err(oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "FAPI2 profiles require sender-constrained access tokens.",
        ));
    }
    Ok(())
}

fn validate_pushed_authorization_request_profile_parameters(
    settings: &Settings,
    params: &HashMap<String, String>,
) -> Result<(), HttpResponse> {
    if settings
        .authorization_server_profile
        .requires_fapi2_security()
        && !params.contains_key("redirect_uri")
    {
        return Err(oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "FAPI2 PAR 请求必须显式包含 redirect_uri.",
        ));
    }
    Ok(())
}

#[cfg(test)]
#[path = "../../../tests/in_source/src/http/authorization/tests/par.rs"]
mod tests;
