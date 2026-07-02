//! /token grant_type 分发入口。
// 只负责客户端认证与 grant_type 分派，不直接签发令牌。
use super::{
    CIBA_GRANT_TYPE, DEVICE_CODE_GRANT_TYPE, JWT_BEARER_GRANT_TYPE, TOKEN_EXCHANGE_GRANT_TYPE,
    TokenForm, TokenFormError, parse_token_form, token_authorization_code, token_ciba,
    token_client_credentials, token_device_code, token_exchange, token_jwt_bearer, token_refresh,
};
use crate::http::prelude::*;

fn pending_authorization_code_payload(raw: &str) -> Result<Option<CodePayload>, serde_json::Error> {
    match serde_json::from_str::<AuthorizationCodeState>(raw)? {
        AuthorizationCodeState::Pending { payload } => Ok(Some(payload)),
        _ => Ok(None),
    }
}

fn token_request_has_client_auth_material(has_basic: bool, form: &TokenForm) -> bool {
    has_basic
        || form.client_id.is_some()
        || form.client_secret.is_some()
        || form.client_assertion_type.is_some()
        || form.client_assertion.is_some()
}

fn mtls_client_credentials(client_id: String) -> ClientCredentials {
    ClientCredentials {
        client_id: Some(client_id),
        client_secret: None,
        client_assertion: None,
        method: "tls_client_auth".to_owned(),
    }
}

async fn mtls_client_credentials_without_client_id(
    state: &AppState,
    req: &HttpRequest,
) -> Result<Option<ClientCredentials>, HttpResponse> {
    let Some(certificate) = request_mtls_client_certificate(req, &state.settings) else {
        return Ok(None);
    };
    match find_active_mtls_client_by_certificate(&state.diesel_db, &certificate).await {
        Ok(Some(client)) => Ok(Some(mtls_client_credentials(client.client_id))),
        Ok(None) => Ok(None),
        Err(error) => {
            tracing::warn!(%error, "failed to query mTLS client by certificate identity");
            Err(oauth_token_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "客户端查询失败.",
                false,
            ))
        }
    }
}

fn authorization_code_holder_missing_client_error(
    dpop_bound: bool,
    mtls_bound: bool,
) -> Option<HttpResponse> {
    if mtls_bound {
        return Some(oauth_token_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "authorization code proof of possession validation failed.",
            false,
        ));
    }
    if dpop_bound {
        return Some(oauth_token_error(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "authorization code proof of possession validation failed.",
            false,
        ));
    }
    None
}

fn client_credentials_holder_missing_client_error(
    form: &TokenForm,
    dpop_present: bool,
) -> Option<HttpResponse> {
    if form.grant_type != "client_credentials" || dpop_present {
        return None;
    }
    Some(oauth_token_error(
        StatusCode::BAD_REQUEST,
        "invalid_request",
        "client_credentials requires a holder-of-key proof.",
        false,
    ))
}

async fn missing_client_authorization_code_holder_error(
    state: &AppState,
    form: &TokenForm,
) -> Option<HttpResponse> {
    if form.grant_type != "authorization_code" {
        return None;
    }
    let code = form.code.as_deref()?;
    let raw = match valkey_get(&state.valkey, authorization_code_key(code)).await {
        Ok(Some(raw)) => raw,
        Ok(None) => return None,
        Err(error) => {
            tracing::warn!(%error, "failed to read authorization code before client authentication");
            return Some(oauth_token_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "授权码校验失败.",
                false,
            ));
        }
    };
    let payload = match pending_authorization_code_payload(&raw) {
        Ok(Some(payload)) => payload,
        Ok(None) => return None,
        Err(error) => {
            tracing::warn!(%error, "authorization code state is malformed before client authentication");
            return Some(oauth_token_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "授权码状态无效.",
                false,
            ));
        }
    };
    if let Some(response) = authorization_code_holder_missing_client_error(
        payload.dpop_jkt.is_some(),
        payload.mtls_x5t_s256.is_some(),
    ) {
        return Some(response);
    }
    match find_client(&state.diesel_db, &payload.client_id).await {
        Ok(Some(client))
            if client.require_dpop_bound_tokens || client.require_mtls_bound_tokens =>
        {
            authorization_code_holder_missing_client_error(
                client.require_dpop_bound_tokens,
                client.require_mtls_bound_tokens,
            )
        }
        Ok(_) => None,
        Err(error) => {
            tracing::warn!(%error, "failed to query authorization code client before client authentication");
            Some(oauth_token_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "客户端查询失败.",
                false,
            ))
        }
    }
}

pub(crate) async fn token(state: Data<AppState>, req: HttpRequest, body: Bytes) -> HttpResponse {
    if let Err(response) = enforce_rate_limit(&state, &req, RateLimitPolicy::Token).await {
        return response;
    }

    let form = match parse_token_form(&req, &body) {
        Ok(form) => form,
        Err(TokenFormError::InvalidContentType) => {
            return oauth_token_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "token 请求必须使用 application/x-www-form-urlencoded.",
                false,
            );
        }
        Err(TokenFormError::InvalidEncoding) => {
            return oauth_token_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "token 请求体必须使用 UTF-8 编码.",
                false,
            );
        }
        Err(TokenFormError::DuplicateParameter) => {
            return oauth_token_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "OAuth 参数不能重复.",
                false,
            );
        }
        Err(TokenFormError::InvalidResourceParameter) => {
            return oauth_token_error(
                StatusCode::BAD_REQUEST,
                "invalid_target",
                "resource must be an absolute URI without a fragment.",
                false,
            );
        }
        Err(TokenFormError::MissingGrantType) => {
            return oauth_token_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "缺少 grant_type.",
                false,
            );
        }
    };
    if form.has_audience_param
        && form.grant_type != TOKEN_EXCHANGE_GRANT_TYPE
        && !state.settings.enable_legacy_audience_param
    {
        return oauth_token_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "audience 参数未启用.",
            false,
        );
    }

    if state
        .settings
        .authorization_server_profile
        .requires_fapi2_security()
        && form.grant_type == "password"
    {
        return oauth_token_error(
            StatusCode::BAD_REQUEST,
            "unsupported_grant_type",
            "FAPI2 profiles do not allow resource owner password credentials.",
            false,
        );
    }
    let has_basic = has_basic_authorization_scheme(req.headers());
    let has_assertion = form.client_assertion_type.is_some() || form.client_assertion.is_some();
    let has_client_auth_material = token_request_has_client_auth_material(has_basic, &form);
    if has_basic && (form.client_id.is_some() || form.client_secret.is_some() || has_assertion) {
        return oauth_token_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "同一 token 请求不能同时使用多种客户端认证方式.",
            false,
        );
    }
    if has_assertion && form.client_secret.is_some() {
        return oauth_token_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "同一 token 请求不能同时使用多种客户端认证方式.",
            false,
        );
    }
    let mut credentials = extract_client_credentials(
        &req,
        &state.settings,
        form.client_id.as_deref(),
        form.client_secret.as_deref(),
        form.client_assertion_type.as_deref(),
        form.client_assertion.as_deref(),
    );
    if credentials.client_id.is_none()
        && credentials.method == "none"
        && form.client_secret.is_none()
        && !has_assertion
    {
        match mtls_client_credentials_without_client_id(&state, &req).await {
            Ok(Some(mtls_credentials)) => credentials = mtls_credentials,
            Ok(None) => {}
            Err(response) => return response,
        }
    }
    let Some(client_id) = credentials.client_id.as_deref() else {
        if !has_client_auth_material {
            if let Some(response) =
                client_credentials_holder_missing_client_error(&form, dpop_proof_present(&req))
            {
                return response;
            }
            if let Some(response) =
                missing_client_authorization_code_holder_error(&state, &form).await
            {
                return response;
            }
        }
        return oauth_token_error(
            StatusCode::UNAUTHORIZED,
            "invalid_client",
            "客户端认证失败.",
            has_basic,
        );
    };
    let client = match find_client(&state.diesel_db, client_id).await {
        Ok(Some(client)) => client,
        Ok(None) => {
            return oauth_token_error(
                StatusCode::UNAUTHORIZED,
                "invalid_client",
                "客户端不存在或已停用.",
                has_basic,
            );
        }
        Err(error) => {
            tracing::warn!(%error, "failed to query oauth client for token request");
            return oauth_token_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "客户端查询失败.",
                false,
            );
        }
    };
    if let Err(response) = validate_token_client_enabled(&client, &form.grant_type) {
        return response;
    }
    let mut client_assertion = None;
    if client.client_type == "confidential" {
        if credentials.method != client.token_endpoint_auth_method {
            return oauth_token_error(
                StatusCode::UNAUTHORIZED,
                "invalid_client",
                "客户端认证失败.",
                has_basic,
            );
        }
        match client.token_endpoint_auth_method.as_str() {
            "private_key_jwt" => {
                let assertion = credentials
                    .client_assertion
                    .as_deref()
                    .expect("private_key_jwt credentials must include an assertion");
                match verify_private_key_jwt_claims(&state, &req, &client, assertion) {
                    Ok(assertion) => client_assertion = Some(assertion),
                    Err(_) => {
                        return oauth_token_error(
                            StatusCode::UNAUTHORIZED,
                            "invalid_client",
                            "客户端认证失败.",
                            false,
                        );
                    }
                }
            }
            "client_secret_basic" | "client_secret_post" => {
                let secret = credentials
                    .client_secret
                    .as_deref()
                    .expect("secret-based client credentials must include client_secret");
                if !verify_password(
                    secret,
                    client.client_secret_argon2_hash.as_deref().unwrap_or(""),
                ) {
                    return oauth_token_error(
                        StatusCode::UNAUTHORIZED,
                        "invalid_client",
                        "客户端认证失败.",
                        has_basic,
                    );
                }
            }
            "tls_client_auth" | "self_signed_tls_client_auth" => {
                let certificate = request_mtls_client_certificate(&req, &state.settings)
                    .expect("mTLS client credentials must include a verified certificate");
                if !client_mtls_certificate_matches(&client, &certificate) {
                    return oauth_token_error(
                        StatusCode::UNAUTHORIZED,
                        "invalid_client",
                        "客户端认证失败.",
                        false,
                    );
                }
            }
            _ => {
                return oauth_token_error(
                    StatusCode::UNAUTHORIZED,
                    "invalid_client",
                    "客户端认证失败.",
                    has_basic,
                );
            }
        }
    } else if credentials.method != "none"
        || credentials.client_secret.is_some()
        || credentials.client_assertion.is_some()
    {
        return oauth_token_error(
            StatusCode::UNAUTHORIZED,
            "invalid_client",
            "public 客户端不能使用 client_secret.",
            has_basic,
        );
    }
    if let Err(response) =
        validate_token_request_profile(&state.settings, &client, credentials.method.as_str())
    {
        return response;
    }
    match form.grant_type.as_str() {
        "authorization_code" => {
            token_authorization_code(&state, &req, &client, &form, client_assertion.as_ref()).await
        }
        "refresh_token" => {
            token_refresh(&state, &req, &client, &form, client_assertion.as_ref()).await
        }
        "client_credentials" => {
            token_client_credentials(&state, &req, &client, &form, client_assertion.as_ref()).await
        }
        JWT_BEARER_GRANT_TYPE => {
            token_jwt_bearer(&state, &req, &client, &form, client_assertion.as_ref()).await
        }
        DEVICE_CODE_GRANT_TYPE => {
            token_device_code(&state, &req, &client, &form, client_assertion.as_ref()).await
        }
        CIBA_GRANT_TYPE => {
            token_ciba(&state, &req, &client, &form, client_assertion.as_ref()).await
        }
        TOKEN_EXCHANGE_GRANT_TYPE => {
            token_exchange(&state, &req, &client, &form, client_assertion.as_ref()).await
        }
        _ => oauth_token_error(
            StatusCode::BAD_REQUEST,
            "unsupported_grant_type",
            "不支持的 grant_type.",
            false,
        ),
    }
}

fn validate_token_client_enabled(client: &ClientRow, grant_type: &str) -> Result<(), HttpResponse> {
    if !client.is_active
        || !json_array_to_strings(&client.grant_types)
            .iter()
            .any(|grant| grant == grant_type)
    {
        return Err(oauth_token_error(
            StatusCode::BAD_REQUEST,
            "unauthorized_client",
            "该客户端未启用当前授权类型.",
            false,
        ));
    }
    Ok(())
}

pub(crate) fn validate_token_request_profile(
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
        return Err(oauth_token_error(
            StatusCode::BAD_REQUEST,
            "unauthorized_client",
            "FAPI2 profiles require confidential clients.",
            false,
        ));
    }
    if !matches!(
        auth_method,
        "private_key_jwt" | "tls_client_auth" | "self_signed_tls_client_auth"
    ) {
        return Err(oauth_token_error(
            StatusCode::UNAUTHORIZED,
            "invalid_client",
            "FAPI2 profiles require private_key_jwt or mTLS client authentication.",
            false,
        ));
    }
    if !(client.require_dpop_bound_tokens || client.require_mtls_bound_tokens) {
        return Err(oauth_token_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "FAPI2 profiles require sender-constrained access tokens.",
            false,
        ));
    }
    Ok(())
}

#[cfg(test)]
#[path = "../../../tests/in_source/src/http/token/tests/dispatch.rs"]
mod tests;
