//! /token grant_type 分发入口。
// 只负责客户端认证与 grant_type 分派，不直接签发令牌。
use super::{
    TokenForm, TokenFormError, parse_token_form, token_authorization_code,
    token_client_credentials, token_refresh,
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
    let Some(thumbprint) = request_mtls_thumbprint(req) else {
        return Ok(None);
    };
    match find_active_mtls_client_by_thumbprint(&state.diesel_db, &thumbprint).await {
        Ok(Some(client)) => Ok(Some(mtls_client_credentials(client.client_id))),
        Ok(None) => Ok(None),
        Err(error) => {
            tracing::warn!(%error, "failed to query mTLS client by certificate thumbprint");
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
        Err(TokenFormError::MissingGrantType) => {
            return oauth_token_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "缺少 grant_type.",
                false,
            );
        }
    };
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
        req.headers(),
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
    if !client.is_active || !json_array_to_strings(&client.grant_types).contains(&form.grant_type) {
        return oauth_token_error(
            StatusCode::BAD_REQUEST,
            "unauthorized_client",
            "该客户端未启用当前授权类型.",
            false,
        );
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
                let Some(assertion) = credentials.client_assertion.as_deref() else {
                    return oauth_token_error(
                        StatusCode::UNAUTHORIZED,
                        "invalid_client",
                        "客户端认证失败.",
                        false,
                    );
                };
                match verify_private_key_jwt_claims(&state, &req, &client, assertion) {
                    Ok(assertion) => client_assertion = Some(assertion),
                    Err(error) => {
                        let store_unavailable =
                            matches!(error, ClientAssertionError::StoreUnavailable);
                        let status = if store_unavailable {
                            StatusCode::SERVICE_UNAVAILABLE
                        } else {
                            StatusCode::UNAUTHORIZED
                        };
                        let oauth_error_code = if store_unavailable {
                            "server_error"
                        } else {
                            "invalid_client"
                        };
                        return oauth_token_error(
                            status,
                            oauth_error_code,
                            "客户端认证失败.",
                            false,
                        );
                    }
                }
            }
            "client_secret_basic" | "client_secret_post" => {
                let Some(secret) = credentials.client_secret.as_deref() else {
                    return oauth_token_error(
                        StatusCode::UNAUTHORIZED,
                        "invalid_client",
                        "机密客户端必须提供 client_secret.",
                        has_basic,
                    );
                };
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
                let Some(thumbprint) = request_mtls_thumbprint(&req) else {
                    return oauth_token_error(
                        StatusCode::UNAUTHORIZED,
                        "invalid_client",
                        "客户端认证失败.",
                        false,
                    );
                };
                if !client_mtls_thumbprint_matches(&client, &thumbprint) {
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
        _ => oauth_token_error(
            StatusCode::BAD_REQUEST,
            "unsupported_grant_type",
            "不支持的 grant_type.",
            false,
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn code_payload(dpop_jkt: Option<&str>) -> CodePayload {
        CodePayload {
            code_id: "code-id".to_owned(),
            user_id: Uuid::nil(),
            client_id: "client-1".to_owned(),
            redirect_uri: "https://client.example/callback".to_owned(),
            redirect_uri_was_supplied: true,
            scopes: vec!["openid".to_owned()],
            nonce: None,
            auth_time: 1,
            amr: vec!["pwd".to_owned()],
            acr: None,
            userinfo_claims: Vec::new(),
            id_token_claims: Vec::new(),
            code_challenge: Some("challenge".to_owned()),
            code_challenge_method: Some("S256".to_owned()),
            dpop_jkt: dpop_jkt.map(ToOwned::to_owned),
            mtls_x5t_s256: None,
            issued_at: Utc::now(),
            expires_at: Utc::now() + Duration::minutes(5),
        }
    }

    #[test]
    fn pending_authorization_code_detects_dpop_binding() {
        let raw = serde_json::to_string(&AuthorizationCodeState::Pending {
            payload: code_payload(Some("thumbprint")),
        })
        .expect("pending code should serialize");

        assert!(
            pending_authorization_code_payload(&raw)
                .expect("state should parse")
                .is_some_and(|payload| payload.dpop_jkt.is_some())
        );
    }

    #[test]
    fn non_dpop_or_non_pending_authorization_code_is_not_holder_bound() {
        let pending = serde_json::to_string(&AuthorizationCodeState::Pending {
            payload: code_payload(None),
        })
        .expect("pending code should serialize");
        let failed = serde_json::to_string(&AuthorizationCodeState::Failed {
            failed_at: Utc::now(),
            error: "invalid_grant".to_owned(),
        })
        .expect("failed code should serialize");

        assert!(
            pending_authorization_code_payload(&pending)
                .expect("state should parse")
                .is_some_and(|payload| payload.dpop_jkt.is_none())
        );
        assert!(
            pending_authorization_code_payload(&failed)
                .expect("state should parse")
                .is_none()
        );
    }

    fn oauth_error_code(response: &HttpResponse) -> String {
        response
            .extensions()
            .get::<OAuthJsonErrorFields>()
            .map(|fields| fields.error.clone())
            .expect("OAuth error response should record its error code")
    }

    #[test]
    fn missing_client_dpop_authorization_code_holder_uses_invalid_grant() {
        let response = authorization_code_holder_missing_client_error(true, false)
            .expect("dpop holder binding should return an error");

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(oauth_error_code(&response), "invalid_grant");
    }

    #[test]
    fn missing_client_mtls_authorization_code_holder_uses_invalid_request() {
        for (dpop_bound, mtls_bound) in [(false, true), (true, true)] {
            let response = authorization_code_holder_missing_client_error(dpop_bound, mtls_bound)
                .expect("mtls holder binding should return an error");

            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
            assert_eq!(oauth_error_code(&response), "invalid_request");
        }
    }

    #[test]
    fn missing_client_client_credentials_without_dpop_uses_invalid_request() {
        let form = TokenForm {
            grant_type: "client_credentials".to_owned(),
            code: None,
            redirect_uri: None,
            code_verifier: None,
            refresh_token: None,
            scope: Some("accounts".to_owned()),
            client_id: None,
            client_secret: None,
            client_assertion_type: None,
            client_assertion: None,
            audience: None,
        };
        let response = client_credentials_holder_missing_client_error(&form, false)
            .expect("missing DPoP proof should be reported before generic client auth");

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(oauth_error_code(&response), "invalid_request");
    }

    #[test]
    fn missing_client_client_credentials_with_dpop_stays_client_auth_failure() {
        let form = TokenForm {
            grant_type: "client_credentials".to_owned(),
            code: None,
            redirect_uri: None,
            code_verifier: None,
            refresh_token: None,
            scope: Some("accounts".to_owned()),
            client_id: None,
            client_secret: None,
            client_assertion_type: None,
            client_assertion: None,
            audience: None,
        };

        assert!(client_credentials_holder_missing_client_error(&form, true).is_none());
    }

    #[test]
    fn missing_client_mtls_client_credentials_uses_invalid_request() {
        let form = TokenForm {
            grant_type: "client_credentials".to_owned(),
            code: None,
            redirect_uri: None,
            code_verifier: None,
            refresh_token: None,
            scope: Some("accounts".to_owned()),
            client_id: None,
            client_secret: None,
            client_assertion_type: None,
            client_assertion: None,
            audience: None,
        };

        let response = client_credentials_holder_missing_client_error(&form, false)
            .expect("missing holder-of-key proof should be reported before generic client auth");

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(oauth_error_code(&response), "invalid_request");
    }

    #[test]
    fn token_request_auth_material_detects_assertion_even_without_client_id() {
        let form = TokenForm {
            grant_type: "authorization_code".to_owned(),
            code: Some("code".to_owned()),
            redirect_uri: None,
            code_verifier: None,
            refresh_token: None,
            scope: None,
            client_id: None,
            client_secret: None,
            client_assertion_type: None,
            client_assertion: Some("malformed-or-missing-sub".to_owned()),
            audience: None,
        };

        assert!(token_request_has_client_auth_material(false, &form));
    }

    #[test]
    fn token_request_auth_material_allows_absent_client_credentials() {
        let form = TokenForm {
            grant_type: "authorization_code".to_owned(),
            code: Some("code".to_owned()),
            redirect_uri: None,
            code_verifier: None,
            refresh_token: None,
            scope: None,
            client_id: None,
            client_secret: None,
            client_assertion_type: None,
            client_assertion: None,
            audience: None,
        };

        assert!(!token_request_has_client_auth_material(false, &form));
    }

    #[test]
    fn mtls_client_credentials_uses_tls_auth_method() {
        let credentials = mtls_client_credentials("client-1".to_owned());

        assert_eq!(credentials.client_id.as_deref(), Some("client-1"));
        assert_eq!(credentials.method, "tls_client_auth");
        assert!(credentials.client_secret.is_none());
        assert!(credentials.client_assertion.is_none());
    }
}
