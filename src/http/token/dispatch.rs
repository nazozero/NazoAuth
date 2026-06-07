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
                let Some(certificate) = request_mtls_client_certificate(&req, &state.settings)
                else {
                    return oauth_token_error(
                        StatusCode::UNAUTHORIZED,
                        "invalid_client",
                        "客户端认证失败.",
                        false,
                    );
                };
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

fn validate_token_request_profile(
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
mod tests {
    use super::*;
    use std::path::PathBuf;

    use crate::settings::{
        AuthorizationServerProfile, DpopNoncePolicy, EmailDelivery, EmailSettings,
        RateLimitSettings, RequestObjectJtiPolicy, SubjectType,
    };
    use crate::support::{ClientIpHeaderMode, IpCidr};

    fn code_payload(dpop_jkt: Option<&str>) -> CodePayload {
        CodePayload {
            code_id: "code-id".to_owned(),
            user_id: Uuid::nil(),
            client_id: "client-1".to_owned(),
            redirect_uri: "https://client.example/callback".to_owned(),
            redirect_uri_was_supplied: true,
            scopes: vec!["openid".to_owned()],
            authorization_details: json!([]),
            nonce: None,
            auth_time: 1,
            amr: vec!["pwd".to_owned()],
            oidc_sid: Some("sid-1".to_owned()),
            acr: None,
            userinfo_claims: Vec::new(),
            userinfo_claim_requests: Vec::new(),
            id_token_claims: Vec::new(),
            id_token_claim_requests: Vec::new(),
            code_challenge: Some("challenge".to_owned()),
            code_challenge_method: Some("S256".to_owned()),
            dpop_jkt: dpop_jkt.map(ToOwned::to_owned),
            mtls_x5t_s256: None,
            issued_at: Utc::now(),
            expires_at: Utc::now() + Duration::minutes(5),
        }
    }

    fn settings(profile: AuthorizationServerProfile) -> Settings {
        Settings {
            issuer: "https://issuer.example".to_owned(),
            mtls_endpoint_base_url: "https://issuer.example".to_owned(),
            frontend_base_url: "https://app.example".to_owned(),
            cors_allowed_origins: vec!["https://app.example".to_owned()],
            default_audience: "resource://default".to_owned(),
            authorization_server_profile: profile,
            dpop_nonce_policy: DpopNoncePolicy::Required,
            request_object_jti_policy: RequestObjectJtiPolicy::Optional,
            session_cookie_name: "sid".to_owned(),
            csrf_cookie_name: "csrf".to_owned(),
            cookie_secure: true,
            session_ttl_seconds: 3600,
            auth_code_ttl_seconds: 60,
            access_token_ttl_seconds: 300,
            id_token_ttl_seconds: 600,
            refresh_token_ttl_seconds: 2_592_000,
            avatar_max_bytes: 2_097_152,
            client_delivery_ttl_seconds: 86_400,
            rate_limit: RateLimitSettings {
                window_seconds: 60,
                auth_max_requests: 30,
                token_max_requests: 60,
                token_management_max_requests: 120,
            },
            email: EmailSettings {
                delivery: EmailDelivery::Disabled,
                code_ttl_seconds: 900,
                send_cooldown_seconds: 60,
                send_peer_cooldown_seconds: 5,
            },
            email_code_dev_response_enabled: false,
            avatar_storage_dir: PathBuf::from("runtime/avatars"),
            jwk_keys_dir: PathBuf::from("runtime/keys"),
            signing_external_command: Vec::new(),
            signing_external_timeout_ms: 2_000,
            trusted_proxy_cidrs: Vec::<IpCidr>::new(),
            client_ip_header_mode: ClientIpHeaderMode::None,
            subject_type: SubjectType::Public,
            pairwise_subject_secret: None,
            par_ttl_seconds: 90,
            require_pushed_authorization_requests: profile.requires_fapi2_security(),
        }
    }

    fn client() -> ClientRow {
        ClientRow {
            id: Uuid::now_v7(),
            tenant_id: DEFAULT_TENANT_ID,
            realm_id: DEFAULT_REALM_ID,
            organization_id: DEFAULT_ORGANIZATION_ID,
            client_id: "client-a".to_owned(),
            client_name: "Client A".to_owned(),
            client_type: "confidential".to_owned(),
            client_secret_argon2_hash: None,
            redirect_uris: json!(["https://client.example/callback"]),
            scopes: json!(["openid"]),
            allowed_audiences: json!(["resource://default"]),
            grant_types: json!(["authorization_code"]),
            token_endpoint_auth_method: "private_key_jwt".to_owned(),
            require_dpop_bound_tokens: true,
            require_mtls_bound_tokens: false,
            tls_client_auth_subject_dn: None,
            tls_client_auth_cert_sha256: None,
            tls_client_auth_san_dns: json!([]),
            tls_client_auth_san_uri: json!([]),
            tls_client_auth_san_ip: json!([]),
            tls_client_auth_san_email: json!([]),
            allow_client_assertion_audience_array: false,
            allow_client_assertion_endpoint_audience: false,
            require_par_request_object: false,
            is_active: true,
            jwks: None,
            post_logout_redirect_uris: json!([]),
            backchannel_logout_uri: None,
            backchannel_logout_session_required: true,
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
            audiences: Vec::new(),
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
            audiences: Vec::new(),
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
            audiences: Vec::new(),
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
            audiences: Vec::new(),
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
            audiences: Vec::new(),
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

    #[test]
    fn baseline_profile_does_not_restrict_token_client_auth() {
        let mut client = client();
        client.token_endpoint_auth_method = "client_secret_basic".to_owned();
        client.require_dpop_bound_tokens = false;

        assert!(
            validate_token_request_profile(
                &settings(AuthorizationServerProfile::Oauth2Baseline),
                &client,
                "client_secret_basic",
            )
            .is_ok()
        );
    }

    #[test]
    fn disabled_client_is_rejected_before_grant_dispatch() {
        let mut client = client();
        client.is_active = false;

        let response = validate_token_client_enabled(&client, "authorization_code")
            .expect_err("disabled clients must not use token grants");

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(oauth_error_code(&response), "unauthorized_client");
    }

    #[test]
    fn missing_grant_registration_is_rejected_before_grant_dispatch() {
        let client = client();

        let response = validate_token_client_enabled(&client, "client_credentials")
            .expect_err("client must be registered for the requested grant");

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(oauth_error_code(&response), "unauthorized_client");
    }

    #[test]
    fn fapi2_profile_requires_confidential_client_auth_and_sender_constraint() {
        let fapi = settings(AuthorizationServerProfile::Fapi2Security);
        let valid_client = client();

        assert!(validate_token_request_profile(&fapi, &valid_client, "private_key_jwt").is_ok());

        let weak_auth = validate_token_request_profile(&fapi, &valid_client, "client_secret_basic")
            .expect_err("client_secret_basic is not a FAPI2 client auth method");
        assert_eq!(weak_auth.status(), StatusCode::UNAUTHORIZED);

        let mut bearer_client = client();
        bearer_client.require_dpop_bound_tokens = false;
        let bearer = validate_token_request_profile(&fapi, &bearer_client, "private_key_jwt")
            .expect_err("FAPI2 requires sender-constrained tokens");
        assert_eq!(bearer.status(), StatusCode::BAD_REQUEST);

        let mut public_client = client();
        public_client.client_type = "public".to_owned();
        let public = validate_token_request_profile(&fapi, &public_client, "none")
            .expect_err("FAPI2 rejects public clients");
        assert_eq!(public.status(), StatusCode::BAD_REQUEST);
    }
}
