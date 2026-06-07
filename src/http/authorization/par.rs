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
    params.remove("request");
    if pushed_authorization_request_contains_request_uri(&params) {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request_object",
            "PAR request object 不能包含 request_uri.",
        );
    }
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
    let mtls_x5t_s256 = if client.require_mtls_bound_tokens {
        request_mtls_thumbprint(&req, &state.settings)
    } else {
        None
    };

    let now = Utc::now();
    let request_token = random_urlsafe_token();
    let request_uri = format!("urn:ietf:params:oauth:request_uri:{request_token}");
    let payload = PushedAuthorizationRequest {
        client_id,
        params,
        dpop_jkt,
        mtls_x5t_s256,
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    use crate::settings::{
        AuthorizationServerProfile, DpopNoncePolicy, EmailDelivery, EmailSettings,
        RateLimitSettings, RequestObjectJtiPolicy, SubjectType,
    };
    use crate::support::{ClientIpHeaderMode, IpCidr};

    fn client(require_dpop_bound_tokens: bool) -> ClientRow {
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
            allowed_audiences: json!([]),
            grant_types: json!(["authorization_code"]),
            token_endpoint_auth_method: "private_key_jwt".to_owned(),
            require_dpop_bound_tokens,
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
    fn par_does_not_require_request_object_for_dpop_bound_clients() {
        let mut params = HashMap::new();
        params.insert(
            "redirect_uri".to_owned(),
            "https://client.example/callback".to_owned(),
        );

        assert!(validate_pushed_authorization_request(&client(true), &params).is_ok());
    }

    #[test]
    fn par_policy_requires_request_object_when_enabled() {
        let mut policy_client = client(true);
        policy_client.require_par_request_object = true;
        let settings = Settings {
            issuer: "https://issuer.example".to_owned(),
            mtls_endpoint_base_url: "https://issuer.example".to_owned(),
            frontend_base_url: "https://app.example".to_owned(),
            cors_allowed_origins: vec!["https://app.example".to_owned()],
            default_audience: "resource://default".to_owned(),
            authorization_server_profile: AuthorizationServerProfile::Oauth2Baseline,
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
            require_pushed_authorization_requests: false,
        };

        assert!(!pushed_authorization_request_requires_request_object(
            &settings,
            &client(true)
        ));
        assert!(pushed_authorization_request_requires_request_object(
            &settings,
            &policy_client
        ));
    }

    #[test]
    fn message_signing_profile_requires_request_object_at_par() {
        let settings = Settings {
            issuer: "https://issuer.example".to_owned(),
            mtls_endpoint_base_url: "https://issuer.example".to_owned(),
            frontend_base_url: "https://app.example".to_owned(),
            cors_allowed_origins: vec!["https://app.example".to_owned()],
            default_audience: "resource://default".to_owned(),
            authorization_server_profile:
                AuthorizationServerProfile::Fapi2MessageSigningAuthzRequest,
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
            require_pushed_authorization_requests: true,
        };

        assert!(pushed_authorization_request_requires_request_object(
            &settings,
            &client(true)
        ));
    }

    #[test]
    fn par_rejects_request_uri_after_request_object_expansion() {
        assert!(!pushed_authorization_request_contains_request_uri(
            &HashMap::new()
        ));

        let mut params = HashMap::new();
        params.insert(
            "request_uri".to_owned(),
            "urn:example:bwc4JK-ESC0w8acc191e-Y1LTC2".to_owned(),
        );
        assert!(pushed_authorization_request_contains_request_uri(&params));
    }

    #[test]
    fn par_rejects_explicit_unsupported_response_type() {
        assert!(!pushed_authorization_request_has_unsupported_response_type(
            &HashMap::new()
        ));

        let mut params = HashMap::new();
        params.insert("response_type".to_owned(), "code".to_owned());
        assert!(!pushed_authorization_request_has_unsupported_response_type(
            &params
        ));

        params.insert("response_type".to_owned(), "code id_token".to_owned());
        assert!(pushed_authorization_request_has_unsupported_response_type(
            &params
        ));
    }
}
