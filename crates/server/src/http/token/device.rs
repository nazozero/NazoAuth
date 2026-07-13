//! RFC 8628 Device Authorization Grant.
use serde::Serialize;

use super::{
    TokenForm, consume_token_client_assertion, consume_token_management_client_assertion,
    issue_token_response, token_management_auth_error, verify_confidential_client,
};
use crate::http::prelude::*;
use nazo_auth::{
    DeviceAuthorizationApproval, DeviceAuthorizationPayload, DeviceAuthorizationState,
};

pub(crate) const DEVICE_CODE_GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:device_code";

pub(crate) struct DeviceAuthorizationForm {
    pub(crate) client_id: Option<String>,
    pub(crate) scope: Option<String>,
    pub(crate) resources: Vec<String>,
    pub(crate) client_secret: Option<String>,
    pub(crate) client_assertion_type: Option<String>,
    pub(crate) client_assertion: Option<String>,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum DeviceAuthorizationFormError {
    InvalidContentType,
    InvalidEncoding,
    DuplicateParameter,
    InvalidResourceParameter,
}

#[derive(Deserialize)]
pub(crate) struct DeviceDecisionForm {
    user_code: String,
    decision: String,
    csrf_token: Option<String>,
}

#[derive(Serialize)]
pub(crate) struct DeviceVerificationView {
    user_code: String,
    csrf_token: Option<String>,
    request: Option<DeviceAuthorizationPayload>,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum DeviceAuthorizationRequestError {
    Disabled,
    UnauthorizedClient,
    InvalidScope,
    InvalidTarget,
}

#[derive(Debug, PartialEq)]
pub(crate) enum DeviceCodePollResult {
    AuthorizationPending {
        next_state: DeviceAuthorizationState,
    },
    SlowDown {
        next_state: DeviceAuthorizationState,
    },
    Approved {
        payload: DeviceAuthorizationPayload,
        approval: DeviceAuthorizationApproval,
    },
    AccessDenied,
    Expired,
    Consumed,
}

pub(crate) fn parse_device_authorization_form(
    req: &HttpRequest,
    body: &Bytes,
) -> Result<DeviceAuthorizationForm, DeviceAuthorizationFormError> {
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
        return Err(DeviceAuthorizationFormError::InvalidContentType);
    }
    let raw =
        std::str::from_utf8(body).map_err(|_| DeviceAuthorizationFormError::InvalidEncoding)?;
    let mut seen = std::collections::HashSet::new();
    let mut resources = Vec::new();
    let mut form = DeviceAuthorizationForm {
        client_id: None,
        scope: None,
        resources: Vec::new(),
        client_secret: None,
        client_assertion_type: None,
        client_assertion: None,
    };

    for (key, value) in url::form_urlencoded::parse(raw.as_bytes()) {
        let key = key.into_owned();
        let value = value.into_owned();
        match key.as_str() {
            "resource" => {
                resources.push(value);
            }
            "client_id" => {
                accept_device_authorization_parameter_once(&mut seen, key)?;
                form.client_id = non_empty(value);
            }
            "scope" => {
                accept_device_authorization_parameter_once(&mut seen, key)?;
                form.scope = non_empty(value);
            }
            "client_secret" => {
                accept_device_authorization_parameter_once(&mut seen, key)?;
                form.client_secret = non_empty(value);
            }
            "client_assertion_type" => {
                accept_device_authorization_parameter_once(&mut seen, key)?;
                form.client_assertion_type = non_empty(value);
            }
            "client_assertion" => {
                accept_device_authorization_parameter_once(&mut seen, key)?;
                form.client_assertion = non_empty(value);
            }
            _ => {}
        }
    }
    form.resources = parse_resource_indicators(&resources)
        .map_err(|_| DeviceAuthorizationFormError::InvalidResourceParameter)?;
    Ok(form)
}

pub(crate) async fn device_authorization(
    state: Data<AppState>,
    req: HttpRequest,
    body: Bytes,
) -> HttpResponse {
    if !state.accepts_module(nazo_runtime_modules::ModuleId::DeviceAuthorization) {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Device Authorization Grant is not enabled.",
        );
    }
    if let Err(response) = enforce_rate_limit(&state, &req, RateLimitPolicy::TokenManagement).await
    {
        return response;
    }
    let form = match parse_device_authorization_form(&req, &body) {
        Ok(form) => form,
        Err(error) => return device_authorization_form_error(error),
    };
    let Some(client_id) = form.client_id.as_deref() else {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "缺少 client_id.",
        );
    };
    let client = match nazo_postgres::OAuthClientRepository::new(state.diesel_db.clone())
        .by_client_id(DEFAULT_TENANT_ID, client_id)
        .await
    {
        Ok(Some(client)) if client.is_active => client,
        Ok(_) => {
            return oauth_error(
                StatusCode::UNAUTHORIZED,
                "invalid_client",
                "客户端认证失败.",
            );
        }
        Err(error) => {
            tracing::warn!(%error, "failed to query device authorization client");
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
        Some(client_id),
        form.client_secret.as_deref(),
        form.client_assertion_type.as_deref(),
        form.client_assertion.as_deref(),
    );
    if let Err(response) =
        authenticate_device_authorization_client(&state, &req, &client, &credentials).await
    {
        return response;
    }
    let payload = match device_authorization_request_payload(
        &state.settings,
        &client,
        &form,
        state.accepts_module(nazo_runtime_modules::ModuleId::DeviceAuthorization),
    ) {
        Ok(payload) => payload,
        Err(error) => return device_authorization_request_error(error),
    };
    let (device_code, user_code) = match persist_new_device_authorization(&state, &payload).await {
        Ok(codes) => codes,
        Err(error) => {
            tracing::warn!(%error, "failed to persist device authorization state");
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "设备授权状态写入失败.",
            );
        }
    };
    audit_event(
        "device_authorization_started",
        audit_fields(&[
            ("client_id", json!(client.client_id)),
            ("scope", json!(payload.scopes.join(" "))),
            ("audience", json!(payload.resource_indicators)),
            (
                "source_ip_hash",
                json!(blake3_hex(&client_ip(&req, &state.settings))),
            ),
        ]),
    );
    let verification_uri = device_verification_uri(&state.settings);
    json_response_no_store(json!({
        "device_code": device_code,
        "user_code": user_code,
        "verification_uri": verification_uri,
        "verification_uri_complete": format!("{verification_uri}?user_code={}", urlencoding::encode(&user_code)),
        "expires_in": state.settings.device_authorization_ttl_seconds,
        "interval": state.settings.device_authorization_poll_interval_seconds
    }))
}

pub(crate) fn device_authorization_request_payload(
    settings: &Settings,
    client: &ClientRow,
    form: &DeviceAuthorizationForm,
    enabled: bool,
) -> Result<DeviceAuthorizationPayload, DeviceAuthorizationRequestError> {
    if !enabled {
        return Err(DeviceAuthorizationRequestError::Disabled);
    }
    if !client.is_active || !client_supports_grant(client, DEVICE_CODE_GRANT_TYPE) {
        return Err(DeviceAuthorizationRequestError::UnauthorizedClient);
    }
    let requested_scopes = parse_scope(form.scope.as_deref().unwrap_or(""));
    if !is_subset(&requested_scopes, &json_array_to_strings(&client.scopes)) {
        return Err(DeviceAuthorizationRequestError::InvalidScope);
    }
    let resource_indicators = if form.resources.is_empty() {
        vec![settings.default_audience.clone()]
    } else {
        form.resources.clone()
    };
    if !audiences_allowed(client, &resource_indicators) {
        return Err(DeviceAuthorizationRequestError::InvalidTarget);
    }
    let now = Utc::now();
    Ok(DeviceAuthorizationPayload {
        client_id: client.client_id.clone(),
        client_name: client.client_name.clone(),
        scopes: requested_scopes,
        resource_indicators,
        authorization_details: json!([]),
        interval_seconds: settings.device_authorization_poll_interval_seconds,
        issued_at: now,
        expires_at: now + Duration::seconds(settings.device_authorization_ttl_seconds as i64),
    })
}

pub(crate) async fn token_device_code(
    state: &AppState,
    req: &HttpRequest,
    client: &ClientRow,
    form: &TokenForm,
    client_assertion: Option<&ValidatedClientAssertion>,
) -> HttpResponse {
    if !state
        .permits_existing_module_transaction(nazo_runtime_modules::ModuleId::DeviceAuthorization)
    {
        return oauth_token_error(
            StatusCode::BAD_REQUEST,
            "unsupported_grant_type",
            "Device Authorization Grant is not enabled.",
            false,
        );
    }
    let Some(device_code) = form.device_code.as_deref() else {
        return oauth_token_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "缺少 device_code.",
            false,
        );
    };
    let dpop_jkt = match validate_dpop_proof(state, req, None, None).await {
        Ok(value) => value,
        Err(error) => return dpop_error_response(error, DpopErrorContext::TokenEndpoint),
    };
    if client.require_dpop_bound_tokens && dpop_jkt.is_none() {
        return dpop_error_response(DpopError::MissingProof, DpopErrorContext::TokenEndpoint);
    }
    let mtls_x5t_s256 = if client.require_mtls_bound_tokens {
        match request_mtls_thumbprint(req, &state.settings) {
            Some(value) => Some(value),
            None => {
                return oauth_token_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_grant",
                    "device_code requires mTLS sender constraint.",
                    false,
                );
            }
        }
    } else {
        None
    };
    if let Err(response) = consume_token_client_assertion(state, client, client_assertion).await {
        return response;
    }

    let store = nazo_valkey::DeviceStore::new(&state.valkey_connection());
    let state_value = match store.load_by_device_code(device_code).await {
        Ok(Some(value)) => value,
        Ok(None) => {
            return oauth_token_error(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "device_code 无效或已过期.",
                false,
            );
        }
        Err(error) => {
            tracing::warn!(%error, "failed to read device authorization state");
            return oauth_token_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "设备授权状态读取失败.",
                false,
            );
        }
    };
    match evaluate_device_code_poll(&state_value, Utc::now()) {
        DeviceCodePollResult::AuthorizationPending { next_state } => {
            persist_device_poll_state(state, &blake3_hex(device_code), &next_state).await;
            oauth_token_error(
                StatusCode::BAD_REQUEST,
                "authorization_pending",
                "授权仍在等待用户确认.",
                false,
            )
        }
        DeviceCodePollResult::SlowDown { next_state } => {
            persist_device_poll_state(state, &blake3_hex(device_code), &next_state).await;
            oauth_token_error(StatusCode::BAD_REQUEST, "slow_down", "设备轮询过快.", false)
        }
        DeviceCodePollResult::AccessDenied => oauth_token_error(
            StatusCode::BAD_REQUEST,
            "access_denied",
            "用户拒绝设备授权.",
            false,
        ),
        DeviceCodePollResult::Expired => oauth_token_error(
            StatusCode::BAD_REQUEST,
            "expired_token",
            "device_code 已过期.",
            false,
        ),
        DeviceCodePollResult::Consumed => oauth_token_error(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "device_code 已使用.",
            false,
        ),
        DeviceCodePollResult::Approved { .. } => {
            let consumed = match store.take_by_device_code(device_code).await {
                Ok(Some(value)) => value,
                Ok(None) => {
                    return oauth_token_error(
                        StatusCode::BAD_REQUEST,
                        "invalid_grant",
                        "device_code 已使用.",
                        false,
                    );
                }
                Err(error) => {
                    tracing::warn!(%error, "failed to consume approved device authorization state");
                    return oauth_token_error(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "server_error",
                        "设备授权状态读取失败.",
                        false,
                    );
                }
            };
            let DeviceAuthorizationState::Approved {
                payload, approval, ..
            } = consumed
            else {
                return oauth_token_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_grant",
                    "device_code 状态无效.",
                    false,
                );
            };
            issue_token_response(
                state,
                client,
                TokenIssue {
                    user_id: Some(approval.user_id),
                    subject: approval.subject,
                    scopes: payload.scopes,
                    authorization_details: payload.authorization_details,
                    audiences: payload.resource_indicators,
                    nonce: None,
                    auth_time: Some(approval.auth_time),
                    amr: approval.amr,
                    oidc_sid: approval.oidc_sid,
                    acr: None,
                    userinfo_claims: Vec::new(),
                    userinfo_claim_requests: Vec::new(),
                    id_token_claims: Vec::new(),
                    id_token_claim_requests: Vec::new(),
                    include_refresh: true,
                    refresh_token_policy: RefreshTokenPolicy::IssueNew,
                    refresh_token_dpop_jkt: dpop_jkt.clone(),
                    dpop_jkt,
                    mtls_x5t_s256: mtls_x5t_s256.clone(),
                    refresh_token_mtls_x5t_s256: mtls_x5t_s256,
                    authorization_code_hash: None,
                    actor: None,
                    issued_token_type: None,
                    native_sso: None,
                },
            )
            .await
        }
    }
}

pub(crate) fn evaluate_device_code_poll(
    state: &DeviceAuthorizationState,
    now: DateTime<Utc>,
) -> DeviceCodePollResult {
    if let Some(payload) = device_authorization_payload(state)
        && now >= payload.expires_at
    {
        return DeviceCodePollResult::Expired;
    }
    match state {
        DeviceAuthorizationState::Pending {
            payload,
            last_poll_at,
            slow_down_count,
        } => {
            let required_wait =
                Duration::seconds(payload.interval_seconds as i64 + (*slow_down_count as i64 * 5));
            if last_poll_at.is_some_and(|last| now - last < required_wait) {
                return DeviceCodePollResult::SlowDown {
                    next_state: DeviceAuthorizationState::Pending {
                        payload: payload.clone(),
                        last_poll_at: Some(now),
                        slow_down_count: slow_down_count.saturating_add(1),
                    },
                };
            }
            DeviceCodePollResult::AuthorizationPending {
                next_state: DeviceAuthorizationState::Pending {
                    payload: payload.clone(),
                    last_poll_at: Some(now),
                    slow_down_count: *slow_down_count,
                },
            }
        }
        DeviceAuthorizationState::Approved {
            payload, approval, ..
        } => DeviceCodePollResult::Approved {
            payload: payload.clone(),
            approval: approval.clone(),
        },
        DeviceAuthorizationState::Denied { .. } => DeviceCodePollResult::AccessDenied,
        DeviceAuthorizationState::Consumed { .. } => DeviceCodePollResult::Consumed,
    }
}

fn device_authorization_payload(
    state: &DeviceAuthorizationState,
) -> Option<&DeviceAuthorizationPayload> {
    match state {
        DeviceAuthorizationState::Pending { payload, .. }
        | DeviceAuthorizationState::Approved { payload, .. }
        | DeviceAuthorizationState::Denied { payload, .. } => Some(payload),
        DeviceAuthorizationState::Consumed { .. } => None,
    }
}

pub(crate) async fn device_verification_page(
    state: Data<AppState>,
    Query(query): Query<HashMap<String, String>>,
) -> HttpResponse {
    if !state
        .permits_existing_module_transaction(nazo_runtime_modules::ModuleId::DeviceAuthorization)
    {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Device Authorization Grant is not enabled.",
        );
    }
    let user_code = query.get("user_code").cloned().unwrap_or_default();
    redirect_to_device_verification_ui(&state.settings, &user_code)
}

pub(crate) async fn device_verification(
    state: Data<AppState>,
    req: HttpRequest,
    Query(query): Query<HashMap<String, String>>,
) -> HttpResponse {
    if !state
        .permits_existing_module_transaction(nazo_runtime_modules::ModuleId::DeviceAuthorization)
    {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Device Authorization Grant is not enabled.",
        );
    }
    let user_code = query.get("user_code").cloned().unwrap_or_default();
    let payload = read_device_authorization_payload_for_user_code(&state, &user_code).await;
    let csrf_token = cookie_value(&req, &state.settings.csrf_cookie_name);
    json_response_no_store(DeviceVerificationView {
        user_code,
        csrf_token,
        request: payload,
    })
}

fn redirect_to_device_verification_ui(settings: &Settings, user_code: &str) -> HttpResponse {
    let mut location = device_verification_uri(settings);
    if !user_code.trim().is_empty() {
        location.push_str("?user_code=");
        location.push_str(&urlencoding::encode(user_code));
    }
    HttpResponse::Found()
        .insert_header((header::LOCATION, location))
        .insert_header((header::CACHE_CONTROL, HeaderValue::from_static("no-store")))
        .insert_header((header::PRAGMA, HeaderValue::from_static("no-cache")))
        .finish()
}

fn device_verification_uri(settings: &Settings) -> String {
    format!(
        "{}/device",
        settings.frontend_base_url.trim_end_matches('/')
    )
}

async fn read_device_authorization_payload_for_user_code(
    state: &AppState,
    user_code: &str,
) -> Option<DeviceAuthorizationPayload> {
    let normalized_user_code = normalize_user_code(user_code);
    if normalized_user_code.is_empty() {
        return None;
    }
    let device_code_hash = read_user_code_mapping(state, &normalized_user_code).await?;
    let store = nazo_valkey::DeviceStore::new(&state.valkey_connection());
    let state_value = match store.load_by_device_hash(&device_code_hash).await {
        Ok(Some(value)) => value,
        Ok(None) => return None,
        Err(error) => {
            tracing::warn!(%error, "failed to read device authorization state for verification page");
            return None;
        }
    };
    let DeviceAuthorizationState::Pending { payload, .. } = state_value else {
        return None;
    };
    if Utc::now() >= payload.expires_at {
        let _ = store.delete_user_code(&normalized_user_code).await;
        return None;
    }
    Some(payload)
}

pub(crate) async fn device_decision(
    state: Data<AppState>,
    req: HttpRequest,
    Form(form): Form<DeviceDecisionForm>,
) -> HttpResponse {
    if !state
        .permits_existing_module_transaction(nazo_runtime_modules::ModuleId::DeviceAuthorization)
    {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Device Authorization Grant is not enabled.",
        );
    }
    if !has_valid_csrf_token(&state, &req, form.csrf_token.as_deref()) {
        return csrf_error();
    }
    let user = match current_user_or_login_required(&state, &req).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    let normalized_user_code = normalize_user_code(&form.user_code);
    if normalized_user_code.is_empty() {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "用户码无效或已过期.",
        );
    }
    let Some(device_code_hash) = read_user_code_mapping(&state, &normalized_user_code).await else {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "用户码无效或已过期.",
        );
    };
    let store = nazo_valkey::DeviceStore::new(&state.valkey_connection());
    let device_state = match store.load_by_device_hash(&device_code_hash).await {
        Ok(Some(value)) => value,
        Ok(None) => {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "用户码无效或已过期.",
            );
        }
        Err(error) => {
            tracing::warn!(%error, "failed to read device authorization state for user decision");
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "设备授权状态读取失败.",
            );
        }
    };
    let DeviceAuthorizationState::Pending { payload, .. } = device_state else {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "用户码无效或已过期.",
        );
    };
    let now = Utc::now();
    if now >= payload.expires_at {
        let _ = store.delete_user_code(&normalized_user_code).await;
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "用户码无效或已过期.",
        );
    }
    let next_state = match form.decision.as_str() {
        "deny" => DeviceAuthorizationState::Denied {
            payload: payload.clone(),
            denied_at: now,
        },
        "approve" => {
            let client = match nazo_postgres::OAuthClientRepository::new(state.diesel_db.clone())
                .by_client_id(DEFAULT_TENANT_ID, &payload.client_id)
                .await
            {
                Ok(Some(client)) if client.is_active => client,
                Ok(_) => {
                    return oauth_error(
                        StatusCode::BAD_REQUEST,
                        "invalid_request",
                        "用户码无效或已过期.",
                    );
                }
                Err(error) => {
                    tracing::warn!(%error, "failed to load device authorization client for approval");
                    return oauth_error(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "server_error",
                        "客户端查询失败.",
                    );
                }
            };
            let subject = match device_authorization_subject(&state.settings, user.id(), &client) {
                Ok(subject) => subject,
                Err(error) => {
                    tracing::warn!(%error, "failed to compute device authorization subject");
                    return oauth_error(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "server_error",
                        "授权主体计算失败.",
                    );
                }
            };
            if let Err(error) = nazo_postgres::GrantRepository::new(state.diesel_db.clone())
                .upsert(
                    client.tenant_id,
                    user.id(),
                    client.id,
                    &payload.scopes,
                    &payload.resource_indicators,
                    &payload.authorization_details,
                )
                .await
            {
                tracing::warn!(%error, "failed to persist device authorization grant");
                return oauth_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "server_error",
                    "授权记录写入失败.",
                );
            }
            DeviceAuthorizationState::Approved {
                payload: payload.clone(),
                approval: DeviceAuthorizationApproval {
                    user_id: user.id(),
                    subject,
                    auth_time: now.timestamp(),
                    amr: vec!["pwd".to_owned()],
                    oidc_sid: None,
                },
                approved_at: now,
            }
        }
        _ => return oauth_error(StatusCode::BAD_REQUEST, "invalid_request", "授权决策无效."),
    };
    if let Err(error) = persist_device_state(&state, &device_code_hash, &next_state).await {
        tracing::warn!(%error, "failed to persist device authorization decision");
        return oauth_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "设备授权状态写入失败.",
        );
    }
    let _ = store.delete_user_code(&normalized_user_code).await;
    HttpResponse::Ok().finish()
}

async fn authenticate_device_authorization_client(
    state: &AppState,
    req: &HttpRequest,
    client: &ClientRow,
    credentials: &ClientCredentials,
) -> Result<(), HttpResponse> {
    if client.client_type == "public" {
        if credentials.method == "none"
            && credentials.client_secret.is_none()
            && credentials.client_assertion.is_none()
        {
            return Ok(());
        }
        return Err(oauth_error(
            StatusCode::UNAUTHORIZED,
            "invalid_client",
            "客户端认证失败.",
        ));
    }
    let assertion = verify_confidential_client(state, req, client, credentials)
        .await
        .map_err(token_management_auth_error)?;
    consume_token_management_client_assertion(state, client, assertion.as_ref())
        .await
        .map_err(token_management_auth_error)
}

fn device_authorization_form_error(error: DeviceAuthorizationFormError) -> HttpResponse {
    match error {
        DeviceAuthorizationFormError::InvalidContentType => oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "device authorization 请求必须使用 application/x-www-form-urlencoded.",
        ),
        DeviceAuthorizationFormError::InvalidEncoding => oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "表单必须使用 UTF-8.",
        ),
        DeviceAuthorizationFormError::DuplicateParameter => oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "OAuth 参数不能重复.",
        ),
        DeviceAuthorizationFormError::InvalidResourceParameter => oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_target",
            "resource must be an absolute URI without a fragment.",
        ),
    }
}

fn device_authorization_request_error(error: DeviceAuthorizationRequestError) -> HttpResponse {
    match error {
        DeviceAuthorizationRequestError::Disabled => oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Device Authorization Grant is not enabled.",
        ),
        DeviceAuthorizationRequestError::UnauthorizedClient => oauth_error(
            StatusCode::BAD_REQUEST,
            "unauthorized_client",
            "该客户端未启用 device_code 授权类型.",
        ),
        DeviceAuthorizationRequestError::InvalidScope => oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_scope",
            "请求的作用域超出客户端允许范围.",
        ),
        DeviceAuthorizationRequestError::InvalidTarget => oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_target",
            "请求的 audience 不在客户端允许范围内.",
        ),
    }
}

async fn persist_new_device_authorization(
    state: &AppState,
    payload: &DeviceAuthorizationPayload,
) -> anyhow::Result<(String, String)> {
    for _ in 0..5 {
        let device_code = random_urlsafe_token();
        let user_code = random_device_user_code();
        let pending = DeviceAuthorizationState::Pending {
            payload: payload.clone(),
            last_poll_at: None,
            slow_down_count: 0,
        };
        match nazo_valkey::DeviceStore::new(&state.valkey_connection())
            .create(
                &device_code,
                &user_code,
                &pending,
                state.settings.device_authorization_ttl_seconds,
            )
            .await?
        {
            nazo_valkey::DeviceCreateResult::Applied => return Ok((device_code, user_code)),
            nazo_valkey::DeviceCreateResult::DeviceCodeCollision
            | nazo_valkey::DeviceCreateResult::UserCodeCollision => continue,
        }
    }
    anyhow::bail!("failed to allocate unique device user code")
}

async fn persist_device_poll_state(
    state: &AppState,
    key: &str,
    next_state: &DeviceAuthorizationState,
) {
    if let Err(error) = persist_device_state(state, key, next_state).await {
        tracing::warn!(%error, "failed to update device authorization poll state");
    }
}

async fn persist_device_state(
    state: &AppState,
    key: &str,
    next_state: &DeviceAuthorizationState,
) -> anyhow::Result<()> {
    let ttl = device_state_ttl_seconds(next_state, Utc::now()).unwrap_or(1);
    nazo_valkey::DeviceStore::new(&state.valkey_connection())
        .store_device_hash(key, next_state, ttl)
        .await?;
    Ok(())
}

fn device_state_ttl_seconds(state: &DeviceAuthorizationState, now: DateTime<Utc>) -> Option<u64> {
    let payload = device_authorization_payload(state)?;
    Some((payload.expires_at - now).num_seconds().max(1) as u64)
}

async fn read_user_code_mapping(state: &AppState, user_code: &str) -> Option<String> {
    match nazo_valkey::DeviceStore::new(&state.valkey_connection())
        .resolve_user_code(user_code)
        .await
    {
        Ok(value) => value,
        Err(error) => {
            tracing::warn!(%error, "failed to read device authorization user code mapping");
            None
        }
    }
}

fn device_authorization_subject(
    settings: &Settings,
    user_id: Uuid,
    client: &ClientRow,
) -> anyhow::Result<String> {
    let redirect_uri = json_array_to_strings(&client.redirect_uris)
        .into_iter()
        .next()
        .unwrap_or_else(|| settings.issuer.clone());
    compute_subject_for_client(
        settings,
        user_id,
        client.subject_type.as_str(),
        client.sector_identifier_host.as_deref(),
        &redirect_uri,
    )
}

fn normalize_user_code(value: &str) -> String {
    value
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .flat_map(char::to_uppercase)
        .collect()
}

fn random_device_user_code() -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    let mut out = String::with_capacity(9);
    let bytes = rand::random::<[u8; 8]>();
    for (idx, byte) in bytes.into_iter().enumerate() {
        if idx == 4 {
            out.push('-');
        }
        out.push(ALPHABET[(byte as usize) % ALPHABET.len()] as char);
    }
    out
}

fn accept_device_authorization_parameter_once(
    seen: &mut std::collections::HashSet<String>,
    key: String,
) -> Result<(), DeviceAuthorizationFormError> {
    if seen.insert(key) {
        Ok(())
    } else {
        Err(DeviceAuthorizationFormError::DuplicateParameter)
    }
}

fn non_empty(value: String) -> Option<String> {
    (!value.is_empty()).then_some(value)
}

#[cfg(test)]
#[path = "../../../tests/in_source/src/http/token/tests/device.rs"]
mod tests;
