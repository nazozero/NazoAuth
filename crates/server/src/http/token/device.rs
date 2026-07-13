//! RFC 8628 Device Authorization Grant.
use crate::domain::{AppState, ClientRow, RefreshTokenPolicy, TokenIssue};
use crate::settings::Settings;
use crate::support::{
    ClientCredentials, DEFAULT_TENANT_ID, DpopError, DpopErrorContext, RateLimitPolicy,
    ValidatedClientAssertion, audit_event, audit_fields, blake3_hex, client_ip,
    client_supports_grant, compute_subject_for_client, current_user_or_login_required,
    dpop_error_response, enforce_rate_limit, extract_client_credentials, has_valid_csrf_token,
    json_array_to_strings, parse_resource_indicators, parse_scope, random_urlsafe_token,
    request_mtls_thumbprint, validate_dpop_proof,
};
#[cfg(test)]
use crate::support::{DEFAULT_ORGANIZATION_ID, DEFAULT_REALM_ID};
use actix_web::http::StatusCode;
use actix_web::http::header;
use actix_web::http::header::HeaderValue;
use actix_web::web::{Bytes, Data, Form, Query};
use actix_web::{HttpRequest, HttpResponse};
#[cfg(test)]
use chrono::Duration;
use chrono::Utc;
#[cfg(test)]
use nazo_http_actix::OAuthJsonErrorFields;
use nazo_http_actix::{cookie_value, csrf_error};
use nazo_http_actix::{json_response_no_store, oauth_error, oauth_token_error};
use serde::Deserialize;
use serde::Serialize;
use serde_json::json;
use std::collections::HashMap;
use uuid::Uuid;

use super::{
    TokenForm, consume_token_client_assertion, consume_token_management_client_assertion,
    issue_token_response, token_management_auth_error, verify_confidential_client,
};
use nazo_auth::{
    DeviceAuthorizationApproval, DeviceAuthorizationPayload, DeviceAuthorizationRequestError,
    DeviceAuthorizationRequestPolicy, DeviceDecisionFailure, DeviceGrantRepositoryPort,
    DeviceGrantService, DevicePollCommit, DevicePollFailure,
};
use nazo_valkey::DeviceStore;

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
    let valkey = state.valkey_connection();
    let device_service = DeviceGrantService::new(DeviceStore::new(&valkey));
    let (device_code, user_code) = match device_service
        .create_unique(
            &payload,
            state.settings.device.device_authorization_ttl_seconds,
            random_urlsafe_token,
            random_device_user_code,
        )
        .await
    {
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
        "expires_in": state.settings.device.device_authorization_ttl_seconds,
        "interval": state.settings.device.device_authorization_poll_interval_seconds
    }))
}

pub(crate) fn device_authorization_request_payload(
    settings: &Settings,
    client: &ClientRow,
    form: &DeviceAuthorizationForm,
    enabled: bool,
) -> Result<DeviceAuthorizationPayload, DeviceAuthorizationRequestError> {
    let requested_scopes = parse_scope(form.scope.as_deref().unwrap_or(""));
    let allowed_scopes = json_array_to_strings(&client.scopes);
    let allowed_resources = json_array_to_strings(&client.allowed_audiences);
    nazo_auth::device_authorization_request_payload(DeviceAuthorizationRequestPolicy {
        enabled,
        client_active: client.is_active,
        client_supports_grant: client_supports_grant(client, DEVICE_CODE_GRANT_TYPE),
        client_id: &client.client_id,
        client_name: &client.client_name,
        requested_scopes,
        allowed_scopes: &allowed_scopes,
        requested_resources: form.resources.clone(),
        allowed_resources: &allowed_resources,
        default_resource: &settings.protocol.default_audience,
        interval_seconds: settings.device.device_authorization_poll_interval_seconds,
        ttl_seconds: settings.device.device_authorization_ttl_seconds,
        now: Utc::now(),
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

    let valkey = state.valkey_connection();
    let device_service = DeviceGrantService::new(DeviceStore::new(&valkey));
    match device_service
        .poll(device_code, &client.client_id, Utc::now)
        .await
    {
        Ok(DevicePollCommit::AuthorizationPending) => oauth_token_error(
            StatusCode::BAD_REQUEST,
            "authorization_pending",
            "授权仍在等待用户确认.",
            false,
        ),
        Ok(DevicePollCommit::SlowDown) => {
            oauth_token_error(StatusCode::BAD_REQUEST, "slow_down", "设备轮询过快.", false)
        }
        Ok(DevicePollCommit::AccessDenied) => oauth_token_error(
            StatusCode::BAD_REQUEST,
            "access_denied",
            "用户拒绝设备授权.",
            false,
        ),
        Ok(DevicePollCommit::Expired) => oauth_token_error(
            StatusCode::BAD_REQUEST,
            "expired_token",
            "device_code 已过期.",
            false,
        ),
        Ok(DevicePollCommit::Consumed) => oauth_token_error(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "device_code 已使用.",
            false,
        ),
        Ok(DevicePollCommit::Approved { payload, approval }) => {
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
        Err(DevicePollFailure::Missing) => oauth_token_error(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "device_code 无效或已过期.",
            false,
        ),
        Err(DevicePollFailure::ClientMismatch) => oauth_token_error(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "device_code 未签发给该客户端.",
            false,
        ),
        Err(DevicePollFailure::Storage(error)) => {
            tracing::warn!(%error, "failed to update device authorization state");
            oauth_token_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "设备授权状态读取失败.",
                false,
            )
        }
        Err(DevicePollFailure::Contended) => oauth_token_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "设备授权状态正忙.",
            false,
        ),
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
    let normalized_user_code = normalize_user_code(&user_code);
    let payload = if normalized_user_code.is_empty() {
        None
    } else {
        let valkey = state.valkey_connection();
        match DeviceGrantService::new(DeviceStore::new(&valkey))
            .pending_request_for_user_code(&normalized_user_code, Utc::now)
            .await
        {
            Ok(payload) => payload,
            Err(error) => {
                tracing::warn!(%error, "failed to read device authorization request");
                None
            }
        }
    };
    let csrf_token = cookie_value(&req, &state.settings.session.csrf_cookie_name);
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
        settings.endpoint.frontend_base_url.trim_end_matches('/')
    )
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
    let valkey = state.valkey_connection();
    let device_service = DeviceGrantService::new(DeviceStore::new(&valkey));
    let payload = match device_service
        .pending_request_for_user_code(&normalized_user_code, Utc::now)
        .await
    {
        Ok(Some(payload)) => payload,
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
    let result = match form.decision.as_str() {
        "deny" => device_service.deny(&normalized_user_code, Utc::now).await,
        "approve" => {
            let repository = nazo_postgres::AuthorizationFlowRepository::new(
                state.diesel_db.clone(),
                DEFAULT_TENANT_ID,
            );
            let client = match repository.client_by_id(&payload.client_id).await {
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
            device_service
                .approve(
                    &normalized_user_code,
                    DeviceAuthorizationApproval {
                        user_id: user.id(),
                        subject,
                        auth_time: Utc::now().timestamp(),
                        amr: vec!["pwd".to_owned()],
                        oidc_sid: None,
                    },
                    &client,
                    &repository,
                    Utc::now,
                )
                .await
        }
        _ => return oauth_error(StatusCode::BAD_REQUEST, "invalid_request", "授权决策无效."),
    };
    match result {
        Ok(()) => HttpResponse::Ok().finish(),
        Err(
            DeviceDecisionFailure::Missing
            | DeviceDecisionFailure::AlreadyHandled
            | DeviceDecisionFailure::Expired,
        ) => oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "用户码无效或已过期.",
        ),
        Err(DeviceDecisionFailure::Storage(error)) => {
            tracing::warn!(%error, "failed to persist device authorization decision");
            oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "设备授权状态写入失败.",
            )
        }
        Err(DeviceDecisionFailure::Repository(error)) => {
            tracing::warn!(%error, "failed to persist device authorization grant");
            oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "授权记录写入失败.",
            )
        }
        Err(DeviceDecisionFailure::Contended) => oauth_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "设备授权状态正忙.",
        ),
    }
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

fn device_authorization_subject(
    settings: &Settings,
    user_id: Uuid,
    client: &nazo_auth::OAuthClient,
) -> anyhow::Result<String> {
    let redirect_uri = client
        .redirect_uris
        .iter()
        .next()
        .cloned()
        .unwrap_or_else(|| settings.endpoint.issuer.clone());
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
