//! RFC 8628 HTTP parsing, security facts, and presentation.
use crate::http::Request as HttpRequest;
use crate::http::Response as HttpResponse;
use bytes::Bytes;

use super::{client_auth_request_facts, device_config::DeviceHttpConfig};
use crate::endpoints::security::{extract_client_credentials, has_basic_authorization_scheme};
use crate::endpoints::sessions::SessionProfileHandles;
use http::StatusCode;
use http::header;

use crate::http::{
    client_ip_with_context, cookie_value, csrf_error, json_response_no_store,
    oauth_endpoint_error_response, oauth_error,
};
use nazo_auth::{CapabilityAdmission, DeviceAuthorizationPayload};
use nazo_oauth_server::domain::client_policy::parse_resource_indicators;
use nazo_oauth_server::{
    contracts::device::{DeviceAuthorizationForm, prepare_device_authorization},
    token::device::DeviceDecisionHandles,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
#[derive(Debug, PartialEq, Eq)]
pub enum DeviceAuthorizationFormError {
    InvalidContentType,
    InvalidEncoding,
    DuplicateParameter,
    InvalidResourceParameter,
}

#[derive(Deserialize)]
pub struct DeviceDecisionForm {
    pub user_code: String,
    pub decision: String,
    pub csrf_token: Option<String>,
}

#[derive(Serialize)]
pub struct DeviceVerificationView {
    pub user_code: String,
    pub csrf_token: Option<String>,
    pub request: Option<DeviceAuthorizationPayload>,
}

pub fn parse_device_authorization_form(
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
        match key.as_ref() {
            "resource" => {
                resources.push(value.into_owned());
            }
            "client_id" => {
                accept_device_authorization_parameter_once(&mut seen, "client_id")?;
                form.client_id = non_empty(value.into_owned());
            }
            "scope" => {
                accept_device_authorization_parameter_once(&mut seen, "scope")?;
                form.scope = non_empty(value.into_owned());
            }
            "client_secret" => {
                accept_device_authorization_parameter_once(&mut seen, "client_secret")?;
                form.client_secret = non_empty(value.into_owned());
            }
            "client_assertion_type" => {
                accept_device_authorization_parameter_once(&mut seen, "client_assertion_type")?;
                form.client_assertion_type = non_empty(value.into_owned());
            }
            "client_assertion" => {
                accept_device_authorization_parameter_once(&mut seen, "client_assertion")?;
                form.client_assertion = non_empty(value.into_owned());
            }
            _ => {}
        }
    }
    form.resources = parse_resource_indicators(resources)
        .map_err(|_| DeviceAuthorizationFormError::InvalidResourceParameter)?;
    Ok(form)
}

pub async fn device_authorization(
    handles: &DeviceDecisionHandles,
    config: &DeviceHttpConfig,
    req: &HttpRequest,
    body: &Bytes,
) -> HttpResponse {
    let _lease = match handles.acquire_request(CapabilityAdmission::NewRequest) {
        Ok(lease) => lease,
        Err(error) => return oauth_endpoint_error_response(error),
    };
    let source_ip = client_ip_with_context(
        req,
        config.client_ip_header_mode,
        &config.trusted_proxy_cidrs,
    );
    if let Err(error) = handles.enforce_creation_rate_limit(&source_ip).await {
        return oauth_endpoint_error_response(error);
    }
    let form = match parse_device_authorization_form(req, body) {
        Ok(form) => form,
        Err(error) => return device_authorization_form_error(error),
    };
    let prepared =
        match prepare_device_authorization(form, has_basic_authorization_scheme(req.headers())) {
            Ok(prepared) => prepared,
            Err(error) => return oauth_endpoint_error_response(error),
        };
    let form = prepared.form();
    let credentials = extract_client_credentials(
        req,
        form.client_id.as_deref(),
        form.client_secret.as_deref(),
        form.client_assertion_type.as_deref(),
        form.client_assertion.as_deref(),
    );
    let auth_request = client_auth_request_facts(req);
    match handles
        .create(prepared, credentials, auth_request, &source_ip)
        .await
    {
        Ok(response) => json_response_no_store(response),
        Err(error) => oauth_endpoint_error_response(error),
    }
}
pub async fn device_verification_page(
    handles: &DeviceDecisionHandles,
    config: &DeviceHttpConfig,
    query: HashMap<String, String>,
) -> HttpResponse {
    let _lease = match handles.acquire_request(CapabilityAdmission::ExistingTransaction) {
        Ok(lease) => lease,
        Err(error) => return oauth_endpoint_error_response(error),
    };
    redirect_to_device_verification_ui(
        config,
        query
            .get("user_code")
            .map(String::as_str)
            .unwrap_or_default(),
    )
}
pub async fn device_verification(
    handles: &DeviceDecisionHandles,
    sessions: &SessionProfileHandles,
    req: &HttpRequest,
    query: HashMap<String, String>,
) -> HttpResponse {
    let _lease = match handles.acquire_request(CapabilityAdmission::ExistingTransaction) {
        Ok(lease) => lease,
        Err(error) => return oauth_endpoint_error_response(error),
    };
    let data = handles
        .verification(
            query
                .get("user_code")
                .map(String::as_str)
                .unwrap_or_default(),
        )
        .await;
    json_response_no_store(DeviceVerificationView {
        user_code: data.user_code,
        request: data.request,
        csrf_token: cookie_value(req, sessions.http_config().csrf_cookie_name()),
    })
}
pub async fn device_decision(
    handles: &DeviceDecisionHandles,
    sessions: &SessionProfileHandles,
    config: &DeviceHttpConfig,
    req: &HttpRequest,
    form: DeviceDecisionForm,
) -> HttpResponse {
    let _lease = match handles.acquire_request(CapabilityAdmission::ExistingTransaction) {
        Ok(lease) => lease,
        Err(error) => return oauth_endpoint_error_response(error),
    };
    if !sessions.has_valid_csrf_token(req, form.csrf_token.as_deref()) {
        return csrf_error();
    }
    let session = match sessions.current_session_or_login_required(req).await {
        Ok(session) => session,
        Err(response) => return response,
    };
    let source_ip = client_ip_with_context(
        req,
        config.client_ip_header_mode,
        &config.trusted_proxy_cidrs,
    );
    match handles
        .decide(&form.user_code, &form.decision, session, &source_ip)
        .await
    {
        Ok(()) => crate::http::empty_response(StatusCode::OK),
        Err(error) => oauth_endpoint_error_response(error),
    }
}
pub fn redirect_to_device_verification_ui(
    config: &DeviceHttpConfig,
    user_code: &str,
) -> HttpResponse {
    let mut location = device_verification_uri(config);
    if !user_code.trim().is_empty() {
        location.push_str("?user_code=");
        urlencoding::Encoded(user_code).append_to(&mut location);
    }
    crate::http::finish(
        http::Response::builder()
            .status(StatusCode::FOUND)
            .header(header::LOCATION, location)
            .header(header::CACHE_CONTROL, "no-store")
            .header(header::PRAGMA, "no-cache"),
        bytes::Bytes::new(),
    )
}

pub fn device_verification_uri(config: &DeviceHttpConfig) -> String {
    format!("{}/device", config.frontend_base_url.trim_end_matches('/'))
}

pub fn device_authorization_form_error(error: DeviceAuthorizationFormError) -> HttpResponse {
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

pub fn accept_device_authorization_parameter_once(
    seen: &mut std::collections::HashSet<&'static str>,
    key: &'static str,
) -> Result<(), DeviceAuthorizationFormError> {
    if seen.insert(key) {
        Ok(())
    } else {
        Err(DeviceAuthorizationFormError::DuplicateParameter)
    }
}

pub fn non_empty(value: String) -> Option<String> {
    (!value.is_empty()).then_some(value)
}
