use crate::http::{Request, Response};
use http::{StatusCode, header};
use std::fmt::Write as _;

use crate::http::html::JsString;

use nazo_oauth_server::contracts::session_management::{
    SessionManagementError, SessionManagementOperations,
};

use std::sync::Arc;

use nazo_auth::{OidcSessionStatus, check_oidc_session_state};
use serde::Deserialize;
use serde_json::json;

use crate::http::{cookie_value, empty_response, json_response_no_store};

#[derive(Clone)]
pub struct SessionManagementConfig {
    issuer: Box<str>,
    session_cookie_name: Box<str>,
}

impl SessionManagementConfig {
    #[must_use]
    pub fn new(issuer: impl Into<Box<str>>, session_cookie_name: impl Into<Box<str>>) -> Self {
        Self {
            issuer: issuer.into(),
            session_cookie_name: session_cookie_name.into(),
        }
    }
}

#[derive(Clone)]
pub struct SessionManagementEndpoint {
    operations: Arc<dyn SessionManagementOperations>,
    config: SessionManagementConfig,
}

impl SessionManagementEndpoint {
    #[must_use]
    pub fn new(
        operations: Arc<dyn SessionManagementOperations>,
        config: SessionManagementConfig,
    ) -> Self {
        Self { operations, config }
    }
}

pub async fn check_session_iframe(endpoint: &SessionManagementEndpoint) -> Response {
    let Some(_lease) = endpoint.operations.acquire_request() else {
        return empty_response(StatusCode::NOT_FOUND);
    };
    let status_endpoint = format!("{}/check_session/status", endpoint.config.issuer);
    crate::http::finish(
        http::Response::builder()
            .status(http::StatusCode::OK)
            .header(header::CACHE_CONTROL, "no-store")
            .header(header::PRAGMA, "no-cache")
            .header(http::header::CONTENT_TYPE, "text/html; charset=utf-8"),
        session_management_iframe_document(&status_endpoint),
    )
}

#[derive(Deserialize)]
pub struct CheckSessionStatusQuery {
    client_id: String,
    origin: String,
    session_state: String,
}

pub async fn check_session_status(
    endpoint: &SessionManagementEndpoint,
    request: &Request,
    query: CheckSessionStatusQuery,
) -> Response {
    let Some(_lease) = endpoint.operations.acquire_request() else {
        return empty_response(StatusCode::NOT_FOUND);
    };

    // Preserve the protocol distinction between malformed state and a missing
    // OP session without performing a storage lookup for malformed input.
    if check_oidc_session_state(&query.client_id, &query.origin, &query.session_state, None)
        == OidcSessionStatus::Error
    {
        return status_response(OidcSessionStatus::Error);
    }

    match endpoint
        .operations
        .is_origin_allowed(&query.client_id, &query.origin)
        .await
    {
        Ok(true) => {}
        Ok(false) | Err(SessionManagementError::SessionLookupUnavailable) => {
            return status_response(OidcSessionStatus::Error);
        }
    }

    let Some(session_id) = cookie_value(request, &endpoint.config.session_cookie_name) else {
        return status_response(OidcSessionStatus::Changed);
    };
    let op_browser_state = match endpoint.operations.op_browser_state(&session_id).await {
        Ok(state) => state,
        Err(SessionManagementError::SessionLookupUnavailable) => {
            return status_response(OidcSessionStatus::Error);
        }
    };
    status_response(check_oidc_session_state(
        &query.client_id,
        &query.origin,
        &query.session_state,
        op_browser_state.as_deref(),
    ))
}

fn status_response(status: OidcSessionStatus) -> Response {
    let status = match status {
        OidcSessionStatus::Unchanged => "unchanged",
        OidcSessionStatus::Changed => "changed",
        OidcSessionStatus::Error => "error",
    };
    json_response_no_store(json!({ "status": status }))
}

fn session_management_iframe_document(status_endpoint: &str) -> String {
    let head = include_str!("session_management_iframe.head.html").trim_end_matches(['\r', '\n']);
    let tail = include_str!("session_management_iframe.tail.html");
    let mut document = String::with_capacity(head.len() + status_endpoint.len() + tail.len());
    document.push_str(head);
    write!(document, "{}", JsString(status_endpoint)).expect("String formatting is infallible");
    document.push_str(tail);
    document
}

#[cfg(test)]
#[path = "../../tests/unit/http/session_management.rs"]
mod tests;
