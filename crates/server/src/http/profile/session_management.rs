//! OpenID Connect Session Management support.

use crate::http::prelude::*;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use sha2::{Digest, Sha256};

pub(crate) fn oidc_session_state(
    client_id: &str,
    client_origin: &str,
    op_browser_state: &str,
    salt: &str,
) -> String {
    let input = format!("{client_id} {client_origin} {op_browser_state} {salt}");
    let digest = Sha256::digest(input.as_bytes());
    format!("{}.{}", URL_SAFE_NO_PAD.encode(digest), salt)
}

pub(crate) fn issue_oidc_session_state(
    client_id: &str,
    redirect_uri: &str,
    op_browser_state: &str,
) -> Option<String> {
    let origin = redirect_uri_origin(redirect_uri)?;
    Some(oidc_session_state(
        client_id,
        &origin,
        op_browser_state,
        &random_urlsafe_token(),
    ))
}

fn redirect_uri_origin(redirect_uri: &str) -> Option<String> {
    let url = url::Url::parse(redirect_uri).ok()?;
    let host = url.host_str()?;
    let mut origin = format!("{}://{}", url.scheme(), host);
    if let Some(port) = url.port() {
        origin.push(':');
        origin.push_str(&port.to_string());
    }
    Some(origin)
}

fn session_management_iframe_document(status_endpoint: &str) -> String {
    let head = include_str!("session_management_iframe.head.html").trim_end_matches(['\r', '\n']);
    format!(
        "{}{}{}{}",
        head,
        escape_js_string(status_endpoint),
        include_str!("session_management_iframe.tail.html"),
        ""
    )
}

fn escape_js_string(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('\'', "\\'")
        .replace('<', "\\u003c")
        .replace('>', "\\u003e")
        .replace('&', "\\u0026")
}

pub(crate) async fn check_session_iframe(state: Data<AppState>) -> HttpResponse {
    if !state.permits_existing_module_transaction(nazo_runtime_modules::ModuleId::SessionManagement)
    {
        return empty_response(StatusCode::NOT_FOUND);
    }
    let status_endpoint = format!("{}/check_session/status", state.settings.issuer);
    HttpResponse::Ok()
        .insert_header((header::CACHE_CONTROL, "no-store"))
        .insert_header((header::PRAGMA, "no-cache"))
        .content_type("text/html; charset=utf-8")
        .body(session_management_iframe_document(&status_endpoint))
}

#[derive(Deserialize)]
pub(crate) struct CheckSessionStatusQuery {
    client_id: String,
    origin: String,
    session_state: String,
}

pub(crate) async fn check_session_status(
    state: Data<AppState>,
    req: HttpRequest,
    Query(query): Query<CheckSessionStatusQuery>,
) -> HttpResponse {
    if !state.permits_existing_module_transaction(nazo_runtime_modules::ModuleId::SessionManagement)
    {
        return empty_response(StatusCode::NOT_FOUND);
    }
    let Some((_, salt)) = query.session_state.rsplit_once('.') else {
        return json_response_no_store(json!({"status": "error"}));
    };
    let status = match current_session(&state, &req).await {
        Ok(Some(session)) => {
            let expected =
                oidc_session_state(&query.client_id, &query.origin, &session.oidc_sid, salt);
            if constant_time_eq(expected.as_bytes(), query.session_state.as_bytes()) {
                "unchanged"
            } else {
                "changed"
            }
        }
        Ok(None) => "changed",
        Err(error) => {
            tracing::warn!(%error, "failed to resolve session management status");
            "error"
        }
    };
    json_response_no_store(json!({ "status": status }))
}

#[cfg(test)]
#[path = "../../../tests/in_source/src/http/profile/tests/session_management.rs"]
mod tests;
