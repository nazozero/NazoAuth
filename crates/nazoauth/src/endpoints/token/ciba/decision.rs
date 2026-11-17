//! CIBA cookie, CSRF and HTTP presentation boundary.
use crate::http::Request as HttpRequest;
use crate::http::Response as HttpResponse;

use crate::endpoints::sessions::AdminSessionHandles;
use http::StatusCode;
use http::header;

use crate::http::{
    ClientIpConfig, client_ip_with_config, cookie_value, csrf_error, empty_response,
    has_valid_csrf_token_for_cookies, json_response_no_store, oauth_endpoint_error_response,
};
use nazo_auth::CapabilityAdmission;
use nazo_oauth_server::{
    contracts::ciba::CibaAuthorizationRequestView, token::ciba::CibaApplication,
};
use serde::{Deserialize, Serialize};
use serde_json::json;

#[derive(Deserialize)]
pub struct CibaDecisionRequest {
    pub decision: String,
    pub csrf_token: Option<String>,
}
#[derive(Serialize)]
pub struct CibaVerificationView {
    pub auth_req_id: String,
    pub csrf_token: Option<String>,
    pub request: Option<CibaAuthorizationRequestView>,
}

pub async fn ciba_verification_page(application: &CibaApplication, path: String) -> HttpResponse {
    let Some(_lease) = application.acquire_request(CapabilityAdmission::ExistingTransaction) else {
        return empty_response(StatusCode::NOT_FOUND);
    };
    crate::http::finish(
        http::Response::builder()
            .status(StatusCode::FOUND)
            .header(
                header::LOCATION,
                application.verification_page_location(&path),
            )
            .header(header::CACHE_CONTROL, "no-store")
            .header(header::PRAGMA, "no-cache"),
        bytes::Bytes::new(),
    )
}
pub async fn ciba_verification(
    application: &CibaApplication,
    sessions: &AdminSessionHandles,
    req: &HttpRequest,
    path: String,
) -> HttpResponse {
    let Some(_lease) = application.acquire_request(CapabilityAdmission::ExistingTransaction) else {
        return empty_response(StatusCode::NOT_FOUND);
    };
    let session = match sessions.current_session_or_login_required(req).await {
        Ok(s) => s,
        Err(response) => return response,
    };
    let auth_req_id = path;
    match application.verification(&auth_req_id, &session).await {
        Ok(request) => json_response_no_store(CibaVerificationView {
            auth_req_id,
            csrf_token: cookie_value(req, sessions.http_config().csrf_cookie_name()),
            request,
        }),
        Err(error) => oauth_endpoint_error_response(error),
    }
}
pub async fn ciba_decision(
    application: &CibaApplication,
    sessions: &AdminSessionHandles,
    client_ip: &ClientIpConfig,
    req: &HttpRequest,
    path: String,
    payload: CibaDecisionRequest,
) -> HttpResponse {
    let Some(_lease) = application.acquire_request(CapabilityAdmission::ExistingTransaction) else {
        return empty_response(StatusCode::NOT_FOUND);
    };
    let session_http = sessions.http_config();
    if !has_valid_csrf_token_for_cookies(
        req,
        payload.csrf_token.as_deref(),
        session_http.session_cookie_name(),
        session_http.csrf_cookie_name(),
    ) {
        return csrf_error();
    }
    let session = match sessions.current_session_or_login_required(req).await {
        Ok(s) => s,
        Err(response) => return response,
    };
    match application
        .decide(
            path,
            &payload.decision,
            &session,
            &client_ip_with_config(req, client_ip),
        )
        .await
    {
        Ok(()) => json_response_no_store(json!({"success":true})),
        Err(error) => oauth_endpoint_error_response(error),
    }
}
