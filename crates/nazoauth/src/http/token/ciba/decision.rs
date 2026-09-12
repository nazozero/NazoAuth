//! CIBA cookie, CSRF and HTTP presentation boundary.
use crate::http::sessions::AdminSessionHandles;
use actix_web::{
    HttpRequest, HttpResponse,
    http::{
        StatusCode,
        header::{self, HeaderValue},
    },
    web::{Data, Json, Path},
};
use nazo_auth::CapabilityAdmission;
use nazo_http_actix::{
    ClientIpConfig, client_ip_with_config, cookie_value, csrf_error, empty_response,
    has_valid_csrf_token_for_cookies, json_response_no_store, oauth_endpoint_error_response,
};
use nazo_oauth_server::{
    contracts::ciba::CibaAuthorizationRequestView, token::ciba::CibaApplication,
};
use serde::{Deserialize, Serialize};
use serde_json::json;

#[derive(Deserialize)]
pub(crate) struct CibaDecisionRequest {
    pub decision: String,
    pub csrf_token: Option<String>,
}
#[derive(Serialize)]
struct CibaVerificationView {
    auth_req_id: String,
    csrf_token: Option<String>,
    request: Option<CibaAuthorizationRequestView>,
}

pub(crate) async fn ciba_verification_page(
    application: Data<CibaApplication>,
    path: Path<String>,
) -> HttpResponse {
    if !application.check_admission(CapabilityAdmission::ExistingTransaction) {
        return empty_response(StatusCode::NOT_FOUND);
    }
    HttpResponse::Found()
        .insert_header((
            header::LOCATION,
            application.verification_page_location(&path.into_inner()),
        ))
        .insert_header((header::CACHE_CONTROL, HeaderValue::from_static("no-store")))
        .insert_header((header::PRAGMA, HeaderValue::from_static("no-cache")))
        .finish()
}
pub(crate) async fn ciba_verification(
    application: Data<CibaApplication>,
    sessions: Data<AdminSessionHandles>,
    req: HttpRequest,
    path: Path<String>,
) -> HttpResponse {
    if !application.check_admission(CapabilityAdmission::ExistingTransaction) {
        return empty_response(StatusCode::NOT_FOUND);
    }
    let session = match sessions.current_session_or_login_required(&req).await {
        Ok(s) => s,
        Err(response) => return response,
    };
    let auth_req_id = path.into_inner();
    match application.verification(&auth_req_id, &session).await {
        Ok(request) => json_response_no_store(CibaVerificationView {
            auth_req_id,
            csrf_token: cookie_value(&req, sessions.http_config().csrf_cookie_name()),
            request,
        }),
        Err(error) => oauth_endpoint_error_response(error),
    }
}
pub(crate) async fn ciba_decision(
    application: Data<CibaApplication>,
    sessions: Data<AdminSessionHandles>,
    client_ip: Data<ClientIpConfig>,
    req: HttpRequest,
    path: Path<String>,
    Json(payload): Json<CibaDecisionRequest>,
) -> HttpResponse {
    if !application.check_admission(CapabilityAdmission::ExistingTransaction) {
        return empty_response(StatusCode::NOT_FOUND);
    }
    let session_http = sessions.http_config();
    if !has_valid_csrf_token_for_cookies(
        &req,
        payload.csrf_token.as_deref(),
        session_http.session_cookie_name(),
        session_http.csrf_cookie_name(),
    ) {
        return csrf_error();
    }
    let session = match sessions.current_session_or_login_required(&req).await {
        Ok(s) => s,
        Err(response) => return response,
    };
    match application
        .decide(
            path.into_inner(),
            &payload.decision,
            &session,
            &client_ip_with_config(&req, &client_ip),
        )
        .await
    {
        Ok(()) => json_response_no_store(json!({"success":true})),
        Err(error) => oauth_endpoint_error_response(error),
    }
}
