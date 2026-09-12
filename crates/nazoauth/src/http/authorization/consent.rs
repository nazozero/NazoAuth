//! Authorization consent HTTP projection and cookie extraction.

use actix_web::web::{Data, Query};
use actix_web::{HttpRequest, HttpResponse};
use nazo_auth::ConsentPayload;
use nazo_http_actix::{cookie_value, json_response, oauth_endpoint_error_response};
use nazo_identity::SessionId;
use nazo_oauth_server::authorization::AuthorizationApplication;
use serde_json::json;
use std::collections::HashMap;

use crate::http::authorization::AuthorizationEndpoint;
use crate::http::sessions::SessionHttpConfig;

fn consent_page_response(payload: ConsentPayload, csrf_token: Option<String>) -> HttpResponse {
    json_response(json!({
        "request_id": payload.request_id,
        "client_id": payload.client_id,
        "client_name": payload.client_name,
        "redirect_uri": payload.redirect_uri,
        "scopes": payload.scopes,
        "userinfo_claims": payload.userinfo_claims,
        "id_token_claims": payload.id_token_claims,
        "authorization_details": payload.authorization_details,
        "csrf_token": csrf_token
    }))
}

pub(crate) async fn authorize_consent(
    endpoint: Data<AuthorizationEndpoint>,
    req: HttpRequest,
    Query(q): Query<HashMap<String, String>>,
) -> HttpResponse {
    authorize_consent_with_context(
        endpoint.application.as_ref(),
        &endpoint.session_http,
        req,
        q,
    )
    .await
}

async fn authorize_consent_with_context(
    application: &AuthorizationApplication,
    session_http: &SessionHttpConfig,
    req: HttpRequest,
    q: HashMap<String, String>,
) -> HttpResponse {
    let session_id = cookie_value(&req, session_http.session_cookie_name()).map(SessionId::new);
    let request_id = q.get("request_id").map(String::as_str);
    match application.consent(session_id.as_ref(), request_id).await {
        Ok(payload) => {
            consent_page_response(payload, cookie_value(&req, session_http.csrf_cookie_name()))
        }
        Err(error) => oauth_endpoint_error_response(error),
    }
}

#[cfg(test)]
#[path = "../../../tests/unit/http/authorization/consent.rs"]
mod tests;
