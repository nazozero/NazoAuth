//! Authorize HTTP parsing, request facts, and response presentation.
use super::super::AuthorizationEndpoint;
use super::form::{parse_authorization_post_form, parse_authorization_query};
use crate::http::Request as HttpRequest;
use crate::http::Response as HttpResponse;
use bytes::Bytes;
use http::header;

use crate::http::{
    client_ip_with_config, cookie_value, form_post_authorization_response,
    oauth_endpoint_error_response, redirect_found,
};
use nazo_identity::SessionId;
use nazo_oauth_server::authorization::AuthorizationApplication;
use nazo_oauth_server::authorization::{AuthorizationOutcome, AuthorizationRequestFacts};
use std::collections::HashMap;

pub async fn authorize_get(endpoint: &AuthorizationEndpoint, req: &HttpRequest) -> HttpResponse {
    let mut parameters = match parse_authorization_query(
        req.uri().query().unwrap_or(""),
        AuthorizationApplication::duplicate_parameters(),
    ) {
        Ok(parameters) => parameters,
        Err(response) => return response,
    };
    authorize(endpoint, req, &mut parameters).await
}

pub async fn authorize_post(
    endpoint: &AuthorizationEndpoint,
    req: &HttpRequest,
    body: &Bytes,
) -> HttpResponse {
    let mut parameters = match parse_authorization_post_form(
        req,
        body,
        AuthorizationApplication::duplicate_parameters(),
    ) {
        Ok(parameters) => parameters,
        Err(response) => return response,
    };
    authorize(endpoint, req, &mut parameters).await
}

pub async fn authorize(
    endpoint: &AuthorizationEndpoint,
    req: &HttpRequest,
    parameters: &mut HashMap<String, String>,
) -> HttpResponse {
    let source_ip = client_ip_with_config(req, &endpoint.client_ip);
    let session_id =
        cookie_value(req, endpoint.session_http.session_cookie_name()).map(SessionId::new);
    let facts = AuthorizationRequestFacts {
        source_ip: &source_ip,
        session_id: session_id.as_ref(),
        user_agent: req
            .headers()
            .get(header::USER_AGENT)
            .and_then(|value| value.to_str().ok()),
    };
    match endpoint.application.authorize(&facts, parameters).await {
        Ok(AuthorizationOutcome::Redirect { location }) => redirect_found(location),
        Ok(AuthorizationOutcome::FormPost {
            action,
            parameters,
            session_state,
            csp_nonce,
        }) => form_post_authorization_response(
            &action,
            &parameters,
            session_state.as_deref(),
            &csp_nonce,
        ),
        Err(error) => oauth_endpoint_error_response(error),
    }
}
