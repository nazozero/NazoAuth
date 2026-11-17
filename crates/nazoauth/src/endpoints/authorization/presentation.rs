//! HTTP parsing and JSON projection for public client display metadata.

use crate::http::Request as HttpRequest;
use crate::http::Response as HttpResponse;
use crate::http::{json_response_no_store, json_response_status_no_store};
use http::StatusCode;
use nazo_oauth_server::authorization::presentation::{ClientPresentation, ClientPresentationError};
use std::borrow::Cow;

use crate::endpoints::authorization::AuthorizationEndpoint;

pub const MAX_CLIENT_ID_BYTES: usize = 255;

pub async fn authorize_client_presentation(
    endpoint: &AuthorizationEndpoint,
    request: &HttpRequest,
) -> HttpResponse {
    let Some(client_id) = presentation_client_id(request.uri().query().unwrap_or("")) else {
        return client_presentation_error(StatusCode::BAD_REQUEST, "invalid_request");
    };
    let result = endpoint.application.client_presentation(&client_id).await;
    client_presentation_response(result)
}

pub fn presentation_client_id(query: &str) -> Option<Cow<'_, str>> {
    let mut pairs = url::form_urlencoded::parse(query.as_bytes());
    let (name, client_id) = pairs.next()?;
    if name != "client_id" || pairs.next().is_some() {
        return None;
    }
    (!client_id.is_empty()
        && client_id.len() <= MAX_CLIENT_ID_BYTES
        && client_id.bytes().all(|byte| (0x21..=0x7e).contains(&byte)))
    .then_some(client_id)
}

pub fn client_presentation_response(
    result: Result<ClientPresentation, ClientPresentationError>,
) -> HttpResponse {
    match result {
        Ok(presentation) => json_response_no_store(presentation),
        Err(ClientPresentationError::NotFound) => {
            client_presentation_error(StatusCode::NOT_FOUND, "not_found")
        }
        Err(ClientPresentationError::Unavailable) => {
            client_presentation_error(StatusCode::SERVICE_UNAVAILABLE, "server_error")
        }
    }
}

pub fn client_presentation_error(status: StatusCode, error: &'static str) -> HttpResponse {
    json_response_status_no_store(status, serde_json::json!({ "error": error }))
}

#[cfg(test)]
#[path = "../../../tests/unit/endpoints/authorization/presentation.rs"]
mod tests;
