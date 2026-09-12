//! HTTP parsing and JSON projection for public client display metadata.

use actix_web::HttpRequest;
use actix_web::HttpResponse;
use actix_web::http::StatusCode;
use actix_web::web::Data;
use nazo_http_actix::{json_response_no_store, json_response_status_no_store};
use nazo_oauth_server::authorization::presentation::{ClientPresentation, ClientPresentationError};

use crate::http::authorization::AuthorizationEndpoint;

const MAX_CLIENT_ID_BYTES: usize = 255;

pub(crate) async fn authorize_client_presentation(
    endpoint: Data<AuthorizationEndpoint>,
    request: HttpRequest,
) -> HttpResponse {
    let Some(client_id) = presentation_client_id(request.query_string()) else {
        return client_presentation_error(StatusCode::BAD_REQUEST, "invalid_request");
    };
    let result = endpoint.application.client_presentation(&client_id).await;
    client_presentation_response(result)
}

fn presentation_client_id(query: &str) -> Option<String> {
    let mut pairs = url::form_urlencoded::parse(query.as_bytes());
    let (name, client_id) = pairs.next()?;
    if name != "client_id" || pairs.next().is_some() {
        return None;
    }
    (!client_id.is_empty()
        && client_id.len() <= MAX_CLIENT_ID_BYTES
        && client_id.bytes().all(|byte| (0x21..=0x7e).contains(&byte)))
    .then(|| client_id.into_owned())
}

fn client_presentation_response(
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

fn client_presentation_error(status: StatusCode, error: &'static str) -> HttpResponse {
    json_response_status_no_store(status, serde_json::json!({ "error": error }))
}

#[cfg(test)]
#[path = "../../../tests/unit/http/authorization/presentation.rs"]
mod tests;
