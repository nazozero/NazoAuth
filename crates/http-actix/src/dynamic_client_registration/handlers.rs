use super::{
    auth::bearer_token, ip::client_ip_with_config, response::dynamic_registration_result_response,
    types::DynamicRegistrationEndpoint,
};
use crate::empty_response;
use actix_web::{
    FromRequest, HttpRequest, HttpResponse,
    http::StatusCode,
    web::{Data, Json, Path, Payload},
};
use nazo_auth::DynamicClientRegistrationRequest;
use serde_json::Value;

pub async fn dynamic_client_registration(
    endpoint: Data<DynamicRegistrationEndpoint>,
    request: HttpRequest,
    body: Payload,
) -> HttpResponse {
    if !endpoint.application.accepts_new_requests() {
        return empty_response(StatusCode::NOT_FOUND);
    }
    let mut body = body.into_inner();
    let Json(payload) =
        match Json::<DynamicClientRegistrationRequest>::from_request(&request, &mut body).await {
            Ok(payload) => payload,
            Err(error) => return error.error_response(),
        };
    let source_ip = client_ip_with_config(&request, &endpoint.client_ip);
    dynamic_registration_result_response(
        endpoint
            .application
            .create(payload, bearer_token(&request), &source_ip)
            .await,
    )
}

pub async fn client_configuration_get(
    endpoint: Data<DynamicRegistrationEndpoint>,
    request: HttpRequest,
    path: Path<String>,
) -> HttpResponse {
    if !endpoint.application.accepts_new_requests() {
        return empty_response(StatusCode::NOT_FOUND);
    }
    let source_ip = client_ip_with_config(&request, &endpoint.client_ip);
    dynamic_registration_result_response(
        endpoint
            .application
            .read(&path, bearer_token(&request), &source_ip)
            .await,
    )
}

pub async fn client_configuration_put(
    endpoint: Data<DynamicRegistrationEndpoint>,
    request: HttpRequest,
    path: Path<String>,
    body: Payload,
) -> HttpResponse {
    if !endpoint.application.accepts_new_requests() {
        return empty_response(StatusCode::NOT_FOUND);
    }
    let mut body = body.into_inner();
    let Json(payload) = match Json::<Value>::from_request(&request, &mut body).await {
        Ok(payload) => payload,
        Err(error) => return error.error_response(),
    };
    let source_ip = client_ip_with_config(&request, &endpoint.client_ip);
    dynamic_registration_result_response(
        endpoint
            .application
            .update(&path, payload, bearer_token(&request), &source_ip)
            .await,
    )
}

pub async fn client_configuration_delete(
    endpoint: Data<DynamicRegistrationEndpoint>,
    request: HttpRequest,
    path: Path<String>,
) -> HttpResponse {
    if !endpoint.application.accepts_new_requests() {
        return empty_response(StatusCode::NOT_FOUND);
    }
    let source_ip = client_ip_with_config(&request, &endpoint.client_ip);
    dynamic_registration_result_response(
        endpoint
            .application
            .delete(&path, bearer_token(&request), &source_ip)
            .await,
    )
}
