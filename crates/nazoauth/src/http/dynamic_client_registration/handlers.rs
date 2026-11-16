use super::{
    auth::bearer_token, ip::client_ip_with_config, response::dynamic_registration_result_response,
    types::DynamicRegistrationEndpoint,
};
use crate::http::empty_response;
use crate::http::{Request, Response};
use bytes::Bytes;
use http::StatusCode;
use nazo_auth::DynamicClientRegistrationRequest;
use serde_json::Value;
use std::future::Future;

pub async fn dynamic_client_registration<F>(
    endpoint: &DynamicRegistrationEndpoint,
    request: &mut Request,
    body: F,
) -> Response
where
    F: Future<Output = Result<Bytes, Response>>,
{
    let Some(_lease) = endpoint.application.acquire_request() else {
        return empty_response(StatusCode::NOT_FOUND);
    };
    if let Err(response) = crate::http::validate_json_head(request, 2 * 1024 * 1024) {
        return response;
    }
    let body = match body.await {
        Ok(body) => body,
        Err(response) => return response,
    };
    *request.body_mut() = body;
    let payload = match crate::http::parse_json::<DynamicClientRegistrationRequest>(request) {
        Ok(payload) => payload,
        Err(response) => return response,
    };
    let source_ip = client_ip_with_config(request, &endpoint.client_ip);
    dynamic_registration_result_response(
        endpoint
            .application
            .create(payload, bearer_token(request), &source_ip)
            .await,
    )
}

pub async fn client_configuration_get(
    endpoint: &DynamicRegistrationEndpoint,
    request: &Request,
    path: String,
) -> Response {
    let Some(_lease) = endpoint.application.acquire_request() else {
        return empty_response(StatusCode::NOT_FOUND);
    };
    let source_ip = client_ip_with_config(request, &endpoint.client_ip);
    dynamic_registration_result_response(
        endpoint
            .application
            .read(&path, bearer_token(request), &source_ip)
            .await,
    )
}

pub async fn client_configuration_put<F>(
    endpoint: &DynamicRegistrationEndpoint,
    request: &mut Request,
    path: String,
    body: F,
) -> Response
where
    F: Future<Output = Result<Bytes, Response>>,
{
    let Some(_lease) = endpoint.application.acquire_request() else {
        return empty_response(StatusCode::NOT_FOUND);
    };
    if let Err(response) = crate::http::validate_json_head(request, 2 * 1024 * 1024) {
        return response;
    }
    let body = match body.await {
        Ok(body) => body,
        Err(response) => return response,
    };
    *request.body_mut() = body;
    let payload = match crate::http::parse_json::<Value>(request) {
        Ok(payload) => payload,
        Err(response) => return response,
    };
    let source_ip = client_ip_with_config(request, &endpoint.client_ip);
    dynamic_registration_result_response(
        endpoint
            .application
            .update(&path, payload, bearer_token(request), &source_ip)
            .await,
    )
}

pub async fn client_configuration_delete(
    endpoint: &DynamicRegistrationEndpoint,
    request: &Request,
    path: String,
) -> Response {
    let Some(_lease) = endpoint.application.acquire_request() else {
        return empty_response(StatusCode::NOT_FOUND);
    };
    let source_ip = client_ip_with_config(request, &endpoint.client_ip);
    dynamic_registration_result_response(
        endpoint
            .application
            .delete(&path, bearer_token(request), &source_ip)
            .await,
    )
}
