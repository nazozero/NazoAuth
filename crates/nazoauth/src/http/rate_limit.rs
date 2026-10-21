use actix_web::{HttpRequest, HttpResponse};
use nazo_http_actix::{ClientIpConfig, client_ip_with_config, oauth_endpoint_error_response};
use nazo_oauth_server::rate_limit::AuthRequestLimiter;

pub(crate) async fn auth_request_budget(
    request: actix_web::dev::ServiceRequest,
    next: actix_web::middleware::Next<impl actix_web::body::MessageBody + 'static>,
) -> Result<actix_web::dev::ServiceResponse<impl actix_web::body::MessageBody>, actix_web::Error> {
    let limiter = request
        .app_data::<actix_web::web::Data<AuthRequestLimiter>>()
        .ok_or_else(|| actix_web::error::ErrorInternalServerError("missing request limiter"))?;
    let source = request
        .app_data::<actix_web::web::Data<ClientIpConfig>>()
        .ok_or_else(|| {
            actix_web::error::ErrorInternalServerError("missing client IP configuration")
        })?;
    if let Err(response) = enforce_auth_request_limit(limiter, request.request(), source).await {
        return Ok(request.into_response(response).map_into_right_body());
    }
    Ok(next.call(request).await?.map_into_left_body())
}

pub(crate) async fn enforce_auth_request_limit(
    limiter: &AuthRequestLimiter,
    request: &HttpRequest,
    client_ip: &ClientIpConfig,
) -> Result<(), HttpResponse> {
    limiter
        .enforce(&client_ip_with_config(request, client_ip))
        .await
        .map_err(oauth_endpoint_error_response)
}

#[cfg(test)]
#[path = "../../tests/unit/http/rate_limit.rs"]
mod tests;
