use actix_web::{HttpRequest, HttpResponse};
use nazo_http_actix::{ClientIpConfig, client_ip_with_config, oauth_endpoint_error_response};
use nazo_oauth_server::rate_limit::AuthRequestLimiter;

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
