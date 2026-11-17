use crate::http::Request as HttpRequest;
use crate::http::Response as HttpResponse;
use crate::http::{ClientIpConfig, client_ip_with_config, oauth_endpoint_error_response};
use nazo_oauth_server::rate_limit::AuthRequestLimiter;

pub async fn enforce_auth_request_limit(
    limiter: &AuthRequestLimiter,
    request: &HttpRequest,
    client_ip: &ClientIpConfig,
) -> Result<(), HttpResponse> {
    limiter
        .enforce(&client_ip_with_config(request, client_ip))
        .await
        .map_err(oauth_endpoint_error_response)
}
