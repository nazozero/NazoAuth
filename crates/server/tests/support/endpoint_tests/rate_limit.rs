// Native regression module: reexports the actual neutral implementation.
#[path = "../../unit/http/rate_limit.rs"]
pub(crate) mod tests;

use crate::test_support::http::{
    ClientIpConfig, client_ip_with_config, oauth_endpoint_error_response,
};
use actix_web::{HttpRequest, HttpResponse};
use nazo_oauth_server::rate_limit::AuthRequestLimiter;

pub(crate) async fn enforce_auth_request_limit(
    limiter: &AuthRequestLimiter,
    request: &HttpRequest,
    client_ip: &ClientIpConfig,
) -> Result<(), HttpResponse> {
    let request = crate::test_support::transport::request_with_client_ip(request, client_ip);
    (nazoauth::test_support::endpoints::rate_limit::enforce_auth_request_limit(
        limiter, &request, client_ip,
    )
    .await)
        .map_err(nazo_http_actix::forward_response)
}
