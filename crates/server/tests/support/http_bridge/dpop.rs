use actix_web::HttpResponse;
use nazo_auth::DpopError;
use nazo_oauth_server::contracts::request_facts::DpopErrorContext;
pub(crate) fn dpop_error_response(error: DpopError, context: DpopErrorContext) -> HttpResponse {
    nazo_http_actix::forward_response(nazoauth::test_support::http::dpop_error_response(
        error, context,
    ))
}
