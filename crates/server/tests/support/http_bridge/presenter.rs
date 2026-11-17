use actix_web::{HttpResponse, http::StatusCode};
pub(crate) fn oauth_error(status: StatusCode, error: &str, description: &str) -> HttpResponse {
    nazo_http_actix::forward_response(nazoauth::test_support::http::oauth_error(
        ::http::StatusCode::from_u16(status.as_u16()).unwrap(),
        error,
        description,
    ))
}

pub(crate) fn authorization_error_response(
    status: StatusCode,
    error: &str,
    description: &str,
) -> HttpResponse {
    nazo_http_actix::forward_response(nazoauth::test_support::http::authorization_error_response(
        ::http::StatusCode::from_u16(status.as_u16()).unwrap(),
        error,
        description,
    ))
}

pub(crate) fn redirect_found(location: String) -> HttpResponse {
    nazo_http_actix::forward_response(nazoauth::test_support::http::redirect_found(location))
}

pub(crate) fn oauth_endpoint_error_response(
    error: nazo_oauth_server::contracts::oauth_error::OAuthEndpointError,
) -> HttpResponse {
    nazo_http_actix::forward_response(nazoauth::test_support::http::oauth_endpoint_error_response(
        error,
    ))
}

pub(crate) fn pre_authorized_token_error_response(
    error: nazo_openid4vci::application::CredentialHttpError,
) -> HttpResponse {
    nazo_http_actix::forward_response(
        nazoauth::test_support::http::pre_authorized_token_error_response(error),
    )
}

pub(crate) fn token_endpoint_success_response(
    success: nazo_oauth_server::contracts::token_endpoint::TokenEndpointSuccess,
) -> HttpResponse {
    nazo_http_actix::forward_response(
        nazoauth::test_support::http::token_endpoint_success_response(success),
    )
}
