use crate::contracts::oauth_error::OAuthEndpointError;
use crate::contracts::token_forms::TokenForm;
use http::StatusCode;

pub(super) fn authorization_code_holder_missing_client_error(
    dpop_bound: bool,
    mtls_bound: bool,
) -> Option<OAuthEndpointError> {
    if mtls_bound {
        return Some(OAuthEndpointError::token(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "authorization code proof of possession validation failed.",
            false,
        ));
    }
    if dpop_bound {
        return Some(OAuthEndpointError::token(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "authorization code proof of possession validation failed.",
            false,
        ));
    }
    None
}

pub(super) fn client_credentials_holder_missing_client_error(
    form: &TokenForm,
    dpop_present: bool,
) -> Option<OAuthEndpointError> {
    if form.grant_type != "client_credentials" || dpop_present {
        return None;
    }
    Some(OAuthEndpointError::token(
        StatusCode::BAD_REQUEST,
        "invalid_request",
        "client_credentials requires a holder-of-key proof.",
        false,
    ))
}
