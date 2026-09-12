use crate::contracts::oauth_error::OAuthEndpointError;
use crate::contracts::token_forms::PreAuthorizedTokenParameters;
use http::StatusCode;

pub(super) fn pre_authorized_parameters(
    parameters: &mut PreAuthorizedTokenParameters,
) -> Result<(String, Option<String>), OAuthEndpointError> {
    if parameters.invalid {
        return Err(OAuthEndpointError::token(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Pre-authorized issuance parameters must be non-empty and must not repeat.",
            false,
        ));
    }
    parameters
        .pre_authorized_code
        .take()
        .map(|code| (code, parameters.tx_code.take()))
        .ok_or_else(|| {
            OAuthEndpointError::token(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "pre-authorized_code is required.",
                false,
            )
        })
}

#[cfg(test)]
#[path = "../../../tests/unit/token/pre_authorized.rs"]
mod tests;
