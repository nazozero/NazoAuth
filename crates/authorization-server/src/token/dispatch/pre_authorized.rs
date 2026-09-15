use crate::contracts::oauth_error::OAuthEndpointError;
use crate::contracts::token_endpoint::TokenEndpointSuccess;
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

/// Maps a strict DPoP validation failure onto the pre-authorized grant's
/// error surface so nonce challenges keep their original wire shape.
fn pre_authorized_dpop_error(error: nazo_auth::DpopError) -> OAuthEndpointError {
    OAuthEndpointError::PreAuthorized(match error {
        nazo_auth::DpopError::UseNonce(nonce) => {
            nazo_openid4vci::application::CredentialHttpError {
                status: 400,
                error: "use_dpop_nonce",
                description: "Credential issuer requires nonce in DPoP proof.",
                dpop_nonce: Some(nonce),
            }
        }
        nazo_auth::DpopError::NonceStoreUnavailable => {
            nazo_openid4vci::application::CredentialHttpError {
                status: 503,
                error: "server_error",
                description: "DPoP nonce validation is unavailable.",
                dpop_nonce: None,
            }
        }
        _ => nazo_openid4vci::application::CredentialHttpError {
            status: 400,
            error: "invalid_dpop_proof",
            description: "DPoP proof is invalid.",
            dpop_nonce: None,
        },
    })
}

/// Validates the anonymous entry's DPoP material with the same strict facts
/// every grant uses: a malformed or duplicated proof header fails instead of
/// degrading into a bearer request.
pub(super) async fn anonymous_pre_authorized_dpop(
    authorization: &crate::services::ServerAuthorizationService,
    security_audit: &dyn crate::ports::audit::SecurityAudit,
    config: &crate::token::issue::TokenIssuanceConfig,
    dpop: &crate::contracts::request_facts::DpopRequestFacts<'_>,
) -> Result<Option<String>, OAuthEndpointError> {
    crate::security::dpop::validate_dpop_proof(
        authorization,
        security_audit,
        config.issuer(),
        config.mtls_endpoint_base_url(),
        config.dpop_nonce_policy(),
        crate::contracts::request_facts::DpopRequestFacts {
            method: dpop.method.clone(),
            path: dpop.path,
            proof: dpop.proof.clone(),
            proof_present: dpop.proof_present,
        },
        None,
        None,
    )
    .await
    .map_err(pre_authorized_dpop_error)
}

/// Maps the shared sender-constraint failure onto the pre-authorized grant's
/// error surface; DPoP failures keep their nonce semantics.
pub(super) fn pre_authorized_sender_error(
    error: crate::token::SenderConstraintValidationError,
) -> OAuthEndpointError {
    match error {
        crate::token::SenderConstraintValidationError::Dpop(error) => {
            pre_authorized_dpop_error(error)
        }
        crate::token::SenderConstraintValidationError::MissingMtls => {
            OAuthEndpointError::PreAuthorized(nazo_openid4vci::application::CredentialHttpError {
                status: 400,
                error: "invalid_request",
                description: "The grant requires an mTLS sender constraint.",
                dpop_nonce: None,
            })
        }
        crate::token::SenderConstraintValidationError::Multiple => {
            crate::token::sender_constraint_multiple_error()
        }
    }
}

/// The single execution point for both pre-authorized entries. Callers pass
/// the verified client identity and sender bindings; the operation receives
/// no raw transport material.
pub(super) async fn execute_pre_authorized(
    endpoint: &dyn nazo_openid4vci::application::CredentialIssuerOperations,
    mut parameters: PreAuthorizedTokenParameters,
    client_id: Option<String>,
    dpop_jkt: Option<String>,
    mtls_x5t_s256: Option<String>,
) -> Result<TokenEndpointSuccess, OAuthEndpointError> {
    let (pre_authorized_code, tx_code) = pre_authorized_parameters(&mut parameters)?;
    match endpoint
        .pre_authorized_token(nazo_openid4vci::application::PreAuthorizedTokenRequest {
            pre_authorized_code,
            tx_code,
            client_id,
            dpop_jkt,
            mtls_x5t_s256,
        })
        .await
    {
        Ok(response) => Ok(TokenEndpointSuccess::PreAuthorized(response)),
        Err(error) => Err(OAuthEndpointError::PreAuthorized(error)),
    }
}

#[cfg(test)]
#[path = "../../../tests/unit/token/pre_authorized.rs"]
mod tests;
