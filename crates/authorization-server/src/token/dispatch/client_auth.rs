use crate::contracts::oauth_error::OAuthEndpointError;
use crate::contracts::token_forms::TokenForm;
use crate::crypto::blake3_hex;
use crate::domain::oauth::AuthorizationCodeState;
use crate::domain::rows::ClientRow;
use crate::services::ServerAuthorizationService;
use crate::services::ServerTokenService;
use http::StatusCode;
use nazo_auth::{
    ClientProfile, ProtocolErrorCode, SecurityProfile, SenderConstraintPolicy,
    validate_token_request_profile as validate_auth_token_request_profile,
};

use super::errors::authorization_code_holder_missing_client_error;

pub(super) async fn missing_client_authorization_code_holder_error(
    token_service: &ServerTokenService,
    authorization_service: &ServerAuthorizationService,
    form: &TokenForm,
) -> Option<OAuthEndpointError> {
    if form.grant_type != "authorization_code" {
        return None;
    }
    let code = form.code.as_deref()?;
    let stored = match token_service
        .load_authorization_code(&blake3_hex(code))
        .await
    {
        Ok(Some(value)) => value,
        Ok(None) => return None,
        Err(error) => {
            tracing::warn!(%error, "failed to read authorization code before client authentication");
            return Some(OAuthEndpointError::token(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "授权码校验失败.",
                false,
            ));
        }
    };
    let payload = match stored {
        AuthorizationCodeState::Pending { payload } => payload,
        _ => return None,
    };
    if let Some(response) = authorization_code_holder_missing_client_error(
        payload.dpop_jkt.is_some(),
        payload.mtls_x5t_s256.is_some(),
    ) {
        return Some(response);
    }
    match authorization_service.client_by_id(&payload.client_id).await {
        Ok(Some(client))
            if client.require_dpop_bound_tokens || client.require_mtls_bound_tokens =>
        {
            authorization_code_holder_missing_client_error(
                client.require_dpop_bound_tokens,
                client.require_mtls_bound_tokens,
            )
        }
        Ok(_) => None,
        Err(error) => {
            tracing::warn!(%error, "failed to query authorization code client before client authentication");
            Some(OAuthEndpointError::token(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "客户端查询失败.",
                false,
            ))
        }
    }
}

pub(super) fn attestation_client_id_matches_form_hint(
    form_client_id: Option<&str>,
    attested_client_id: &str,
) -> bool {
    form_client_id.is_none_or(|client_id| client_id == attested_client_id)
}

pub(super) fn validate_token_client_enabled(
    client: &ClientRow,
    grant_type: &str,
) -> Result<(), OAuthEndpointError> {
    if !client.is_active || !client.grant_types.iter().any(|grant| grant == grant_type) {
        return Err(OAuthEndpointError::token(
            StatusCode::BAD_REQUEST,
            "unauthorized_client",
            "该客户端未启用当前授权类型.",
            false,
        ));
    }
    Ok(())
}

pub fn validate_token_request_profile(
    client: &ClientRow,
    auth_method: &str,
) -> Result<(), OAuthEndpointError> {
    let profile = if client.security_policy.requires_fapi2_security() {
        SecurityProfile::Fapi2Security
    } else {
        SecurityProfile::Baseline
    };
    let sender_constraint = match (
        client.require_dpop_bound_tokens,
        client.require_mtls_bound_tokens,
    ) {
        (false, false) => SenderConstraintPolicy::BearerAllowed,
        (true, false) => SenderConstraintPolicy::DpopRequired,
        (false, true) => SenderConstraintPolicy::MtlsRequired,
        (true, true) => SenderConstraintPolicy::DpopOrMtls,
    };
    validate_auth_token_request_profile(
        profile,
        ClientProfile {
            client_type: &client.client_type,
            authentication_method: auth_method,
            sender_constraint,
        },
    )
    .map_err(|error| {
        let status = if error.code == ProtocolErrorCode::InvalidClient {
            StatusCode::UNAUTHORIZED
        } else {
            StatusCode::BAD_REQUEST
        };
        OAuthEndpointError::token(status, error.code.as_str(), error.description, false)
    })
}
