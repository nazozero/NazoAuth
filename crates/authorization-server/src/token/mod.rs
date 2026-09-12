pub mod client_auth;

pub const TOKEN_EXCHANGE_GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:token-exchange";

use crate::contracts::oauth_error::OAuthEndpointError;
use crate::contracts::token_endpoint::TokenRequestFacts;
use crate::crypto::constant_time_eq;
use crate::domain::rows::ClientRow;
use crate::token::client_auth::TokenManagementClientAuthError;
use http::StatusCode;
use nazo_auth::{
    DpopError, PresentedSenderConstraint, apply_sender_constraint, sender_constraint_policy,
};
/// Sender proofs admitted for one token request.
///
/// The token service stores at most one sender constraint in a token.  Keep
/// this exact-one invariant at the HTTP boundary too: when both client flags
/// are enabled, either proof is sufficient, but presenting both proofs is a
/// protocol error rather than an implicit AND binding.
#[derive(Debug, Eq, PartialEq)]
pub struct ValidatedSenderConstraints {
    pub dpop_jkt: Option<String>,
    pub mtls_x5t_s256: Option<String>,
}

#[derive(Debug)]
pub enum SenderConstraintValidationError {
    Dpop(DpopError),
    MissingMtls,
    Multiple,
}

/// Validate the DPoP and mTLS sender proofs for a token endpoint request.
///
/// `expected_*` bind redemption of a previously constrained grant/token.  The
/// optional `token_for_ath` is used by token exchange, where the DPoP proof is
/// also bound to the subject access token.  mTLS material is read only through
/// the configured trusted-proxy/direct-TLS extractor; ordinary request
/// headers never become sender proof.
pub async fn validate_token_sender_constraints(
    issuance: &issue::TokenIssuanceContext<'_>,
    facts: &TokenRequestFacts<'_>,
    client: &ClientRow,
    token_for_ath: Option<&str>,
    expected_dpop_jkt: Option<&str>,
    expected_mtls_x5t_s256: Option<&str>,
) -> Result<ValidatedSenderConstraints, SenderConstraintValidationError> {
    let dpop_jkt = crate::security::dpop::validate_dpop_proof(
        issuance.authorization,
        issuance.security_audit,
        issuance.config.issuer(),
        issuance.config.mtls_endpoint_base_url(),
        issuance.config.dpop_nonce_policy(),
        crate::contracts::request_facts::DpopRequestFacts {
            method: facts.dpop.method.clone(),
            path: facts.dpop.path,
            proof: facts.dpop.proof.clone(),
            proof_present: facts.dpop.proof_present,
        },
        token_for_ath,
        expected_dpop_jkt,
    )
    .await
    .map_err(SenderConstraintValidationError::Dpop)?;

    // A client certificate may authenticate the token request without being
    // the sender constraint.  Only inspect it when mTLS binding is required by
    // policy or by an already-bound grant; otherwise a DPoP-only client using
    // mTLS client authentication must remain DPoP-only.
    let request_mtls_x5t_s256 = (expected_mtls_x5t_s256.is_some()
        || client.require_mtls_bound_tokens)
        .then(|| {
            facts
                .certificate
                .as_ref()
                .and_then(|certificate| certificate.thumbprint.clone())
        })
        .flatten();
    let mtls_x5t_s256 = match (expected_mtls_x5t_s256, request_mtls_x5t_s256) {
        (Some(expected), Some(actual))
            if constant_time_eq(expected.as_bytes(), actual.as_bytes()) =>
        {
            Some(expected.to_owned())
        }
        (Some(_), _) => return Err(SenderConstraintValidationError::MissingMtls),
        (None, actual) => actual,
    };

    let has_dpop = dpop_jkt.is_some();
    let has_mtls = mtls_x5t_s256.is_some();
    if apply_sender_constraint(
        sender_constraint_policy(
            client.require_dpop_bound_tokens,
            client.require_mtls_bound_tokens,
        ),
        PresentedSenderConstraint {
            dpop_jkt: dpop_jkt.as_deref(),
            mtls_x5t_s256: mtls_x5t_s256.as_deref(),
        },
    )
    .is_err()
    {
        if has_dpop && has_mtls {
            return Err(SenderConstraintValidationError::Multiple);
        }
        if client.require_dpop_bound_tokens && !client.require_mtls_bound_tokens {
            return Err(SenderConstraintValidationError::Dpop(
                DpopError::MissingProof,
            ));
        }
        return Err(SenderConstraintValidationError::MissingMtls);
    }

    Ok(ValidatedSenderConstraints {
        dpop_jkt,
        mtls_x5t_s256,
    })
}

pub fn sender_constraint_multiple_error() -> OAuthEndpointError {
    OAuthEndpointError::token(
        StatusCode::BAD_REQUEST,
        "invalid_request",
        "multiple sender proofs are not allowed.",
        false,
    )
}

pub fn token_client_assertion_error(error: TokenManagementClientAuthError) -> OAuthEndpointError {
    match error {
        TokenManagementClientAuthError::InvalidClient
        | TokenManagementClientAuthError::PublicClientCredentialsForbidden => {
            OAuthEndpointError::token(
                StatusCode::UNAUTHORIZED,
                "invalid_client",
                "客户端认证失败.",
                false,
            )
        }
        TokenManagementClientAuthError::StoreUnavailable => OAuthEndpointError::token(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "客户端认证状态存储不可用.",
            false,
        ),
    }
}

pub const DEVICE_CODE_GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:device_code";
pub mod authorization_code;
pub mod ciba;
pub mod client_credentials;
pub mod device_issuance;
pub mod dispatch;
pub mod issue;
pub mod jwt_bearer;
pub mod native_sso;
pub mod refresh;
pub mod token_exchange;

pub mod device;

pub mod device_config;
