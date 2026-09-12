//! Device grant handoff into the shared typed token-issuance pipeline.
//!
//! Device state admission, polling, client binding, and one-time consumption live
//! behind [`crate::services::ServerDeviceGrantService`], while token minting uses
//! [`TokenIssuanceContext`] and [`ServerTokenService`]. Sender constraints and
//! client-assertion consumption use the focused authorization service carried by
//! the issuance context.
use crate::contracts::request_facts::DpopErrorContext;
use crate::contracts::{
    oauth_error::OAuthEndpointError, token_endpoint::TokenEndpointSuccess,
    token_endpoint::TokenRequestFacts,
};
use crate::crypto::blake3_hex;
use crate::domain::oauth::{RefreshTokenPolicy, TokenIssue};
use crate::domain::rows::ClientRow;
use chrono::Utc;
use http::StatusCode;
use nazo_auth::ValidatedClientAssertion;
use nazo_auth::{DevicePollCommit, DevicePollFailure, TokenIssuanceMode};

use crate::contracts::token_forms::TokenForm;
use crate::services::ServerDeviceGrantService;
use crate::services::ServerTokenService;
use crate::token::SenderConstraintValidationError;
use crate::token::client_auth::consume_token_client_assertion_with_authorization_service;
use crate::token::issue::TokenIssuanceContext;
use crate::token::issue::issue_token_response;
use crate::token::sender_constraint_multiple_error;
use crate::token::validate_token_sender_constraints;

pub(super) fn device_grant_key(
    device_code: &str,
    dpop_jkt: Option<&str>,
    mtls_x5t_s256: Option<&str>,
) -> String {
    format!(
        "device_code:{}:{}:{}",
        blake3_hex(device_code),
        dpop_jkt.map(blake3_hex).unwrap_or_default(),
        mtls_x5t_s256.map(blake3_hex).unwrap_or_default(),
    )
}

pub async fn token_device_code_with_service(
    token_service: &ServerTokenService,
    issuance: &TokenIssuanceContext<'_>,
    device_service: &ServerDeviceGrantService,
    facts: &TokenRequestFacts<'_>,
    client: &ClientRow,
    form: &TokenForm,
    client_assertion: Option<&ValidatedClientAssertion>,
) -> Result<TokenEndpointSuccess, OAuthEndpointError> {
    if !issuance.permits(nazo_runtime_modules::ModuleId::DeviceAuthorization) {
        return Err(OAuthEndpointError::token(
            StatusCode::BAD_REQUEST,
            "unsupported_grant_type",
            "Device Authorization Grant is not enabled.",
            false,
        ));
    }
    if !client.security_policy.allow_cross_device_flows {
        return Err(OAuthEndpointError::token(
            StatusCode::BAD_REQUEST,
            "unauthorized_client",
            "This client is not authorized for cross-device flows.",
            false,
        ));
    }
    let device_code = match required_device_code(form) {
        Ok(device_code) => device_code,
        Err(response) => return Err(response),
    };
    let sender =
        match validate_token_sender_constraints(issuance, facts, client, None, None, None).await {
            Ok(value) => value,
            Err(SenderConstraintValidationError::Dpop(error)) => {
                return Err(OAuthEndpointError::Dpop {
                    error,
                    context: DpopErrorContext::TokenEndpoint,
                });
            }
            Err(SenderConstraintValidationError::MissingMtls) => {
                return Err(OAuthEndpointError::token(
                    StatusCode::BAD_REQUEST,
                    "invalid_grant",
                    "device_code requires mTLS sender constraint.",
                    false,
                ));
            }
            Err(SenderConstraintValidationError::Multiple) => {
                return Err(sender_constraint_multiple_error());
            }
        };
    let device_grant_key = device_grant_key(
        device_code,
        sender.dpop_jkt.as_deref(),
        sender.mtls_x5t_s256.as_deref(),
    );
    if let Err(error) = consume_token_client_assertion_with_authorization_service(
        issuance.authorization,
        client,
        client_assertion,
        issuance.security_audit,
    )
    .await
    {
        return Err(crate::token::token_client_assertion_error(error));
    }

    match device_service
        .poll(device_code, &client.client_id, Utc::now)
        .await
    {
        Ok(DevicePollCommit::AuthorizationPending) => Err(OAuthEndpointError::token(
            StatusCode::BAD_REQUEST,
            "authorization_pending",
            "授权仍在等待用户确认.",
            false,
        )),
        Ok(DevicePollCommit::SlowDown) => Err(OAuthEndpointError::token(
            StatusCode::BAD_REQUEST,
            "slow_down",
            "设备轮询过快.",
            false,
        )),
        Ok(DevicePollCommit::AccessDenied) => Err(OAuthEndpointError::token(
            StatusCode::BAD_REQUEST,
            "access_denied",
            "用户拒绝设备授权.",
            false,
        )),
        Ok(DevicePollCommit::Expired) => Err(OAuthEndpointError::token(
            StatusCode::BAD_REQUEST,
            "expired_token",
            "device_code 已过期.",
            false,
        )),
        Ok(DevicePollCommit::Consumed) => Err(OAuthEndpointError::token(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "device_code 已使用.",
            false,
        )),
        Ok(DevicePollCommit::Approved(approved)) => {
            let nazo_auth::ApprovedDeviceAuthorization { payload, approval } = *approved;
            issue_token_response(
                issuance,
                token_service,
                client,
                TokenIssuanceMode::SingleUse {
                    grant_key: device_grant_key.clone(),
                },
                TokenIssue {
                    user_id: Some(approval.user_id),
                    subject: approval.subject,
                    scopes: payload.scopes,
                    authorization_details: payload.authorization_details,
                    audiences: payload.resource_indicators,
                    nonce: None,
                    auth_time: Some(approval.auth_time),
                    amr: approval.amr,
                    oidc_sid: approval.oidc_sid,
                    acr: None,
                    userinfo_claims: Vec::new(),
                    userinfo_claim_requests: Vec::new(),
                    id_token_claims: Vec::new(),
                    id_token_claim_requests: Vec::new(),
                    refresh_id_token_sid: None,
                    include_refresh: true,
                    refresh_token_policy: RefreshTokenPolicy::IssueNew,
                    refresh_token_dpop_jkt: sender.dpop_jkt.clone(),
                    dpop_jkt: sender.dpop_jkt,
                    mtls_x5t_s256: sender.mtls_x5t_s256.clone(),
                    refresh_token_mtls_x5t_s256: sender.mtls_x5t_s256,
                    refresh_token_client_attestation_jkt: None,
                    refresh_token_scopes: None,
                    authorization_code_hash: None,
                    actor: None,
                    issued_token_type: None,
                    native_sso: None,
                },
            )
            .await
        }
        Err(DevicePollFailure::Missing) => Err(OAuthEndpointError::token(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "device_code 无效或已过期.",
            false,
        )),
        Err(DevicePollFailure::ClientMismatch) => Err(OAuthEndpointError::token(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "device_code 未签发给该客户端.",
            false,
        )),
        Err(DevicePollFailure::Storage(error)) => {
            tracing::warn!(%error, "failed to update device authorization state");
            Err(OAuthEndpointError::token(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "设备授权状态读取失败.",
                false,
            ))
        }
        Err(DevicePollFailure::Contended) => Err(OAuthEndpointError::token(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "设备授权状态正忙.",
            false,
        )),
    }
}

pub(super) fn required_device_code(form: &TokenForm) -> Result<&str, OAuthEndpointError> {
    form.device_code
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| {
            OAuthEndpointError::token(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "缺少 device_code.",
                false,
            )
        })
}

#[cfg(test)]
#[path = "../../tests/unit/token/device_issuance.rs"]
mod tests;
