//! refresh_token grant 处理。
use crate::contracts::{
    oauth_error::OAuthEndpointError, token_endpoint::TokenEndpointSuccess,
    token_endpoint::TokenRequestFacts,
};
use crate::crypto::constant_time_eq;
use nazo_auth::ValidatedClientAssertion;

use crate::domain::client_policy::audiences_allowed;
use crate::domain::client_policy::is_subset;
use crate::domain::client_policy::parse_scope;

use crate::contracts::request_facts::DpopErrorContext;
use crate::domain::oauth::{RefreshTokenPolicy, TokenIssue};
use crate::domain::rows::{ClientRow, TokenRow};
use nazo_auth::DpopError;

use http::StatusCode;

use chrono::Utc;

use nazo_auth::TokenIssuanceMode;
// 只处理 refresh token 校验、复用检测和轮换前置约束。

use crate::contracts::token_forms::TokenForm;
use crate::services::ServerTokenService;
use crate::token::SenderConstraintValidationError;
use crate::token::client_auth::consume_token_client_assertion_with_authorization_service;
use crate::token::issue::TokenIssuanceContext;
use crate::token::issue::issue_token_response;
use crate::token::issue::should_issue_refresh_token;
use crate::token::sender_constraint_multiple_error;
use crate::token::validate_token_sender_constraints;
pub fn refresh_token_policy(client: &ClientRow, token: &TokenRow) -> RefreshTokenPolicy {
    let sender_constrained_confidential_client = client.client_type == "confidential"
        && (client.require_dpop_bound_tokens || client.require_mtls_bound_tokens);
    if sender_constrained_confidential_client
        || (client.security_policy.requires_fapi2_security()
            && refresh_token_has_stable_sender_constraint(token))
    {
        RefreshTokenPolicy::PreserveExisting
    } else {
        RefreshTokenPolicy::Rotate {
            family_id: token.token_family_id,
            rotated_from_id: token.id,
        }
    }
}

fn refresh_token_has_stable_sender_constraint(token: &TokenRow) -> bool {
    token.dpop_jkt.is_some() || token.mtls_x5t_s256.is_some()
}

fn refresh_token_scopes(
    original_scopes: Vec<String>,
    requested_scope: Option<&str>,
) -> Result<Vec<String>, ()> {
    let Some(requested) = requested_scope.map(parse_scope) else {
        return Ok(original_scopes);
    };
    if requested.is_empty() {
        return Ok(original_scopes);
    }
    if is_subset(&requested, &original_scopes) {
        Ok(requested)
    } else {
        Err(())
    }
}

fn refresh_requests_oidc_subject(requested_scope: Option<&str>) -> bool {
    let requested = requested_scope.map(parse_scope).unwrap_or_default();
    requested.is_empty() || requested.iter().any(|scope| scope == "openid")
}

fn client_attestation_refresh_binding_matches(
    token_endpoint_auth_method: &str,
    expected: Option<&str>,
    presented: Option<&str>,
) -> bool {
    // Attestation-Based Client Authentication draft-07 section 10.3 binds a
    // refresh token to the Client Instance and the public key in cnf.jwk.
    if token_endpoint_auth_method != "attest_jwt_client_auth" {
        return expected.is_none() && presented.is_none();
    }
    matches!(
        (expected, presented),
        (Some(expected), Some(presented))
            if constant_time_eq(expected.as_bytes(), presented.as_bytes())
    )
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RefreshAudienceError {
    MissingOriginal,
    RequestedExceedsOriginal,
}

pub fn refresh_token_audiences(
    token: &TokenRow,
    form: &TokenForm,
) -> Result<Vec<String>, RefreshAudienceError> {
    let original_audiences = token.audience.clone();
    if original_audiences.is_empty() {
        return Err(RefreshAudienceError::MissingOriginal);
    }
    if form.audiences.is_empty() {
        return Ok(original_audiences);
    }
    is_subset(&form.audiences, &original_audiences)
        .then(|| form.audiences.clone())
        .ok_or(RefreshAudienceError::RequestedExceedsOriginal)
}

pub async fn token_refresh_with_service(
    token_service: &ServerTokenService,
    issuance: &TokenIssuanceContext<'_>,
    facts: &TokenRequestFacts<'_>,
    client: &ClientRow,
    form: &TokenForm,
    client_assertion: Option<&ValidatedClientAssertion>,
    client_attestation_jkt: Option<&str>,
) -> Result<TokenEndpointSuccess, OAuthEndpointError> {
    let request_started_at = Utc::now();
    let Some(refresh_token) = &form.refresh_token else {
        return Err(OAuthEndpointError::token(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "缺少 refresh_token.",
            false,
        ));
    };
    let token = match token_service
        .refresh_token_snapshot_with_subject(
            client.tenant_id,
            refresh_token,
            client.id,
            request_started_at,
            refresh_requests_oidc_subject(form.scope.as_deref()),
        )
        .await
    {
        Ok(value) => value,
        Err(error) => {
            tracing::warn!(?error, "failed to load refresh token");
            return Err(OAuthEndpointError::token(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "refresh_token 校验失败.",
                false,
            ));
        }
    };
    let Some(snapshot) = token else {
        return Err(OAuthEndpointError::token(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "refresh_token 无效.",
            false,
        ));
    };
    let mut token = snapshot.presented;
    if token.client_id != client.id || token.expires_at <= Utc::now() {
        return Err(OAuthEndpointError::token(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "refresh_token 无效或已撤销.",
            false,
        ));
    }
    if !client_attestation_refresh_binding_matches(
        &client.token_endpoint_auth_method,
        token.client_attestation_jkt.as_deref(),
        client_attestation_jkt,
    ) {
        return Err(OAuthEndpointError::token(
            StatusCode::UNAUTHORIZED,
            "invalid_client_attestation",
            "Refresh token is not bound to this client instance key.",
            false,
        ));
    }
    let mut lost_response_original: Option<(uuid::Uuid, [u8; 32])> = None;
    // Keep the original token's authentication context independent from the
    // optional lost-response successor replacement below.  Borrowing the
    // context through `token` would prevent assigning the successor in place.
    let authentication_context = token.authentication_context.clone();
    if !authentication_context.is_well_formed()
        || token
            .id_token_sid
            .as_deref()
            .is_some_and(|sid| sid.trim().is_empty())
        || authentication_context.issuer != issuance.config.issuer()
        || authentication_context.audience != client.client_id
    {
        return Err(OAuthEndpointError::token(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "refresh_token 的 OpenID 上下文无效或与当前客户端不匹配.",
            false,
        ));
    }
    let original_scopes = token.scopes.clone();
    if client.client_type == "public"
        && client.require_dpop_bound_tokens
        && !client.require_mtls_bound_tokens
        && token.dpop_jkt.is_none()
    {
        return Err(OAuthEndpointError::token(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "refresh_token is not DPoP-bound.",
            false,
        ));
    }
    let sender = match validate_token_sender_constraints(
        issuance,
        facts,
        client,
        None,
        token.dpop_jkt.as_deref(),
        token.mtls_x5t_s256.as_deref(),
    )
    .await
    {
        Ok(value) => value,
        Err(SenderConstraintValidationError::Dpop(DpopError::MissingProof)) => {
            return Err(OAuthEndpointError::token(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "refresh_token requires proof of possession.",
                false,
            ));
        }
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
                "refresh_token requires mTLS proof of possession.",
                false,
            ));
        }
        Err(SenderConstraintValidationError::Multiple) => {
            return Err(sender_constraint_multiple_error());
        }
    };
    let dpop_jkt = sender.dpop_jkt;
    let mtls_x5t_s256 = sender.mtls_x5t_s256;
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
    if token.revoked_at.is_some() {
        let original_id = token.id;
        let original_blake3 = token.token_blake3;
        match snapshot.successor {
            Ok(Some(successor)) => token = successor,
            Ok(None) => {}
            Err(error) => {
                tracing::warn!(%error, "failed to inspect rotated refresh token family");
                return Err(OAuthEndpointError::token(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "server_error",
                    "refresh_token 复用处理失败.",
                    false,
                ));
            }
        }
        // The durable commit distinguishes a lost-response successor from an
        // authenticated reuse.  In the latter case it atomically compromises
        // the family and appends the rejection audit before returning
        // RotationConflict.
        lost_response_original = Some((original_id, original_blake3));
    }
    let openid4vci_credential_authorization = issuance
        .config
        .openid4vci_audience(&original_scopes, &token.authorization_details)
        .is_some();
    if !should_issue_refresh_token(
        client,
        &original_scopes,
        openid4vci_credential_authorization,
    ) {
        return Err(OAuthEndpointError::token(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "refresh_token 不具备可续期授权.",
            false,
        ));
    }
    let scopes = match refresh_token_scopes(original_scopes, form.scope.as_deref()) {
        Ok(scopes) => scopes,
        Err(()) => {
            return Err(OAuthEndpointError::token(
                StatusCode::BAD_REQUEST,
                "invalid_scope",
                "请求的作用域超出 refresh_token 原始授权范围.",
                false,
            ));
        }
    };
    let audiences = match refresh_token_audiences(&token, form) {
        Ok(audiences) => audiences,
        Err(RefreshAudienceError::MissingOriginal) => {
            return Err(OAuthEndpointError::token(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "refresh_token 缺少持久化 audience 绑定.",
                false,
            ));
        }
        Err(RefreshAudienceError::RequestedExceedsOriginal) => {
            return Err(OAuthEndpointError::token(
                StatusCode::BAD_REQUEST,
                "invalid_target",
                "请求的 resource 超出 refresh_token 原始授权范围.",
                false,
            ));
        }
    };
    if !audiences_allowed(client, &audiences) {
        return Err(OAuthEndpointError::token(
            StatusCode::BAD_REQUEST,
            "invalid_target",
            "请求的 audience 不在客户端允许范围内.",
            false,
        ));
    }
    // Only a normal source and the effective OIDC scope consume successful
    // early preparation. Holder/sender/scope/audience errors retain their
    // original priority; missing/corrupt preparation uses the later read.
    // Lost-response recovery deliberately retains its established path.
    let prepared_subject =
        if lost_response_original.is_none() && scopes.iter().any(|scope| scope == "openid") {
            snapshot.prepared_subject
        } else {
            None
        };
    let refresh_token_policy = match lost_response_original {
        Some((original_id, original_blake3)) => RefreshTokenPolicy::RotateLostResponse {
            family_id: token.token_family_id,
            original_id,
            original_blake3,
            successor_id: token.id,
            retry_started_at: request_started_at,
        },
        None => refresh_token_policy(client, &token),
    };
    let refresh_id_token_sid = Some(token.id_token_sid.clone());
    let refresh_authority = token.authority();
    issue_token_response(
        issuance,
        token_service,
        client,
        TokenIssuanceMode::Fresh,
        TokenIssue {
            native_sso_source: None,
            user_id: token.user_id,
            prepared_subject,
            subject: token.subject,
            scopes,
            authorization_details: token.authorization_details,
            audiences,
            // A refreshed ID Token omits the original nonce; the immutable
            // source contract also strips this first-response-only value.
            nonce: None,
            auth_time: Some(authentication_context.auth_time),
            amr: authentication_context.amr,
            oidc_sid: authentication_context.oidc_sid,
            acr: authentication_context.acr,
            userinfo_claim_requests: authentication_context.userinfo_claim_requests,
            id_token_claim_requests: authentication_context.id_token_claim_requests,
            refresh_id_token_sid,
            include_refresh: true,
            refresh_token_policy,
            dpop_jkt: dpop_jkt.clone(),
            refresh_token_dpop_jkt: token.dpop_jkt,
            mtls_x5t_s256,
            // Client policy can newly bind this access token; the source RT
            // and any rotated successor retain their original sender binding.
            refresh_token_mtls_x5t_s256: token.mtls_x5t_s256,
            refresh_token_client_attestation_jkt: token.client_attestation_jkt,
            refresh_authority: Some(refresh_authority),
            refresh_grant_audiences: None,
            authorization_code_hash: None,
            actor: None,
            issued_token_type: None,
            native_sso: None,
        },
    )
    .await
}

#[cfg(test)]
#[path = "../../tests/unit/token/refresh.rs"]
mod tests;
