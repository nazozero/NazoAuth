//! client_credentials grant 处理。
use crate::contracts::{
    oauth_error::OAuthEndpointError, token_endpoint::TokenEndpointSuccess,
    token_endpoint::TokenRequestFacts,
};
use crate::domain::client_policy::audiences_allowed;
use crate::domain::client_policy::is_subset;
use crate::domain::client_policy::parse_scope;
use nazo_auth::ValidatedClientAssertion;

use crate::contracts::request_facts::DpopErrorContext;
use crate::domain::rows::ClientRow;
use nazo_auth::{CommitTokenIssuanceResult, TokenIssuanceMode};

use http::StatusCode;

use serde_json::json;

// 只为机密客户端签发无用户主体的访问令牌。
use crate::contracts::token_forms::TokenForm;
use crate::services::ServerTokenService;
use crate::token::SenderConstraintValidationError;
use crate::token::client_auth::consume_token_client_assertion_with_authorization_service;
use crate::token::issue::{TokenIssuanceContext, sign_access_response};
use crate::token::sender_constraint_multiple_error;
use crate::token::validate_token_sender_constraints;

#[derive(Debug)]
pub struct ClientCredentialsIssue {
    pub scopes: Vec<String>,
    pub audiences: Vec<String>,
}

pub fn reject_non_confidential_client_credentials_client(
    client: &ClientRow,
) -> Option<OAuthEndpointError> {
    if client.client_type == "confidential" {
        return None;
    }
    Some(OAuthEndpointError::token(
        StatusCode::BAD_REQUEST,
        "unauthorized_client",
        "client_credentials 只允许机密客户端使用.",
        false,
    ))
}

pub fn client_credentials_issue_request_with_default_audience(
    default_audience: &str,
    client: &ClientRow,
    form: TokenForm,
) -> Result<ClientCredentialsIssue, OAuthEndpointError> {
    let requested = parse_scope(form.scope.as_deref().unwrap_or(""));
    if !requested.is_empty() && !is_subset(&requested, &client.scopes) {
        return Err(OAuthEndpointError::token(
            StatusCode::BAD_REQUEST,
            "invalid_scope",
            "请求的作用域超出客户端允许范围.",
            false,
        ));
    }
    let scopes = if requested.is_empty() {
        client.scopes.clone()
    } else {
        requested
    };
    if scopes.iter().any(|scope| scope == "openid") {
        return Err(OAuthEndpointError::token(
            StatusCode::BAD_REQUEST,
            "invalid_scope",
            "client_credentials 不支持 openid scope.",
            false,
        ));
    }
    let audiences = if form.audiences.is_empty() {
        vec![default_audience.to_owned()]
    } else {
        form.audiences
    };
    if !audiences_allowed(client, &audiences) {
        return Err(OAuthEndpointError::token(
            StatusCode::BAD_REQUEST,
            "invalid_target",
            "请求的 audience 不在客户端允许范围内.",
            false,
        ));
    }
    Ok(ClientCredentialsIssue { scopes, audiences })
}

pub async fn token_client_credentials_with_service(
    token_service: &ServerTokenService,
    authorization_service: &crate::services::ServerAuthorizationService,
    issuance: &TokenIssuanceContext<'_>,
    facts: &TokenRequestFacts<'_>,
    client: &ClientRow,
    form: TokenForm,
    client_assertion: Option<&ValidatedClientAssertion>,
) -> Result<TokenEndpointSuccess, OAuthEndpointError> {
    if let Some(response) = reject_non_confidential_client_credentials_client(client) {
        return Err(response);
    }
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
                    "client_credentials requires mTLS sender constraint.",
                    false,
                ));
            }
            Err(SenderConstraintValidationError::Multiple) => {
                return Err(sender_constraint_multiple_error());
            }
        };
    if let Err(error) = consume_token_client_assertion_with_authorization_service(
        authorization_service,
        client,
        client_assertion,
        issuance.security_audit,
    )
    .await
    {
        return Err(crate::token::token_client_assertion_error(error));
    }
    let issue_request = match client_credentials_issue_request_with_default_audience(
        issuance.config.default_audience(),
        client,
        form,
    ) {
        Ok(issue_request) => issue_request,
        Err(response) => return Err(response),
    };
    let audit = issuance.config.audit_client_credentials_issuance;
    if audit && let Err(error) = issuance.security_audit.ensure_transactional_ready().await {
        tracing::error!(%error, "token issuance audit preflight failed");
        return Err(OAuthEndpointError::token(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "令牌签发审计存储不可用.",
            false,
        ));
    }
    let issuance_id = uuid::Uuid::now_v7();
    let require_fapi2 = issuance.config.profile.requires_fapi2_security()
        || client.security_policy.requires_fapi2_security();
    let signed = sign_access_response(
        issuance,
        token_service,
        nazo_auth::AccessTokenSignInput {
            signing_algorithm: require_fapi2.then_some("PS256"),
            authorization_id: Some(issuance_id),
            client_epoch: Some(issuance.client_epoch),
            user_epoch: None,
            issuer: issuance.config.issuer(),
            tenant_id: client.tenant_id,
            subject: &client.client_id,
            user_id: None,
            subject_type: "client",
            client_id: &client.client_id,
            audiences: &issue_request.audiences,
            scopes: &issue_request.scopes,
            authorization_details: &json!([]),
            userinfo_claim_requests: &[],
            ttl_seconds: issuance.config.access_token_ttl_seconds,
            sender_constraint: sender.as_borrowed(),
            actor: None,
        },
        None,
    )
    .await?;
    let active = if audit {
        let outcome = token_service
            .commit_token_issuance(nazo_auth::CommitTokenIssuance {
                authorization_id: Some(issuance_id),
                issuance_id,
                tenant_id: client.tenant_id,
                client_id: client.id,
                user_id: None,
                subject: client.client_id.clone(),
                principal_state: nazo_auth::TokenPrincipalState {
                    client_epoch: issuance.client_epoch,
                    user_epoch: None,
                    subject_bound: false,
                },
                native_sso_source: None,
                mode: TokenIssuanceMode::Fresh,
                refresh_token: None,
                access_token_jti: signed.jti,
                access_token_expires_at: signed.expires_at,
                audit_fields: nazo_auth::TokenIssuedAuditFields {
                    client_id: client.client_id.clone(),
                    subject_hash: crate::crypto::blake3_hex(&client.client_id),
                    scope: signed.scope,
                    audience: issue_request.audiences,
                },
            })
            .await;
        outcome.and_then(|result| match result {
            CommitTokenIssuanceResult::Committed => Ok(true),
            CommitTokenIssuanceResult::ClientInactive => Ok(false),
            _ => Err(nazo_auth::TokenPortError::CorruptData),
        })
    } else {
        // With nothing to commit, this final primary read orders issuance against client disable.
        token_service
            .machine_client_active(client.tenant_id, client.id, issuance.client_epoch)
            .await
    };
    match active {
        Ok(true) => Ok(TokenEndpointSuccess::Issued {
            body: signed.body,
            dpop_nonce: signed.dpop_nonce,
        }),
        Ok(false) => Err(OAuthEndpointError::token(
            StatusCode::BAD_REQUEST,
            "unauthorized_client",
            "该客户端未启用当前授权类型.",
            false,
        )),
        Err(error) => {
            tracing::warn!(%error, %issuance_id, "failed to finalize machine token issuance");
            Err(OAuthEndpointError::token(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "令牌签发状态不可用.",
                false,
            ))
        }
    }
}
