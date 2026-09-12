//! RFC 8693 OAuth 2.0 Token Exchange grant.
//!
//! This implementation intentionally accepts only locally issued access tokens
//! and issues only locally signed access tokens. External token trust, refresh
//! token exchange, and ID-token issuance require separate policy models.
use crate::contracts::{
    oauth_error::OAuthEndpointError, token_endpoint::TokenEndpointSuccess,
    token_endpoint::TokenRequestFacts,
};

use super::native_sso::token_native_sso_exchange;
use crate::contracts::token_forms::TokenForm;
use crate::services::ServerTokenService;
use crate::token::client_auth::consume_token_client_assertion_with_authorization_service;
use crate::token::issue::{TokenIssuanceContext, issue_token_response};
use crate::token::native_sso::native_sso_profile_requested;
use crate::token::{
    SenderConstraintValidationError, ValidatedSenderConstraints, sender_constraint_multiple_error,
    validate_token_sender_constraints,
};
use nazo_auth::ValidatedClientAssertion;

use http::StatusCode;

use crate::contracts::request_facts::DpopErrorContext;
use crate::domain::oauth::{RefreshTokenPolicy, TokenIssue};
use crate::domain::rows::ClientRow;
use chrono::Utc;
use nazo_auth::DpopError;

use nazo_auth::{
    Claims, PresentedSenderConstraint, TokenExchangeError, TokenExchangePolicy,
    TokenExchangeRequestInput, TokenExchangeSenderBinding, TokenIssuanceMode, admit_token_exchange,
    parse_scope, token_exchange_actor_claim, token_exchange_issuance_binding,
    validate_token_exchange_access_token, validate_token_exchange_grant_prerequisites,
    validate_token_exchange_subject,
};
use serde_json::{Value, json};
use uuid::Uuid;

#[derive(Debug, PartialEq, Eq)]
pub enum TokenExchangeTokenError {
    Invalid,
    StoreUnavailable,
}

pub fn token_exchange_error_response(error: TokenExchangeError) -> OAuthEndpointError {
    match error {
        TokenExchangeError::Disabled => OAuthEndpointError::token(
            StatusCode::BAD_REQUEST,
            "unsupported_grant_type",
            "Token exchange is disabled.",
            false,
        ),
        TokenExchangeError::UnauthorizedClient => OAuthEndpointError::token(
            StatusCode::BAD_REQUEST,
            "unauthorized_client",
            "token exchange requires a confidential client.",
            false,
        ),
        TokenExchangeError::MissingParameter => OAuthEndpointError::token(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "token exchange request is missing required token parameters.",
            false,
        ),
        TokenExchangeError::UnsupportedTokenType => OAuthEndpointError::token(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "unsupported token exchange token type.",
            false,
        ),
        TokenExchangeError::InvalidScope => OAuthEndpointError::token(
            StatusCode::BAD_REQUEST,
            "invalid_scope",
            "token exchange scope must be a subset of the subject token and client scopes.",
            false,
        ),
        TokenExchangeError::InvalidTarget => OAuthEndpointError::token(
            StatusCode::BAD_REQUEST,
            "invalid_target",
            "requested token exchange target is not allowed for this client.",
            false,
        ),
        TokenExchangeError::InvalidGrant => OAuthEndpointError::token(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "token exchange input token is invalid.",
            false,
        ),
    }
}

pub fn token_exchange_request(form: &TokenForm) -> TokenExchangeRequestInput {
    TokenExchangeRequestInput {
        subject_token: form.subject_token.clone(),
        subject_token_type: form.subject_token_type.clone(),
        actor_token: form.actor_token.clone(),
        actor_token_type: form.actor_token_type.clone(),
        requested_token_type: form.requested_token_type.clone(),
        scope: form.scope.clone(),
        audiences: form.audiences.clone(),
    }
}

pub fn token_exchange_policy<'a>(
    issuance: &'a TokenIssuanceContext<'_>,
    client: &'a ClientRow,
    now: i64,
) -> TokenExchangePolicy<'a> {
    TokenExchangePolicy {
        enabled: issuance.accepts(nazo_runtime_modules::ModuleId::TokenExchange),
        client_id: &client.client_id,
        client_is_confidential: client.client_type == "confidential",
        client_tenant_id: client.tenant_id,
        allowed_scopes: &client.scopes,
        allowed_audiences: &client.allowed_audiences,
        require_dpop_bound_tokens: client.require_dpop_bound_tokens,
        require_mtls_bound_tokens: client.require_mtls_bound_tokens,
        now,
    }
}

pub fn token_exchange_admission_error_response(
    error: TokenExchangeError,
    form: &TokenForm,
) -> OAuthEndpointError {
    if error == TokenExchangeError::InvalidTarget && form.audiences.is_empty() {
        return OAuthEndpointError::token(
            StatusCode::BAD_REQUEST,
            "invalid_target",
            "token exchange requires an explicit resource or audience.",
            false,
        );
    }
    token_exchange_error_response(error)
}

pub fn token_exchange_subject_error_response(
    error: TokenExchangeError,
    client: &ClientRow,
    form: &TokenForm,
    claims: &Claims,
) -> OAuthEndpointError {
    if error == TokenExchangeError::InvalidScope {
        let requested = parse_scope(form.scope.as_deref().unwrap_or(""));
        let subject_scopes = parse_scope(&claims.scope);
        let safe_default_is_empty = requested.is_empty()
            && !subject_scopes
                .iter()
                .any(|scope| scope != "openid" && client.scopes.contains(scope));
        let description = if safe_default_is_empty {
            "token exchange cannot issue an access token without non-OIDC scopes."
        } else {
            "token exchange scope must be a subset of the subject token and client scopes."
        };
        return OAuthEndpointError::token(
            StatusCode::BAD_REQUEST,
            "invalid_scope",
            description,
            false,
        );
    }
    if claims.client_id != client.client_id {
        return OAuthEndpointError::token(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "client is not authorized to exchange this subject token.",
            false,
        );
    }
    if claims
        .user_id
        .as_deref()
        .is_some_and(|user_id| user_id.parse::<Uuid>().is_err())
    {
        return OAuthEndpointError::token(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "subject token contains an invalid user boundary.",
            false,
        );
    }
    token_exchange_error_response(error)
}

pub async fn validate_exchange_access_token(
    token_service: &ServerTokenService,
    issuer: &str,
    client: &ClientRow,
    raw_token: &str,
    policy: TokenExchangePolicy<'_>,
) -> Result<Claims, TokenExchangeTokenError> {
    let Some(claims) = token_service
        .decode_access_token(issuer, raw_token)
        .await
        .map_err(|error| {
            tracing::warn!(?error, "failed to decode token exchange access token");
            TokenExchangeTokenError::StoreUnavailable
        })?
    else {
        return Err(TokenExchangeTokenError::Invalid);
    };
    validate_token_exchange_access_token(&claims, policy)
        .map_err(|_| TokenExchangeTokenError::Invalid)?;
    let revoked = token_service
        .access_token_revoked(client.tenant_id, &claims.jti)
        .await
        .map_err(|error| {
            tracing::warn!(%error, "failed to query token exchange access token revocation state");
            TokenExchangeTokenError::StoreUnavailable
        })?;
    if revoked {
        return Err(TokenExchangeTokenError::Invalid);
    }
    Ok(claims)
}

pub fn exchange_token_error_response(error: TokenExchangeTokenError) -> OAuthEndpointError {
    match error {
        TokenExchangeTokenError::Invalid => OAuthEndpointError::token(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "token exchange input token is invalid.",
            false,
        ),
        TokenExchangeTokenError::StoreUnavailable => OAuthEndpointError::token(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "token exchange token state is unavailable.",
            false,
        ),
    }
}

pub async fn validate_subject_sender_binding(
    issuance: &TokenIssuanceContext<'_>,
    facts: &TokenRequestFacts<'_>,
    client: &ClientRow,
    subject_token: &str,
    subject_binding: &TokenExchangeSenderBinding,
) -> Result<ValidatedSenderConstraints, OAuthEndpointError> {
    let (expected_dpop, expected_mtls, token_for_ath) = match subject_binding {
        TokenExchangeSenderBinding::Dpop(jkt) => (Some(jkt.as_str()), None, Some(subject_token)),
        TokenExchangeSenderBinding::MutualTls(thumbprint) => {
            (None, Some(thumbprint.as_str()), None)
        }
        TokenExchangeSenderBinding::Bearer => (None, None, None),
    };
    validate_token_sender_constraints(
        issuance,
        facts,
        client,
        token_for_ath,
        expected_dpop,
        expected_mtls,
    )
    .await
    .map_err(|error| match error {
        SenderConstraintValidationError::Dpop(DpopError::MissingProof)
            if matches!(subject_binding, TokenExchangeSenderBinding::MutualTls(_))
                && client.require_dpop_bound_tokens
                && !client.require_mtls_bound_tokens =>
        {
            OAuthEndpointError::token(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "token exchange cannot convert mTLS subject binding to DPoP.",
                false,
            )
        }
        SenderConstraintValidationError::Dpop(error) => OAuthEndpointError::Dpop {
            error,
            context: DpopErrorContext::TokenEndpoint,
        },
        SenderConstraintValidationError::MissingMtls
            if matches!(subject_binding, TokenExchangeSenderBinding::Dpop(_))
                && client.require_mtls_bound_tokens
                && !client.require_dpop_bound_tokens =>
        {
            OAuthEndpointError::token(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "token exchange cannot convert DPoP subject binding to mTLS.",
                false,
            )
        }
        SenderConstraintValidationError::MissingMtls
            if matches!(subject_binding, TokenExchangeSenderBinding::MutualTls(_)) =>
        {
            OAuthEndpointError::token(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "mTLS-bound subject token requires a verified client certificate.",
                false,
            )
        }
        SenderConstraintValidationError::MissingMtls => OAuthEndpointError::token(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "token exchange requires mTLS sender constraint.",
            false,
        ),
        SenderConstraintValidationError::Multiple => sender_constraint_multiple_error(),
    })
}

pub fn token_exchange_issue_binding(
    client: &ClientRow,
    subject_binding: &TokenExchangeSenderBinding,
    presented: &ValidatedSenderConstraints,
    policy: TokenExchangePolicy<'_>,
) -> Result<TokenExchangeSenderBinding, OAuthEndpointError> {
    token_exchange_issuance_binding(
        subject_binding,
        PresentedSenderConstraint {
            dpop_jkt: presented.dpop_jkt.as_deref(),
            mtls_x5t_s256: presented.mtls_x5t_s256.as_deref(),
        },
        policy,
    )
    .map_err(|_| match subject_binding {
        TokenExchangeSenderBinding::Dpop(_) if client.require_mtls_bound_tokens => {
            OAuthEndpointError::token(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "token exchange cannot convert DPoP subject binding to mTLS.",
                false,
            )
        }
        TokenExchangeSenderBinding::MutualTls(_) if client.require_dpop_bound_tokens => {
            OAuthEndpointError::token(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "token exchange cannot convert mTLS subject binding to DPoP.",
                false,
            )
        }
        _ => token_exchange_error_response(TokenExchangeError::InvalidGrant),
    })
}

fn token_exchange_binding_claims(
    binding: TokenExchangeSenderBinding,
) -> (Option<String>, Option<String>) {
    match binding {
        TokenExchangeSenderBinding::Bearer => (None, None),
        TokenExchangeSenderBinding::Dpop(jkt) => (Some(jkt), None),
        TokenExchangeSenderBinding::MutualTls(thumbprint) => (None, Some(thumbprint)),
    }
}

pub async fn validate_actor_token(
    token_service: &ServerTokenService,
    issuer: &str,
    client: &ClientRow,
    actor_token: Option<&str>,
    policy: TokenExchangePolicy<'_>,
) -> Result<Option<Value>, OAuthEndpointError> {
    let Some(actor_token) = actor_token else {
        return Ok(None);
    };
    let actor = validate_exchange_access_token(token_service, issuer, client, actor_token, policy)
        .await
        .map_err(exchange_token_error_response)?;
    match token_exchange_actor_claim(&actor, policy) {
        Ok(claim) => Ok(Some(claim)),
        Err(_) if actor.cnf.is_some() => Err(OAuthEndpointError::token(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "sender-constrained actor tokens are not supported for token exchange.",
            false,
        )),
        Err(_) => Err(OAuthEndpointError::token(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "actor token must be issued to the authenticated client.",
            false,
        )),
    }
}

pub async fn token_exchange(
    token_service: &ServerTokenService,
    authorization_service: &crate::services::ServerAuthorizationService,
    issuance: &TokenIssuanceContext<'_>,
    facts: &TokenRequestFacts<'_>,
    client: &ClientRow,
    form: &TokenForm,
    client_assertion: Option<&ValidatedClientAssertion>,
) -> Result<TokenEndpointSuccess, OAuthEndpointError> {
    if native_sso_profile_requested(form) {
        return token_native_sso_exchange(
            token_service,
            issuance,
            facts,
            client,
            form,
            client_assertion,
        )
        .await;
    }
    let request = token_exchange_request(form);
    let policy = token_exchange_policy(issuance, client, Utc::now().timestamp());
    if let Err(error) = validate_token_exchange_grant_prerequisites(&request, policy) {
        return Err(token_exchange_error_response(error));
    }
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
    let subject_token = form
        .subject_token
        .as_deref()
        .expect("validated token exchange form must contain subject_token");
    let subject = match validate_exchange_access_token(
        token_service,
        issuance.config.issuer(),
        client,
        subject_token,
        policy,
    )
    .await
    {
        Ok(claims) => claims,
        Err(error) => return Err(exchange_token_error_response(error)),
    };
    let validated_subject =
        match validate_token_exchange_subject(&subject, form.scope.as_deref(), policy) {
            Ok(subject) => subject,
            Err(error) => {
                return Err(token_exchange_subject_error_response(
                    error, client, form, &subject,
                ));
            }
        };
    let presented_sender = match validate_subject_sender_binding(
        issuance,
        facts,
        client,
        subject_token,
        &validated_subject.sender_binding,
    )
    .await
    {
        Ok(presented) => presented,
        Err(response) => return Err(response),
    };
    let issuance_binding = match token_exchange_issue_binding(
        client,
        &validated_subject.sender_binding,
        &presented_sender,
        policy,
    ) {
        Ok(binding) => binding,
        Err(response) => return Err(response),
    };
    let (dpop_jkt, mtls_x5t_s256) = token_exchange_binding_claims(issuance_binding);
    let actor = match validate_actor_token(
        token_service,
        issuance.config.issuer(),
        client,
        form.actor_token.as_deref(),
        policy,
    )
    .await
    {
        Ok(actor) => actor,
        Err(response) => return Err(response),
    };
    let admission = match admit_token_exchange(&request, policy) {
        Ok(admission) => admission,
        Err(error) => return Err(token_exchange_admission_error_response(error, form)),
    };
    let idempotency_key = facts.idempotency_key.clone();
    let mode = idempotency_key.map_or(TokenIssuanceMode::Fresh, |grant_key| {
        TokenIssuanceMode::Idempotent { grant_key }
    });
    issue_token_response(
        issuance,
        token_service,
        client,
        mode,
        TokenIssue {
            user_id: validated_subject.user_id,
            subject: validated_subject.subject,
            scopes: validated_subject.scopes,
            authorization_details: json!([]),
            audiences: admission.audiences,
            nonce: None,
            auth_time: None,
            amr: Vec::new(),
            oidc_sid: None,
            acr: None,
            userinfo_claims: Vec::new(),
            userinfo_claim_requests: Vec::new(),
            id_token_claims: Vec::new(),
            id_token_claim_requests: Vec::new(),
            refresh_id_token_sid: None,
            include_refresh: false,
            refresh_token_policy: RefreshTokenPolicy::PreserveExisting,
            dpop_jkt,
            refresh_token_dpop_jkt: None,
            mtls_x5t_s256,
            refresh_token_mtls_x5t_s256: None,
            refresh_token_client_attestation_jkt: None,
            refresh_token_scopes: None,
            authorization_code_hash: None,
            actor,
            issued_token_type: Some(admission.issued_token_type),
            native_sso: None,
        },
    )
    .await
}

#[cfg(test)]
#[path = "../../tests/unit/token/token_exchange.rs"]
mod tests;
