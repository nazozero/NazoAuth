use crate::authorization::AuthorizationRequestContext;
use crate::authorization::request::{
    AuthorizationResponseClientPolicy, AuthorizationResponseRedirect,
    authorization_response_redirect_with_context,
};
use crate::authorization::{AuthorizationOutcome, AuthorizationRequestFacts};
use crate::contracts::oauth_error::OAuthEndpointError;
use crate::crypto::blake3_hex;
use crate::crypto::random_urlsafe_token;
use crate::domain::oauth::ConsentPayload;
use crate::ports::audit::audit_fields;
use chrono::{DateTime, Utc};
use http::StatusCode;
use nazo_auth::{
    AuthorizationApprovalInput, AuthorizationDecisionCommit, AuthorizationDecisionCommitResult,
    AuthorizationDecisionKind, prepare_authorization_code,
};
use serde_json::{Value, json};
use uuid::Uuid;

pub(super) async fn user_grant_covers_requested_scopes_with_context(
    context: &AuthorizationRequestContext<'_>,
    user_id: Uuid,
    client_id: Uuid,
    requested_scopes: &[String],
    requested_resource_indicators: &[String],
    requested_authorization_details: &Value,
) -> Result<bool, OAuthEndpointError> {
    match context
        .service
        .grant_covers(
            user_id,
            client_id,
            requested_scopes,
            requested_resource_indicators,
            requested_authorization_details,
        )
        .await
    {
        Ok(value) => Ok(value),
        Err(error) => {
            tracing::warn!(%error, "failed to query authorization grant");
            Err(OAuthEndpointError::json(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "授权记录查询失败.",
            ))
        }
    }
}

pub(super) async fn issue_authorization_code_without_interaction_with_context(
    context: &AuthorizationRequestContext<'_>,
    facts: &AuthorizationRequestFacts<'_>,
    payload: ConsentPayload,
    pushed_request_version: Option<&str>,
    pushed_request_expires_at: Option<DateTime<Utc>>,
) -> Result<AuthorizationOutcome, OAuthEndpointError> {
    let (Some(signed_response_required), Some(session_management_allowed), Some(ttl_seconds)) = (
        payload.signed_authorization_response_required,
        payload.session_management_allowed,
        payload.authorization_code_ttl_seconds,
    ) else {
        return Err(OAuthEndpointError::json(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "authorization request has no current client security policy.",
        ));
    };
    let response_policy = AuthorizationResponseClientPolicy {
        signed_response_required,
        session_management_allowed,
        ttl_seconds,
    };
    // Prompt-none shares the same durable decision fence as interactive
    // approval. Preparation/cache disposal cannot grant authorization.
    let mut intent_fields = audit_fields(&[
        ("request_id_hash", json!(blake3_hex(&payload.request_id))),
        ("user_id", json!(payload.user_id)),
        ("client_id", json!(payload.client_id.clone())),
        ("decision", json!("approve")),
        ("decision_source", json!("prompt_none")),
        ("scope", json!(payload.scopes.join(" "))),
        ("source_ip_hash", json!(blake3_hex(facts.source_ip))),
    ]);
    if !payload.resource_indicators.is_empty() {
        intent_fields.insert(
            "resource_digest".to_owned(),
            json!(blake3_hex(&payload.resource_indicators.join("\u{1f}"))),
        );
    }
    if payload
        .authorization_details
        .as_array()
        .is_some_and(|details| !details.is_empty())
    {
        intent_fields.insert(
            "authorization_details_digest".to_owned(),
            json!(blake3_hex(&payload.authorization_details.to_string())),
        );
    }
    if let Some(digest) = payload.pushed_request_digest.as_deref() {
        intent_fields.insert("pushed_request_digest".to_owned(), json!(digest));
    }
    let retain_until = pushed_request_expires_at.map_or(payload.expires_at, |expires_at| {
        payload.expires_at.max(expires_at)
    });
    let valid_until = match (
        payload.pushed_request_uri.as_ref(),
        pushed_request_expires_at,
    ) {
        (Some(_), Some(expires_at)) => payload.expires_at.min(expires_at),
        (None, _) => payload.expires_at,
        (Some(_), None) => {
            return Err(OAuthEndpointError::json(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "授权请求期限不可用.",
            ));
        }
    };
    let now = Utc::now();
    let event_id = Uuid::now_v7();
    let code = random_urlsafe_token();
    let oidc_sid = payload.oidc_sid.clone();
    let prepared = prepare_authorization_code(AuthorizationApprovalInput {
        consent: &payload,
        code_hash: &blake3_hex(&code),
        code_id: &event_id.to_string(),
        issued_at: now,
        code_ttl_seconds: ttl_seconds,
        tenant_id: context.tenant_id,
    });
    let result = context
        .service
        .commit_decision(
            AuthorizationDecisionCommit {
                tenant_id: context.tenant_id,
                user_id: payload.user_id,
                client_id: payload.client_id.clone(),
                request_id: payload.request_id.clone(),
                pushed_request_uri: payload.pushed_request_uri.clone(),
                valid_until,
                retain_until,
                decision: AuthorizationDecisionKind::PromptNone,
                event_id,
                occurred_at: now,
                audit_fields: Value::Object(intent_fields),
                scopes: payload.scopes.clone(),
                resource_indicators: payload.resource_indicators.clone(),
                authorization_details: payload.authorization_details.clone(),
            },
            Some(prepared),
        )
        .await
        .map_err(|error| {
            tracing::warn!(%error, "prompt-none decision commit or code publication failed");
            OAuthEndpointError::json(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "授权决定提交失败.",
            )
        })?;
    if result != AuthorizationDecisionCommitResult::Committed {
        let error = match result {
            AuthorizationDecisionCommitResult::Conflict
            | AuthorizationDecisionCommitResult::Expired => {
                if payload.pushed_request_uri.is_some() {
                    "invalid_request_uri"
                } else {
                    "invalid_request"
                }
            }
            AuthorizationDecisionCommitResult::GrantUnavailable => "consent_required",
            _ => "server_error",
        };
        return authorization_response_redirect_with_context(
            context,
            AuthorizationResponseRedirect {
                redirect_uri: &payload.redirect_uri,
                client_id: &payload.client_id,
                response_mode: payload.response_mode.as_deref(),
                code: None,
                error: Some(error),
                state: payload.state.as_deref(),
                oidc_sid: None,
                client_policy: Some(response_policy),
            },
        )
        .await;
    }
    if let (Some(uri), Some(version)) = (
        payload.pushed_request_uri.as_deref(),
        pushed_request_version,
    ) && let Err(error) = context
        .service
        .discard_pushed_authorization_request(uri, version)
        .await
    {
        tracing::warn!(?error, "failed to discard committed PAR preparation");
    }
    authorization_response_redirect_with_context(
        context,
        AuthorizationResponseRedirect {
            redirect_uri: &payload.redirect_uri,
            client_id: &payload.client_id,
            response_mode: payload.response_mode.as_deref(),
            code: Some(&code),
            error: None,
            state: payload.state.as_deref(),
            oidc_sid: oidc_sid.as_deref(),
            client_policy: Some(response_policy),
        },
    )
    .await
}

#[cfg(test)]
#[path = "../../../tests/unit/authorization/request/prompt_none.rs"]
mod tests;
