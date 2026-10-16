use crate::authorization::AuthorizationRequestContext;
use crate::authorization::request::{
    AuthorizationResponseRedirect, authorization_response_redirect_with_context,
};
use crate::authorization::{AuthorizationOutcome, AuthorizationRequestFacts};
use crate::contracts::oauth_error::OAuthEndpointError;
use crate::crypto::blake3_hex;
use crate::crypto::random_urlsafe_token;
use crate::domain::oauth::ConsentPayload;
use crate::domain::rows::ClientRow;
use crate::ports::audit::audit_fields;
use chrono::{DateTime, Utc};
use http::StatusCode;
use nazo_auth::{
    AuthorizationApprovalInput, AuthorizationDecisionCommit, AuthorizationDecisionCommitResult,
    AuthorizationDecisionKind, prepare_authorization_code,
};
use serde_json::{Value, json};
use uuid::Uuid;

pub(super) async fn issue_authorization_code_without_interaction_with_context(
    context: &AuthorizationRequestContext<'_>,
    client: &mut ClientRow,
    facts: &AuthorizationRequestFacts<'_>,
    payload: ConsentPayload,
    pushed_request_expires_at: Option<DateTime<Utc>>,
    pushed_request_version: Option<&str>,
) -> Result<AuthorizationOutcome, OAuthEndpointError> {
    let ttl_seconds = payload
        .authorization_code_ttl_seconds
        .expect("prompt-none uses the freshly admitted authorization request");
    context
        .security_audit
        .ensure_transactional_ready()
        .await
        .map_err(|error| {
            tracing::error!(%error, "prompt-none authorization audit readiness failed");
            OAuthEndpointError::json(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "Authorization audit is unavailable.",
            )
        })?;
    // Prompt-none shares the same durable decision fence as interactive
    // approval. Preparation/cache disposal cannot grant authorization.
    // Only request context is supplied here; the commit binds its own digests
    // and derives actor, client, decision and scope from durable inputs.
    let mut intent_fields = audit_fields([("source_ip_hash", json!(blake3_hex(facts.source_ip)))]);
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
    let requests_openid = payload.scopes.iter().any(|scope| scope == "openid");
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
                scopes: payload.scopes,
                resource_indicators: payload.resource_indicators,
                authorization_details: payload.authorization_details,
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
            client,
            AuthorizationResponseRedirect {
                redirect_uri: &payload.redirect_uri,
                response_mode: payload.response_mode.as_deref(),
                code: None,
                error: Some(error),
                state: payload.state.as_deref(),
                oidc_sid: None,
            },
        )
        .await;
    }
    // Cleanup uses the admission snapshot, never a reread or reconstructed
    // version. The committed decision remains authoritative if cleanup fails.
    if let (Some(uri), Some(version)) = (
        payload.pushed_request_uri.as_deref(),
        pushed_request_version,
    ) && let Err(error) = context
        .service
        .discard_pushed_authorization_request(uri, version)
        .await
    {
        tracing::warn!(
            ?error,
            "failed to discard committed prompt-none preparation"
        );
    }
    if requests_openid {
        let bound = match facts.session_id {
            Some(session_id) => context
                .sessions
                .bind_client(session_id, &payload.client_id)
                .await
                .map_err(|error| {
                    tracing::warn!(%error, "failed to bind silent RP login to OP browser session");
                    OAuthEndpointError::json(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "server_error",
                        "Session binding is unavailable.",
                    )
                })?,
            None => false,
        };
        if !bound {
            return authorization_response_redirect_with_context(
                context,
                client,
                AuthorizationResponseRedirect {
                    redirect_uri: &payload.redirect_uri,
                    response_mode: payload.response_mode.as_deref(),
                    code: None,
                    error: Some("login_required"),
                    state: payload.state.as_deref(),
                    oidc_sid: None,
                },
            )
            .await;
        }
    }
    authorization_response_redirect_with_context(
        context,
        client,
        AuthorizationResponseRedirect {
            redirect_uri: &payload.redirect_uri,
            response_mode: payload.response_mode.as_deref(),
            code: Some(&code),
            error: None,
            state: payload.state.as_deref(),
            oidc_sid: payload.oidc_sid.as_deref(),
        },
    )
    .await
}

#[cfg(test)]
#[path = "../../../tests/unit/authorization/request/prompt_none.rs"]
mod tests;
