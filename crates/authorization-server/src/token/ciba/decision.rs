//! CIBA verification and authenticated user decisions.
use super::application::CibaApplication;
use super::state::CibaDecisionSource;
use crate::{
    contracts::{ciba::CibaAuthorizationRequestView, oauth_error::OAuthEndpointError},
    crypto::blake3_hex,
    ports::audit::{SecurityAudit, audit_fields},
    services::{ServerAuthorizationService, ServerCibaService},
    sessions::CurrentSession,
};
use chrono::{DateTime, Utc};
use http::StatusCode;
use nazo_auth::{
    CibaAuthenticationContext, CibaCommittedDecision, CibaDecision, CibaDecisionFailure,
    CibaRequestState, CibaStatePortError, CibaStatus,
};
use serde_json::json;
use uuid::Uuid;

impl CibaApplication {
    pub fn verification_page_location(&self, auth_req_id: &str) -> String {
        format!(
            "{}/ciba/{}",
            self.handles.config.frontend_base_url.trim_end_matches('/'),
            urlencoding::encode(auth_req_id)
        )
    }
    pub async fn verification(
        &self,
        auth_req_id: &str,
        session: &CurrentSession,
    ) -> Result<Option<CibaAuthorizationRequestView>, OAuthEndpointError> {
        let state_payload =
            match load_ciba_request_payload(&self.handles.service, auth_req_id).await? {
                Some(value) => value,
                None => {
                    return Err(OAuthEndpointError::json(
                        StatusCode::NOT_FOUND,
                        "invalid_request",
                        "CIBA request expired.",
                    ));
                }
            };
        if state_payload.user_id != session.user.id() {
            return Err(OAuthEndpointError::json(
                StatusCode::FORBIDDEN,
                "access_denied",
                "CIBA request user mismatch.",
            ));
        }
        if state_payload.status == CibaStatus::Pending
            && state_payload.expires_at > Utc::now().timestamp()
        {
            ciba_authorization_request_view(&self.authorization, &state_payload).await
        } else {
            Ok(None)
        }
    }
    pub async fn decide(
        &self,
        auth_req_id: String,
        decision: &str,
        session: &CurrentSession,
        source_ip: &str,
    ) -> Result<(), OAuthEndpointError> {
        if !matches!(decision, "approve" | "deny") {
            return Err(OAuthEndpointError::json(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "CIBA decision is invalid.",
            ));
        }
        let decision = if decision == "approve" {
            CibaDecision::Approve(CibaAuthenticationContext {
                auth_time: session.auth_time,
                amr: session.amr.clone(),
                oidc_sid: Some(session.oidc_sid.clone()),
            })
        } else {
            CibaDecision::Deny
        };
        set_ciba_request_decision(
            &self.handles.service,
            self.security_audit.as_ref(),
            CibaDecisionCommand {
                auth_req_id,
                decision,
                expected_user_id: Some(session.user.id()),
                source: CibaDecisionSource::User,
                source_ip_hash: Some(blake3_hex(source_ip)),
            },
        )
        .await
    }
}
async fn load_ciba_request_payload(
    ciba_service: &ServerCibaService,
    auth_req_id: &str,
) -> Result<Option<CibaRequestState>, OAuthEndpointError> {
    ciba_service
        .load(auth_req_id)
        .await
        .map(|stored| stored.map(|stored| stored.into_state()))
        .map_err(ciba_state_error)
}
fn ciba_state_error(error: CibaStatePortError) -> OAuthEndpointError {
    tracing::warn!(%error,"failed to load CIBA state");
    OAuthEndpointError::authorization(
        StatusCode::SERVICE_UNAVAILABLE,
        "server_error",
        "CIBA state unavailable.",
    )
}
struct CibaDecisionCommand {
    auth_req_id: String,
    decision: CibaDecision,
    expected_user_id: Option<Uuid>,
    source: CibaDecisionSource,
    source_ip_hash: Option<String>,
}

async fn prepare_ciba_decision_intent(
    ciba_service: &ServerCibaService,
    security_audit: &dyn SecurityAudit,
    command: &CibaDecisionCommand,
) -> Result<(), OAuthEndpointError> {
    let state = match load_ciba_request_payload(ciba_service, &command.auth_req_id).await {
        Ok(Some(state)) => state,
        Ok(None) => {
            return Err(OAuthEndpointError::authorization(
                StatusCode::NOT_FOUND,
                "invalid_request",
                "CIBA request expired.",
            ));
        }
        Err(response) => return Err(response),
    };
    if let Err(error) = security_audit.ensure_storage().await {
        tracing::error!(%error, "CIBA decision audit preflight failed");
        return Err(OAuthEndpointError::authorization(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "CIBA decision audit storage unavailable.",
        ));
    }
    let decision_name = match &command.decision {
        CibaDecision::Approve(_) => "approve",
        CibaDecision::Deny => "deny",
    };
    let mut fields = audit_fields(&[
        ("client_id", json!(state.client_id)),
        ("user_id", json!(state.user_id)),
        ("auth_req_id_hash", json!(blake3_hex(&command.auth_req_id))),
        ("decision", json!(decision_name)),
        ("decision_source", json!(command.source.as_str())),
        ("scope", json!(state.scopes.join(" "))),
        ("audience", json!(state.audiences)),
    ]);
    if let Some(source_ip_hash) = command.source_ip_hash.as_deref() {
        fields.insert("source_ip_hash".to_owned(), json!(source_ip_hash));
    }
    if let Some(expected_user_id) = command.expected_user_id {
        fields.insert("expected_user_id".to_owned(), json!(expected_user_id));
    }
    security_audit
        .record_required("ciba_decision_intent", fields)
        .await
        .map_err(|error| {
            tracing::error!(%error, "CIBA decision audit intent failed");
            OAuthEndpointError::authorization(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "CIBA decision audit could not be persisted.",
            )
        })
}

async fn set_ciba_request_decision(
    ciba_service: &ServerCibaService,
    security_audit: &dyn SecurityAudit,
    command: CibaDecisionCommand,
) -> Result<(), OAuthEndpointError> {
    prepare_ciba_decision_intent(ciba_service, security_audit, &command).await?;
    let CibaDecisionCommand {
        auth_req_id,
        decision,
        expected_user_id,
        source,
        source_ip_hash,
    } = command;
    let result = ciba_service
        .decide(&auth_req_id, decision, expected_user_id, || {
            Utc::now().timestamp()
        })
        .await;
    complete_ciba_decision(security_audit, result, &auth_req_id, source, source_ip_hash)
}

fn complete_ciba_decision(
    security_audit: &dyn SecurityAudit,
    result: Result<CibaCommittedDecision, CibaDecisionFailure>,
    auth_req_id: &str,
    source: CibaDecisionSource,
    source_ip_hash: Option<String>,
) -> Result<(), OAuthEndpointError> {
    match result {
        Ok(committed) => {
            let event = match &committed.decision {
                CibaDecision::Approve(_) => "ciba_authorization_approved",
                CibaDecision::Deny => "ciba_authorization_denied",
            };
            let decision_name = match &committed.decision {
                CibaDecision::Approve(_) => "approve",
                CibaDecision::Deny => "deny",
            };
            let mut fields = audit_fields(&[
                ("client_id", json!(committed.state.client_id)),
                ("user_id", json!(committed.state.user_id)),
                ("auth_req_id_hash", json!(blake3_hex(auth_req_id))),
                ("decision", json!(decision_name)),
                ("decision_source", json!(source.as_str())),
            ]);
            if let Some(source_ip_hash) = source_ip_hash {
                fields.insert("source_ip_hash".to_owned(), json!(source_ip_hash));
            }
            security_audit.record(event, fields);
            Ok(())
        }
        Err(CibaDecisionFailure::Missing | CibaDecisionFailure::Expired) => {
            Err(OAuthEndpointError::authorization(
                StatusCode::NOT_FOUND,
                "invalid_request",
                "CIBA request expired.",
            ))
        }
        Err(CibaDecisionFailure::UserMismatch) => Err(OAuthEndpointError::authorization(
            StatusCode::FORBIDDEN,
            "access_denied",
            "CIBA request user mismatch.",
        )),
        Err(CibaDecisionFailure::AlreadyHandled) => Err(OAuthEndpointError::authorization(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "CIBA request was already handled.",
        )),
        Err(CibaDecisionFailure::InvalidAuthenticationContext) => {
            Err(OAuthEndpointError::authorization(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "CIBA authentication context is invalid.",
            ))
        }
        Err(CibaDecisionFailure::Storage(error)) => Err(ciba_state_error(error)),
        Err(CibaDecisionFailure::Contended) => Err(OAuthEndpointError::authorization(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "CIBA state is busy.",
        )),
    }
}

async fn ciba_authorization_request_view(
    authorization_service: &ServerAuthorizationService,
    payload: &CibaRequestState,
) -> Result<Option<CibaAuthorizationRequestView>, OAuthEndpointError> {
    let client = match authorization_service.client_by_id(&payload.client_id).await {
        Ok(Some(client)) if client.is_active => client,
        Ok(_) => return Ok(None),
        Err(error) => {
            tracing::warn!(%error, "failed to load CIBA client for verification page");
            return Err(OAuthEndpointError::json(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "CIBA client unavailable.",
            ));
        }
    };
    Ok(Some(CibaAuthorizationRequestView {
        client_id: payload.client_id.clone(),
        client_name: client.client_name.clone(),
        scopes: payload.scopes.clone(),
        audiences: payload.audiences.clone(),
        binding_message: payload.binding_message.clone(),
        interval_seconds: payload.interval_seconds,
        issued_at: DateTime::<Utc>::from_timestamp(payload.issued_at, 0).unwrap_or_else(Utc::now),
        expires_at: DateTime::<Utc>::from_timestamp(payload.expires_at, 0).unwrap_or_else(Utc::now),
    }))
}

#[cfg(test)]
#[path = "../../../tests/unit/token/ciba/decision.rs"]
mod tests;
