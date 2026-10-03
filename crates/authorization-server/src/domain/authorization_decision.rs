use std::sync::Arc;

use crate::contracts::authorization_decision::{
    AuthorizationDecisionCommand, AuthorizationDecisionError, AuthorizationDecisionFuture,
    AuthorizationDecisionOperations, AuthorizationDecisionResponse,
};
use chrono::Utc;
use nazo_auth::{
    AuthorizationApprovalInput, AuthorizationDecisionAdmissionError, AuthorizationDecisionCommit,
    AuthorizationDecisionCommitResult, AuthorizationDecisionKind, AuthorizationResponsePlan,
    AuthorizationResponsePolicyError, AuthorizationResponsePolicyInput, CapabilityAdmission,
    SignedJarmAuthorizationResponse, UserAuthorizationDecision, module_admissible,
    plain_authorization_response_uri, plan_authorization_response, prepare_authorization_code,
    signed_jarm_authorization_response_uri,
};
use nazo_identity::{SessionResolution, SessionService};
use nazo_runtime_modules::ModuleId;
use serde_json::json;
use uuid::Uuid;

use crate::authorization::config::AuthorizationConfig;
use crate::crypto::blake3_hex;
use crate::crypto::random_urlsafe_token;
use crate::domain::client_jwe::JwePayloadKind;
use crate::domain::client_jwe::client_jwe_key;
use crate::domain::client_jwe::encrypt_compact_jwe;
use crate::domain::client_policy::refresh_client_jwks_for_encryption;
use crate::ports::audit::{SecurityAudit, audit_fields};
use crate::services::ServerAuthorizationService;
use nazo_runtime_modules::SnapshotStore;

#[derive(Clone)]
pub struct ServerAuthorizationDecisionOperations {
    service: Arc<ServerAuthorizationService>,
    sessions: SessionService,
    tenant_id: nazo_identity::TenantId,
    config: Arc<AuthorizationConfig>,
    runtime_modules: Arc<SnapshotStore>,
    security_audit: Arc<dyn SecurityAudit>,
    remote_client_documents:
        Arc<dyn crate::contracts::dynamic_client_registration::RemoteJwksResolverPort>,
}

impl ServerAuthorizationDecisionOperations {
    pub fn new(
        service: Arc<ServerAuthorizationService>,
        sessions: SessionService,
        tenant_id: nazo_identity::TenantId,
        config: Arc<AuthorizationConfig>,
        runtime_modules: Arc<SnapshotStore>,
        remote_client_documents: Arc<
            dyn crate::contracts::dynamic_client_registration::RemoteJwksResolverPort,
        >,
        security_audit: Arc<dyn SecurityAudit>,
    ) -> Self {
        Self {
            service,
            sessions,
            tenant_id,
            config,
            runtime_modules,
            security_audit,
            remote_client_documents,
        }
    }

    async fn decide_inner(
        &self,
        command: AuthorizationDecisionCommand,
    ) -> Result<AuthorizationDecisionResponse, AuthorizationDecisionError> {
        let session = match self
            .sessions
            .current(&command.session_id, Utc::now().timestamp())
            .await
            .map_err(|error| {
                tracing::warn!(%error, "failed to resolve authorization decision session");
                AuthorizationDecisionError::SessionLookupUnavailable
            })? {
            SessionResolution::Present(session) => session,
            SessionResolution::Missing | SessionResolution::Invalidated => {
                return Err(AuthorizationDecisionError::LoginRequired);
            }
        };

        self.security_audit
            .ensure_transactional_ready()
            .await
            .map_err(|error| {
                tracing::error!(%error, "authorization decision audit preflight failed");
                AuthorizationDecisionError::AuditUnavailable
            })?;
        let decision = match command.decision {
            UserAuthorizationDecision::Approve => "approve",
            UserAuthorizationDecision::Deny => "deny",
        };

        // 1. Non-destructive preview: consent + PAR are loaded and validated,
        //    nothing is consumed yet.
        let preview = match self
            .service
            .preview_user_decision(&command.request_id, session.user().id())
            .await
        {
            Ok(preview) => preview,
            Err(
                AuthorizationDecisionAdmissionError::ConsentMissing
                | AuthorizationDecisionAdmissionError::ConsentMalformed,
            ) => return Err(AuthorizationDecisionError::ConsentInvalid),
            Err(AuthorizationDecisionAdmissionError::ConsentReadFailed(error)) => {
                tracing::warn!(%error, "failed to claim authorization consent state");
                return Err(AuthorizationDecisionError::ConsentReadUnavailable);
            }
            Err(AuthorizationDecisionAdmissionError::UserMismatch) => {
                return Err(AuthorizationDecisionError::UserMismatch);
            }
            Err(AuthorizationDecisionAdmissionError::PushedRequestMissing(consent)) => {
                return self
                    .response_location(&consent, None, Some("invalid_request_uri"), None)
                    .await;
            }
            Err(AuthorizationDecisionAdmissionError::PushedRequestMalformed(consent)) => {
                tracing::warn!("PAR payload is malformed while claiming authorization consent");
                return self
                    .response_location(&consent, None, Some("server_error"), None)
                    .await;
            }
            Err(AuthorizationDecisionAdmissionError::PushedRequestReadFailed {
                consent,
                source,
            }) => {
                tracing::warn!(%source, "failed to claim consent-bound PAR state");
                return self
                    .response_location(&consent, None, Some("server_error"), None)
                    .await;
            }
        };

        let establishes_oidc_login = preview
            .consent()
            .scopes
            .iter()
            .any(|scope| scope == "openid");
        if establishes_oidc_login
            && preview.consent().oidc_sid.as_deref() != Some(session.oidc_sid())
        {
            tracing::warn!("authorization consent is not bound to the current OP browser session");
            return Err(AuthorizationDecisionError::ConsentInvalid);
        }

        // Prepare the immutable committed-decision fact. No authority is
        // consumed and no usable code is published before its durable commit.
        let mut intent_fields = audit_fields(&[
            ("request_id_hash", json!(blake3_hex(&command.request_id))),
            ("user_id", json!(session.user().id())),
            ("client_id", json!(preview.consent().client_id.clone())),
            ("decision", json!(decision)),
            ("scope", json!(preview.consent().scopes.join(" "))),
            ("source_ip_hash", json!(blake3_hex(&command.source_ip))),
        ]);
        if !preview.consent().resource_indicators.is_empty() {
            intent_fields.insert(
                "resource_digest".to_owned(),
                json!(blake3_hex(
                    &preview.consent().resource_indicators.join("\u{1f}")
                )),
            );
        }
        if preview
            .consent()
            .authorization_details
            .as_array()
            .is_some_and(|details| !details.is_empty())
        {
            intent_fields.insert(
                "authorization_details_digest".to_owned(),
                json!(blake3_hex(
                    &preview.consent().authorization_details.to_string()
                )),
            );
        }
        if let Some(digest) = preview.consent().pushed_request_digest.as_deref() {
            intent_fields.insert("pushed_request_digest".to_owned(), json!(digest));
        }
        let valid_until = preview.valid_until();
        let retain_until = preview.retain_until();
        let payload = preview.consent().clone();
        let now = Utc::now();
        let event_id = Uuid::now_v7();
        let code =
            (command.decision == UserAuthorizationDecision::Approve).then(random_urlsafe_token);
        let prepared = code.as_ref().map(|code| {
            prepare_authorization_code(AuthorizationApprovalInput {
                consent: &payload,
                code_hash: &blake3_hex(code),
                code_id: &event_id.to_string(),
                issued_at: now,
                code_ttl_seconds: payload
                    .authorization_code_ttl_seconds
                    .unwrap_or(self.config.auth_code_ttl_seconds),
                tenant_id: self.tenant_id.as_uuid(),
            })
        });
        let result = self
            .service
            .commit_decision(
                AuthorizationDecisionCommit {
                    tenant_id: self.tenant_id.as_uuid(),
                    user_id: payload.user_id,
                    client_id: payload.client_id.clone(),
                    request_id: command.request_id.clone(),
                    pushed_request_uri: payload.pushed_request_uri.clone(),
                    valid_until,
                    retain_until,
                    decision: if command.decision == UserAuthorizationDecision::Approve {
                        AuthorizationDecisionKind::Approve
                    } else {
                        AuthorizationDecisionKind::Deny
                    },
                    event_id,
                    occurred_at: now,
                    audit_fields: serde_json::Value::Object(intent_fields),
                    scopes: payload.scopes.clone(),
                    resource_indicators: payload.resource_indicators.clone(),
                    authorization_details: payload.authorization_details.clone(),
                },
                prepared,
            )
            .await
            .map_err(|error| {
                tracing::warn!(%error, "authorization decision commit or code publication failed");
                AuthorizationDecisionError::ApprovalUnavailable
            })?;
        match result {
            AuthorizationDecisionCommitResult::Committed => {}
            AuthorizationDecisionCommitResult::Conflict
            | AuthorizationDecisionCommitResult::Expired => {
                return Err(AuthorizationDecisionError::ConsentInvalid);
            }
            AuthorizationDecisionCommitResult::ClientUnavailable
            | AuthorizationDecisionCommitResult::GrantUnavailable => {
                return Err(AuthorizationDecisionError::ApprovalUnavailable);
            }
        }
        // The original consent/PAR TTL disposes preparation. The durable
        // accepting decision owns reuse prevention; response completion does
        // not wait for cache compare-delete or start detached cleanup work.
        let Some(code) = code else {
            return self
                .response_location(&payload, None, Some("access_denied"), None)
                .await;
        };

        if establishes_oidc_login
            && !self
                .sessions
                .bind_client(&command.session_id, &payload.client_id)
                .await
                .map_err(|error| {
                    tracing::warn!(%error, "failed to bind logged-in RP to OP browser session");
                    AuthorizationDecisionError::SessionLookupUnavailable
                })?
        {
            tracing::warn!("OP browser session disappeared while binding logged-in RP");
            return Err(AuthorizationDecisionError::LoginRequired);
        }

        self.response_location(&payload, Some(&code), None, payload.oidc_sid.as_deref())
            .await
    }

    async fn response_location(
        &self,
        payload: &nazo_auth::ConsentPayload,
        code: Option<&str>,
        error: Option<&str>,
        oidc_sid: Option<&str>,
    ) -> Result<AuthorizationDecisionResponse, AuthorizationDecisionError> {
        let modules = self.runtime_modules.load_full();
        let plan = plan_authorization_response(AuthorizationResponsePolicyInput {
            issuer: &self.config.issuer,
            redirect_uri: &payload.redirect_uri,
            client_id: &payload.client_id,
            response_mode: payload.response_mode.as_deref(),
            code,
            error,
            state: payload.state.as_deref(),
            ttl_seconds: payload
                .authorization_code_ttl_seconds
                .unwrap_or(self.config.auth_code_ttl_seconds) as i64,
            signed_response_required: payload
                .signed_authorization_response_required
                .unwrap_or_else(|| self.config.profile.requires_signed_authorization_response()),
            jarm_available: module_admissible(
                &modules,
                ModuleId::Jarm,
                CapabilityAdmission::ExistingTransaction,
            ),
            session_management_available: payload.session_management_allowed.unwrap_or(true)
                && module_admissible(
                    &modules,
                    ModuleId::SessionManagement,
                    CapabilityAdmission::NewRequest,
                ),
        })
        .map_err(map_response_policy_error)?;

        let response = match plan {
            AuthorizationResponsePlan::Plain(plain) => {
                let session_state = if plain.issue_session_state {
                    oidc_sid.and_then(|sid| {
                        nazo_auth::issue_oidc_session_state(
                            &payload.client_id,
                            &payload.redirect_uri,
                            sid,
                        )
                    })
                } else {
                    None
                };
                AuthorizationDecisionResponse::Redirect {
                    location: plain_authorization_response_uri(&plain, session_state.as_deref()),
                }
            }
            AuthorizationResponsePlan::FormPost(plain) => {
                let session_state = if plain.issue_session_state {
                    oidc_sid.and_then(|sid| {
                        nazo_auth::issue_oidc_session_state(
                            &payload.client_id,
                            &payload.redirect_uri,
                            sid,
                        )
                    })
                } else {
                    None
                };
                AuthorizationDecisionResponse::FormPost {
                    action: plain.redirect_uri,
                    parameters: plain.parameters,
                    session_state,
                    csp_nonce: random_urlsafe_token(),
                }
            }
            AuthorizationResponsePlan::Jarm(jarm) => {
                let mut client = self
                    .service
                    .client_by_id(&payload.client_id)
                    .await
                    .map_err(|error| {
                        tracing::warn!(%error, client_id_hash = %blake3_hex(&payload.client_id), "failed to load JARM client response policy");
                        AuthorizationDecisionError::ResponseProtectionUnavailable
                    })?
                    .filter(|client| client.is_active)
                    .ok_or_else(|| {
                        tracing::warn!(client_id_hash = %blake3_hex(&payload.client_id), "JARM client is missing or inactive");
                        AuthorizationDecisionError::ResponseProtectionUnavailable
                    })?;
                let response_encryption_configured =
                    client.authorization_encrypted_response_alg.is_some()
                        || client.authorization_encrypted_response_enc.is_some();
                refresh_client_jwks_for_encryption(
                    &mut client,
                    self.remote_client_documents.as_ref(),
                    response_encryption_configured,
                )
                .await
                .map_err(|error| {
                    tracing::warn!(%error, "JARM encryption jwks_uri could not be refreshed");
                    AuthorizationDecisionError::ResponseProtectionUnavailable
                })?;
                let signed = self
                    .service
                    .sign_authorization_response(
                        jarm.signing_input(client.authorization_signed_response_alg.as_deref()),
                    )
                    .await
                    .map_err(|error| {
                        tracing::warn!(?error, "failed to sign JARM authorization response");
                        AuthorizationDecisionError::ResponseSigningUnavailable
                    })?;
                let response = match client_jwe_key(
                    client.jwks.as_ref(),
                    client.authorization_encrypted_response_alg.as_deref(),
                    client.authorization_encrypted_response_enc.as_deref(),
                    "authorization response",
                )
                .map_err(|error| {
                    tracing::warn!(%error, "failed to select JARM encryption key");
                    AuthorizationDecisionError::ResponseSigningUnavailable
                })? {
                    Some(key) => encrypt_compact_jwe(
                        &key,
                        signed.as_bytes(),
                        JwePayloadKind::NestedJwt,
                    )
                    .map_err(|error| {
                        tracing::warn!(%error, "failed to encrypt JARM authorization response");
                        AuthorizationDecisionError::ResponseSigningUnavailable
                    })?,
                    None => signed,
                };
                AuthorizationDecisionResponse::Redirect {
                    location: signed_jarm_authorization_response_uri(
                        &SignedJarmAuthorizationResponse {
                            redirect_uri: jarm.redirect_uri,
                            response,
                        },
                    ),
                }
            }
        };
        Ok(response)
    }
}

impl AuthorizationDecisionOperations for ServerAuthorizationDecisionOperations {
    fn decide(&self, command: AuthorizationDecisionCommand) -> AuthorizationDecisionFuture<'_> {
        Box::pin(self.decide_inner(command))
    }
}

fn map_response_policy_error(
    error: AuthorizationResponsePolicyError,
) -> AuthorizationDecisionError {
    match error {
        AuthorizationResponsePolicyError::UnsupportedResponseMode => {
            AuthorizationDecisionError::UnsupportedResponseMode
        }
        AuthorizationResponsePolicyError::MissingClientId => {
            AuthorizationDecisionError::ResponseSigningUnavailable
        }
        AuthorizationResponsePolicyError::Dependency(error) => {
            tracing::warn!(?error, "authorization response policy dependency failed");
            AuthorizationDecisionError::ResponseProtectionUnavailable
        }
    }
}
