use std::sync::Arc;

use crate::contracts::scim::{
    ScimAuthenticationFacts, ScimAuthorizationError, ScimAuthorizedRequest, ScimCursorProtector,
    ScimDependencyError, ScimFuture, ScimRequestAuthorizer,
};
use hmac::{Hmac, KeyInit, Mac};
use nazo_identity::{
    TenantContext,
    scim::{
        SCIM_CURSOR_AAD, SCIM_CURSOR_KEY_LABEL, SCIM_CURSOR_NONCE_LEN, SCIM_CURSOR_TAG_LEN,
        ScimCursorSubject, ScimRequiredScope, ScimService, ScimTokenCredential,
        scim_credential_allows,
    },
};
use nazo_scim_events::{
    EventFuture, EventReceiver, EventSignerPort, EventSigningError, SecurityEventClaims,
};
use sha2::Sha256;

use crate::crypto::blake3_hex;
use crate::ports::audit::SecurityAudit;
use crate::ports::audit::audit_fields;

use nazo_runtime_modules::SnapshotStore;

type HmacSha256 = Hmac<Sha256>;

#[derive(Clone)]
pub struct ServerScimRequestAuthorizer {
    service: ScimService,
    tenant: TenantContext,
    audit: Arc<dyn SecurityAudit>,
    runtime_modules: Arc<SnapshotStore>,
    denial_rate_limit: Arc<dyn nazo_auth::RequestRateLimitPort>,
    denial_window_seconds: u64,
    denial_max_requests: u64,
}

impl ServerScimRequestAuthorizer {
    pub fn new(
        service: ScimService,
        tenant: TenantContext,
        runtime_modules: Arc<SnapshotStore>,
        audit: Arc<dyn SecurityAudit>,
        denial_rate_limit: Arc<dyn nazo_auth::RequestRateLimitPort>,
        denial_window_seconds: u64,
        denial_max_requests: u64,
    ) -> Self {
        Self {
            service,
            tenant,
            audit,
            runtime_modules,
            denial_rate_limit,
            denial_window_seconds,
            denial_max_requests,
        }
    }

    fn enabled(&self) -> bool {
        nazo_auth::module_admissible(
            &self.runtime_modules.load_full(),
            nazo_runtime_modules::ModuleId::Scim,
            nazo_auth::CapabilityAdmission::NewRequest,
        )
    }

    async fn credential(&self, token: &str) -> Result<ScimTokenCredential, ScimAuthorizationError> {
        match self.service.active_credential(&blake3_hex(token)).await {
            Ok(Some(credential)) => {
                if credential.tenant_id != self.tenant.tenant_id.as_uuid() {
                    return Err(ScimAuthorizationError::TenantMismatch);
                }
                Ok(credential)
            }
            Ok(None) => Err(ScimAuthorizationError::InvalidBearer),
            Err(error) => {
                tracing::warn!(%error, "failed to query SCIM token");
                Err(ScimAuthorizationError::BackendUnavailable)
            }
        }
    }

    fn record_use(
        &self,
        ip_hash: String,
        user_agent_hash: Option<String>,
        required_scope: ScimRequiredScope,
        credential: &ScimTokenCredential,
    ) {
        self.audit.record(
            "scim_token_used",
            audit_fields([
                ("token_id", serde_json::json!(credential.id)),
                (
                    "tenant_id",
                    serde_json::json!(self.tenant.tenant_id.as_uuid()),
                ),
                ("scope", serde_json::json!(required_scope.as_str())),
                ("source", serde_json::json!("database")),
                ("ip_hash", serde_json::json!(ip_hash)),
                ("user_agent_hash", serde_json::json!(user_agent_hash)),
            ]),
        );
    }

    async fn audit_denied(
        &self,
        ip_hash: &str,
        required_scope: ScimRequiredScope,
        reason: &str,
        token_id: Option<uuid::Uuid>,
    ) -> Result<(), ScimAuthorizationError> {
        let count = self
            .denial_rate_limit
            .increment(
                nazo_auth::RequestRateLimitBucket::TokenManagement,
                &format!("scim-denied:{ip_hash}"),
                self.denial_window_seconds,
            )
            .await
            .map_err(|_| ScimAuthorizationError::BackendUnavailable)?;
        if count > self.denial_max_requests {
            return Err(ScimAuthorizationError::RateLimited {
                retry_after_seconds: self.denial_window_seconds,
            });
        }
        // Denial evidence is Required: it must be durable before the rejection
        // is returned, so an audit outage fails closed as BackendUnavailable.
        self.audit
            .record_required(
                "scim_token_denied",
                audit_fields([
                    ("token_id", serde_json::json!(token_id)),
                    ("scope", serde_json::json!(required_scope.as_str())),
                    ("reason", serde_json::json!(reason)),
                    ("ip_hash", serde_json::json!(ip_hash)),
                ]),
            )
            .await
            .map_err(|error| {
                tracing::error!(%error, "SCIM denial audit append failed");
                ScimAuthorizationError::BackendUnavailable
            })
    }
}

impl ScimRequestAuthorizer for ServerScimRequestAuthorizer {
    fn authorize<'a>(
        &'a self,
        facts: ScimAuthenticationFacts<'a>,
        required_scope: ScimRequiredScope,
    ) -> ScimFuture<'a, Result<ScimAuthorizedRequest, ScimAuthorizationError>> {
        let enabled = self.enabled();
        let token = facts.bearer_token;
        Box::pin(async move {
            if !enabled {
                return Err(ScimAuthorizationError::Disabled);
            }
            let ip_hash = blake3_hex(&facts.source_ip);
            let Some(token) = token else {
                self.audit_denied(&ip_hash, required_scope, "missing_bearer", None)
                    .await?;
                return Err(ScimAuthorizationError::MissingBearer);
            };
            let credential = match self.credential(token).await {
                Ok(credential) => credential,
                Err(ScimAuthorizationError::InvalidBearer) => {
                    self.audit_denied(&ip_hash, required_scope, "invalid_token", None)
                        .await?;
                    return Err(ScimAuthorizationError::InvalidBearer);
                }
                Err(ScimAuthorizationError::TenantMismatch) => {
                    self.audit_denied(&ip_hash, required_scope, "tenant_mismatch", None)
                        .await?;
                    return Err(ScimAuthorizationError::TenantMismatch);
                }
                Err(error) => return Err(error),
            };
            if !scim_credential_allows(&credential.scopes, required_scope) {
                self.audit_denied(
                    &ip_hash,
                    required_scope,
                    "insufficient_scope",
                    Some(credential.id),
                )
                .await?;
                return Err(ScimAuthorizationError::InsufficientScope);
            }
            if !self.enabled() {
                return Err(ScimAuthorizationError::Disabled);
            }
            self.record_use(
                ip_hash,
                facts.user_agent.map(blake3_hex),
                required_scope,
                &credential,
            );
            Ok(ScimAuthorizedRequest {
                tenant: self.tenant,
                cursor_subject: ScimCursorSubject {
                    tenant_id: self.tenant.tenant_id.as_uuid(),
                    actor: format!("database:{}", credential.id),
                },
                event_receiver: credential.event_audience.map(|audience| EventReceiver {
                    token_id: credential.id,
                    tenant_id: self.tenant.tenant_id.as_uuid(),
                    audience,
                }),
            })
        })
    }

    fn security_events_enabled(&self) -> bool {
        nazo_auth::module_admissible(
            &self.runtime_modules.load_full(),
            nazo_runtime_modules::ModuleId::ScimSecurityEvents,
            nazo_auth::CapabilityAdmission::NewRequest,
        )
    }

    fn security_event_delivery_enabled(&self) -> bool {
        nazo_auth::module_admissible(
            &self.runtime_modules.load_full(),
            nazo_runtime_modules::ModuleId::ScimSecurityEvents,
            nazo_auth::CapabilityAdmission::ExistingTransaction,
        )
    }
}

#[derive(Clone)]
pub struct ServerScimEventSigner {
    keyset: nazo_key_management::KeyManager,
}

impl ServerScimEventSigner {
    #[must_use]
    pub fn new(keyset: nazo_key_management::KeyManager) -> Self {
        Self { keyset }
    }
}

impl EventSignerPort for ServerScimEventSigner {
    fn sign<'a>(
        &'a self,
        claims: &'a SecurityEventClaims,
    ) -> EventFuture<'a, Result<String, EventSigningError>> {
        Box::pin(async move {
            self.keyset
                .encode_response_jwt(
                    nazo_auth::SigningPurpose::SecurityEvent,
                    None,
                    nazo_scim_events::SECURITY_EVENT_MEDIA_TYPE,
                    claims,
                )
                .await
                .map_err(|_| EventSigningError::Unavailable)
        })
    }
}

#[derive(Clone)]
pub struct ServerScimCursorProtector {
    key: [u8; 32],
}

impl ServerScimCursorProtector {
    pub fn new(client_secret_pepper: &str) -> anyhow::Result<Self> {
        let mut mac = <HmacSha256 as KeyInit>::new_from_slice(client_secret_pepper.as_bytes())?;
        mac.update(SCIM_CURSOR_KEY_LABEL);
        Ok(Self {
            key: mac.finalize().into_bytes().into(),
        })
    }
}

impl ScimCursorProtector for ServerScimCursorProtector {
    fn protect(&self, plaintext: &[u8]) -> Result<Vec<u8>, ScimDependencyError> {
        let nonce = rand::random::<[u8; SCIM_CURSOR_NONCE_LEN]>();
        nazo_crypto::aead::encrypt_prefixed(&self.key, &nonce, SCIM_CURSOR_AAD, plaintext, &nonce)
            .map_err(|_| ScimDependencyError::Unavailable)
    }

    fn unprotect<'a>(&self, protected: &'a mut [u8]) -> Result<&'a [u8], ScimDependencyError> {
        if protected.len() <= SCIM_CURSOR_NONCE_LEN + SCIM_CURSOR_TAG_LEN {
            return Err(ScimDependencyError::Unavailable);
        }
        nazo_crypto::aead::decrypt_nonce_prefixed(&self.key, SCIM_CURSOR_AAD, protected)
            .map_err(|_| ScimDependencyError::Unavailable)
    }
}

#[cfg(test)]
#[path = "../../tests/unit/domain/scim.rs"]
mod tests;
