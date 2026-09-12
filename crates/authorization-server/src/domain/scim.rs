use std::sync::Arc;

use crate::contracts::scim::{
    ScimAuthenticationFacts, ScimAuthorizationError, ScimAuthorizedRequest, ScimCursorProtector,
    ScimDependencyError, ScimFuture, ScimRequestAuthorizer,
};
use hmac::{Hmac, KeyInit, Mac};
use nazo_identity::{
    TenantContext, TenantId,
    ports::ScimCredentialUse,
    scim::{
        SCIM_CURSOR_AAD, SCIM_CURSOR_KEY_LABEL, SCIM_CURSOR_NONCE_LEN, SCIM_CURSOR_TAG_LEN,
        ScimCursorSubject, ScimRequiredScope, ScimService, scim_credential_allows,
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
}

impl ServerScimRequestAuthorizer {
    pub fn new(
        service: ScimService,
        tenant: TenantContext,
        runtime_modules: Arc<SnapshotStore>,
        audit: Arc<dyn SecurityAudit>,
    ) -> Self {
        Self {
            service,
            tenant,
            audit,
            runtime_modules,
        }
    }

    fn enabled(&self) -> bool {
        nazo_auth::module_admissible(
            &self.runtime_modules.load_full(),
            nazo_runtime_modules::ModuleId::Scim,
            nazo_auth::CapabilityAdmission::NewRequest,
        )
    }

    async fn credential(
        &self,
        token: &str,
    ) -> Result<AuthorizedCredential, ScimAuthorizationError> {
        match self.service.active_credential(&blake3_hex(token)).await {
            Ok(Some(credential)) => {
                let tenant_id = TenantId::new(credential.tenant_id)
                    .map_err(|_| ScimAuthorizationError::TenantMismatch)?;
                if tenant_id != self.tenant.tenant_id {
                    return Err(ScimAuthorizationError::TenantMismatch);
                }
                Ok(AuthorizedCredential {
                    token_id: Some(credential.id),
                    tenant: self.tenant,
                    scopes: credential.scopes,
                    event_audience: credential.event_audience,
                    source: "database",
                    cursor_actor: format!("database:{}", credential.id),
                })
            }
            Ok(None) => Err(ScimAuthorizationError::InvalidBearer),
            Err(error) => {
                tracing::warn!(%error, "failed to query SCIM token");
                Err(ScimAuthorizationError::BackendUnavailable)
            }
        }
    }

    async fn record_use(
        &self,
        ip_hash: String,
        user_agent_hash: Option<String>,
        required_scope: ScimRequiredScope,
        credential: &AuthorizedCredential,
    ) {
        if let Some(token_id) = credential.token_id
            && let Err(error) = self
                .service
                .record_credential_use(ScimCredentialUse {
                    token_id,
                    tenant_id: credential.tenant.tenant_id.as_uuid(),
                    scopes: vec![required_scope.as_str().to_owned()],
                    ip_hash: Some(ip_hash.clone()),
                    user_agent_hash,
                })
                .await
        {
            tracing::warn!(%error, %token_id, "failed to insert SCIM token audit event");
        }
        self.audit.record(
            "scim_token_used",
            audit_fields(&[
                ("token_id", serde_json::json!(credential.token_id)),
                (
                    "tenant_id",
                    serde_json::json!(credential.tenant.tenant_id.as_uuid()),
                ),
                ("scope", serde_json::json!(required_scope.as_str())),
                ("source", serde_json::json!(credential.source)),
                ("ip_hash", serde_json::json!(ip_hash)),
            ]),
        );
    }

    fn audit_denied(
        &self,
        ip_hash: &str,
        required_scope: ScimRequiredScope,
        reason: &str,
        token_id: Option<uuid::Uuid>,
    ) {
        self.audit.record(
            "scim_token_denied",
            audit_fields(&[
                ("token_id", serde_json::json!(token_id)),
                ("scope", serde_json::json!(required_scope.as_str())),
                ("reason", serde_json::json!(reason)),
                ("ip_hash", serde_json::json!(ip_hash)),
            ]),
        );
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
        let ip_hash = blake3_hex(&facts.source_ip);
        let user_agent_hash = facts.user_agent.map(blake3_hex);
        Box::pin(async move {
            if !enabled {
                return Err(ScimAuthorizationError::Disabled);
            }
            let Some(token) = token else {
                self.audit_denied(&ip_hash, required_scope, "missing_bearer", None);
                return Err(ScimAuthorizationError::MissingBearer);
            };
            let credential = match self.credential(token).await {
                Ok(credential) => credential,
                Err(ScimAuthorizationError::InvalidBearer) => {
                    self.audit_denied(&ip_hash, required_scope, "invalid_token", None);
                    return Err(ScimAuthorizationError::InvalidBearer);
                }
                Err(ScimAuthorizationError::TenantMismatch) => {
                    self.audit_denied(&ip_hash, required_scope, "tenant_mismatch", None);
                    return Err(ScimAuthorizationError::TenantMismatch);
                }
                Err(error) => return Err(error),
            };
            if !scim_credential_allows(&credential.scopes, required_scope) {
                self.audit_denied(
                    &ip_hash,
                    required_scope,
                    "insufficient_scope",
                    credential.token_id,
                );
                return Err(ScimAuthorizationError::InsufficientScope);
            }
            if credential.tenant != self.tenant {
                self.audit_denied(
                    &ip_hash,
                    required_scope,
                    "tenant_mismatch",
                    credential.token_id,
                );
                return Err(ScimAuthorizationError::TenantMismatch);
            }
            self.record_use(ip_hash, user_agent_hash, required_scope, &credential)
                .await;
            Ok(ScimAuthorizedRequest {
                tenant: credential.tenant,
                cursor_subject: ScimCursorSubject {
                    tenant_id: credential.tenant.tenant_id.as_uuid(),
                    actor: credential.cursor_actor,
                },
                event_receiver: match (credential.token_id, credential.event_audience) {
                    (Some(token_id), Some(audience)) => Some(EventReceiver {
                        token_id,
                        tenant_id: credential.tenant.tenant_id.as_uuid(),
                        audience,
                    }),
                    _ => None,
                },
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

struct AuthorizedCredential {
    token_id: Option<uuid::Uuid>,
    tenant: TenantContext,
    scopes: Vec<String>,
    event_audience: Option<String>,
    source: &'static str,
    cursor_actor: String,
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
            let snapshot = self.keyset.snapshot();
            let mut header = jsonwebtoken::Header::new(snapshot.active_alg);
            header.typ = Some(nazo_scim_events::SECURITY_EVENT_MEDIA_TYPE.to_owned());
            self.keyset
                .encode_jwt(nazo_auth::SigningPurpose::SecurityEvent, &header, claims)
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
        let (ciphertext, tag) =
            crate::crypto::aes_256_gcm_encrypt(&self.key, &nonce, SCIM_CURSOR_AAD, plaintext)
                .map_err(|_| ScimDependencyError::Unavailable)?;
        let mut protected = Vec::with_capacity(nonce.len() + ciphertext.len() + tag.len());
        protected.extend_from_slice(&nonce);
        protected.extend_from_slice(&ciphertext);
        protected.extend_from_slice(&tag);
        Ok(protected)
    }

    fn unprotect(&self, protected: &[u8]) -> Result<Vec<u8>, ScimDependencyError> {
        if protected.len() <= SCIM_CURSOR_NONCE_LEN + SCIM_CURSOR_TAG_LEN {
            return Err(ScimDependencyError::Unavailable);
        }
        let (nonce, remainder) = protected.split_at(SCIM_CURSOR_NONCE_LEN);
        let (ciphertext, tag) = remainder.split_at(remainder.len() - SCIM_CURSOR_TAG_LEN);
        crate::crypto::aes_256_gcm_decrypt(&self.key, nonce, SCIM_CURSOR_AAD, ciphertext, tag)
            .map_err(|_| ScimDependencyError::Unavailable)
    }
}

#[cfg(test)]
#[path = "../../tests/unit/domain/scim.rs"]
mod tests;
