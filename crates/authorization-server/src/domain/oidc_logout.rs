use std::{future::Future, sync::Arc};

use crate::contracts::oidc_logout::{
    OidcLogoutCommand, OidcLogoutError, OidcLogoutFuture, OidcLogoutOperations, OidcLogoutSuccess,
};
use chrono::{DateTime, Utc};
use nazo_auth::{
    BackchannelLogoutClaimsInput, BackchannelLogoutOutboxPort, LogoutClientRepositoryPort,
    LogoutDependencyError, LogoutInput, LogoutService, LogoutServiceError, LogoutSession,
    LogoutTokenSignerPort, RpLogoutRequest,
};
use nazo_key_management::KeyManager;

use crate::ports::audit::{SecurityAudit, audit_fields};
use crate::sessions::SessionResolver;
use nazo_runtime_modules::SnapshotStore;
use serde_json::json;

#[derive(Clone)]
pub struct OidcLogoutConfig {
    pub require_fapi2: bool,
    pub issuer: Box<str>,
    pub pairwise_subject_secret: Option<Box<str>>,
}

/// OIDC logout dependencies assembled once at the composition root.
///
/// Transport code can resolve the current session and invoke logout operations,
/// but cannot obtain backend connections or complete settings.
#[derive(Clone)]
pub struct OidcLogoutHandles {
    sessions: Arc<SessionResolver>,
    service: LogoutService,
    keys: KeyManager,
    config: OidcLogoutConfig,
    snapshots: Arc<SnapshotStore>,
    audit: Arc<dyn SecurityAudit>,
}

impl OidcLogoutHandles {
    pub fn new(
        sessions: Arc<SessionResolver>,
        clients: Arc<dyn LogoutClientRepositoryPort>,
        deliveries: Arc<dyn BackchannelLogoutOutboxPort>,
        keys: KeyManager,
        config: OidcLogoutConfig,
        snapshots: Arc<SnapshotStore>,
        audit: Arc<dyn SecurityAudit>,
    ) -> Self {
        let service = LogoutService::new(
            clients,
            deliveries,
            Arc::new(ServerLogoutTokenSigner {
                keys: keys.clone(),
                issuer: config.issuer.clone(),
                require_fapi2: config.require_fapi2,
            }),
            config.issuer.clone(),
            config.pairwise_subject_secret.clone(),
        );
        Self {
            sessions,
            service,
            keys,
            config,
            snapshots,
            audit,
        }
    }

    pub fn issuer(&self) -> &str {
        &self.config.issuer
    }

    fn decode_id_token_hint_with_expiry(
        &self,
        token: &str,
        now: DateTime<Utc>,
    ) -> Option<DecodedIdTokenHint> {
        let (claims, expires_at) = self.keys.decode_id_token_hint(self.issuer(), token)?;
        Some(DecodedIdTokenHint {
            expired: id_token_hint_expired(expires_at, now),
            claims,
        })
    }
}

struct DecodedIdTokenHint {
    claims: nazo_auth::IdTokenHintClaims,
    expired: bool,
}

#[derive(Clone)]
struct ServerLogoutTokenSigner {
    require_fapi2: bool,
    keys: KeyManager,
    issuer: Box<str>,
}

impl LogoutTokenSignerPort for ServerLogoutTokenSigner {
    fn sign_logout_token<'a>(
        &'a self,
        client: &'a nazo_auth::RegisteredLogoutClient,
        subject: Option<&'a str>,
        sid: &'a str,
        issued_at: DateTime<Utc>,
        ttl_seconds: i64,
    ) -> nazo_auth::LogoutFuture<'a, String> {
        Box::pin(async move {
            let claims = nazo_auth::backchannel_logout_token_claims(
                &self.issuer,
                &BackchannelLogoutClaimsInput {
                    client_id: &client.client_id,
                    subject,
                    sid: Some(sid),
                    ttl: ttl_seconds,
                },
                issued_at.timestamp(),
            );
            self.keys
                .encode_response_jwt(
                    nazo_auth::SigningPurpose::LogoutToken,
                    nazo_auth::jwt_response_signing_algorithm(
                        client.id_token_signed_response_alg.as_deref(),
                        self.require_fapi2 || client.require_fapi2,
                    )
                    .map_err(|_| LogoutDependencyError::Consistency)?
                    .map(|name| {
                        nazo_key_management::signing_algorithm_from_name(name)
                            .ok_or(LogoutDependencyError::Consistency)
                    })
                    .transpose()?,
                    "logout+jwt",
                    &serde_json::Value::Object(claims),
                )
                .await
                .map_err(|_| LogoutDependencyError::Unavailable)
        })
    }
}

impl OidcLogoutOperations for OidcLogoutHandles {
    fn logout(&self, command: OidcLogoutCommand) -> OidcLogoutFuture<'_> {
        Box::pin(async move {
            let modules = self.snapshots.request();
            let now = Utc::now();
            let current_session = match command.session_id.as_deref() {
                Some(session_id) => self
                    .sessions
                    .current_session_by_id(session_id)
                    .await
                    .map_err(|error| {
                        tracing::warn!(%error, "failed to resolve session for oidc logout");
                        OidcLogoutError::SessionLookupUnavailable
                    })?,
                None => None,
            };
            let decoded_id_token_hint = command
                .request
                .id_token_hint
                .as_deref()
                .and_then(|token| self.decode_id_token_hint_with_expiry(token, now));
            let subject_hash = current_session.as_ref().map(|session| {
                blake3::hash(session.user.id().as_bytes())
                    .to_hex()
                    .to_string()
            });
            let audit_client_id = command.request.client_id.clone();
            let (id_token_hint, id_token_hint_expired) = match decoded_id_token_hint {
                Some(decoded) => (Some(decoded.claims), decoded.expired),
                None => (None, false),
            };
            let execution = self
                .service
                .prepare(LogoutInput {
                    tenant_id: self.sessions.tenant_id().as_uuid(),
                    request: RpLogoutRequest {
                        id_token_hint_present: command.request.id_token_hint.is_some(),
                        client_id: command.request.client_id,
                        post_logout_redirect_uri: command.request.post_logout_redirect_uri,
                        state: command.request.state,
                    },
                    id_token_hint,
                    id_token_hint_expired,
                    session: current_session.map(|session| LogoutSession {
                        user_id: session.user.id(),
                        oidc_sid: session.oidc_sid,
                        logged_in_client_ids: session.logged_in_client_ids,
                    }),
                    csrf_authorized: command.csrf_authorized,
                    user_confirmed: command.user_confirmed,
                    frontchannel_enabled: modules.permits(
                        nazo_runtime_modules::ModuleId::FrontchannelLogout,
                        nazo_auth::CapabilityAdmission::ExistingTransaction,
                    ),
                    now,
                })
                .await;

            let operation_key = execution
                .as_ref()
                .ok()
                .and_then(|prepared| prepared.execution.operation_key.clone());
            let execution = match execution {
                Ok(prepared) => {
                    let mut fields = audit_fields([
                        ("operation_key", json!(operation_key)),
                        ("client_id", json!(audit_client_id)),
                    ]);
                    if let Some(subject_hash) = subject_hash.as_ref() {
                        fields.insert("subject_hash".to_owned(), json!(subject_hash));
                    }
                    self.audit
                        .ensure_transactional_ready()
                        .await
                        .map_err(|_| OidcLogoutError::AuditUnavailable)?;
                    self.audit
                        .record_required("oidc_logout", fields)
                        .await
                        .map_err(|_| OidcLogoutError::AuditUnavailable)?;
                    let execution = self
                        .service
                        .commit(prepared)
                        .await
                        .map_err(map_logout_service_error)?;
                    Ok(execution)
                }
                Err(error) => Err(error),
            };
            let success = finalize_logout_execution(execution, command.session_id, |session_id| {
                let sessions = self.sessions.clone();
                async move {
                    sessions.delete_session(&session_id).await.map_err(|error| {
                        tracing::warn!(%error, "failed to delete session after oidc logout");
                    })
                }
            })
            .await?;

            tracing::info!(
                event = "oidc_logout",
                subject_hash = ?subject_hash,
                operation_key = ?operation_key,
                "oidc logout completed"
            );
            Ok(success)
        })
    }
}

fn id_token_hint_expired(exp: i64, now: DateTime<Utc>) -> bool {
    exp <= now.timestamp()
}

async fn finalize_logout_execution<F, Fut>(
    execution: Result<nazo_auth::LogoutExecution, LogoutServiceError>,
    session_id: Option<String>,
    delete_session: F,
) -> Result<OidcLogoutSuccess, OidcLogoutError>
where
    F: FnOnce(String) -> Fut,
    Fut: Future<Output = Result<(), ()>>,
{
    let execution = execution.map_err(map_logout_service_error)?;
    if let Some(session_id) = session_id {
        delete_session(session_id)
            .await
            .map_err(|()| OidcLogoutError::SessionDeleteUnavailable)?;
    }
    Ok(OidcLogoutSuccess {
        redirect_uri: execution.redirect_uri,
        frontchannel_logout_urls: execution.frontchannel_logout_urls,
    })
}

fn map_logout_service_error(error: LogoutServiceError) -> OidcLogoutError {
    match error {
        LogoutServiceError::Policy(policy) => match policy {
            nazo_auth::LogoutPolicyError::ClientAudienceMismatch => {
                OidcLogoutError::ClientAudienceMismatch
            }
            nazo_auth::LogoutPolicyError::AmbiguousAudience => OidcLogoutError::AmbiguousAudience,
            nazo_auth::LogoutPolicyError::ClientRequiredForRedirect => {
                OidcLogoutError::ClientRequiredForRedirect
            }
            nazo_auth::LogoutPolicyError::RegisteredClientRequired => {
                OidcLogoutError::RegisteredClientRequired
            }
            nazo_auth::LogoutPolicyError::UnregisteredRedirect => {
                OidcLogoutError::UnregisteredRedirect
            }
            nazo_auth::LogoutPolicyError::InvalidRedirect
            | nazo_auth::LogoutPolicyError::PairwiseSecretMissing
            | nazo_auth::LogoutPolicyError::UnsupportedSubjectType => {
                OidcLogoutError::InvalidRedirect
            }
        },
        LogoutServiceError::InvalidIdTokenHint => OidcLogoutError::InvalidIdTokenHint,
        LogoutServiceError::ConfirmationRequired => OidcLogoutError::ConfirmationRequired,
        LogoutServiceError::ClientNotFound => OidcLogoutError::ClientNotFound,
        LogoutServiceError::ClientUnavailable => OidcLogoutError::ClientLookupUnavailable,
        LogoutServiceError::SigningUnavailable => OidcLogoutError::SigningUnavailable,
        LogoutServiceError::OutboxUnavailable => OidcLogoutError::OutboxUnavailable,
    }
}

#[cfg(test)]
#[path = "../../tests/unit/domain/oidc_logout/orchestration.rs"]
mod orchestration_tests;
