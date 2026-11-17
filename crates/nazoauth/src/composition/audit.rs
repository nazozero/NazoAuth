use nazo_oauth_server::crypto::blake3_hex;
use nazo_oauth_server::ports::audit::{SecurityAudit, audit_fields};
use serde_json::json;
use std::sync::Arc;

#[derive(Clone)]
pub struct TracingAuthenticationAudit {
    audit: Arc<dyn SecurityAudit>,
}

impl TracingAuthenticationAudit {
    pub fn new(audit: Arc<dyn SecurityAudit>) -> Self {
        Self { audit }
    }
}

impl nazo_identity::ports::AuthenticationAuditPort for TracingAuthenticationAudit {
    fn record(&self, event: nazo_identity::ports::AuthenticationAuditEvent) {
        match event {
            nazo_identity::ports::AuthenticationAuditEvent::Failure {
                email,
                source_ip,
                user_id,
            } => {
                let mut fields = vec![
                    ("email_hash", blake3_hex(&email).into()),
                    ("source_ip_hash", blake3_hex(&source_ip).into()),
                ];
                if let Some(user_id) = user_id {
                    fields.push(("user_id", json!(user_id.as_uuid())));
                }
                self.audit.record("login_failure", audit_fields(fields));
            }
            nazo_identity::ports::AuthenticationAuditEvent::Success {
                user_id,
                source_ip,
                amr,
            } => self.audit.record(
                "login_success",
                audit_fields([
                    ("user_id", json!(user_id.as_uuid())),
                    ("source_ip_hash", blake3_hex(&source_ip).into()),
                    ("amr", amr.into()),
                ]),
            ),
        }
    }
}

#[derive(Clone)]
pub struct TracingPasskeyAudit {
    audit: Arc<dyn SecurityAudit>,
}

impl TracingPasskeyAudit {
    pub fn new(audit: Arc<dyn SecurityAudit>) -> Self {
        Self { audit }
    }
}

impl TracingPasskeyAudit {
    fn map(
        event: nazo_identity::PasskeyAuditEvent,
    ) -> (&'static str, serde_json::Map<String, serde_json::Value>) {
        match event {
            nazo_identity::PasskeyAuditEvent::LoginFailureEmail { email, reason } => (
                "passkey_login_failure",
                audit_fields([
                    ("email_hash", blake3_hex(&email).into()),
                    ("reason", json!(reason.as_str())),
                ]),
            ),
            nazo_identity::PasskeyAuditEvent::LoginFailureUser { user_id, reason } => (
                "passkey_login_failure",
                audit_fields([
                    ("user_id", json!(user_id.as_uuid())),
                    ("reason", json!(reason.as_str())),
                ]),
            ),
            nazo_identity::PasskeyAuditEvent::LoginSuccess { user_id, source_ip } => (
                "passkey_login_success",
                audit_fields([
                    ("user_id", json!(user_id.as_uuid())),
                    ("source_ip_hash", blake3_hex(&source_ip).into()),
                ]),
            ),
            nazo_identity::PasskeyAuditEvent::RegistrationRejected { user_id, reason } => (
                "passkey_registration_rejected",
                audit_fields([
                    ("user_id", json!(user_id.as_uuid())),
                    ("reason", json!(reason.as_str())),
                ]),
            ),
        }
    }
}

impl nazo_identity::ports::PasskeyAuditPort for TracingPasskeyAudit {
    fn record(&self, event: nazo_identity::PasskeyAuditEvent) {
        let (name, fields) = Self::map(event);
        self.audit.record(name, fields);
    }

    fn record_required<'a>(
        &'a self,
        event: nazo_identity::PasskeyAuditEvent,
    ) -> nazo_identity::ports::RepositoryFuture<'a, ()> {
        Box::pin(async move {
            let (name, fields) = Self::map(event);
            self.audit
                .record_required(name, fields)
                .await
                .map_err(|error| {
                    tracing::error!(%error, event = name, "required passkey audit append failed");
                    nazo_identity::ports::RepositoryError::Unavailable
                })
        })
    }
}

#[derive(Clone)]
pub struct TracingFederationAudit {
    audit: Arc<dyn SecurityAudit>,
}

impl TracingFederationAudit {
    pub fn new(audit: Arc<dyn SecurityAudit>) -> Self {
        Self { audit }
    }
}

impl TracingFederationAudit {
    fn map(
        event: nazo_identity::FederationAuditEvent,
    ) -> (&'static str, serde_json::Map<String, serde_json::Value>) {
        match event {
            nazo_identity::FederationAuditEvent::RelinkDenied {
                provider_type,
                provider_id,
                email,
            } => (
                "external_identity_relink_denied",
                audit_fields([
                    ("provider_type", provider_type.into()),
                    ("provider_id", provider_id.into()),
                    ("email_hash", blake3_hex(&email).into()),
                ]),
            ),
            nazo_identity::FederationAuditEvent::LoginSuccess {
                user_id,
                method,
                source_ip,
            } => (
                "federation_login_success",
                audit_fields([
                    ("user_id", json!(user_id.as_uuid())),
                    ("method", method.into()),
                    ("source_ip_hash", blake3_hex(&source_ip).into()),
                ]),
            ),
            nazo_identity::FederationAuditEvent::ProviderMismatchRejected {
                expected_provider_id,
                actual_provider_id,
            } => (
                "federation_provider_mismatch_rejected",
                audit_fields([
                    ("expected_provider_id", expected_provider_id.into()),
                    ("actual_provider_id", actual_provider_id.into()),
                ]),
            ),
            nazo_identity::FederationAuditEvent::SamlReplayRejected => {
                ("federation_saml_replay_rejected", serde_json::Map::new())
            }
        }
    }
}

impl nazo_identity::ports::FederationAuditPort for TracingFederationAudit {
    fn record(&self, event: nazo_identity::FederationAuditEvent) {
        let (name, fields) = Self::map(event);
        self.audit.record(name, fields);
    }

    fn record_required<'a>(
        &'a self,
        event: nazo_identity::FederationAuditEvent,
    ) -> nazo_identity::ports::RepositoryFuture<'a, ()> {
        Box::pin(async move {
            let (name, fields) = Self::map(event);
            self.audit
                .record_required(name, fields)
                .await
                .map_err(|error| {
                    tracing::error!(%error, event = name, "required federation audit append failed");
                    nazo_identity::ports::RepositoryError::Unavailable
                })
        })
    }
}
