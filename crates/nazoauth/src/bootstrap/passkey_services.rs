use nazo_oauth_server::ports::audit::{SecurityAudit, audit_fields};
use serde_json::json;
use std::sync::Arc;

use nazo_oauth_server::crypto::blake3_hex;

#[derive(Clone)]
pub(crate) struct TracingPasskeyAudit {
    audit: Arc<dyn SecurityAudit>,
}

impl TracingPasskeyAudit {
    pub(crate) fn new(audit: Arc<dyn SecurityAudit>) -> Self {
        Self { audit }
    }
}

impl nazo_identity::ports::PasskeyAuditPort for TracingPasskeyAudit {
    fn record(&self, event: nazo_identity::PasskeyAuditEvent) {
        match event {
            nazo_identity::PasskeyAuditEvent::LoginFailureEmail { email, reason } => {
                self.audit.record(
                    "passkey_login_failure",
                    audit_fields(&[
                        ("email_hash", json!(blake3_hex(&email))),
                        ("reason", json!(reason.as_str())),
                    ]),
                )
            }
            nazo_identity::PasskeyAuditEvent::LoginFailureUser { user_id, reason } => {
                self.audit.record(
                    "passkey_login_failure",
                    audit_fields(&[
                        ("user_id", json!(user_id.as_uuid())),
                        ("reason", json!(reason.as_str())),
                    ]),
                )
            }
            nazo_identity::PasskeyAuditEvent::LoginSuccess { user_id, source_ip } => {
                self.audit.record(
                    "passkey_login_success",
                    audit_fields(&[
                        ("user_id", json!(user_id.as_uuid())),
                        ("source_ip_hash", json!(blake3_hex(&source_ip))),
                    ]),
                )
            }
            nazo_identity::PasskeyAuditEvent::RegistrationRejected { user_id, reason } => {
                self.audit.record(
                    "passkey_registration_rejected",
                    audit_fields(&[
                        ("user_id", json!(user_id.as_uuid())),
                        ("reason", json!(reason.as_str())),
                    ]),
                );
            }
            nazo_identity::PasskeyAuditEvent::Registered {
                user_id,
                credential_id,
            } => self.audit.record(
                "passkey_registered",
                audit_fields(&[
                    ("user_id", json!(user_id.as_uuid())),
                    ("credential_id", json!(credential_id)),
                ]),
            ),
        }
    }
}
