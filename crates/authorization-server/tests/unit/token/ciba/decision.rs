use super::*;
use crate::ports::audit::AuditFuture;
use std::io::{self, Write};
use std::sync::atomic::{AtomicUsize, Ordering};
struct Audit {
    calls: AtomicUsize,
    fail_writer: bool,
}
struct FailingAuditWriter;
impl Write for FailingAuditWriter {
    fn write(&mut self, _: &[u8]) -> io::Result<usize> {
        Err(io::Error::other("deliberate audit writer failure"))
    }
    fn flush(&mut self) -> io::Result<()> {
        Err(io::Error::other("deliberate audit writer failure"))
    }
}
impl SecurityAudit for Audit {
    fn ensure_storage(&self) -> AuditFuture<'_> {
        Box::pin(async { Ok(()) })
    }
    fn record(&self, _: &str, _: serde_json::Map<String, serde_json::Value>) {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.fail_writer {
            assert!(FailingAuditWriter.write_all(b"event").is_err());
        }
    }
    fn record_required<'a>(
        &'a self,
        _: &'a str,
        _: serde_json::Map<String, serde_json::Value>,
    ) -> AuditFuture<'a> {
        Box::pin(async { Ok(()) })
    }
}
fn committed_decision_fixture(decision: CibaDecision) -> CibaCommittedDecision {
    let now = Utc::now().timestamp();
    let (status, authentication_context) = match &decision {
        CibaDecision::Approve(authentication_context) => {
            (CibaStatus::Approved, Some(authentication_context.clone()))
        }
        CibaDecision::Deny => (CibaStatus::Denied, None),
    };
    CibaCommittedDecision {
        state: CibaRequestState {
            client_id: "client-1".to_owned(),
            user_id: Uuid::now_v7(),
            scopes: vec!["openid".to_owned()],
            audiences: vec!["resource://default".to_owned()],
            acr: None,
            authentication_context,
            binding_message: None,
            issued_at: now,
            status,
            interval_seconds: 5,
            expires_at: now + 60,
            retention_expires_at: now + 180,
            last_poll_at: None,
            ping_notification: None,
        },
        decision,
    }
}
#[test]
fn ciba_decision_audit_is_emitted_only_for_committed_outcome() {
    let audit = Audit {
        calls: AtomicUsize::new(0),
        fail_writer: false,
    };
    for failure in [
        CibaDecisionFailure::Missing,
        CibaDecisionFailure::InvalidAuthenticationContext,
        CibaDecisionFailure::UserMismatch,
        CibaDecisionFailure::AlreadyHandled,
        CibaDecisionFailure::Expired,
        CibaDecisionFailure::Contended,
        CibaDecisionFailure::Storage(CibaStatePortError::CorruptData),
    ] {
        assert!(
            complete_ciba_decision(
                &audit,
                Err(failure),
                "auth-req-id",
                CibaDecisionSource::User,
                Some("source-ip-hash".to_owned())
            )
            .is_err()
        );
    }
    assert_eq!(audit.calls.load(Ordering::SeqCst), 0);
    let result = complete_ciba_decision(
        &audit,
        Ok(committed_decision_fixture(CibaDecision::Approve(
            CibaAuthenticationContext {
                auth_time: Utc::now().timestamp(),
                amr: vec!["pwd".into()],
                oidc_sid: Some("audit-session".into()),
            },
        ))),
        "auth-req-id",
        CibaDecisionSource::User,
        Some("source-ip-hash".to_owned()),
    );
    assert!(result.is_ok());
    assert_eq!(audit.calls.load(Ordering::SeqCst), 1);
}
#[test]
fn ciba_audit_writer_failure_does_not_change_committed_response() {
    let audit = Audit {
        calls: AtomicUsize::new(0),
        fail_writer: true,
    };
    let result = complete_ciba_decision(
        &audit,
        Ok(committed_decision_fixture(CibaDecision::Deny)),
        "auth-req-id",
        CibaDecisionSource::User,
        None,
    );
    assert!(result.is_ok());
    assert_eq!(audit.calls.load(Ordering::SeqCst), 1);
}
