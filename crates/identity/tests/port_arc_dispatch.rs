//! Arc-owned trait objects preserve the original identity Port dispatch.
use std::sync::{Arc, Mutex};

use nazo_identity::ports::{
    AuthenticationAuditEvent, AuthenticationAuditPort, FederationAuditPort,
    FederationPasswordHasherPort, PasskeyAuditPort, PasswordHashInput, RepositoryError,
    RepositoryFuture, SecretHashPort, SecretVerifyError, SecretVerifyFuture, SecretVerifyPort,
    VerificationEmailDeliveryPort,
};
use nazo_identity::{FederationAuditEvent, PasskeyAuditEvent, PasswordHash};

#[derive(Debug, PartialEq)]
enum Call {
    Verify(String, PasswordHash),
    Hash(String),
    HashVerify(String, PasswordHash),
    Deliver(String, String, u64),
    BootstrapHash,
    Authentication(AuthenticationAuditEvent),
    Passkey(PasskeyAuditEvent),
    Federation(FederationAuditEvent),
}

#[derive(Default)]
struct RecordingPorts(Mutex<Vec<Call>>);

impl RecordingPorts {
    fn record(&self, call: Call) {
        self.0.lock().unwrap().push(call);
    }

    fn take(&self) -> Vec<Call> {
        std::mem::take(&mut *self.0.lock().unwrap())
    }
}

impl SecretVerifyPort for RecordingPorts {
    fn verify_secret(&self, secret: String, password_hash: PasswordHash) -> SecretVerifyFuture<'_> {
        self.record(Call::Verify(secret, password_hash));
        Box::pin(async { Err(SecretVerifyError::Busy) })
    }
}

impl SecretHashPort for RecordingPorts {
    fn hash_secret(&self, secret: String) -> RepositoryFuture<'_, PasswordHashInput> {
        self.record(Call::Hash(secret));
        Box::pin(async { Ok(PasswordHashInput::new("stored-hash").unwrap()) })
    }

    fn verify_secret(
        &self,
        secret: String,
        password_hash: PasswordHash,
    ) -> RepositoryFuture<'_, bool> {
        self.record(Call::HashVerify(secret, password_hash));
        Box::pin(async { Ok(false) })
    }
}

impl VerificationEmailDeliveryPort for RecordingPorts {
    fn deliver<'a>(
        &'a self,
        normalized_email: &'a str,
        code: &'a str,
        code_ttl_seconds: u64,
    ) -> RepositoryFuture<'a, ()> {
        self.record(Call::Deliver(
            normalized_email.to_owned(),
            code.to_owned(),
            code_ttl_seconds,
        ));
        Box::pin(async { Err(RepositoryError::Unavailable) })
    }
}

impl FederationPasswordHasherPort for RecordingPorts {
    fn hash_bootstrap_secret(&self) -> RepositoryFuture<'_, PasswordHashInput> {
        self.record(Call::BootstrapHash);
        Box::pin(async { Ok(PasswordHashInput::new("bootstrap-hash").unwrap()) })
    }
}

impl AuthenticationAuditPort for RecordingPorts {
    fn record(&self, event: AuthenticationAuditEvent) {
        self.record(Call::Authentication(event));
    }
}

impl PasskeyAuditPort for RecordingPorts {
    fn record(&self, event: PasskeyAuditEvent) {
        self.record(Call::Passkey(event));
    }
}

impl FederationAuditPort for RecordingPorts {
    fn record(&self, event: FederationAuditEvent) {
        self.record(Call::Federation(event));
    }
}

#[tokio::test]
async fn secret_verifier_arc_preserves_arguments_and_busy_error() {
    let recorder = Arc::new(RecordingPorts::default());
    let port: Arc<dyn SecretVerifyPort> = recorder.clone();
    let hash = PasswordHash::new("verifier").unwrap();
    assert_eq!(
        SecretVerifyPort::verify_secret(&port, "secret".to_owned(), hash.clone()).await,
        Err(SecretVerifyError::Busy)
    );
    assert_eq!(
        recorder.take(),
        vec![Call::Verify("secret".to_owned(), hash)]
    );
}

#[tokio::test]
async fn secret_hasher_arc_dispatches_both_operations_without_changing_results() {
    let recorder = Arc::new(RecordingPorts::default());
    let port: Arc<dyn SecretHashPort> = recorder.clone();
    let hash = PasswordHash::new("verifier").unwrap();
    let stored = SecretHashPort::hash_secret(&port, "new-secret".to_owned())
        .await
        .unwrap();
    assert_eq!(stored.into_persistence_value(), "stored-hash");
    assert!(
        !SecretHashPort::verify_secret(&port, "candidate".to_owned(), hash.clone())
            .await
            .unwrap()
    );
    assert_eq!(
        recorder.take(),
        vec![
            Call::Hash("new-secret".to_owned()),
            Call::HashVerify("candidate".to_owned(), hash)
        ]
    );
}

#[tokio::test]
async fn delivery_arc_preserves_borrowed_fields_ttl_and_error() {
    let recorder = Arc::new(RecordingPorts::default());
    let port: Arc<dyn VerificationEmailDeliveryPort> = recorder.clone();
    assert_eq!(
        VerificationEmailDeliveryPort::deliver(&port, "user@example.test", "004291", 317).await,
        Err(RepositoryError::Unavailable)
    );
    assert_eq!(
        recorder.take(),
        vec![Call::Deliver(
            "user@example.test".to_owned(),
            "004291".to_owned(),
            317
        )]
    );
}

#[tokio::test]
async fn federation_hasher_arc_preserves_generated_value() {
    let recorder = Arc::new(RecordingPorts::default());
    let port: Arc<dyn FederationPasswordHasherPort> = recorder.clone();
    let stored = FederationPasswordHasherPort::hash_bootstrap_secret(&port)
        .await
        .unwrap();
    assert_eq!(stored.into_persistence_value(), "bootstrap-hash");
    assert_eq!(recorder.take(), vec![Call::BootstrapHash]);
}

#[test]
fn authentication_audit_arc_dispatches_complete_event_once() {
    let recorder = Arc::new(RecordingPorts::default());
    let port: Arc<dyn AuthenticationAuditPort> = recorder.clone();
    let event = AuthenticationAuditEvent::Failure {
        email: "a@example.test".to_owned(),
        source_ip: "192.0.2.3".to_owned(),
        user_id: None,
    };
    AuthenticationAuditPort::record(&port, event.clone());
    assert_eq!(recorder.take(), vec![Call::Authentication(event)]);
}

#[test]
fn passkey_audit_arc_dispatches_complete_event_once() {
    let recorder = Arc::new(RecordingPorts::default());
    let port: Arc<dyn PasskeyAuditPort> = recorder.clone();
    let event = PasskeyAuditEvent::LoginFailureEmail {
        email: "b@example.test".to_owned(),
        reason: nazo_identity::passkey::PasskeyAuditReason::InvalidAssertion,
    };
    PasskeyAuditPort::record(&port, event.clone());
    assert_eq!(recorder.take(), vec![Call::Passkey(event)]);
}

#[test]
fn federation_audit_arc_dispatches_complete_event_once() {
    let recorder = Arc::new(RecordingPorts::default());
    let port: Arc<dyn FederationAuditPort> = recorder.clone();
    let event = FederationAuditEvent::ProviderMismatchRejected {
        expected_provider_id: "expected".to_owned(),
        actual_provider_id: "actual".to_owned(),
    };
    FederationAuditPort::record(&port, event.clone());
    assert_eq!(recorder.take(), vec![Call::Federation(event)]);
}
