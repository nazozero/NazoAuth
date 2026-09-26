use super::*;
use nazo_identity::scim::{SCIM_CURSOR_NONCE_LEN, SCIM_CURSOR_TAG_LEN};

#[test]
fn scim_cursor_protection_round_trips_and_rejects_tampering_or_truncation() {
    let protector = ServerScimCursorProtector::new("cursor-pepper")
        .expect("cursor protector should derive a key");
    let plaintext = b"tenant=system;actor=token-1;offset=20";
    let protected = protector
        .protect(plaintext)
        .expect("cursor should be encrypted");

    assert!(protected.len() > SCIM_CURSOR_NONCE_LEN + SCIM_CURSOR_TAG_LEN);
    assert_eq!(
        protector
            .unprotect(&protected)
            .expect("cursor should decrypt"),
        plaintext
    );

    let mut tampered = protected.clone();
    tampered[SCIM_CURSOR_NONCE_LEN] ^= 1;
    assert!(protector.unprotect(&tampered).is_err());
    assert!(
        protector
            .unprotect(&[0; SCIM_CURSOR_NONCE_LEN + SCIM_CURSOR_TAG_LEN])
            .is_err()
    );
}

use crate::ports::audit::AuditFuture;
use nazo_identity::{
    PublicAccount, UserId,
    ports::{
        NewScimUser, RepositoryFuture, ScimCredentialPort, ScimListQuery, ScimRepositoryPort,
        UserPage,
    },
    scim::{NormalizedScimUser, ScimPatch, ScimTokenCredential},
};
use nazo_runtime_modules::{ActiveModuleSnapshot, ModuleId, ModuleRevision};
use serde_json::{Map, Value, json};
use std::sync::{
    Mutex,
    atomic::{AtomicUsize, Ordering},
};

struct Credentials {
    active: Mutex<Option<ScimTokenCredential>>,
    lookups: AtomicUsize,
}

impl ScimCredentialPort for Credentials {
    fn active_credential<'a>(
        &'a self,
        token_hash: &'a str,
    ) -> RepositoryFuture<'a, Option<ScimTokenCredential>> {
        assert_eq!(token_hash, blake3_hex("bearer-secret"));
        self.lookups.fetch_add(1, Ordering::Relaxed);
        Box::pin(async { Ok(self.active.lock().unwrap().clone()) })
    }
}

struct UnusedUsers;

impl ScimRepositoryPort for UnusedUsers {
    fn list<'a>(&'a self, _: ScimListQuery) -> RepositoryFuture<'a, UserPage> {
        panic!("authorization must not query users")
    }
    fn get<'a>(
        &'a self,
        _: TenantContext,
        _: UserId,
    ) -> RepositoryFuture<'a, Option<PublicAccount>> {
        panic!("authorization must not query users")
    }
    fn create<'a>(&'a self, _: NewScimUser) -> RepositoryFuture<'a, PublicAccount> {
        panic!("authorization must not mutate users")
    }
    fn replace<'a>(
        &'a self,
        _: TenantContext,
        _: UserId,
        _: NormalizedScimUser,
        _: nazo_scim_events::MutationContext,
    ) -> RepositoryFuture<'a, PublicAccount> {
        panic!("authorization must not mutate users")
    }
    fn patch<'a>(
        &'a self,
        _: TenantContext,
        _: UserId,
        _: ScimPatch,
        _: nazo_scim_events::MutationContext,
    ) -> RepositoryFuture<'a, PublicAccount> {
        panic!("authorization must not mutate users")
    }
    fn deactivate<'a>(
        &'a self,
        _: TenantContext,
        _: UserId,
        _: nazo_scim_events::MutationContext,
    ) -> RepositoryFuture<'a, bool> {
        panic!("authorization must not mutate users")
    }
}

#[derive(Default)]
struct Audit {
    events: Mutex<Vec<(String, Map<String, Value>)>>,
    required: Mutex<Vec<(String, Map<String, Value>)>>,
    fail_required: bool,
}

impl SecurityAudit for Audit {
    fn ensure_storage(&self) -> AuditFuture<'_> {
        panic!("successful SCIM authorization does not require a separate storage probe")
    }
    fn record(&self, event: &str, fields: Map<String, Value>) {
        self.events.lock().unwrap().push((event.to_owned(), fields));
    }
    fn record_required<'a>(
        &'a self,
        event: &'a str,
        fields: Map<String, Value>,
    ) -> AuditFuture<'a> {
        self.required
            .lock()
            .unwrap()
            .push((event.to_owned(), fields));
        Box::pin(async {
            if self.fail_required {
                anyhow::bail!("audit unavailable");
            }
            Ok(())
        })
    }
}

fn authorizer(audit: Arc<Audit>) -> (ServerScimRequestAuthorizer, Arc<Credentials>) {
    let tenant = TenantContext::default_system();
    let credentials = Arc::new(Credentials {
        active: Mutex::new(Some(ScimTokenCredential {
            id: uuid::Uuid::from_u128(11),
            tenant_id: tenant.tenant_id.as_uuid(),
            scopes: vec!["scim:read".to_owned()],
            event_audience: None,
        })),
        lookups: AtomicUsize::new(0),
    });
    (
        ServerScimRequestAuthorizer::new(
            ScimService::new(Arc::new(UnusedUsers), credentials.clone()),
            tenant,
            Arc::new(SnapshotStore::new(ActiveModuleSnapshot {
                revision: ModuleRevision::new(1),
                accepting: [ModuleId::Scim].into(),
                draining: Default::default(),
            })),
            audit,
        ),
        credentials,
    )
}

fn facts() -> ScimAuthenticationFacts<'static> {
    ScimAuthenticationFacts {
        bearer_token: Some("bearer-secret"),
        source_ip: "192.0.2.1".to_owned(),
        user_agent: Some("SCIM test client"),
    }
}

#[tokio::test]
async fn successful_authorization_uses_one_live_lookup_and_one_unified_audit_event() {
    let audit = Arc::new(Audit::default());
    let (authorizer, credentials) = authorizer(audit.clone());
    let authorized = authorizer
        .authorize(facts(), ScimRequiredScope::Read)
        .await
        .unwrap();
    assert_eq!(authorized.tenant, TenantContext::default_system());
    assert_eq!(credentials.lookups.load(Ordering::Relaxed), 1);
    let events = audit.events.lock().unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].0, "scim_token_used");
    assert_eq!(
        events[0].1,
        audit_fields(&[
            ("token_id", json!(uuid::Uuid::from_u128(11))),
            ("tenant_id", json!(authorized.tenant.tenant_id.as_uuid())),
            ("scope", json!("scim:read")),
            ("source", json!("database")),
            ("ip_hash", json!(blake3_hex("192.0.2.1"))),
            ("user_agent_hash", json!(blake3_hex("SCIM test client"))),
        ])
    );
    assert!(audit.required.lock().unwrap().is_empty());
}

#[tokio::test]
async fn authorization_preserves_scope_tenant_and_live_credential_denials() {
    let audit = Arc::new(Audit::default());
    let (authorizer, credentials) = authorizer(audit.clone());
    assert_eq!(
        authorizer
            .authorize(facts(), ScimRequiredScope::Write)
            .await
            .expect_err("read scope must not authorize writes"),
        ScimAuthorizationError::InsufficientScope
    );
    credentials
        .active
        .lock()
        .unwrap()
        .as_mut()
        .unwrap()
        .tenant_id = uuid::Uuid::from_u128(12);
    assert_eq!(
        authorizer
            .authorize(facts(), ScimRequiredScope::Read)
            .await
            .expect_err("cross-tenant bearer must fail"),
        ScimAuthorizationError::TenantMismatch
    );
    *credentials.active.lock().unwrap() = None;
    assert_eq!(
        authorizer
            .authorize(facts(), ScimRequiredScope::Read)
            .await
            .expect_err("inactive credential must fail"),
        ScimAuthorizationError::InvalidBearer
    );
    let denied = audit.required.lock().unwrap();
    assert_eq!(denied.len(), 3);
    assert!(denied.iter().all(|(event, _)| event == "scim_token_denied"));
    assert_eq!(denied[0].1["reason"], "insufficient_scope");
    assert_eq!(denied[1].1["reason"], "tenant_mismatch");
    assert_eq!(denied[2].1["reason"], "invalid_token");
    assert!(audit.events.lock().unwrap().is_empty());
    assert_eq!(credentials.lookups.load(Ordering::Relaxed), 3);
}

#[tokio::test]
async fn denied_authorization_fails_closed_if_required_audit_is_unavailable() {
    let audit = Arc::new(Audit {
        fail_required: true,
        ..Audit::default()
    });
    let (authorizer, _) = authorizer(audit.clone());
    assert_eq!(
        authorizer
            .authorize(facts(), ScimRequiredScope::Write)
            .await
            .expect_err("audit failure must take precedence over denial"),
        ScimAuthorizationError::BackendUnavailable
    );
    assert_eq!(audit.required.lock().unwrap().len(), 1);
    assert!(audit.events.lock().unwrap().is_empty());
}
