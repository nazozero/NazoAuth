use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use chrono::TimeZone as _;

use super::*;

fn committed_execution(operation_key: &str) -> nazo_auth::LogoutExecution {
    nazo_auth::LogoutExecution {
        redirect_uri: None,
        frontchannel_logout_urls: Vec::new(),
        operation_key: Some(operation_key.to_owned()),
    }
}

#[test]
fn id_token_hint_expires_at_the_exact_exp_boundary() {
    let now = Utc.timestamp_opt(2_000_000_000, 0).unwrap();
    assert!(!id_token_hint_expired(2_000_000_001, now));
    assert!(id_token_hint_expired(2_000_000_000, now));
    assert!(id_token_hint_expired(1_999_999_999, now));
}

#[test]
fn postgres_outbox_failure_never_deletes_the_valkey_session() {
    futures_executor::block_on(async {
        let delete_calls = Arc::new(AtomicUsize::new(0));
        let observed = delete_calls.clone();
        let result = finalize_logout_execution(
            Err(LogoutServiceError::OutboxUnavailable),
            Some("session-cookie".to_owned()),
            move |_| {
                observed.fetch_add(1, Ordering::SeqCst);
                async { Ok(()) }
            },
        )
        .await;
        assert_eq!(result, Err(OidcLogoutError::OutboxUnavailable));
        assert_eq!(delete_calls.load(Ordering::SeqCst), 0);
    });
}

#[test]
fn valkey_failure_keeps_the_committed_operation_retryable() {
    futures_executor::block_on(async {
        let operation_key = "same-user-and-oidc-session";
        let first = finalize_logout_execution(
            Ok(committed_execution(operation_key)),
            Some("session-cookie".to_owned()),
            |_| async { Err(()) },
        )
        .await;
        assert_eq!(first, Err(OidcLogoutError::SessionDeleteUnavailable));

        let second = finalize_logout_execution(
            Ok(committed_execution(operation_key)),
            Some("session-cookie".to_owned()),
            |_| async { Ok(()) },
        )
        .await;
        assert_eq!(
            second,
            Ok(OidcLogoutSuccess {
                redirect_uri: None,
                frontchannel_logout_urls: Vec::new(),
            })
        );
    });
}

#[derive(Default)]
struct LogoutPorts {
    readiness_fails: std::sync::atomic::AtomicBool,
    audit_fails: std::sync::atomic::AtomicBool,
    enqueue_fails: std::sync::atomic::AtomicBool,
    delete_fails: std::sync::atomic::AtomicBool,
    enqueues: AtomicUsize,
    deletes: AtomicUsize,
    audit_keys: std::sync::Mutex<Vec<String>>,
    delivery_keys: std::sync::Mutex<Vec<String>>,
}

impl nazo_identity::ports::SessionStorePort for LogoutPorts {
    fn load<'a>(
        &'a self,
        _: &'a nazo_identity::SessionId,
    ) -> nazo_identity::ports::RepositoryFuture<'a, Option<nazo_identity::session::SessionSnapshot>>
    {
        Box::pin(async move {
            let now = Utc::now().timestamp();
            let mut record = nazo_identity::session::SessionRecord::new(
                nazo_identity::UserId::new(uuid::Uuid::from_u128(2)).unwrap(),
                0,
                now - 10,
                vec!["password".to_owned()],
                false,
                Some("oidc-session".to_owned()),
            );
            record.add_logged_in_client("client-a");
            Ok(Some(nazo_identity::session::SessionSnapshot::new(
                record,
                nazo_identity::session::SessionVersion::from_storage(
                    b"version".to_vec().into_boxed_slice(),
                ),
            )))
        })
    }
    fn delete<'a>(
        &'a self,
        _: &'a nazo_identity::SessionId,
    ) -> nazo_identity::ports::RepositoryFuture<'a, bool> {
        self.deletes.fetch_add(1, Ordering::SeqCst);
        Box::pin(async move {
            if self.delete_fails.load(Ordering::SeqCst) {
                Err(nazo_identity::ports::RepositoryError::Unavailable)
            } else {
                Ok(true)
            }
        })
    }
    fn rotate<'a>(
        &'a self,
        _: &'a nazo_identity::SessionId,
        _: &'a nazo_identity::session::SessionVersion,
        _: &'a nazo_identity::SessionId,
        _: &'a nazo_identity::session::SessionRecord,
        _: u64,
    ) -> nazo_identity::ports::RepositoryFuture<'a, nazo_identity::session::SessionRotationOutcome>
    {
        panic!("unexpected rotation")
    }
    fn compare_and_set<'a>(
        &'a self,
        _: &'a nazo_identity::SessionId,
        _: &'a nazo_identity::session::SessionVersion,
        _: &'a nazo_identity::session::SessionRecord,
    ) -> nazo_identity::ports::RepositoryFuture<'a, nazo_identity::session::SessionUpdateOutcome>
    {
        panic!("unexpected update")
    }
}
impl nazo_identity::ports::SessionAccountPort for LogoutPorts {
    fn principal_by_id(
        &self,
        tenant_id: nazo_identity::TenantId,
        user_id: nazo_identity::UserId,
    ) -> nazo_identity::ports::RepositoryFuture<'_, Option<nazo_identity::Principal>> {
        Box::pin(async move {
            Ok(Some(nazo_identity::Principal {
                authorization_epoch: 0,
                user_id,
                tenant: nazo_identity::TenantContext::default_system(),
                role: nazo_identity::UserRole::User,
                active: tenant_id == nazo_identity::TenantContext::default_system().tenant_id,
            }))
        })
    }
    fn public_account_by_id(
        &self,
        _: nazo_identity::TenantId,
        _: nazo_identity::UserId,
    ) -> nazo_identity::ports::RepositoryFuture<'_, Option<nazo_identity::PublicAccount>> {
        panic!("unexpected account lookup")
    }
}
impl nazo_auth::LogoutClientRepositoryPort for LogoutPorts {
    fn by_client_id<'a>(
        &'a self,
        _: uuid::Uuid,
        _: &'a str,
    ) -> nazo_auth::LogoutFuture<'a, Option<nazo_auth::RegisteredLogoutClient>> {
        Box::pin(async { Ok(None) })
    }
    fn by_client_ids<'a>(
        &'a self,
        tenant: uuid::Uuid,
        _: &'a [&'a str],
    ) -> nazo_auth::LogoutFuture<'a, Vec<nazo_auth::RegisteredLogoutClient>> {
        Box::pin(async move {
            Ok(vec![nazo_auth::RegisteredLogoutClient {
                require_fapi2: false,
                id_token_signed_response_alg: None,
                id: uuid::Uuid::from_u128(3),
                tenant_id: tenant,
                client_id: "client-a".to_owned(),
                active: true,
                redirect_uris: vec![],
                post_logout_redirect_uris: vec![],
                backchannel_logout_uri: Some("https://client.example/logout".to_owned()),
                frontchannel_logout_uri: None,
                frontchannel_logout_session_required: false,
                subject_type: "public".to_owned(),
                sector_identifier_host: None,
            }])
        })
    }
}
impl nazo_auth::BackchannelLogoutOutboxPort for LogoutPorts {
    fn enqueue_idempotent_batch<'a>(
        &'a self,
        deliveries: &'a [nazo_auth::IdempotentBackchannelLogoutDelivery],
    ) -> nazo_auth::LogoutFuture<'a, ()> {
        self.enqueues.fetch_add(1, Ordering::SeqCst);
        self.delivery_keys.lock().unwrap().extend(
            deliveries
                .iter()
                .map(|delivery| delivery.operation_key.clone()),
        );
        Box::pin(async move {
            if self.enqueue_fails.load(Ordering::SeqCst) {
                Err(nazo_auth::LogoutDependencyError::Unavailable)
            } else {
                Ok(())
            }
        })
    }
}
impl SecurityAudit for LogoutPorts {
    fn ensure_storage(&self) -> crate::ports::audit::AuditFuture<'_> {
        self.ensure_transactional_ready()
    }
    fn ensure_transactional_ready(&self) -> crate::ports::audit::AuditFuture<'_> {
        Box::pin(async move {
            if self.readiness_fails.load(Ordering::SeqCst) {
                anyhow::bail!("unavailable")
            }
            Ok(())
        })
    }
    fn record(&self, _: &str, _: serde_json::Map<String, serde_json::Value>) {}
    fn record_required<'a>(
        &'a self,
        _: &'a str,
        fields: serde_json::Map<String, serde_json::Value>,
    ) -> crate::ports::audit::AuditFuture<'a> {
        Box::pin(async move {
            if self.audit_fails.load(Ordering::SeqCst) {
                anyhow::bail!("audit unavailable")
            }
            self.audit_keys
                .lock()
                .unwrap()
                .push(fields["operation_key"].as_str().unwrap().to_owned());
            Ok(())
        })
    }
}

fn real_logout_fixture(ports: Arc<LogoutPorts>) -> OidcLogoutHandles {
    use nazo_runtime_modules::{ActiveModuleSnapshot, ModuleRevision, SnapshotStore};
    use std::collections::BTreeSet;
    let tenant = nazo_identity::TenantContext::default_system().tenant_id;
    OidcLogoutHandles::new(
        Arc::new(SessionResolver::new(ports.clone(), ports.clone(), tenant)),
        ports.clone(),
        ports.clone(),
        KeyManager::for_test(jsonwebtoken::Algorithm::EdDSA),
        OidcLogoutConfig {
            require_fapi2: false,
            issuer: "https://issuer.example".into(),
            pairwise_subject_secret: None,
        },
        Arc::new(SnapshotStore::new(ActiveModuleSnapshot {
            revision: ModuleRevision::new(1),
            accepting: BTreeSet::new(),
            draining: BTreeSet::new(),
        })),
        ports,
    )
}

fn real_logout_command() -> OidcLogoutCommand {
    OidcLogoutCommand {
        request: Default::default(),
        session_id: Some("session".to_owned()),
        csrf_authorized: true,
        user_confirmed: true,
    }
}

#[test]
fn logout_entry_fails_closed_and_retries_with_the_same_operation_key() {
    futures_executor::block_on(async {
        for fail_readiness in [true, false] {
            let ports = Arc::new(LogoutPorts::default());
            ports
                .readiness_fails
                .store(fail_readiness, Ordering::SeqCst);
            ports.audit_fails.store(!fail_readiness, Ordering::SeqCst);
            assert_eq!(
                real_logout_fixture(ports.clone())
                    .logout(real_logout_command())
                    .await,
                Err(OidcLogoutError::AuditUnavailable)
            );
            assert_eq!(ports.enqueues.load(Ordering::SeqCst), 0);
            assert_eq!(ports.deletes.load(Ordering::SeqCst), 0);
        }
        let ports = Arc::new(LogoutPorts::default());
        let handles = real_logout_fixture(ports.clone());
        ports.enqueue_fails.store(true, Ordering::SeqCst);
        assert_eq!(
            handles.logout(real_logout_command()).await,
            Err(OidcLogoutError::OutboxUnavailable)
        );
        assert_eq!(ports.deletes.load(Ordering::SeqCst), 0);
        ports.enqueue_fails.store(false, Ordering::SeqCst);
        ports.delete_fails.store(true, Ordering::SeqCst);
        assert_eq!(
            handles.logout(real_logout_command()).await,
            Err(OidcLogoutError::SessionDeleteUnavailable)
        );
        ports.delete_fails.store(false, Ordering::SeqCst);
        assert!(handles.logout(real_logout_command()).await.is_ok());
        let keys = ports.audit_keys.lock().unwrap();
        assert_eq!(keys.len(), 3);
        assert!(keys.iter().all(|key| key == &keys[0]));
        let delivery_keys = ports.delivery_keys.lock().unwrap();
        assert_eq!(delivery_keys.len(), 3);
        assert!(delivery_keys.iter().all(|key| key == &keys[0]));
        assert_eq!(ports.enqueues.load(Ordering::SeqCst), 3);
        assert_eq!(ports.deletes.load(Ordering::SeqCst), 2);
    });
}
