use jiff::Timestamp;
use nazo_identity::federation::oidc::{OidcIdTokenClaims, OidcUpstreamLogin};
use nazo_identity::{
    AccountIdentity, FederationAuditEvent, FederationService, FederationServiceConfig,
    OidcFederationState, Principal, PublicAccount, SocialFederationState, TenantContext, TenantId,
    UserId, UserProfile, UserRole, VerifiedExternalIdentity, ports::*, session::SessionRecord,
};
use serde_json::json;
use std::sync::{Arc, Mutex};

#[derive(Clone)]
struct Ports {
    account: PublicAccount,
    sessions: Arc<Mutex<Vec<(SessionRecord, u64)>>>,
    audit: Arc<Mutex<Vec<FederationAuditEvent>>>,
    defer_session_completion: bool,
}

impl Ports {
    fn new(mfa_enabled: bool) -> Self {
        Self {
            account: PublicAccount {
                principal: Principal {
                    authorization_epoch: 0,
                    user_id: UserId::new(uuid::Uuid::now_v7()).unwrap(),
                    tenant: TenantContext::default_system(),
                    role: UserRole::User,
                    active: true,
                },
                account: AccountIdentity {
                    username: "linked".into(),
                    email: "linked@example.com".into(),
                    email_verified: true,
                    mfa_enabled,
                },
                profile: UserProfile::default(),
                created_at: Timestamp::now(),
                updated_at: Timestamp::now(),
            },
            sessions: Arc::new(Mutex::new(Vec::new())),
            audit: Arc::new(Mutex::new(Vec::new())),
            defer_session_completion: false,
        }
    }
}
impl FederationLoginRepositoryPort for Ports {
    fn resolve_existing<'a>(
        &'a self,
        _: &'a FederationLogin,
    ) -> RepositoryFuture<'a, Option<PublicAccount>> {
        Box::pin(async { Ok(Some(self.account.clone())) })
    }
    fn email_exists<'a>(&'a self, _: TenantId, _: &'a str) -> RepositoryFuture<'a, bool> {
        panic!("existing link must be resolved directly")
    }
    fn create_federated(&self, _: NewFederatedIdentity) -> RepositoryFuture<'_, PublicAccount> {
        panic!("existing link must not provision an account")
    }
    fn link_authenticated(&self, _: NewFederationLink) -> RepositoryFuture<'_, ()> {
        panic!("unexpected link mutation in login-only fixture")
    }
}
impl FederationStatePort for Ports {
    fn store_oidc<'a>(
        &'a self,
        _: &'a str,
        _: &'a OidcFederationState,
        _: u64,
    ) -> RepositoryFuture<'a, ()> {
        panic!("unexpected ceremony")
    }
    fn take_oidc<'a>(
        &'a self,
        _: &'a str,
        _: &'a str,
    ) -> RepositoryFuture<'a, Option<OidcFederationState>> {
        panic!("unexpected ceremony")
    }
    fn store_social<'a>(
        &'a self,
        _: &'a str,
        _: &'a SocialFederationState,
        _: u64,
    ) -> RepositoryFuture<'a, ()> {
        panic!("unexpected ceremony")
    }
    fn take_social<'a>(
        &'a self,
        _: &'a str,
        _: &'a str,
    ) -> RepositoryFuture<'a, Option<SocialFederationState>> {
        panic!("unexpected ceremony")
    }
    fn reserve_saml_replay<'a>(&'a self, _: &'a str, _: u64) -> RepositoryFuture<'a, bool> {
        panic!("unexpected ceremony")
    }
}
impl FederationPasswordHasherPort for Ports {
    fn hash_bootstrap_secret(&self) -> RepositoryFuture<'_, PasswordHashInput> {
        panic!("existing account must not get a new password")
    }
}
impl FederationAuditPort for Ports {
    fn record(&self, event: FederationAuditEvent) {
        self.audit.lock().unwrap().push(event);
    }
    fn record_required<'a>(&'a self, event: FederationAuditEvent) -> RepositoryFuture<'a, ()> {
        self.audit.lock().unwrap().push(event);
        Box::pin(async { Ok(()) })
    }
}
impl LoginSessionPort for Ports {
    fn create<'a>(
        &'a self,
        _: &'a str,
        record: &'a SessionRecord,
        ttl: u64,
    ) -> RepositoryFuture<'a, LoginSessionCreate> {
        self.sessions.lock().unwrap().push((record.clone(), ttl));
        let mut defer = self.defer_session_completion;
        Box::pin(std::future::poll_fn(move |context| {
            if std::mem::take(&mut defer) {
                context.waker().wake_by_ref();
                std::task::Poll::Pending
            } else {
                std::task::Poll::Ready(Ok(LoginSessionCreate::Created))
            }
        }))
    }
    fn create_replacing<'a>(
        &'a self,
        _: Option<&'a str>,
        _: &'a str,
        _: &'a SessionRecord,
        _: u64,
    ) -> RepositoryFuture<'a, LoginSessionCreate> {
        panic!("unexpected replacement")
    }
}

fn upstream_login(started_at: i64) -> OidcUpstreamLogin {
    let claims: OidcIdTokenClaims = serde_json::from_value(json!({
        "iss": "https://issuer.example",
        "aud": "client",
        "sub": "linked-subject",
        "iat": started_at,
    }))
    .unwrap();
    claims
        .upstream_login(
            TenantContext::default_system().tenant_id,
            "provider",
            "client",
            started_at,
        )
        .unwrap()
}

#[cfg_attr(
    all(target_arch = "wasm32", target_os = "unknown"),
    wasm_bindgen_test::wasm_bindgen_test
)]
#[cfg_attr(not(all(target_arch = "wasm32", target_os = "unknown")), tokio::test)]
async fn linked_federation_obeys_local_mfa_and_uses_pending_session_lifetime() {
    for enabled in [false, true] {
        for method in ["oidc", "social", "saml"] {
            for existing_only in [false, true] {
                let ports = Ports::new(enabled);
                let service = FederationService::new(
                    ports.clone(),
                    ports.clone(),
                    ports.clone(),
                    ports.clone(),
                    ports.clone(),
                    FederationServiceConfig {
                        tenant: TenantContext::default_system(),
                        state_ttl_seconds: 300,
                        saml_replay_ttl_seconds: 300,
                        session_ttl_seconds: 3600,
                        pending_mfa_session_ttl_seconds: 120,
                    },
                );
                let identity = VerifiedExternalIdentity {
                    provider_type: method.into(),
                    provider_id: "provider".into(),
                    subject: "linked-subject".into(),
                    email: None,
                    display_name: None,
                    // Raw upstream claims are not a configured assurance mapping.
                    claims: json!({"amr": ["mfa"], "acr": "high"}),
                };
                let result = if existing_only {
                    service
                        .complete_existing_only(identity, method.into(), "127.0.0.1".into())
                        .await
                } else if method == "oidc" {
                    service
                        .complete_oidc(
                            identity,
                            Some(upstream_login(Timestamp::now().as_second())),
                            "127.0.0.1".into(),
                        )
                        .await
                } else {
                    service
                        .complete_verified(identity, method.into(), "127.0.0.1".into())
                        .await
                }
                .unwrap();
                assert_eq!(result.session.pending_mfa(), enabled);
                assert_eq!(
                    result.session.amr(),
                    &[method.to_owned(), "federated".to_owned()]
                );
                let stored = ports.sessions.lock().unwrap();
                assert_eq!(stored.len(), 1);
                assert_eq!(stored[0].0, result.session);
                assert_eq!(stored[0].1, if enabled { 120 } else { 3600 });
                assert!(matches!(
                    ports.audit.lock().unwrap().as_slice(),
                    [FederationAuditEvent::LoginSuccess { .. }]
                ));
            }
        }
    }
}

#[cfg(not(target_arch = "wasm32"))]
#[tokio::test]
async fn oidc_completion_expiring_during_session_storage_is_not_delivered_or_audited() {
    use nazo_identity::FederationError;
    use std::{
        future::Future,
        task::{Context, Poll, Waker},
        time::{Duration, SystemTime, UNIX_EPOCH},
    };

    let mut ports = Ports::new(false);
    ports.defer_session_completion = true;
    let service = FederationService::new(
        ports.clone(),
        ports.clone(),
        ports.clone(),
        ports.clone(),
        ports.clone(),
        FederationServiceConfig {
            tenant: TenantContext::default_system(),
            state_ttl_seconds: 2,
            saml_replay_ttl_seconds: 300,
            session_ttl_seconds: 3600,
            pending_mfa_session_ttl_seconds: 120,
        },
    );
    let started_at = Timestamp::now().as_second();
    let expires_at = started_at + 2;
    let identity = VerifiedExternalIdentity {
        provider_type: "oidc".into(),
        provider_id: "provider".into(),
        subject: "linked-subject".into(),
        email: None,
        display_name: None,
        claims: json!({}),
    };
    let mut completion = Box::pin(service.complete_oidc(
        identity,
        Some(upstream_login(started_at)),
        "127.0.0.1".into(),
    ));
    assert!(matches!(
        completion
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop())),
        Poll::Pending,
    ));
    {
        let stored = ports.sessions.lock().unwrap();
        assert_eq!(stored.len(), 1);
        assert!(stored[0].0.auth_time() < expires_at);
    }
    assert!(ports.audit.lock().unwrap().is_empty());

    // Resume the already pending storage operation at the absolute ceremony deadline.
    let deadline = UNIX_EPOCH + Duration::from_secs(expires_at as u64);
    std::thread::sleep(
        deadline
            .duration_since(SystemTime::now())
            .unwrap_or_default(),
    );
    assert!(matches!(
        completion.await,
        Err(FederationError::StateExpired)
    ));
    assert_eq!(ports.sessions.lock().unwrap().len(), 1);
    assert!(ports.audit.lock().unwrap().is_empty());
}
