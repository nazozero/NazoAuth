use chrono::Utc;
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
    fn record(&self, _: FederationAuditEvent) {}
    fn record_required<'a>(&'a self, _: FederationAuditEvent) -> RepositoryFuture<'a, ()> {
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
        Box::pin(async { Ok(LoginSessionCreate::Created) })
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

#[tokio::test]
async fn linked_federation_obeys_local_mfa_and_uses_pending_session_lifetime() {
    for enabled in [false, true] {
        for method in ["oidc", "social", "saml"] {
            for existing_only in [false, true] {
                let ports = Ports {
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
                            mfa_enabled: enabled,
                        },
                        profile: UserProfile::default(),
                        created_at: Utc::now(),
                        updated_at: Utc::now(),
                    },
                    sessions: Arc::new(Mutex::new(Vec::new())),
                };
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
            }
        }
    }
}
