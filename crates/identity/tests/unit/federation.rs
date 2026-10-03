use super::*;

#[test]
fn browser_binding_digest_is_tenant_scoped_and_canonical_hex() {
    let tenant_a = crate::TenantId::new(uuid::Uuid::from_u128(1)).unwrap();
    let tenant_b = crate::TenantId::new(uuid::Uuid::from_u128(2)).unwrap();
    let seed = [7_u8; 32];
    let digest = browser_binding_hash(tenant_a, &seed);
    assert_eq!(digest.len(), 64);
    assert!(
        digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    );
    assert_eq!(digest, browser_binding_hash(tenant_a, &seed));
    assert_ne!(digest, browser_binding_hash(tenant_b, &seed));
    assert_ne!(digest, browser_binding_hash(tenant_a, &[8_u8; 32]));
}

#[test]
fn legacy_state_deserializes_without_inventing_a_browser_binding() {
    let oidc: OidcFederationState = serde_json::from_value(serde_json::json!({
        "nonce": "nonce",
        "pkce_verifier": "verifier",
        "created_at": 1
    }))
    .unwrap();
    let social: SocialFederationState = serde_json::from_value(serde_json::json!({
        "provider_id": "social",
        "pkce_verifier": "verifier",
        "created_at": 1
    }))
    .unwrap();
    assert!(oidc.browser_binding_hash.is_none());
    assert!(social.browser_binding_hash.is_none());
    assert!(
        serde_json::to_value(oidc)
            .unwrap()
            .get("browser_binding_hash")
            .is_none()
    );
    assert!(
        serde_json::to_value(social)
            .unwrap()
            .get("browser_binding_hash")
            .is_none()
    );
}

#[derive(Clone)]
struct CompletionPorts {
    existing: bool,
    account: PublicAccount,
    creates: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    sessions: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    audit: std::sync::Arc<std::sync::Mutex<Vec<FederationAuditEvent>>>,
}

impl FederationLoginRepositoryPort for CompletionPorts {
    fn resolve_existing(
        &self,
        _login: FederationLogin,
    ) -> crate::ports::RepositoryFuture<'_, Option<PublicAccount>> {
        let account = self.existing.then(|| self.account.clone());
        Box::pin(async move { Ok(account) })
    }
    fn account_by_email<'a>(
        &'a self,
        _tenant: crate::TenantId,
        _email: &'a str,
    ) -> crate::ports::RepositoryFuture<'a, Option<PublicAccount>> {
        Box::pin(async { Ok(None) })
    }
    fn create_federated(
        &self,
        _identity: NewFederatedIdentity,
    ) -> crate::ports::RepositoryFuture<'_, PublicAccount> {
        self.creates
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let account = self.account.clone();
        Box::pin(async move { Ok(account) })
    }
}

impl FederationStatePort for CompletionPorts {
    fn store_oidc<'a>(
        &'a self,
        _state: &'a str,
        _value: &'a OidcFederationState,
        _ttl: u64,
    ) -> crate::ports::RepositoryFuture<'a, ()> {
        panic!("verified completion must not repeat upstream state processing")
    }
    fn take_oidc<'a>(
        &'a self,
        _state: &'a str,
        _binding: &'a str,
    ) -> crate::ports::RepositoryFuture<'a, Option<OidcFederationState>> {
        panic!("verified completion must not repeat upstream state processing")
    }
    fn store_social<'a>(
        &'a self,
        _state: &'a str,
        _value: &'a SocialFederationState,
        _ttl: u64,
    ) -> crate::ports::RepositoryFuture<'a, ()> {
        panic!("verified completion must not repeat upstream state processing")
    }
    fn take_social<'a>(
        &'a self,
        _state: &'a str,
        _binding: &'a str,
    ) -> crate::ports::RepositoryFuture<'a, Option<SocialFederationState>> {
        panic!("verified completion must not repeat upstream state processing")
    }
    fn reserve_saml_replay<'a>(
        &'a self,
        _signature: &'a str,
        _ttl: u64,
    ) -> crate::ports::RepositoryFuture<'a, bool> {
        panic!("verified completion must not repeat gateway replay processing")
    }
}

impl FederationPasswordHasherPort for CompletionPorts {
    fn hash_bootstrap_secret(
        &self,
    ) -> crate::ports::RepositoryFuture<'_, crate::ports::PasswordHashInput> {
        Box::pin(async { Ok(crate::ports::PasswordHashInput::new("test-bootstrap-hash").unwrap()) })
    }
}

impl LoginSessionPort for CompletionPorts {
    fn create<'a>(
        &'a self,
        _id: &'a str,
        _record: &'a SessionRecord,
        _ttl: u64,
    ) -> crate::ports::RepositoryFuture<'a, LoginSessionCreate> {
        self.sessions
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Box::pin(async { Ok(LoginSessionCreate::Created) })
    }
    fn create_replacing<'a>(
        &'a self,
        _previous: Option<&'a str>,
        _id: &'a str,
        _record: &'a SessionRecord,
        _ttl: u64,
    ) -> crate::ports::RepositoryFuture<'a, LoginSessionCreate> {
        panic!("federation completion uses its existing session creation contract")
    }
}

impl FederationAuditPort for CompletionPorts {
    fn record(&self, event: FederationAuditEvent) {
        self.audit.lock().unwrap().push(event);
    }
    fn record_required<'a>(
        &'a self,
        event: FederationAuditEvent,
    ) -> crate::ports::RepositoryFuture<'a, ()> {
        self.audit.lock().unwrap().push(event);
        Box::pin(async { Ok(()) })
    }
}

fn completion_ports(existing: bool, active: bool) -> std::sync::Arc<CompletionPorts> {
    let now = Utc::now();
    std::sync::Arc::new(CompletionPorts {
        existing,
        account: PublicAccount {
            principal: crate::Principal {
                user_id: crate::UserId::new(uuid::Uuid::from_u128(1)).unwrap(),
                tenant: TenantContext::default_system(),
                role: crate::UserRole::User,
                active,
            },
            account: crate::AccountIdentity {
                username: "federated".to_owned(),
                email: "federated@example.test".to_owned(),
                email_verified: true,
                mfa_enabled: false,
            },
            profile: crate::UserProfile::default(),
            created_at: now,
            updated_at: now,
        },
        creates: Default::default(),
        sessions: Default::default(),
        audit: Default::default(),
    })
}

fn completion_identity() -> VerifiedExternalIdentity {
    VerifiedExternalIdentity {
        provider_type: "oidc".to_owned(),
        provider_id: "provider".to_owned(),
        subject: "subject".to_owned(),
        email: Some("federated@example.test".to_owned()),
        display_name: None,
        claims: serde_json::json!({}),
    }
}

#[tokio::test]
async fn every_account_result_passes_active_gate_before_link_audit_or_session_creation() {
    for existing in [false, true] {
        for active in [false, true] {
            let ports = completion_ports(existing, active);
            let service = FederationService::from_port(
                ports.clone(),
                ports.clone(),
                ports.clone(),
                ports.clone(),
                ports.clone(),
                FederationServiceConfig {
                    tenant: TenantContext::default_system(),
                    state_ttl_seconds: 300,
                    saml_replay_ttl_seconds: 300,
                    session_ttl_seconds: 300,
                },
            );
            let result = service
                .complete_verified(
                    completion_identity(),
                    "oidc".to_owned(),
                    "source".to_owned(),
                )
                .await;
            assert_eq!(
                ports.creates.load(std::sync::atomic::Ordering::Relaxed),
                usize::from(!existing)
            );
            assert_eq!(
                ports.sessions.load(std::sync::atomic::Ordering::Relaxed),
                usize::from(active)
            );
            if active {
                assert!(result.is_ok());
            } else {
                assert!(matches!(result, Err(FederationError::LoginFailed)));
                assert!(ports.audit.lock().unwrap().is_empty());
            }
        }
    }
    let ports = completion_ports(true, false);
    let service = FederationService::from_port(
        ports.clone(),
        ports.clone(),
        ports.clone(),
        ports.clone(),
        ports.clone(),
        FederationServiceConfig {
            tenant: TenantContext::default_system(),
            state_ttl_seconds: 300,
            saml_replay_ttl_seconds: 300,
            session_ttl_seconds: 300,
        },
    );
    assert!(matches!(
        service
            .complete_existing_only(
                completion_identity(),
                "social".to_owned(),
                "source".to_owned()
            )
            .await,
        Err(FederationError::InactiveExistingLink)
    ));
    assert_eq!(ports.sessions.load(std::sync::atomic::Ordering::Relaxed), 0);
}
