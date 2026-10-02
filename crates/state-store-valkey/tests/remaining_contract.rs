use std::time::Duration;

use fred::interfaces::{ClientLike, KeysInterface};
use fred::prelude::{Builder, Config};
use nazo_identity::TenantId;
use nazo_identity::ports::{
    EmailVerificationConsume, EmailVerificationStorePort, FederationStatePort, LoginSessionCreate,
    LoginSessionPort, MfaAttemptThrottleDecision, MfaAttemptThrottlePort, PasskeyCeremonyPort,
    PasswordHashInput,
};
use nazo_identity::session::SessionRecord;
use nazo_valkey::{
    AuthenticationStore, RateDimension, RateLimitStore, TokenStateStore, ValkeyConnection,
};
use serde_json::json;

async fn setup() -> Option<(ValkeyConnection, fred::prelude::Client)> {
    let url = std::env::var("VALKEY_URL").ok()?;
    let connection = nazo_valkey::test_support::scoped_connect(&url, Duration::from_secs(1))
        .await
        .unwrap();
    let inspector = Builder::from_config(Config::from_url(&url).unwrap())
        .build()
        .unwrap();
    inspector
        .init()
        .await
        .expect("explicit Valkey must be available");
    Some((connection, inspector))
}

fn tenant(value: u128) -> TenantId {
    TenantId::new(uuid::Uuid::from_u128(value)).expect("test tenant must be non-nil")
}

#[tokio::test]
async fn authentication_short_state_preserves_exact_keys_and_one_time_semantics() {
    let Some((connection, inspector)) = setup().await else {
        return;
    };
    let store = AuthenticationStore::new(&connection);
    let suffix = uuid::Uuid::now_v7().to_string();
    let email = format!("{suffix}@example.com");
    let tenant_id = tenant(10);
    let ceremony = format!("ceremony-{suffix}");
    assert!(
        store
            .reserve_email_send(tenant_id, &email, "test-owner", 30)
            .await
            .unwrap()
    );
    assert!(
        !store
            .reserve_email_send(tenant_id, &email, "test-owner", 30)
            .await
            .unwrap()
    );
    let email_digest = blake3::hash(email.as_bytes()).to_hex();
    let send_key = nazo_valkey::test_support::state_storage_key(format!(
        "oauth:email_verify:{}:send:{email_digest}",
        tenant_id.as_uuid()
    ));
    assert_eq!(
        inspector.get::<String, _>(&send_key).await.unwrap(),
        "test-owner"
    );
    assert!(!send_key.contains(&email));
    store
        .store_email_code(tenant_id, &email, "test-owner", "123456", 30)
        .await
        .unwrap();
    assert_eq!(
        store
            .load_email_code(tenant_id, &email)
            .await
            .unwrap()
            .as_deref(),
        Some("123456")
    );
    let payload = json!({"challenge":"opaque", "user_id": suffix});
    store
        .store_passkey_registration(&ceremony, &payload, 30)
        .await
        .unwrap();
    assert_eq!(
        store.take_passkey_registration(&ceremony).await.unwrap(),
        Some(payload)
    );
    assert!(
        store
            .take_passkey_registration(&ceremony)
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn social_federation_state_is_consumed_once_and_keeps_provider_binding() {
    let Some((connection, _inspector)) = setup().await else {
        return;
    };
    let store = AuthenticationStore::new(&connection);
    let state = format!("social-{}", uuid::Uuid::now_v7());
    let value = nazo_identity::federation::SocialFederationState {
        browser_binding_hash: Some("owner-browser".to_owned()),
        provider_id: "github".to_owned(),
        pkce_verifier: "verifier".to_owned(),
        created_at: 1_700_000_000,
    };

    FederationStatePort::store_social(&store, &state, &value, 30)
        .await
        .unwrap();
    assert_eq!(
        FederationStatePort::take_social(&store, &state, "owner-browser")
            .await
            .unwrap()
            .map(|stored| (stored.provider_id, stored.pkce_verifier, stored.created_at)),
        Some(("github".to_owned(), "verifier".to_owned(), 1_700_000_000))
    );
    assert!(
        FederationStatePort::take_social(&store, &state, "owner-browser")
            .await
            .unwrap()
            .is_none(),
        "social federation callback state must be one-time"
    );
}

#[tokio::test]
async fn typed_passkey_ceremony_is_atomically_consumed_once_under_concurrency() {
    let Some((connection, _inspector)) = setup().await else {
        return;
    };
    let store = AuthenticationStore::new(&connection);
    let suffix = uuid::Uuid::now_v7();
    let ceremony_id = format!("typed-{suffix}");
    let stored: nazo_identity::StoredPasskeyRegistration = serde_json::from_value(json!({
        "tenant_id": nazo_identity::TenantId::new(uuid::Uuid::now_v7()).unwrap(),
        "user_id": nazo_identity::UserId::new(uuid::Uuid::now_v7()).unwrap(),
        "label": "Concurrent key",
        "state": {
            "challenge": vec![7_u8; 32],
            "user_id": vec![9_u8; 32],
            "created_at": 1,
        },
    }))
    .unwrap();
    PasskeyCeremonyPort::store_registration(&store, &ceremony_id, &stored, 30)
        .await
        .unwrap();

    let (left, right) = tokio::join!(
        PasskeyCeremonyPort::take_registration(&store, &ceremony_id),
        PasskeyCeremonyPort::take_registration(&store, &ceremony_id)
    );
    let consumed = [left.unwrap(), right.unwrap()]
        .into_iter()
        .filter(Option::is_some)
        .count();
    assert_eq!(
        consumed, 1,
        "GETDEL must publish the ceremony to one finisher"
    );
}

#[tokio::test]
async fn saml_assertion_replay_reservation_is_atomic() {
    let Some((connection, _inspector)) = setup().await else {
        return;
    };
    let store = AuthenticationStore::new(&connection);
    let signature = format!("saml-signature-{}", uuid::Uuid::now_v7());
    let (left, right) = tokio::join!(
        FederationStatePort::reserve_saml_replay(&store, &signature, 30),
        FederationStatePort::reserve_saml_replay(&store, &signature, 30)
    );
    assert_eq!(
        usize::from(left.unwrap()) + usize::from(right.unwrap()),
        1,
        "one SAML assertion must be accepted at most once"
    );
}

#[tokio::test]
async fn email_code_compare_delete_never_removes_a_newer_value() {
    let Some((connection, _inspector)) = setup().await else {
        return;
    };
    let store = AuthenticationStore::new(&connection);
    let email = format!("cas-{}@example.com", uuid::Uuid::now_v7());
    let tenant_id = tenant(20);
    assert!(
        store
            .reserve_email_send(tenant_id, &email, "test-owner", 30)
            .await
            .unwrap()
    );
    EmailVerificationStorePort::store_code(
        &store,
        tenant_id,
        &email,
        "test-owner",
        PasswordHashInput::new("first-code-hash").unwrap(),
        30,
    )
    .await
    .unwrap();
    let stale = EmailVerificationStorePort::load_code(&store, tenant_id, &email)
        .await
        .unwrap()
        .unwrap();
    store
        .store_email_code(tenant_id, &email, "test-owner", "newer-code-hash", 30)
        .await
        .unwrap();

    assert_eq!(
        EmailVerificationStorePort::consume_code(&store, tenant_id, &email, &stale)
            .await
            .unwrap(),
        EmailVerificationConsume::MissingOrChanged
    );
    assert_eq!(
        store
            .load_email_code(tenant_id, &email)
            .await
            .unwrap()
            .as_deref(),
        Some("newer-code-hash"),
        "a stale consumer must not delete a newer verification code"
    );

    let current = EmailVerificationStorePort::load_code(&store, tenant_id, &email)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        EmailVerificationStorePort::consume_code(&store, tenant_id, &email, &current)
            .await
            .unwrap(),
        EmailVerificationConsume::Consumed
    );
    assert!(
        store
            .load_email_code(tenant_id, &email)
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn email_verification_state_isolated_by_tenant() {
    let Some((connection, _inspector)) = setup().await else {
        return;
    };
    let store = AuthenticationStore::new(&connection);
    let first_tenant = tenant(101);
    let second_tenant = tenant(202);
    let email = format!("shared-{}@example.com", uuid::Uuid::now_v7());
    let peer = format!("peer-{}", uuid::Uuid::now_v7());

    assert!(
        store
            .reserve_email_send(first_tenant, &email, "test-owner", 30)
            .await
            .unwrap()
    );
    assert!(
        store
            .reserve_email_send(second_tenant, &email, "test-owner", 30)
            .await
            .unwrap(),
        "the same email must have an independent tenant cooldown"
    );
    assert!(
        !store
            .reserve_email_send(first_tenant, &email, "test-owner", 30)
            .await
            .unwrap()
    );
    assert!(
        store
            .reserve_email_peer_send(first_tenant, &peer, "test-owner", 30)
            .await
            .unwrap()
    );
    assert!(
        store
            .reserve_email_peer_send(second_tenant, &peer, "test-owner", 30)
            .await
            .unwrap(),
        "the same peer must have an independent tenant cooldown"
    );
    assert!(
        !store
            .reserve_email_peer_send(first_tenant, &peer, "test-owner", 30)
            .await
            .unwrap()
    );

    EmailVerificationStorePort::store_code(
        &store,
        first_tenant,
        &email,
        "test-owner",
        PasswordHashInput::new("first-tenant-code-hash").unwrap(),
        30,
    )
    .await
    .unwrap();
    assert!(
        EmailVerificationStorePort::load_code(&store, second_tenant, &email)
            .await
            .unwrap()
            .is_none(),
        "another tenant must not load the first tenant's code"
    );
    let first_before_foreign_delete =
        EmailVerificationStorePort::load_code(&store, first_tenant, &email)
            .await
            .unwrap()
            .unwrap();
    EmailVerificationStorePort::delete_code(&store, second_tenant, &email, "test-owner")
        .await
        .unwrap();
    assert_eq!(
        EmailVerificationStorePort::load_code(&store, first_tenant, &email)
            .await
            .unwrap(),
        Some(first_before_foreign_delete),
        "deleting a tenant's absent code must not remove another tenant's code"
    );
    EmailVerificationStorePort::store_code(
        &store,
        second_tenant,
        &email,
        "test-owner",
        PasswordHashInput::new("second-tenant-code-hash").unwrap(),
        30,
    )
    .await
    .unwrap();
    let first = EmailVerificationStorePort::load_code(&store, first_tenant, &email)
        .await
        .unwrap()
        .unwrap();
    let second = EmailVerificationStorePort::load_code(&store, second_tenant, &email)
        .await
        .unwrap()
        .unwrap();
    assert_ne!(first, second);
    assert_eq!(
        EmailVerificationStorePort::consume_code(&store, first_tenant, &email, &first)
            .await
            .unwrap(),
        EmailVerificationConsume::Consumed
    );
    assert!(
        EmailVerificationStorePort::load_code(&store, first_tenant, &email)
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        EmailVerificationStorePort::load_code(&store, second_tenant, &email)
            .await
            .unwrap(),
        Some(second),
        "consuming one tenant's code must not change another tenant's code"
    );
    EmailVerificationStorePort::release_email_send(&store, first_tenant, &email, "test-owner")
        .await
        .unwrap();
    assert!(
        store
            .reserve_email_send(first_tenant, &email, "test-owner", 30)
            .await
            .unwrap(),
        "releasing one tenant's email cooldown must affect only that tenant"
    );
    assert!(
        !store
            .reserve_email_send(second_tenant, &email, "test-owner", 30)
            .await
            .unwrap(),
        "another tenant's email cooldown must remain reserved"
    );
    EmailVerificationStorePort::release_peer_send(&store, first_tenant, &peer, "test-owner")
        .await
        .unwrap();
    assert!(
        store
            .reserve_email_peer_send(first_tenant, &peer, "test-owner", 30)
            .await
            .unwrap(),
        "releasing one tenant's peer cooldown must affect only that tenant"
    );
    assert!(
        !store
            .reserve_email_peer_send(second_tenant, &peer, "test-owner", 30)
            .await
            .unwrap(),
        "another tenant's peer cooldown must remain reserved"
    );
}

#[tokio::test]
async fn login_session_create_is_atomic_and_never_overwrites_a_collision() {
    let Some((connection, _inspector)) = setup().await else {
        return;
    };
    let sessions = nazo_valkey::SessionStore::new(&connection);
    let session_id = format!("login-collision-{}", uuid::Uuid::now_v7());
    let first = SessionRecord::new(
        nazo_identity::UserId::new(uuid::Uuid::now_v7()).unwrap(),
        1,
        vec!["password".to_owned()],
        false,
        Some("first-oidc-sid".to_owned()),
    );
    let second = SessionRecord::new(
        nazo_identity::UserId::new(uuid::Uuid::now_v7()).unwrap(),
        2,
        vec!["password".to_owned()],
        true,
        Some("second-oidc-sid".to_owned()),
    );

    assert_eq!(
        LoginSessionPort::create(&sessions, &session_id, &first, 30)
            .await
            .unwrap(),
        LoginSessionCreate::Created
    );
    assert_eq!(
        LoginSessionPort::create(&sessions, &session_id, &second, 30)
            .await
            .unwrap(),
        LoginSessionCreate::Collision
    );
    assert_eq!(
        sessions.load(&session_id).await.unwrap().unwrap().value(),
        &first
    );
}

#[tokio::test]
async fn login_session_replacement_atomically_invalidates_the_previous_session() {
    let Some((connection, inspector)) = setup().await else {
        return;
    };
    let sessions = nazo_valkey::SessionStore::new(&connection);
    let previous_id = format!("login-previous-{}", uuid::Uuid::now_v7());
    let collision_id = format!("login-collision-{}", uuid::Uuid::now_v7());
    let replacement_id = format!("login-replacement-{}", uuid::Uuid::now_v7());
    let previous = SessionRecord::new(
        nazo_identity::UserId::new(uuid::Uuid::now_v7()).unwrap(),
        1,
        vec!["password".to_owned()],
        false,
        Some("previous-oidc-sid".to_owned()),
    );
    let replacement = SessionRecord::new(
        nazo_identity::UserId::new(uuid::Uuid::now_v7()).unwrap(),
        2,
        vec!["password".to_owned()],
        true,
        Some("replacement-oidc-sid".to_owned()),
    );
    assert_eq!(
        LoginSessionPort::create(&sessions, &previous_id, &previous, 120)
            .await
            .unwrap(),
        LoginSessionCreate::Created
    );
    assert_eq!(
        LoginSessionPort::create(&sessions, &collision_id, &replacement, 120)
            .await
            .unwrap(),
        LoginSessionCreate::Created
    );
    assert_eq!(
        LoginSessionPort::create_replacing(
            &sessions,
            Some(&previous_id),
            &collision_id,
            &previous,
            60,
        )
        .await
        .unwrap(),
        LoginSessionCreate::Collision
    );
    assert_eq!(
        sessions.load(&previous_id).await.unwrap().unwrap().value(),
        &previous
    );
    assert_eq!(
        sessions.load(&collision_id).await.unwrap().unwrap().value(),
        &replacement
    );
    assert_eq!(
        LoginSessionPort::create_replacing(
            &sessions,
            Some(&previous_id),
            &replacement_id,
            &replacement,
            60,
        )
        .await
        .unwrap(),
        LoginSessionCreate::Created
    );
    assert!(sessions.load(&previous_id).await.unwrap().is_none());
    assert_eq!(
        sessions
            .load(&replacement_id)
            .await
            .unwrap()
            .unwrap()
            .value(),
        &replacement
    );
    let replacement_key =
        nazo_valkey::test_support::state_storage_key(format!("oauth:session:{replacement_id}"));
    assert!((1..=60).contains(&inspector.ttl::<i64, _>(replacement_key).await.unwrap()));
}

#[tokio::test]
async fn concurrent_rate_counters_are_atomic_and_preserve_first_window_ttl() {
    let Some((connection, inspector)) = setup().await else {
        return;
    };
    let store = RateLimitStore::new(&connection);
    let subject = format!("subject-{}", uuid::Uuid::now_v7());
    let futures = (0..20).map(|_| store.increment(RateDimension::Token, &subject, 30));
    let results = futures_util::future::join_all(futures).await;
    let mut counts = results.into_iter().collect::<Result<Vec<_>, _>>().unwrap();
    counts.sort_unstable();
    assert_eq!(counts, (1..=20).collect::<Vec<_>>());
    let key = nazo_valkey::test_support::state_storage_key(format!(
        "oauth:rate:token:{}",
        blake3::hash(subject.as_bytes()).to_hex()
    ));
    assert!((1..=30).contains(&inspector.ttl::<i64, _>(&key).await.unwrap()));
}

#[tokio::test]
async fn mfa_failure_budget_is_session_bound_and_clears_after_success() {
    let Some((connection, inspector)) = setup().await else {
        return;
    };
    let store = RateLimitStore::new(&connection);
    let tenant = nazo_identity::TenantId::new(uuid::Uuid::from_u128(1)).unwrap();
    let user = nazo_identity::UserId::new(uuid::Uuid::from_u128(2)).unwrap();
    let session = format!("pending-{}", uuid::Uuid::now_v7());

    for _ in 0..5 {
        assert_eq!(
            store
                .reserve_attempt(tenant, user, &session, 30, 5)
                .await
                .unwrap(),
            MfaAttemptThrottleDecision::Allowed
        );
    }
    assert_eq!(
        store
            .reserve_attempt(tenant, user, &session, 30, 5)
            .await
            .unwrap(),
        MfaAttemptThrottleDecision::Limited {
            retry_after_seconds: 30
        }
    );
    let subject = format!("{}:{}:{session}", tenant.as_uuid(), user.as_uuid());
    let key = nazo_valkey::test_support::state_storage_key(format!(
        "oauth:mfa_failure:{}",
        blake3::hash(subject.as_bytes()).to_hex()
    ));
    assert!((1..=30).contains(&inspector.ttl::<i64, _>(&key).await.unwrap()));

    store.clear_attempts(tenant, user, &session).await.unwrap();
    assert_eq!(
        store
            .reserve_attempt(tenant, user, &session, 30, 5)
            .await
            .unwrap(),
        MfaAttemptThrottleDecision::Allowed
    );
    let other_session = format!("pending-{}", uuid::Uuid::now_v7());
    assert_eq!(
        store
            .reserve_attempt(tenant, user, &other_session, 30, 5)
            .await
            .unwrap(),
        MfaAttemptThrottleDecision::Allowed
    );
}

#[tokio::test]
async fn token_state_preserves_native_sso_key_contract() {
    let Some((connection, _)) = setup().await else {
        return;
    };
    let store = TokenStateStore::new(&connection);
    let tenant = uuid::Uuid::from_u128(1);
    let user = uuid::Uuid::from_u128(2);
    let secret = format!("secret-{}", uuid::Uuid::now_v7());
    let payload = json!({"tenant_id":tenant,"user_id":user,"sid":"sid"});
    store.store_native_sso(&secret, &payload, 30).await.unwrap();
    assert_eq!(store.load_native_sso(&secret).await.unwrap(), Some(payload));
}

#[derive(Clone, Copy)]
struct EmptyRegistrationAccounts;
impl nazo_identity::ports::RegistrationAccountRepositoryPort for EmptyRegistrationAccounts {
    fn account_by_email<'a>(
        &'a self,
        _: TenantId,
        _: &'a str,
    ) -> nazo_identity::ports::RepositoryFuture<'a, Option<nazo_identity::PublicAccount>> {
        Box::pin(async { Ok(None) })
    }
    fn create_user(
        &self,
        _: nazo_identity::ports::NewUser,
    ) -> nazo_identity::ports::RepositoryFuture<'_, nazo_identity::PublicAccount> {
        Box::pin(async { Err(nazo_identity::ports::RepositoryError::Unavailable) })
    }
}
#[derive(Clone, Copy)]
struct EqualCodeHashes;
impl nazo_identity::ports::SecretHashPort for EqualCodeHashes {
    fn hash_secret(
        &self,
        _: String,
    ) -> nazo_identity::ports::RepositoryFuture<'_, PasswordHashInput> {
        Box::pin(async { Ok(PasswordHashInput::new("same-test-hash").unwrap()) })
    }
    fn verify_secret(
        &self,
        _: String,
        _: nazo_identity::PasswordHash,
    ) -> nazo_identity::ports::RepositoryFuture<'_, bool> {
        Box::pin(async { Ok(true) })
    }
}
#[derive(Clone)]
struct ControlledEmailDelivery {
    started: std::sync::Arc<tokio::sync::Notify>,
    release: std::sync::Arc<tokio::sync::Notify>,
    block_and_fail: bool,
}
impl nazo_identity::ports::VerificationEmailDeliveryPort for ControlledEmailDelivery {
    fn deliver<'a>(
        &'a self,
        _: &'a str,
        _: &'a str,
        _: u64,
    ) -> nazo_identity::ports::RepositoryFuture<'a, ()> {
        Box::pin(async move {
            if self.block_and_fail {
                self.started.notify_one();
                self.release.notified().await;
                Err(nazo_identity::ports::RepositoryError::Unavailable)
            } else {
                Ok(())
            }
        })
    }
}

#[tokio::test]
async fn late_smtp_failure_preserves_newer_code_and_both_cooldowns() {
    let Some((connection, inspector)) = setup().await else {
        return;
    };
    let store = AuthenticationStore::new(&connection);
    let email = format!("late-smtp-{}@example.test", uuid::Uuid::now_v7());
    let peer = format!("late-smtp-peer-{}", uuid::Uuid::now_v7());
    let started = std::sync::Arc::new(tokio::sync::Notify::new());
    let release = std::sync::Arc::new(tokio::sync::Notify::new());
    let tenant = nazo_identity::TenantContext {
        tenant_id: TenantId::new(uuid::Uuid::now_v7()).unwrap(),
        ..Default::default()
    };
    let config = nazo_identity::RegistrationServiceConfig {
        delivery_enabled: true,
        send_peer_cooldown_seconds: 1,
        send_cooldown_seconds: 1,
        code_ttl_seconds: 30,
    };
    let older = nazo_identity::RegistrationService::new(
        EmptyRegistrationAccounts,
        store.clone(),
        EqualCodeHashes,
        ControlledEmailDelivery {
            started: started.clone(),
            release: release.clone(),
            block_and_fail: true,
        },
        tenant,
        config,
    );
    let newer = nazo_identity::RegistrationService::new(
        EmptyRegistrationAccounts,
        store.clone(),
        EqualCodeHashes,
        ControlledEmailDelivery {
            started: started.clone(),
            release: release.clone(),
            block_and_fail: false,
        },
        tenant,
        config,
    );
    let old_email = email.clone();
    let old_peer = peer.clone();
    let old_send =
        tokio::spawn(async move { older.send_verification_code(&old_email, &old_peer).await });
    tokio::time::timeout(Duration::from_secs(2), started.notified())
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(1100)).await;
    assert!(matches!(
        newer.send_verification_code(&email, &peer).await.unwrap(),
        nazo_identity::SendVerificationCodeOutcome::Sent { .. }
    ));
    let before = EmailVerificationStorePort::load_code(&store, tenant.tenant_id, &email)
        .await
        .unwrap()
        .unwrap();
    let code_key = nazo_valkey::test_support::state_storage_key(format!(
        "oauth:email_verify:{}:code:{}",
        tenant.tenant_id.as_uuid(),
        blake3::hash(email.as_bytes()).to_hex()
    ));
    let deadline = inspector.expire_time::<i64, _>(&code_key).await.unwrap();
    release.notify_one();
    assert!(matches!(
        tokio::time::timeout(Duration::from_secs(2), old_send)
            .await
            .unwrap()
            .unwrap(),
        Err(nazo_identity::SendVerificationCodeError::Delivery(_))
    ));
    assert_eq!(
        EmailVerificationStorePort::load_code(&store, tenant.tenant_id, &email)
            .await
            .unwrap(),
        Some(before)
    );
    assert_eq!(
        inspector.expire_time::<i64, _>(&code_key).await.unwrap(),
        deadline
    );
    assert_eq!(
        newer.send_verification_code(&email, &peer).await.unwrap(),
        nazo_identity::SendVerificationCodeOutcome::Suppressed,
        "old cleanup must not remove the newer peer reservation"
    );
    let different_peer = format!("different-{}", uuid::Uuid::now_v7());
    assert_eq!(
        newer
            .send_verification_code(&email, &different_peer)
            .await
            .unwrap(),
        nazo_identity::SendVerificationCodeOutcome::Suppressed,
        "old cleanup must not remove the newer email reservation"
    );
}

#[derive(Clone)]
struct BlockedCodeHashes {
    entered: std::sync::Arc<tokio::sync::Notify>,
    release: std::sync::Arc<tokio::sync::Notify>,
}
impl nazo_identity::ports::SecretHashPort for BlockedCodeHashes {
    fn hash_secret(
        &self,
        _: String,
    ) -> nazo_identity::ports::RepositoryFuture<'_, PasswordHashInput> {
        Box::pin(async move {
            self.entered.notify_one();
            self.release.notified().await;
            Ok(PasswordHashInput::new("same-test-hash").unwrap())
        })
    }
    fn verify_secret(
        &self,
        _: String,
        _: nazo_identity::PasswordHash,
    ) -> nazo_identity::ports::RepositoryFuture<'_, bool> {
        Box::pin(async { Ok(true) })
    }
}
#[derive(Clone)]
struct CountingEmailDelivery(std::sync::Arc<std::sync::atomic::AtomicUsize>);
impl nazo_identity::ports::VerificationEmailDeliveryPort for CountingEmailDelivery {
    fn deliver<'a>(
        &'a self,
        _: &'a str,
        _: &'a str,
        _: u64,
    ) -> nazo_identity::ports::RepositoryFuture<'a, ()> {
        Box::pin(async move {
            self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(())
        })
    }
}

#[tokio::test]
async fn late_hash_cannot_store_after_owner_expiry_or_overwrite_a_new_sender() {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    let Some((connection, inspector)) = setup().await else {
        return;
    };
    for with_newer_sender in [false, true] {
        let store = AuthenticationStore::new(&connection);
        let email = format!("late-hash-{}@example.test", uuid::Uuid::now_v7());
        let peer = format!("late-hash-{}", uuid::Uuid::now_v7());
        let context = nazo_identity::TenantContext {
            tenant_id: TenantId::new(uuid::Uuid::now_v7()).unwrap(),
            ..Default::default()
        };
        let config = nazo_identity::RegistrationServiceConfig {
            delivery_enabled: true,
            send_peer_cooldown_seconds: 1,
            send_cooldown_seconds: 1,
            code_ttl_seconds: 30,
        };
        let entered = Arc::new(tokio::sync::Notify::new());
        let release = Arc::new(tokio::sync::Notify::new());
        let old_delivery = Arc::new(AtomicUsize::new(0));
        let new_delivery = Arc::new(AtomicUsize::new(0));
        let older = nazo_identity::RegistrationService::new(
            EmptyRegistrationAccounts,
            store.clone(),
            BlockedCodeHashes {
                entered: entered.clone(),
                release: release.clone(),
            },
            CountingEmailDelivery(old_delivery.clone()),
            context,
            config,
        );
        let newer = nazo_identity::RegistrationService::new(
            EmptyRegistrationAccounts,
            store.clone(),
            EqualCodeHashes,
            CountingEmailDelivery(new_delivery.clone()),
            context,
            config,
        );
        let old_email = email.clone();
        let old_peer = peer.clone();
        let old_send =
            tokio::spawn(async move { older.send_verification_code(&old_email, &old_peer).await });
        tokio::time::timeout(Duration::from_secs(2), entered.notified())
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(1100)).await;
        let code_key = nazo_valkey::test_support::state_storage_key(format!(
            "oauth:email_verify:{}:code:{}",
            context.tenant_id.as_uuid(),
            blake3::hash(email.as_bytes()).to_hex()
        ));
        let email_key = nazo_valkey::test_support::state_storage_key(format!(
            "oauth:email_verify:{}:send:{}",
            context.tenant_id.as_uuid(),
            blake3::hash(email.as_bytes()).to_hex()
        ));
        let peer_key = nazo_valkey::test_support::state_storage_key(format!(
            "oauth:email_verify:{}:peer_send:{}",
            context.tenant_id.as_uuid(),
            blake3::hash(peer.as_bytes()).to_hex()
        ));
        let before = if with_newer_sender {
            assert!(matches!(
                newer.send_verification_code(&email, &peer).await.unwrap(),
                nazo_identity::SendVerificationCodeOutcome::Sent { .. }
            ));
            Some((
                inspector.get::<String, _>(&code_key).await.unwrap(),
                inspector.expire_time::<i64, _>(&code_key).await.unwrap(),
                inspector.get::<String, _>(&email_key).await.unwrap(),
                inspector.get::<String, _>(&peer_key).await.unwrap(),
            ))
        } else {
            None
        };
        release.notify_one();
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(2), old_send)
                .await
                .unwrap()
                .unwrap(),
            Err(nazo_identity::SendVerificationCodeError::CodeStore(
                nazo_identity::ports::RepositoryError::Conflict
            ))
        );
        assert_eq!(
            old_delivery.load(Ordering::SeqCst),
            0,
            "expired owner must fail before SMTP"
        );
        if let Some((raw, deadline, email_owner, peer_owner)) = before {
            assert_eq!(inspector.get::<String, _>(&code_key).await.unwrap(), raw);
            assert_eq!(
                inspector.expire_time::<i64, _>(&code_key).await.unwrap(),
                deadline
            );
            assert_eq!(
                inspector.get::<String, _>(&email_key).await.unwrap(),
                email_owner
            );
            assert_eq!(
                inspector.get::<String, _>(&peer_key).await.unwrap(),
                peer_owner
            );
            assert_eq!(new_delivery.load(Ordering::SeqCst), 1);
        } else {
            assert!(
                EmailVerificationStorePort::load_code(&store, context.tenant_id, &email)
                    .await
                    .unwrap()
                    .is_none()
            );
        }
    }
}

#[tokio::test]
async fn typed_passkey_codec_preserves_legacy_json_unknown_fields_expiry_and_corrupt_consumption() {
    let Some((connection, inspector)) = setup().await else {
        return;
    };
    let store = AuthenticationStore::new(&connection);
    let id = format!("typed-legacy-{}", uuid::Uuid::now_v7());
    let wire = json!({
        "tenant_id": TenantId::new(uuid::Uuid::now_v7()).unwrap(),
        "user_id": nazo_identity::UserId::new(uuid::Uuid::now_v7()).unwrap(),
        "label": "Legacy key", "ignored_future_field": "ignored",
        "state": { "challenge": vec![7_u8;32], "user_id": vec![9_u8;32], "created_at": 1 },
    });
    store
        .store_passkey_registration(&id, &wire, 30)
        .await
        .unwrap();
    let value = PasskeyCeremonyPort::take_registration(&store, &id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(value.label, "Legacy key");
    PasskeyCeremonyPort::store_registration(&store, &id, &value, 30)
        .await
        .unwrap();
    let key =
        nazo_valkey::test_support::state_storage_key(format!("oauth:passkey:registration:{id}"));
    let raw: String = inspector.get(&key).await.unwrap();
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&raw).unwrap(),
        serde_json::to_value(&value).unwrap()
    );
    let ttl: i64 = inspector.ttl(&key).await.unwrap();
    assert!((28..=30).contains(&ttl));
    assert!(
        PasskeyCeremonyPort::take_registration(&store, &id)
            .await
            .unwrap()
            .is_some()
    );
    store
        .store_passkey_registration(&id, &json!({"invalid":"shape"}), 30)
        .await
        .unwrap();
    assert!(matches!(
        PasskeyCeremonyPort::take_registration(&store, &id).await,
        Err(nazo_identity::ports::RepositoryError::Consistency(_))
    ));
    assert!(
        PasskeyCeremonyPort::take_registration(&store, &id)
            .await
            .unwrap()
            .is_none()
    );
    PasskeyCeremonyPort::store_registration(&store, &id, &value, 1)
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(1100)).await;
    assert!(
        PasskeyCeremonyPort::take_registration(&store, &id)
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn typed_passkey_authentication_keeps_legacy_default_fields() {
    let Some((connection, _inspector)) = setup().await else {
        return;
    };
    let store = AuthenticationStore::new(&connection);
    let id = format!("typed-auth-legacy-{}", uuid::Uuid::now_v7());
    let wire = json!({
        "tenant_id": TenantId::new(uuid::Uuid::now_v7()).unwrap(),
        "user_id": nazo_identity::UserId::new(uuid::Uuid::now_v7()).unwrap(),
        "ignored_future_field": "ignored",
        "state": { "challenge": vec![7_u8;32], "allow_credentials": [] },
    });
    store
        .store_passkey_authentication(&id, &wire, 30)
        .await
        .unwrap();
    let value = PasskeyCeremonyPort::take_authentication(&store, &id)
        .await
        .unwrap()
        .unwrap();
    assert!(!value.dummy);
    assert_eq!(value.state.created_at, 0);
    assert!(value.state.user_handle.is_none());
    PasskeyCeremonyPort::store_authentication(&store, &id, &value, 30)
        .await
        .unwrap();
    assert!(
        PasskeyCeremonyPort::take_authentication(&store, &id)
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        PasskeyCeremonyPort::take_authentication(&store, &id)
            .await
            .unwrap()
            .is_none()
    );
}
