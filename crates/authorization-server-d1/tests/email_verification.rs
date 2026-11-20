#![cfg(feature = "local-sqlite")]
mod support;

use futures_executor::block_on;
use nazo_identity::{
    PasswordHash, RegisterLocalAccountError, RegisterLocalAccountInput, RegistrationService,
    RegistrationServiceConfig, SendVerificationCodeOutcome, TenantContext, TenantId,
    ports::{
        EmailVerificationConsume, EmailVerificationStorePort, PasswordHashInput, RepositoryFuture,
        SecretHashPort, VerificationEmailDeliveryPort,
    },
};
use nazo_oauth_server_d1::{D1Provider, Database};
use std::sync::{Arc, Barrier};
use support::TENANT;
use uuid::Uuid;

fn tenant() -> TenantId {
    TenantId::new(TENANT).unwrap()
}
fn hash(value: &str) -> PasswordHashInput {
    PasswordHashInput::new(format!("fixture:{value}")).unwrap()
}
async fn challenge(provider: &D1Provider, email: &str, owner: &str) {
    assert!(
        provider
            .reserve_email_send(tenant(), email, owner, 60)
            .await
            .unwrap()
    );
    provider
        .store_code(tenant(), email, owner, hash("123456"), 300)
        .await
        .unwrap();
}
fn assert_sql(database: &Database, predicate: &str) {
    database.execute_sql(&format!("CREATE TEMP TABLE assertion(ok INTEGER CHECK(ok=1));INSERT INTO assertion SELECT CASE WHEN ({predicate}) THEN 1 ELSE 0 END;DROP TABLE assertion;")).unwrap();
}

#[test]
fn reservations_and_cleanup_are_owner_scoped_and_do_not_replace_live_challenges() {
    block_on(async {
        let (database, provider) = support::fixture().await;
        challenge(&provider, "a@example.com", "first").await;
        let old = provider
            .reserve_code_attempt(tenant(), "a@example.com", 5)
            .await
            .unwrap()
            .unwrap();
        assert!(
            !provider
                .reserve_email_send(tenant(), "a@example.com", "second", 60)
                .await
                .unwrap()
        );
        assert!(
            provider
                .store_code(tenant(), "a@example.com", "second", hash("654321"), 300)
                .await
                .is_err()
        );
        provider
            .delete_code(tenant(), "a@example.com", "second")
            .await
            .unwrap();
        provider
            .release_email_send(tenant(), "a@example.com", "second")
            .await
            .unwrap();
        assert!(
            !provider
                .reserve_email_send(tenant(), "a@example.com", "second", 60)
                .await
                .unwrap()
        );
        database
            .execute_sql("UPDATE nazo_state SET expires_at=unixepoch()-1 WHERE kind='email_send'")
            .unwrap();
        challenge(&provider, "a@example.com", "second").await;
        provider
            .delete_code(tenant(), "a@example.com", "first")
            .await
            .unwrap();
        provider
            .release_email_send(tenant(), "a@example.com", "first")
            .await
            .unwrap();
        assert_eq!(
            provider
                .consume_code(tenant(), "a@example.com", &old.opaque_version)
                .await
                .unwrap(),
            EmailVerificationConsume::MissingOrChanged
        );
        let new = provider
            .reserve_code_attempt(tenant(), "a@example.com", 5)
            .await
            .unwrap()
            .unwrap();
        assert_ne!(old.opaque_version, new.opaque_version);
        assert_eq!(
            provider
                .consume_code(tenant(), "a@example.com", &new.opaque_version)
                .await
                .unwrap(),
            EmailVerificationConsume::Consumed
        );
        assert!(
            provider
                .reserve_code_attempt(tenant(), "a@example.com", 5)
                .await
                .unwrap()
                .is_none()
        );
        assert_sql(&database, "NOT EXISTS(SELECT 1 FROM nazo_email_codes)");
    });
}

#[test]
fn concurrent_attempt_budget_and_consumption_have_strict_limits() {
    let (database, provider) = block_on(support::fixture());
    block_on(challenge(&provider, "race@example.com", "owner"));
    let provider = Arc::new(provider);
    let barrier = Arc::new(Barrier::new(16));
    let tasks = (0..16)
        .map(|_| {
            let provider = provider.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                block_on(provider.reserve_code_attempt(tenant(), "race@example.com", 5)).unwrap()
            })
        })
        .collect::<Vec<_>>();
    let records = tasks
        .into_iter()
        .filter_map(|task| task.join().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(records.len(), 5);
    assert!(
        records
            .iter()
            .all(|record| record.opaque_version == records[0].opaque_version)
    );
    assert_sql(&database, "(SELECT attempts FROM nazo_email_codes)=5");
    let barrier = Arc::new(Barrier::new(8));
    let tasks = (0..8)
        .map(|_| {
            let provider = provider.clone();
            let barrier = barrier.clone();
            let version = records[0].opaque_version.clone();
            std::thread::spawn(move || {
                barrier.wait();
                block_on(provider.consume_code(tenant(), "race@example.com", &version)).unwrap()
            })
        })
        .collect::<Vec<_>>();
    assert_eq!(
        tasks
            .into_iter()
            .map(|task| task.join().unwrap())
            .filter(|result| *result == EmailVerificationConsume::Consumed)
            .count(),
        1
    );
}

#[test]
fn expiration_peer_reservations_and_tenant_binding_are_enforced() {
    block_on(async {
        let (database, provider) = support::fixture().await;
        challenge(&provider, "expiry@example.com", "owner").await;
        let record = provider
            .reserve_code_attempt(tenant(), "expiry@example.com", 5)
            .await
            .unwrap()
            .unwrap();
        let foreign = D1Provider::new(database.clone(), foreign_tenant());
        assert!(
            foreign
                .reserve_code_attempt(foreign_tenant(), "expiry@example.com", 5)
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            provider
                .reserve_code_attempt(
                    TenantId::new(Uuid::new_v4()).unwrap(),
                    "expiry@example.com",
                    5
                )
                .await
                .is_err()
        );
        database
            .execute_sql("UPDATE nazo_email_codes SET expires_at=unixepoch()-1")
            .unwrap();
        assert!(
            provider
                .reserve_code_attempt(tenant(), "expiry@example.com", 5)
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(
            provider
                .consume_code(tenant(), "expiry@example.com", &record.opaque_version)
                .await
                .unwrap(),
            EmailVerificationConsume::MissingOrChanged
        );
        assert!(
            provider
                .reserve_peer_send(tenant(), "peer", "owner", 60)
                .await
                .unwrap()
        );
        provider
            .release_peer_send(tenant(), "peer", "stale")
            .await
            .unwrap();
        assert!(
            !provider
                .reserve_peer_send(tenant(), "peer", "other", 60)
                .await
                .unwrap()
        );
        provider
            .release_peer_send(tenant(), "peer", "owner")
            .await
            .unwrap();
        assert!(
            provider
                .reserve_peer_send(tenant(), "peer", "other", 60)
                .await
                .unwrap()
        );
        assert!(
            provider
                .reserve_email_send(tenant(), "zero@example.com", "owner", 0)
                .await
                .is_err()
        );
    });
}

fn foreign_tenant() -> TenantId {
    TenantId::new(Uuid::from_u128(999)).unwrap()
}

#[derive(Clone, Copy)]
struct TestHashes;
impl SecretHashPort for TestHashes {
    fn hash_secret(&self, secret: String) -> RepositoryFuture<'_, PasswordHashInput> {
        Box::pin(async move { Ok(hash(&secret)) })
    }
    fn verify_secret(
        &self,
        secret: String,
        password_hash: PasswordHash,
    ) -> RepositoryFuture<'_, bool> {
        Box::pin(async move {
            Ok(password_hash == PasswordHash::new(format!("fixture:{secret}")).unwrap())
        })
    }
}
#[derive(Clone, Copy)]
struct TestDelivery;
impl VerificationEmailDeliveryPort for TestDelivery {
    fn deliver<'a>(
        &'a self,
        _email: &'a str,
        _code: &'a str,
        _ttl: u64,
    ) -> RepositoryFuture<'a, ()> {
        Box::pin(async { Ok(()) })
    }
}

#[test]
fn shared_registration_service_sends_verifies_creates_and_rejects_replay() {
    block_on(async {
        let (database, provider) = support::fixture().await;
        let mut context = TenantContext::default_system();
        context.tenant_id = tenant();
        let service = RegistrationService::new(
            provider.clone(),
            provider.clone(),
            TestHashes,
            TestDelivery,
            context,
            RegistrationServiceConfig {
                delivery_enabled: true,
                send_peer_cooldown_seconds: 60,
                send_cooldown_seconds: 60,
                code_ttl_seconds: 300,
            },
        );
        let sent = service
            .send_verification_code("registration@example.com", "peer")
            .await
            .unwrap();
        let SendVerificationCodeOutcome::Sent { code } = sent else {
            panic!("verification was suppressed")
        };
        let mut input = RegisterLocalAccountInput {
            email: "registration@example.com".into(),
            verification_code: "wrong".into(),
            password: Uuid::new_v4().to_string(),
        };
        assert_eq!(
            service.register_local_account(input.clone()).await,
            Err(RegisterLocalAccountError::InvalidVerificationCode)
        );
        input.verification_code = code;
        let account = service.register_local_account(input.clone()).await.unwrap();
        assert_eq!(account.principal.tenant, context);
        assert!(account.account.email_verified);
        assert_eq!(account.principal.admin_level(), None);
        assert_eq!(
            service.register_local_account(input).await,
            Err(RegisterLocalAccountError::InvalidVerificationCode)
        );
        assert!(matches!(
            service
                .send_verification_code("registration@example.com", "other")
                .await
                .unwrap(),
            SendVerificationCodeOutcome::Suppressed
        ));
        assert_sql(
            &database,
            "(SELECT count(*) FROM nazo_users WHERE email='registration@example.com')=1 AND NOT EXISTS(SELECT 1 FROM nazo_email_codes)",
        );
    });
}
