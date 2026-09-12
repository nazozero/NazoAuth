use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

use crate::{
    KeyHealth, KeyHealthStatus, KeyManager, KeySettings, SigningKeyRepository,
    SigningKeyRepositoryFuture, SigningKeyWrappingKeyRing, SigningKeysetCompareAndSwapResult,
    SigningKeysetCreateResult, test_support::MemorySigningKeyRepository,
};
use nazo_auth::{SignRequest, Signer, SigningPurpose};

fn settings() -> KeySettings {
    KeySettings {
        rotation_interval: chrono::Duration::days(90),
        prepublish_window: chrono::Duration::days(1),
        verification_grace: chrono::Duration::minutes(10),
    }
}

struct FailingRepository {
    inner: Arc<MemorySigningKeyRepository>,
    fail_load: AtomicBool,
}

impl FailingRepository {
    fn new(inner: Arc<MemorySigningKeyRepository>) -> Self {
        Self {
            inner,
            fail_load: AtomicBool::new(false),
        }
    }
}

impl SigningKeyRepository for FailingRepository {
    fn load(&self) -> SigningKeyRepositoryFuture<'_, Option<crate::PersistedSigningKeyset>> {
        Box::pin(async move {
            if self.fail_load.load(Ordering::Acquire) {
                anyhow::bail!("injected repository read failure");
            }
            self.inner.load().await
        })
    }

    fn create_if_absent(
        &self,
        candidate: crate::PersistedSigningKeyset,
    ) -> SigningKeyRepositoryFuture<'_, SigningKeysetCreateResult> {
        self.inner.create_if_absent(candidate)
    }

    fn compare_and_swap(
        &self,
        expected_revision: i64,
        candidate: crate::PersistedSigningKeyset,
    ) -> SigningKeyRepositoryFuture<'_, SigningKeysetCompareAndSwapResult> {
        self.inner.compare_and_swap(expected_revision, candidate)
    }
}

#[tokio::test]
async fn database_refresh_failure_keeps_last_generation_and_recovers() {
    let inner = Arc::new(MemorySigningKeyRepository::default());
    let repository = Arc::new(FailingRepository::new(Arc::clone(&inner)));
    let manager = KeyManager::load_or_create_database(
        settings(),
        None,
        uuid::Uuid::now_v7(),
        repository.clone(),
        SigningKeyWrappingKeyRing::new("test", [0xA5; 32], None).unwrap(),
    )
    .await
    .unwrap();
    let previous_kid = manager.snapshot().active_kid.clone();

    repository.fail_load.store(true, Ordering::Release);
    assert!(manager.refresh().await.is_err());
    assert_eq!(manager.health().status, KeyHealthStatus::Unhealthy);
    assert_eq!(manager.snapshot().active_kid, previous_kid);
    assert!(
        manager
            .sign(SignRequest {
                purpose: SigningPurpose::AccessToken,
                algorithm: "RS256",
                signing_input: b"must-fail-closed",
            })
            .await
            .is_err()
    );

    repository.fail_load.store(false, Ordering::Release);
    manager.refresh().await.expect("refresh should recover");
    assert_eq!(manager.health(), KeyHealth::healthy());
    assert!(
        manager
            .sign(SignRequest {
                purpose: SigningPurpose::AccessToken,
                algorithm: "RS256",
                signing_input: b"must-sign-after-recovery",
            })
            .await
            .is_ok()
    );
}
