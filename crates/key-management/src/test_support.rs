//! Database-backed fixtures for consumers that exercise signing-key behavior.
//!
//! This module is available only to crate tests and dependents that explicitly
//! enable the `test-support` feature. It never participates in production
//! startup or provides a filesystem fallback.

use std::{sync::Arc, sync::Mutex};

use crate::{
    KeyManager, KeySettings, PersistedSigningKeyset, SigningKeyRepository,
    SigningKeyRepositoryFuture, SigningKeyWrappingKeyRing, SigningKeysetCompareAndSwapResult,
    SigningKeysetCreateResult,
};

/// In-memory implementation of the current repository boundary for tests.
#[derive(Default)]
pub struct MemorySigningKeyRepository(Mutex<Option<PersistedSigningKeyset>>);

impl MemorySigningKeyRepository {
    /// Snapshot the repository record for fixtures that exercise recovery.
    #[must_use]
    pub fn snapshot(&self) -> Option<PersistedSigningKeyset> {
        self.0.lock().expect("memory repository lock").clone()
    }

    /// Replace the repository record for fixtures that exercise recovery.
    pub fn replace(&self, record: Option<PersistedSigningKeyset>) {
        *self.0.lock().expect("memory repository lock") = record;
    }
}

impl SigningKeyRepository for MemorySigningKeyRepository {
    fn load(&self) -> SigningKeyRepositoryFuture<'_, Option<PersistedSigningKeyset>> {
        Box::pin(async move { Ok(self.0.lock().expect("memory repository lock").clone()) })
    }

    fn create_if_absent(
        &self,
        candidate: PersistedSigningKeyset,
    ) -> SigningKeyRepositoryFuture<'_, SigningKeysetCreateResult> {
        Box::pin(async move {
            let mut record = self.0.lock().expect("memory repository lock");
            Ok(match record.clone() {
                Some(existing) => SigningKeysetCreateResult::Existing(existing),
                None => {
                    *record = Some(candidate.clone());
                    SigningKeysetCreateResult::Created(candidate)
                }
            })
        })
    }

    fn compare_and_swap(
        &self,
        expected_revision: i64,
        candidate: PersistedSigningKeyset,
    ) -> SigningKeyRepositoryFuture<'_, SigningKeysetCompareAndSwapResult> {
        Box::pin(async move {
            let mut record = self.0.lock().expect("memory repository lock");
            let current = record
                .clone()
                .ok_or_else(|| anyhow::anyhow!("memory repository has no keyset"))?;
            Ok(if current.revision == expected_revision {
                *record = Some(candidate.clone());
                SigningKeysetCompareAndSwapResult::Applied(candidate)
            } else {
                SigningKeysetCompareAndSwapResult::Conflict(current)
            })
        })
    }
}

pub(crate) fn wrapping_key_ring() -> SigningKeyWrappingKeyRing {
    SigningKeyWrappingKeyRing::new("test", [0xA5; 32], None)
        .expect("fixed test wrapping ring is valid")
}

/// Build an isolated manager through the same database-backed path as runtime.
pub async fn key_manager(settings: KeySettings) -> anyhow::Result<KeyManager> {
    KeyManager::load_or_create_database(
        settings,
        uuid::Uuid::now_v7(),
        Arc::new(MemorySigningKeyRepository::default()),
        wrapping_key_ring(),
    )
    .await
}
