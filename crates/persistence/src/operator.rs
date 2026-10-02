//! Persistence capabilities used by the one-shot operator workflow.

use std::future::Future;
use std::pin::Pin;

use chrono::{DateTime, Utc};
use nazo_identity::ports::RepositoryError;
use uuid::Uuid;

/// A typed temporary failure at this persistence owner; Context preserves it.
#[derive(Debug)]
pub struct MigrationUnavailable(pub anyhow::Error);

impl std::fmt::Display for MigrationUnavailable {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("migration persistence is temporarily unavailable")
    }
}

impl std::error::Error for MigrationUnavailable {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.0.as_ref())
    }
}

pub type OperatorPersistenceFuture<'a, T> =
    Pin<Box<dyn Future<Output = Result<T, RepositoryError>> + Send + 'a>>;

/// Durable result of invalidating credentials after a state restore.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryInvalidation {
    pub state_epoch: Uuid,
    pub not_before: DateTime<Utc>,
    pub revoked_refresh_tokens: u64,
}

/// Atomic restore invalidation boundary.
///
/// Implementations must fence by operation id/request hash and revoke the
/// restored deployment's unrevoked refresh-family state in the same transaction that
/// publishes the durable ingress-reopen boundary.
pub trait RecoveryInvalidationStore: Send + Sync {
    fn invalidate_after_restore<'a>(
        &'a self,
        operation_id: Uuid,
        request_hash: &'a str,
        state_epoch: Uuid,
        not_before: DateTime<Utc>,
        completed_at: DateTime<Utc>,
    ) -> OperatorPersistenceFuture<'a, RecoveryInvalidation>;
}
