//! Bounded security-state maintenance.
//!
//! One process-local worker owns periodic reclamation of expired security
//! state. Each call performs at most one bounded batch; the adapter decides
//! the per-category row budgets and lock strategy.

use std::future::Future;
use std::pin::Pin;

use nazo_identity::ports::RepositoryError;

pub type SecurityStateMaintenanceFuture<'a, T> =
    Pin<Box<dyn Future<Output = Result<T, RepositoryError>> + Send + 'a>>;

/// Deletion counters for one bounded maintenance batch.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CleanupBatchResult {
    pub issuances: u64,
    pub refresh_tokens: u64,
    pub revocations: u64,
    pub scim_audit_events: u64,
    pub logout_deliveries: u64,
    pub scim_security_events: u64,
    pub presentations: u64,
    /// `true` when a category or candidate scan hit its per-batch budget, so
    /// another batch probably has deletable work. Callers use it to keep
    /// draining backlog instead of waiting a full interval.
    pub saturated: bool,
}

/// The single security-state maintenance boundary.
///
/// Implementations must bound every category (no drain-until-empty loops) and
/// coordinate with writers through the existing refresh-family advisory key —
/// never by taking a second family lock or a global lock.
pub trait SecurityStateMaintenancePort: Send + Sync {
    fn cleanup_batch(&self) -> SecurityStateMaintenanceFuture<'_, CleanupBatchResult>;
}
