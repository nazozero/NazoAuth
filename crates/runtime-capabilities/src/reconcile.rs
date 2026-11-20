use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use crate::{ModuleId, ModuleRevision};

pub type LifecycleFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
#[error("module lifecycle failed with {code}")]
pub struct LifecycleFailure {
    pub code: &'static str,
}

/// One bounded observation of stored work, without waiting for its deadline.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DrainProgress {
    Pending,
    Complete,
}

pub trait ModuleLifecycle: Send + Sync {
    fn drain_stored_transactions(
        &self,
        module_id: ModuleId,
        revision: ModuleRevision,
        remaining_duration: Duration,
    ) -> LifecycleFuture<'_, Result<bool, LifecycleFailure>>;

    /// Inspect stored work once. Implementations must not sleep or retain a
    /// request-owned future for another request to resume. `Pending` never
    /// acknowledges a completed drain, including when the deadline has passed.
    fn poll_stored_transactions(
        &self,
        _module_id: ModuleId,
        _revision: ModuleRevision,
        _remaining_duration: Duration,
    ) -> LifecycleFuture<'_, Result<DrainProgress, LifecycleFailure>> {
        Box::pin(async {
            Err(LifecycleFailure {
                code: "bounded_drain_unavailable",
            })
        })
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct NoopModuleLifecycle;

impl ModuleLifecycle for NoopModuleLifecycle {
    fn drain_stored_transactions(
        &self,
        _module_id: ModuleId,
        _revision: ModuleRevision,
        _remaining_duration: Duration,
    ) -> LifecycleFuture<'_, Result<bool, LifecycleFailure>> {
        Box::pin(async { Ok(true) })
    }

    fn poll_stored_transactions(
        &self,
        _module_id: ModuleId,
        _revision: ModuleRevision,
        _remaining_duration: Duration,
    ) -> LifecycleFuture<'_, Result<DrainProgress, LifecycleFailure>> {
        Box::pin(async { Ok(DrainProgress::Complete) })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReconcileOutcome {
    NoChange,
    Enabled,
    Disabled,
    Pending,
    StaleDiscarded,
    Failed,
}

#[derive(Debug)]
pub enum RegistryError<E> {
    Repository(E),
    Compensation {
        operation: Box<RegistryError<E>>,
        compensation: Box<RegistryError<E>>,
    },
    MissingDesiredState(ModuleId),
    InconsistentDesiredState(ModuleId),
    RuntimeDisableBlocked(ModuleId),
    ServiceNotConstructed(ModuleId),
    ActiveDependent {
        module_id: ModuleId,
        dependent: ModuleId,
    },
    DependencyUnavailable {
        module_id: ModuleId,
        dependency: ModuleId,
    },
    RevisionExhausted(ModuleId),
    SnapshotRevisionExhausted,
    DrainDeadlineOverflow(ModuleId),
    SynchronizationBusy,
    SynchronizationChanged,
}
