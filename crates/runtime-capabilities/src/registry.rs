use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};

use crate::{
    ActiveModuleSnapshot, DesiredStateRecord, ModuleCatalog, ModuleId, ModuleLifecycle,
    ModuleStateRepository, SnapshotStore,
};

#[path = "registry/dependency.rs"]
mod dependency;
#[path = "registry/desired.rs"]
mod desired;
#[path = "registry/lease.rs"]
mod lease;
#[path = "registry/persistence.rs"]
mod persistence;
#[path = "registry/reconcile.rs"]
mod reconcile;
#[path = "registry/synchronize.rs"]
mod synchronize;
#[path = "registry/transition.rs"]
mod transition;

#[derive(Clone, Copy, Eq, PartialEq)]
enum ReconcileMode {
    Wait,
    Step,
}

#[derive(Clone, Copy)]
struct DrainObservation {
    revision: crate::ModuleRevision,
    deadline: Option<web_time::SystemTime>,
    stored_complete: bool,
}

#[derive(Default)]
struct SynchronizationState {
    desired: BTreeMap<ModuleId, DesiredStateRecord>,
    last_published: BTreeMap<ModuleId, DesiredStateRecord>,
    observed: BTreeMap<ModuleId, DesiredStateRecord>,
    pending: BTreeSet<ModuleId>,
    invalidation: u64,
    next_module: usize,
}

/// Coordinates durable desired state, one process instance's lifecycle, and
/// the lock-free admission snapshot used by request handlers.
pub struct RuntimeModuleRegistry<R, L: ?Sized> {
    repository: Arc<R>,
    lifecycle: Arc<L>,
    catalog: ModuleCatalog,
    instance_id: String,
    snapshots: Arc<SnapshotStore>,
    desired_policy_lock: futures_util::lock::Mutex<()>,
    transition_locks: BTreeMap<ModuleId, futures_util::lock::Mutex<()>>,
    synchronization: Mutex<SynchronizationState>,
    synchronization_transition: futures_util::lock::Mutex<()>,
    drain_observations: Mutex<BTreeMap<ModuleId, DrainObservation>>,
}

impl<R, L> RuntimeModuleRegistry<R, L>
where
    R: ModuleStateRepository,
    L: ModuleLifecycle + ?Sized,
{
    #[must_use]
    pub fn new(
        repository: Arc<R>,
        lifecycle: Arc<L>,
        catalog: ModuleCatalog,
        instance_id: String,
        mut initial_snapshot: ActiveModuleSnapshot,
    ) -> Self {
        initial_snapshot
            .accepting
            .retain(|id| catalog.is_available(*id));
        initial_snapshot
            .draining
            .retain(|id| catalog.is_available(*id));
        Self {
            repository,
            lifecycle,
            catalog,
            instance_id,
            snapshots: Arc::new(SnapshotStore::new(initial_snapshot)),
            desired_policy_lock: futures_util::lock::Mutex::new(()),
            transition_locks: ModuleId::ALL
                .into_iter()
                .map(|module_id| (module_id, futures_util::lock::Mutex::new(())))
                .collect(),
            synchronization: Mutex::new(SynchronizationState::default()),
            synchronization_transition: futures_util::lock::Mutex::new(()),
            drain_observations: Mutex::new(BTreeMap::new()),
        }
    }

    #[must_use]
    pub fn snapshot_store(&self) -> Arc<SnapshotStore> {
        Arc::clone(&self.snapshots)
    }
}
