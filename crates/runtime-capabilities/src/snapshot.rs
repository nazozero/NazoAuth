use std::collections::BTreeSet;
use std::sync::Arc;

use arc_swap::{ArcSwap, Guard};

use crate::{ModuleId, ModuleRevision, StaleTransition};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CapabilityAdmission {
    NewRequest,
    ExistingTransaction,
}

/// Immutable request-facing generation of runtime module admission state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActiveModuleSnapshot {
    pub revision: ModuleRevision,
    pub accepting: BTreeSet<ModuleId>,
    pub draining: BTreeSet<ModuleId>,
}

impl ActiveModuleSnapshot {
    #[must_use]
    pub fn admits(&self, module_id: ModuleId) -> bool {
        self.accepting.contains(&module_id)
    }

    #[must_use]
    pub fn advertises(&self, module_id: ModuleId) -> bool {
        self.admits(module_id)
    }

    #[must_use]
    pub fn permits(&self, module_id: ModuleId, admission: CapabilityAdmission) -> bool {
        self.admits(module_id)
            || (admission == CapabilityAdmission::ExistingTransaction
                && self.draining.contains(&module_id))
    }
}

/// Atomically publishes immutable request-facing module state.
pub struct SnapshotStore {
    current: ArcSwap<ActiveModuleSnapshot>,
    pub(crate) leases: crate::RequestLeaseTracker,
}

impl SnapshotStore {
    #[must_use]
    pub fn new(initial: ActiveModuleSnapshot) -> Self {
        Self {
            current: ArcSwap::from_pointee(initial),
            leases: crate::RequestLeaseTracker::default(),
        }
    }

    #[must_use]
    pub fn load(&self) -> Guard<Arc<ActiveModuleSnapshot>> {
        self.current.load()
    }

    #[must_use]
    pub fn load_full(&self) -> Arc<ActiveModuleSnapshot> {
        self.current.load_full()
    }

    /// Hold the returned lease until the admitted operation finishes or is cancelled.
    #[must_use]
    pub fn lease(
        &self,
        module_id: ModuleId,
        admission: CapabilityAdmission,
    ) -> Option<crate::RequestLease> {
        self.leases
            .acquire_for(self.load_full(), module_id, admission)
    }

    /// A coherent request view that retains leases only for capabilities it uses.
    pub fn request(&self) -> crate::RequestSnapshot {
        crate::RequestSnapshot::new(self.load_full(), self.leases.clone())
    }

    /// Close admission before waiting, so new requests cannot extend the wait.
    pub async fn wait_until_idle(&self, module_id: ModuleId) {
        self.leases.wait_until_zero(module_id).await;
    }

    pub fn compare_and_publish(
        &self,
        expected: ModuleRevision,
        next: ActiveModuleSnapshot,
    ) -> Result<(), StaleTransition> {
        if next.revision <= expected {
            return Err(StaleTransition::NonMonotonicPublication {
                expected,
                attempted: next.revision,
            });
        }

        // Serialize publication with lease acquisition. A request either owns
        // its old-generation lease before admission closes, or is rejected.
        let mut publication = self.leases.publication_guard();
        let current = self.current.load();
        if current.revision != expected {
            return Err(StaleTransition::RevisionChanged {
                expected,
                current: current.revision,
            });
        }

        publication.close_removed_generations(&current, &next);
        self.current.store(Arc::new(next));
        Ok(())
    }
}
