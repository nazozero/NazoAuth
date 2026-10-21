use std::collections::BTreeMap;
use std::future::poll_fn;
use std::sync::{Arc, Mutex, MutexGuard};
use std::task::{Poll, Waker};

use crate::{ActiveModuleSnapshot, CapabilityAdmission, ModuleId, ModuleRevision};

type GenerationKey = (ModuleId, ModuleRevision);

#[derive(Default)]
pub(crate) struct LeaseState {
    active: BTreeMap<GenerationKey, usize>,
    waiters: BTreeMap<ModuleId, Vec<Waker>>,
    closed_through: BTreeMap<ModuleId, ModuleRevision>,
}

impl LeaseState {
    pub(crate) fn close_removed_generations(
        &mut self,
        current: &ActiveModuleSnapshot,
        next: &ActiveModuleSnapshot,
    ) {
        for module_id in ModuleId::ALL {
            if (current.admits(module_id) && !next.admits(module_id))
                || (current.draining.contains(&module_id) && !next.draining.contains(&module_id))
            {
                self.close_generation(module_id, current.revision);
            }
        }
    }

    fn close_generation(&mut self, module_id: ModuleId, generation: ModuleRevision) {
        self.closed_through
            .entry(module_id)
            .and_modify(|closed| *closed = (*closed).max(generation))
            .or_insert(generation);
    }
}

#[derive(Clone, Default)]
pub struct RequestLeaseTracker {
    state: Arc<Mutex<LeaseState>>,
}

impl RequestLeaseTracker {
    #[must_use]
    pub fn acquire(
        &self,
        snapshot: Arc<ActiveModuleSnapshot>,
        module_id: ModuleId,
    ) -> Option<RequestLease> {
        self.acquire_for(snapshot, module_id, CapabilityAdmission::NewRequest)
    }

    pub(crate) fn acquire_for(
        &self,
        snapshot: Arc<ActiveModuleSnapshot>,
        module_id: ModuleId,
        admission: CapabilityAdmission,
    ) -> Option<RequestLease> {
        if !snapshot.permits(module_id, admission) {
            return None;
        }
        let key = (module_id, snapshot.revision);
        let mut state = self.state.lock().expect("request lease lock poisoned");
        if state
            .closed_through
            .get(&module_id)
            .is_some_and(|closed| snapshot.revision <= *closed)
        {
            return None;
        }
        *state.active.entry(key).or_default() += 1;
        drop(state);
        Some(RequestLease {
            key,
            state: Arc::clone(&self.state),
            snapshot,
        })
    }

    pub fn close_generation(&self, module_id: ModuleId, generation: ModuleRevision) {
        let mut state = self.state.lock().expect("request lease lock poisoned");
        state.close_generation(module_id, generation);
    }

    pub(crate) fn publication_guard(&self) -> MutexGuard<'_, LeaseState> {
        self.state.lock().expect("request lease lock poisoned")
    }

    #[must_use]
    pub fn active(&self, module_id: ModuleId, generation: ModuleRevision) -> usize {
        self.state
            .lock()
            .expect("request lease lock poisoned")
            .active
            .get(&(module_id, generation))
            .copied()
            .unwrap_or_default()
    }

    pub async fn wait_until_zero(&self, module_id: ModuleId) {
        poll_fn(|context| {
            let mut state = self.state.lock().expect("request lease lock poisoned");
            if !state.active.keys().any(|(id, _)| *id == module_id) {
                return Poll::Ready(());
            }
            let waiters = state.waiters.entry(module_id).or_default();
            if !waiters.iter().any(|waker| waker.will_wake(context.waker())) {
                waiters.push(context.waker().clone());
            }
            Poll::Pending
        })
        .await;
    }
}

#[must_use = "retain the lease until the admitted operation finishes"]
pub struct RequestLease {
    key: GenerationKey,
    state: Arc<Mutex<LeaseState>>,
    snapshot: Arc<ActiveModuleSnapshot>,
}

impl std::fmt::Debug for RequestLease {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RequestLease")
            .field("key", &self.key)
            .finish()
    }
}

/// Request-owned admission facts. Successful checks retain their lease across
/// awaits; reading metadata uses `ActiveModuleSnapshot` without acquiring leases.
#[must_use = "retain the request view until all admitted operations finish"]
pub struct RequestSnapshot {
    snapshot: Arc<ActiveModuleSnapshot>,
    tracker: RequestLeaseTracker,
    leases: Mutex<Vec<RequestLease>>,
}

impl std::fmt::Debug for RequestSnapshot {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RequestSnapshot")
            .field("snapshot", &self.snapshot)
            .finish_non_exhaustive()
    }
}

impl RequestSnapshot {
    pub(crate) fn new(snapshot: Arc<ActiveModuleSnapshot>, tracker: RequestLeaseTracker) -> Self {
        Self {
            snapshot,
            tracker,
            leases: Mutex::new(Vec::new()),
        }
    }

    /// Advertisement alone does not execute the advertised capability.
    #[must_use]
    pub fn advertises(&self, module_id: ModuleId) -> bool {
        self.snapshot.advertises(module_id)
    }

    #[must_use]
    pub fn permits(&self, module_id: ModuleId, admission: CapabilityAdmission) -> bool {
        if !self.snapshot.permits(module_id, admission) {
            return false;
        }
        let mut leases = self.leases.lock().expect("request snapshot lock poisoned");
        if leases.iter().any(|lease| lease.key.0 == module_id) {
            return true;
        }
        let Some(lease) =
            self.tracker
                .acquire_for(Arc::clone(&self.snapshot), module_id, admission)
        else {
            return false;
        };
        leases.push(lease);
        true
    }
}

impl RequestLease {
    #[must_use]
    pub fn snapshot(&self) -> &ActiveModuleSnapshot {
        &self.snapshot
    }
}

impl Drop for RequestLease {
    fn drop(&mut self) {
        let mut state = self.state.lock().expect("request lease lock poisoned");
        let active = state
            .active
            .get_mut(&self.key)
            .expect("a live lease owns an active count");
        *active -= 1;
        if *active == 0 {
            state.active.remove(&self.key);
            for waker in state.waiters.remove(&self.key.0).unwrap_or_default() {
                waker.wake();
            }
        }
    }
}

#[cfg(test)]
#[path = "../tests/unit/lease.rs"]
mod tests;
