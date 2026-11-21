use std::collections::{BTreeMap, BTreeSet};

use crate::{
    ActiveModuleSnapshot, DesiredStateRecord, DisablePolicy, ModuleId, ModuleLifecycle,
    ModuleReconcileState, ModuleRevision, ModuleState, ModuleStateRepository, ReconcileOutcome,
    RegistryError,
};

use super::RuntimeModuleRegistry;

type DesiredStates = BTreeMap<ModuleId, DesiredStateRecord>;
type ReconcileStates = BTreeMap<ModuleId, ModuleReconcileState>;

struct SynchronizationWork {
    modules: BTreeSet<ModuleId>,
    invalidation: u64,
}

enum PreparedSynchronization {
    Settled,
    Pending(Vec<(ModuleId, ReconcileOutcome)>),
    Work(SynchronizationWork),
}

impl<R, L> RuntimeModuleRegistry<R, L>
where
    R: ModuleStateRepository,
    L: ModuleLifecycle + ?Sized,
{
    /// Synchronize admission with one coherent durable snapshot, advancing only
    /// changed or unfinished modules. Each caller owns its repository futures.
    /// Stable requests perform one read, no writes, and never wait for another
    /// request. A call advances at most one module, using a try-lock and at most
    /// two snapshot attempts. Other unfinished modules remain closed/Pending.
    ///
    /// A cold instance can project settled desired state without inventing
    /// instance history. A disabled stored-work module instead resumes from
    /// `desired.updated_at + catalog duration`, even without an instance row.
    /// Durations must remain stable throughout that disable; a policy change
    /// needs a durable policy version or completion of the existing drain.
    pub async fn synchronize_step(
        &self,
    ) -> Result<Vec<(ModuleId, ReconcileOutcome)>, RegistryError<R::Error>> {
        let mut step_available = true;
        for _ in 0..2 {
            // In particular, do not hold the transition lock across this read:
            // concurrent unchanged requests must all be able to make progress.
            let read_invalidation = self
                .synchronization
                .lock()
                .expect("synchronization state")
                .invalidation;
            let states = match self.read_synchronization_state().await {
                Ok(states) => states,
                Err(error) => return self.invalidate_synchronization(error),
            };
            let desired = desired_states(&states);
            let prepared = self.prepare_synchronization(&states, &desired, read_invalidation);
            let SynchronizationWork {
                modules: work,
                invalidation,
            } = match prepared {
                Ok(PreparedSynchronization::Settled) => return Ok(Vec::new()),
                Ok(PreparedSynchronization::Pending(outcomes)) => return Ok(outcomes),
                Ok(PreparedSynchronization::Work(prepared)) => prepared,
                Err(RegistryError::SynchronizationChanged) => continue,
                Err(RegistryError::SynchronizationBusy) => {
                    return Err(RegistryError::SynchronizationBusy);
                }
                Err(error) => return self.invalidate_synchronization(error),
            };
            let Some(_transition_guard) = self.synchronization_transition.try_lock() else {
                // The owner already cleared the settled marker. Do not wait on
                // its request-owned I/O or acknowledge another request's work.
                return self
                    .stable_pending_synchronization(&states, &desired, invalidation)
                    .ok_or(RegistryError::SynchronizationBusy);
            };
            {
                let mut sync = self.synchronization.lock().expect("synchronization state");
                if sync.invalidation != invalidation || !not_older_than(&desired, &sync.observed) {
                    continue;
                }
                sync.desired.clear();
            }

            let mut outcomes = Vec::with_capacity(work.len());
            // The budget spans both snapshot attempts. Rotate ready modules so
            // a long stored-work drain cannot starve independent changes.
            let selected = step_available
                .then(|| self.next_synchronization_module(&work, &desired))
                .flatten();
            for module_id in work {
                if selected == Some(module_id) {
                    step_available = false;
                    match self.reconcile_step(module_id).await {
                        Ok(outcome) => outcomes.push((module_id, outcome)),
                        Err(error) => return self.invalidate_synchronization(error),
                    }
                } else {
                    outcomes.push((module_id, ReconcileOutcome::Pending));
                }
            }

            let confirmed = match self.read_synchronization_state().await {
                Ok(states) => states,
                Err(error) => return self.invalidate_synchronization(error),
            };
            let confirmed_desired = desired_states(&confirmed);
            let mut sync = self.synchronization.lock().expect("synchronization state");
            let confirmed_is_current = not_older_than(&confirmed_desired, &sync.observed);
            if confirmed_is_current {
                sync.observed = confirmed_desired.clone();
            }
            if desired != confirmed_desired
                || sync.invalidation != invalidation
                || !confirmed_is_current
            {
                sync.desired.clear();
                sync.invalidation = sync.invalidation.wrapping_add(1);
                self.publish_synchronization_snapshot(BTreeSet::new(), BTreeSet::new())?;
                continue;
            }
            // Fence a delayed same-intent read of older instance facts. A pure
            // Pending poll changes no facts and must not invalidate concurrent
            // stable readers just because another observer finished its read.
            if states != confirmed {
                sync.invalidation = sync.invalidation.wrapping_add(1);
            }
            sync.pending = outcomes
                .iter()
                .filter_map(|(module, outcome)| {
                    matches!(
                        outcome,
                        ReconcileOutcome::Pending
                            | ReconcileOutcome::Failed
                            | ReconcileOutcome::StaleDiscarded
                    )
                    .then_some(*module)
                })
                .collect();
            sync.desired = confirmed_desired.clone();
            sync.last_published = confirmed_desired;
            return Ok(outcomes);
        }
        // An older read must not erase a newer successfully published snapshot.
        // This request receives no authority to dispatch from the stale read.
        Err(RegistryError::SynchronizationChanged)
    }

    async fn read_synchronization_state(&self) -> Result<ReconcileStates, RegistryError<R::Error>> {
        let states = self
            .repository
            .read_reconcile_state(&self.instance_id)
            .await
            .map_err(RegistryError::Repository)?;
        let mut by_module = BTreeMap::new();
        for state in states {
            if by_module.insert(state.desired.module_id, state).is_some() {
                return Err(RegistryError::SynchronizationChanged);
            }
        }
        for module_id in ModuleId::ALL {
            let state = by_module
                .get(&module_id)
                .ok_or(RegistryError::MissingDesiredState(module_id))?;
            let enabled = self
                .catalog
                .effective_enabled(module_id, state.desired.mode.is_enabled());
            if self.catalog.runtime_disable_blocked(module_id) && !enabled {
                return Err(RegistryError::RuntimeDisableBlocked(module_id));
            }
            if enabled {
                for dependency in &self.catalog.spec(module_id).dependencies {
                    let dependency_state = by_module
                        .get(dependency)
                        .ok_or(RegistryError::MissingDesiredState(*dependency))?;
                    if !self
                        .catalog
                        .effective_enabled(*dependency, dependency_state.desired.mode.is_enabled())
                    {
                        return Err(RegistryError::DependencyUnavailable {
                            module_id,
                            dependency: *dependency,
                        });
                    }
                }
            }
        }
        Ok(by_module)
    }

    fn prepare_synchronization(
        &self,
        states: &ReconcileStates,
        desired: &DesiredStates,
        read_invalidation: u64,
    ) -> Result<PreparedSynchronization, RegistryError<R::Error>> {
        let mut sync = self.synchronization.lock().expect("synchronization state");
        if sync.invalidation != read_invalidation {
            return Err(RegistryError::SynchronizationChanged);
        }
        if let Some((module, _)) = desired.iter().find(|(module, record)| {
            sync.observed
                .get(module)
                .is_some_and(|previous| previous.revision == record.revision && previous != *record)
        }) {
            return Err(RegistryError::InconsistentDesiredState(*module));
        }
        if !not_older_than(desired, &sync.observed) {
            return Err(RegistryError::SynchronizationChanged);
        }
        sync.observed = desired.clone();
        let mut accepting = BTreeSet::new();
        let mut work = BTreeSet::new();
        for (module_id, state) in states {
            let enabled = self
                .catalog
                .effective_enabled(*module_id, state.desired.mode.is_enabled());
            let baseline = sync.last_published.is_empty()
                || sync.last_published.get(module_id) == Some(&state.desired);
            let settled_instance = state.instance.as_ref().is_some_and(|instance| {
                instance.applied_revision == Some(state.desired.revision)
                    && instance.transition_revision == state.desired.revision
                    && instance.state
                        == if enabled {
                            ModuleState::Enabled
                        } else {
                            ModuleState::Disabled
                        }
            });
            let lease_idle = enabled
                || matches!(
                    self.catalog.effective_disable_policy(*module_id),
                    DisablePolicy::Immediate
                )
                || self.snapshots.is_idle(*module_id);
            let cold_settled = state.instance.is_none()
                && baseline
                && !sync.pending.contains(module_id)
                && (enabled
                    || self
                        .drain_deadline(&state.desired, None)?
                        .is_none_or(|deadline| web_time::SystemTime::now() >= deadline));
            if lease_idle && (settled_instance || cold_settled) {
                if enabled {
                    accepting.insert(*module_id);
                }
            } else {
                work.insert(*module_id);
            }
        }
        // A dependency being enabled is not ready until its own transition has
        // settled. Keep dependents in the work set rather than advertising them.
        loop {
            let blocked = accepting
                .iter()
                .filter(|module| {
                    self.catalog
                        .spec(**module)
                        .dependencies
                        .iter()
                        .any(|dependency| !accepting.contains(dependency))
                })
                .copied()
                .collect::<Vec<_>>();
            if blocked.is_empty() {
                break;
            }
            for module in blocked {
                accepting.remove(&module);
                work.insert(module);
            }
        }
        if work.is_empty() {
            // No async work or invented transition events are necessary. The
            // coherent read is the publication's authority. Holding only this
            // short memory lock prevents an older reader overwriting it.
            let snapshot = self.snapshot();
            if sync.desired == *desired
                && sync.pending.is_empty()
                && snapshot.accepting == accepting
                && snapshot.draining.is_empty()
            {
                return Ok(PreparedSynchronization::Settled);
            }
            let Some(_transition_guard) = self.synchronization_transition.try_lock() else {
                return Err(RegistryError::SynchronizationBusy);
            };
            self.publish_synchronization_snapshot(accepting, BTreeSet::new())?;
            sync.desired = desired.clone();
            sync.last_published = desired.clone();
            sync.pending.clear();
            return Ok(PreparedSynchronization::Settled);
        }
        // Close new admissions immediately on observing a new disabled intent.
        // A coherent, live stored-work window also applies to a cold instance.
        // Projecting ExistingTransaction admission creates no persistent event
        // or applied revision; unfinished dependent work still blocks its parent.
        let Some(_transition_guard) = self.synchronization_transition.try_lock() else {
            return self
                .stable_pending_with_state(states, desired, &sync)
                .map(PreparedSynchronization::Pending)
                .ok_or(RegistryError::SynchronizationBusy);
        };
        let mut draining = BTreeSet::new();
        for module_id in &work {
            let state = &states[module_id];
            let stored_complete = self
                .drain_observations
                .lock()
                .expect("drain observations")
                .get(module_id)
                .is_some_and(|observation| {
                    observation.revision == state.desired.revision && observation.stored_complete
                });
            if !stored_complete
                && self.catalog.stored_transaction_admission(
                    &state.desired,
                    state.instance.as_ref(),
                    web_time::SystemTime::now(),
                )
            {
                draining.insert(*module_id);
            }
        }
        self.publish_synchronization_snapshot(accepting, draining)?;
        sync.desired.clear();
        Ok(PreparedSynchronization::Work(SynchronizationWork {
            modules: work,
            invalidation: sync.invalidation,
        }))
    }

    fn stable_pending_synchronization(
        &self,
        states: &ReconcileStates,
        desired: &DesiredStates,
        invalidation: u64,
    ) -> Option<Vec<(ModuleId, ReconcileOutcome)>> {
        let sync = self.synchronization.lock().expect("synchronization state");
        if sync.invalidation != invalidation {
            return None;
        }
        self.stable_pending_with_state(states, desired, &sync)
    }

    fn stable_pending_with_state(
        &self,
        states: &ReconcileStates,
        desired: &DesiredStates,
        sync: &super::SynchronizationState,
    ) -> Option<Vec<(ModuleId, ReconcileOutcome)>> {
        if sync.pending.is_empty()
            || sync.last_published != *desired
            || !not_older_than(desired, &sync.observed)
        {
            return None;
        }
        let snapshot = self.snapshot();
        for (module, state) in states {
            let enabled = self
                .catalog
                .effective_enabled(*module, state.desired.mode.is_enabled());
            if snapshot.admits(*module) != enabled {
                return None;
            }
            if snapshot.draining.contains(module)
                && self
                    .drain_deadline(&state.desired, state.instance.as_ref())
                    .ok()
                    .flatten()
                    .is_none_or(|deadline| web_time::SystemTime::now() >= deadline)
            {
                return None;
            }
            // A pending enable/failure must finish its own transition. Only
            // a previously published disabled drain can be observed in parallel.
            if sync.pending.contains(module)
                && (enabled
                    || state.instance.as_ref().is_some_and(|instance| {
                        instance.state != ModuleState::Draining
                            || instance.transition_revision != state.desired.revision
                    }))
            {
                return None;
            }
        }
        Some(
            sync.pending
                .iter()
                .map(|module| (*module, ReconcileOutcome::Pending))
                .collect(),
        )
    }

    /// Revision applied by a verified in-memory projection, without inventing a
    /// persistent instance observation. A different or invalidated generation
    /// never supplies this acknowledgement to the administration view.
    pub(crate) fn projected_applied_revision(
        &self,
        desired: &DesiredStateRecord,
        snapshot: &ActiveModuleSnapshot,
    ) -> Option<ModuleRevision> {
        let sync = self.synchronization.lock().expect("synchronization state");
        (sync.desired.get(&desired.module_id) == Some(desired)
            && !sync.pending.contains(&desired.module_id)
            && self.snapshot().revision == snapshot.revision
            && snapshot.admits(desired.module_id)
                == self
                    .catalog
                    .effective_enabled(desired.module_id, desired.mode.is_enabled())
            && !snapshot.draining.contains(&desired.module_id))
        .then_some(desired.revision)
    }

    fn next_synchronization_module(
        &self,
        work: &BTreeSet<ModuleId>,
        desired: &DesiredStates,
    ) -> Option<ModuleId> {
        let mut sync = self.synchronization.lock().expect("synchronization state");
        let snapshot = self.snapshot();
        for offset in 0..ModuleId::ALL.len() {
            let index = (sync.next_module + offset) % ModuleId::ALL.len();
            let module = ModuleId::ALL[index];
            if !work.contains(&module) {
                continue;
            }
            let ready = if self
                .catalog
                .effective_enabled(module, desired[&module].mode.is_enabled())
            {
                self.catalog
                    .spec(module)
                    .dependencies
                    .iter()
                    .all(|dependency| snapshot.admits(*dependency))
            } else {
                self.catalog
                    .specs()
                    .values()
                    .filter(|spec| {
                        self.catalog.is_available(spec.id) && spec.dependencies.contains(&module)
                    })
                    .all(|dependent| {
                        !work.contains(&dependent.id)
                            && !snapshot.admits(dependent.id)
                            && !snapshot.draining.contains(&dependent.id)
                    })
            };
            if ready {
                sync.next_module = (index + 1) % ModuleId::ALL.len();
                return Some(module);
            }
        }
        None
    }

    fn invalidate_synchronization<T>(
        &self,
        error: RegistryError<R::Error>,
    ) -> Result<T, RegistryError<R::Error>> {
        let mut sync = self.synchronization.lock().expect("synchronization state");
        sync.desired.clear();
        sync.invalidation = sync.invalidation.wrapping_add(1);
        self.publish_synchronization_snapshot(BTreeSet::new(), BTreeSet::new())?;
        Err(error)
    }

    fn publish_synchronization_snapshot(
        &self,
        accepting: BTreeSet<ModuleId>,
        draining: BTreeSet<ModuleId>,
    ) -> Result<(), RegistryError<R::Error>> {
        loop {
            let current = self.snapshot();
            if current.accepting == accepting && current.draining == draining {
                return Ok(());
            }
            let revision = current
                .revision
                .get()
                .checked_add(1)
                .ok_or(RegistryError::SnapshotRevisionExhausted)?;
            if self
                .snapshots
                .compare_and_publish(
                    current.revision,
                    ActiveModuleSnapshot {
                        revision: ModuleRevision::new(revision),
                        accepting: accepting.clone(),
                        draining: draining.clone(),
                    },
                )
                .is_ok()
            {
                return Ok(());
            }
        }
    }
}

fn desired_states(states: &ReconcileStates) -> DesiredStates {
    states
        .iter()
        .map(|(module, state)| (*module, state.desired.clone()))
        .collect()
}

fn not_older_than(candidate: &DesiredStates, observed: &DesiredStates) -> bool {
    observed.iter().all(|(module, previous)| {
        candidate
            .get(module)
            .is_some_and(|next| next.revision > previous.revision || next == previous)
    })
}
