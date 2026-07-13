use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::SystemTime;

use crate::{
    ActiveModuleSnapshot, CasOutcome, DesiredMode, DesiredStateChange, DesiredStateRecord,
    DisablePolicy, InstanceStateChange, InstanceStateMutation, InstanceStateRecord,
    LifecycleFailure, ModuleCatalog, ModuleEventRecord, ModuleEventState, ModuleEventType,
    ModuleId, ModuleLifecycle, ModuleRevision, ModuleState, ModuleStateRepository,
    ReconcileOutcome, RegistryError, RequestLease, RequestLeaseTracker, SnapshotStore,
};

pub struct RuntimeModuleRegistry<R, L> {
    repository: Arc<R>,
    lifecycle: Arc<L>,
    catalog: ModuleCatalog,
    instance_id: String,
    snapshots: Arc<SnapshotStore>,
    leases: RequestLeaseTracker,
    transition_locks: BTreeMap<ModuleId, Arc<futures_util::lock::Mutex<()>>>,
    event_sequence: AtomicU64,
}

impl<R, L> RuntimeModuleRegistry<R, L>
where
    R: ModuleStateRepository,
    L: ModuleLifecycle,
{
    #[must_use]
    pub fn new(
        repository: Arc<R>,
        lifecycle: Arc<L>,
        catalog: ModuleCatalog,
        instance_id: String,
        initial_snapshot: ActiveModuleSnapshot,
    ) -> Self {
        Self {
            repository,
            lifecycle,
            catalog,
            instance_id,
            snapshots: Arc::new(SnapshotStore::new(initial_snapshot)),
            leases: RequestLeaseTracker::default(),
            transition_locks: ModuleId::ALL
                .into_iter()
                .map(|module_id| (module_id, Arc::new(futures_util::lock::Mutex::new(()))))
                .collect(),
            event_sequence: AtomicU64::new(1),
        }
    }

    #[must_use]
    pub fn snapshot(&self) -> Arc<ActiveModuleSnapshot> {
        self.snapshots.load_full()
    }

    #[must_use]
    pub fn lease(&self, module_id: ModuleId) -> Option<RequestLease> {
        self.leases.acquire(self.snapshot(), module_id)
    }

    pub async fn set_desired_mode(
        &self,
        module_id: ModuleId,
        mode: DesiredMode,
        expected_revision: Option<ModuleRevision>,
        actor_id: Option<String>,
        reason: Option<String>,
        changed_at: SystemTime,
    ) -> Result<CasOutcome<DesiredStateRecord>, RegistryError<R::Error>> {
        let spec = self
            .catalog
            .spec(module_id)
            .ok_or(RegistryError::MissingCatalogSpec(module_id))?;
        let enabling = mode.resolve(self.catalog.inherited_enabled(module_id));
        let snapshot = self.snapshot();
        if enabling {
            for dependency in &spec.dependencies {
                if !snapshot.admits(*dependency) {
                    return Err(RegistryError::DependencyUnavailable {
                        module_id,
                        dependency: *dependency,
                    });
                }
            }
        } else {
            if matches!(spec.disable_policy, DisablePolicy::NotRuntimeDisableable)
                || self.catalog.runtime_disable_blocked(module_id)
            {
                return Err(RegistryError::RuntimeDisableBlocked(module_id));
            }
            if let Some(dependent) = self
                .catalog
                .active_dependents(module_id, &snapshot.accepting)
                .into_iter()
                .next()
            {
                return Err(RegistryError::ActiveDependent {
                    module_id,
                    dependent,
                });
            }
        }
        let next_revision = ModuleRevision::new(
            expected_revision.map_or(1, |revision| revision.get().saturating_add(1)),
        );
        self.repository
            .compare_and_set_desired(DesiredStateChange {
                expected_revision,
                next: DesiredStateRecord {
                    module_id,
                    mode,
                    revision: next_revision,
                    actor_id,
                    reason,
                    updated_at: changed_at,
                },
            })
            .await
            .map_err(RegistryError::Repository)
    }

    pub async fn reconcile_once(
        &self,
        module_id: ModuleId,
    ) -> Result<ReconcileOutcome, RegistryError<R::Error>> {
        let transition_lock = self
            .transition_locks
            .get(&module_id)
            .expect("the closed module catalog must have a transition lock");
        let _transition_guard = transition_lock.lock().await;
        self.reconcile_once_serialized(module_id).await
    }

    async fn reconcile_once_serialized(
        &self,
        module_id: ModuleId,
    ) -> Result<ReconcileOutcome, RegistryError<R::Error>> {
        let desired = self
            .repository
            .read_desired(module_id)
            .await
            .map_err(RegistryError::Repository)?
            .ok_or(RegistryError::MissingDesiredState(module_id))?;
        let enabled = desired
            .mode
            .resolve(self.catalog.inherited_enabled(module_id));
        let current = self
            .repository
            .read_instance(&self.instance_id, module_id)
            .await
            .map_err(RegistryError::Repository)?;
        if current.as_ref().is_some_and(|instance| {
            instance.applied_revision == Some(desired.revision)
                && ((enabled && instance.state == ModuleState::Enabled)
                    || (!enabled && instance.state == ModuleState::Disabled))
        }) {
            return Ok(ReconcileOutcome::NoChange);
        }

        if enabled {
            self.enable(module_id, desired.revision, current).await
        } else {
            self.disable(module_id, desired.revision, current).await
        }
    }

    async fn enable(
        &self,
        module_id: ModuleId,
        revision: ModuleRevision,
        current: Option<InstanceStateRecord>,
    ) -> Result<ReconcileOutcome, RegistryError<R::Error>> {
        let starting = self
            .persist_state(
                module_id,
                revision,
                current.as_ref().map(|state| state.transition_revision),
                ModuleState::Starting,
                None,
                ModuleEventType::TransitionStarted,
                current.as_ref().map(|state| state.state),
                None,
                None,
            )
            .await?;
        let CasOutcome::Applied(starting) = starting else {
            return Ok(ReconcileOutcome::StaleDiscarded);
        };
        if let Err(failure) = self.lifecycle.initialize(module_id).await {
            return Ok(if self.persist_failure(&starting, failure).await? {
                ReconcileOutcome::Failed
            } else {
                ReconcileOutcome::StaleDiscarded
            });
        }
        if !self.revision_is_current(module_id, revision).await? {
            self.discard_stale(starting).await?;
            return Ok(ReconcileOutcome::StaleDiscarded);
        }
        self.publish(module_id, true, false);
        if !self.revision_is_current(module_id, revision).await? {
            self.publish(module_id, false, false);
            self.discard_stale(starting).await?;
            return Ok(ReconcileOutcome::StaleDiscarded);
        }
        let completed = self
            .persist_state(
                module_id,
                revision,
                Some(revision),
                ModuleState::Enabled,
                Some(revision),
                ModuleEventType::TransitionCompleted,
                Some(ModuleState::Starting),
                None,
                None,
            )
            .await?;
        Ok(match completed {
            CasOutcome::Applied(_) => ReconcileOutcome::Enabled,
            CasOutcome::Stale { .. } => {
                // A desired-state revision can change after the last explicit
                // check but before the repository CAS. The per-module guard
                // ensures this rollback cannot erase a newer reconciler's
                // publication.
                self.publish(module_id, false, false);
                ReconcileOutcome::StaleDiscarded
            }
        })
    }

    async fn disable(
        &self,
        module_id: ModuleId,
        revision: ModuleRevision,
        current: Option<InstanceStateRecord>,
    ) -> Result<ReconcileOutcome, RegistryError<R::Error>> {
        let spec = self
            .catalog
            .spec(module_id)
            .ok_or(RegistryError::MissingCatalogSpec(module_id))?;
        let prior_generation = self.snapshot().revision;
        let drain_deadline = match spec.disable_policy {
            DisablePolicy::DrainStoredTransactions { max_duration } => {
                SystemTime::now().checked_add(max_duration)
            }
            _ => None,
        };
        let draining = self
            .persist_state(
                module_id,
                revision,
                current.as_ref().map(|state| state.transition_revision),
                ModuleState::Draining,
                None,
                ModuleEventType::TransitionStarted,
                current.as_ref().map(|state| state.state),
                drain_deadline,
                None,
            )
            .await?;
        let CasOutcome::Applied(draining) = draining else {
            return Ok(ReconcileOutcome::StaleDiscarded);
        };
        if !self.revision_is_current(module_id, revision).await? {
            self.discard_stale(draining).await?;
            return Ok(ReconcileOutcome::StaleDiscarded);
        }
        self.publish(module_id, false, true);
        if !self.revision_is_current(module_id, revision).await? {
            self.discard_stale(draining).await?;
            return Ok(ReconcileOutcome::StaleDiscarded);
        }
        if !matches!(
            self.persist_state(
                module_id,
                revision,
                Some(revision),
                ModuleState::Draining,
                None,
                ModuleEventType::DrainStarted,
                Some(ModuleState::Draining),
                drain_deadline,
                None,
            )
            .await?,
            CasOutcome::Applied(_)
        ) {
            return Ok(ReconcileOutcome::StaleDiscarded);
        }
        self.leases
            .wait_until_zero(module_id, prior_generation)
            .await;
        if let DisablePolicy::DrainStoredTransactions { max_duration } = spec.disable_policy {
            match self
                .lifecycle
                .drain_stored_transactions(module_id, max_duration)
                .await
            {
                Ok(true) => {}
                Ok(false) => {
                    let failed = self
                        .persist_failure(
                            &draining,
                            LifecycleFailure {
                                code: "drain_deadline_elapsed",
                            },
                        )
                        .await?;
                    return Ok(if failed {
                        ReconcileOutcome::Failed
                    } else {
                        ReconcileOutcome::StaleDiscarded
                    });
                }
                Err(failure) => {
                    return Ok(if self.persist_failure(&draining, failure).await? {
                        ReconcileOutcome::Failed
                    } else {
                        ReconcileOutcome::StaleDiscarded
                    });
                }
            }
        }
        if !self.revision_is_current(module_id, revision).await? {
            self.discard_stale(draining).await?;
            return Ok(ReconcileOutcome::StaleDiscarded);
        }
        if !matches!(
            self.persist_state(
                module_id,
                revision,
                Some(revision),
                ModuleState::Draining,
                None,
                ModuleEventType::DrainCompleted,
                Some(ModuleState::Draining),
                drain_deadline,
                None,
            )
            .await?,
            CasOutcome::Applied(_)
        ) {
            return Ok(ReconcileOutcome::StaleDiscarded);
        }
        if !self.revision_is_current(module_id, revision).await? {
            self.discard_stale(draining).await?;
            return Ok(ReconcileOutcome::StaleDiscarded);
        }
        if let Err(failure) = self.lifecycle.stop(module_id).await {
            return Ok(if self.persist_failure(&draining, failure).await? {
                ReconcileOutcome::Failed
            } else {
                ReconcileOutcome::StaleDiscarded
            });
        }
        if !self.revision_is_current(module_id, revision).await? {
            self.discard_stale(draining).await?;
            return Ok(ReconcileOutcome::StaleDiscarded);
        }
        let completed = self
            .persist_state(
                module_id,
                revision,
                Some(revision),
                ModuleState::Disabled,
                Some(revision),
                ModuleEventType::TransitionCompleted,
                Some(ModuleState::Draining),
                None,
                None,
            )
            .await?;
        match completed {
            CasOutcome::Applied(_) => {
                if !self.revision_is_current(module_id, revision).await? {
                    return Ok(ReconcileOutcome::StaleDiscarded);
                }
                self.publish(module_id, false, false);
                Ok(ReconcileOutcome::Disabled)
            }
            CasOutcome::Stale { .. } => Ok(ReconcileOutcome::StaleDiscarded),
        }
    }

    async fn revision_is_current(
        &self,
        module_id: ModuleId,
        revision: ModuleRevision,
    ) -> Result<bool, RegistryError<R::Error>> {
        self.repository
            .validate_revision(module_id, revision)
            .await
            .map_err(RegistryError::Repository)
    }

    fn publish(&self, module_id: ModuleId, accepting: bool, draining: bool) {
        loop {
            let current = self.snapshots.load_full();
            let mut accepting_set = current.accepting.clone();
            let mut draining_set = current.draining.clone();
            set_membership(&mut accepting_set, module_id, accepting);
            set_membership(&mut draining_set, module_id, draining);
            let next = ActiveModuleSnapshot {
                revision: ModuleRevision::new(current.revision.get().saturating_add(1)),
                accepting: accepting_set,
                draining: draining_set,
            };
            if self
                .snapshots
                .compare_and_publish(current.revision, next)
                .is_ok()
            {
                return;
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn persist_state(
        &self,
        module_id: ModuleId,
        revision: ModuleRevision,
        expected_revision: Option<ModuleRevision>,
        state: ModuleState,
        applied_revision: Option<ModuleRevision>,
        event_type: ModuleEventType,
        before: Option<ModuleState>,
        drain_deadline: Option<SystemTime>,
        outcome_code: Option<&'static str>,
    ) -> Result<CasOutcome<InstanceStateRecord>, RegistryError<R::Error>> {
        let now = SystemTime::now();
        let next = InstanceStateRecord {
            instance_id: self.instance_id.clone(),
            module_id,
            state,
            transition_revision: revision,
            applied_revision,
            drain_deadline,
            error_code: outcome_code.map(str::to_owned),
            updated_at: now,
        };
        let event = self.event(&next, event_type, before, outcome_code);
        self.repository
            .compare_and_set_instance(
                revision,
                InstanceStateMutation {
                    change: InstanceStateChange {
                        expected_revision,
                        next,
                    },
                    applied_event: event.clone(),
                    stale_event: self.event_from(event, ModuleEventType::StaleTransitionDiscarded),
                },
            )
            .await
            .map_err(RegistryError::Repository)
    }

    async fn discard_stale(
        &self,
        current: InstanceStateRecord,
    ) -> Result<(), RegistryError<R::Error>> {
        let event = self.event(
            &current,
            ModuleEventType::StaleTransitionDiscarded,
            Some(current.state),
            Some("revision_changed"),
        );
        self.repository
            .compare_and_set_instance(
                current.transition_revision,
                InstanceStateMutation {
                    change: InstanceStateChange {
                        expected_revision: Some(current.transition_revision),
                        next: current,
                    },
                    applied_event: event.clone(),
                    stale_event: event,
                },
            )
            .await
            .map_err(RegistryError::Repository)?;
        Ok(())
    }

    async fn persist_failure(
        &self,
        current: &InstanceStateRecord,
        failure: LifecycleFailure,
    ) -> Result<bool, RegistryError<R::Error>> {
        let outcome = self
            .persist_state(
                current.module_id,
                current.transition_revision,
                Some(current.transition_revision),
                ModuleState::Failed,
                None,
                ModuleEventType::TransitionFailed,
                Some(current.state),
                current.drain_deadline,
                Some(failure.code),
            )
            .await?;
        Ok(matches!(outcome, CasOutcome::Applied(_)))
    }

    fn event(
        &self,
        state: &InstanceStateRecord,
        event_type: ModuleEventType,
        before: Option<ModuleState>,
        outcome_code: Option<&'static str>,
    ) -> ModuleEventRecord {
        ModuleEventRecord {
            event_id: format!(
                "{}-{}",
                self.instance_id,
                self.event_sequence.fetch_add(1, Ordering::Relaxed)
            ),
            module_id: state.module_id,
            event_type,
            revision: state.transition_revision,
            instance_id: Some(self.instance_id.clone()),
            actor_id: None,
            reason: None,
            before: before.map(ModuleEventState::Actual),
            after: Some(ModuleEventState::Actual(state.state)),
            outcome_code: outcome_code.map(str::to_owned),
            occurred_at: state.updated_at,
        }
    }

    fn event_from(
        &self,
        mut event: ModuleEventRecord,
        event_type: ModuleEventType,
    ) -> ModuleEventRecord {
        event.event_id = format!(
            "{}-{}",
            self.instance_id,
            self.event_sequence.fetch_add(1, Ordering::Relaxed)
        );
        event.event_type = event_type;
        event
    }
}

fn set_membership(set: &mut BTreeSet<ModuleId>, module_id: ModuleId, present: bool) {
    if present {
        set.insert(module_id);
    } else {
        set.remove(&module_id);
    }
}
