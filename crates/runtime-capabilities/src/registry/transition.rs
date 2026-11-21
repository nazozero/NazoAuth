use std::time::Duration;
use web_time::SystemTime;

use crate::{
    CasOutcome, DesiredStateRecord, DisablePolicy, DrainProgress, InstanceStateRecord,
    LifecycleFailure, ModuleEventType, ModuleId, ModuleLifecycle, ModuleRevision, ModuleState,
    ModuleStateRepository, ReconcileOutcome, RegistryError,
};

use super::{DrainObservation, ReconcileMode, RuntimeModuleRegistry};

impl<R, L> RuntimeModuleRegistry<R, L>
where
    R: ModuleStateRepository,
    L: ModuleLifecycle + ?Sized,
{
    pub(super) async fn enable(
        &self,
        module_id: ModuleId,
        revision: ModuleRevision,
        current: Option<InstanceStateRecord>,
        mode: ReconcileMode,
    ) -> Result<ReconcileOutcome, RegistryError<R::Error>> {
        let mut can_restore = false;
        let result = self
            .enable_transition(module_id, revision, current, &mut can_restore)
            .await;
        self.finish_admission(module_id, can_restore, true, mode, result)
            .await
    }

    pub(super) async fn disable(
        &self,
        desired: DesiredStateRecord,
        current: Option<InstanceStateRecord>,
        mode: ReconcileMode,
    ) -> Result<ReconcileOutcome, RegistryError<R::Error>> {
        let module_id = desired.module_id;
        let mut can_restore = current.as_ref().is_some_and(|state| {
            matches!(state.state, ModuleState::Enabled | ModuleState::Draining)
        });
        let mut allow_stored_admission = true;
        let result = self
            .disable_transition(
                &desired,
                current,
                mode,
                &mut can_restore,
                &mut allow_stored_admission,
            )
            .await;
        self.finish_admission(module_id, can_restore, allow_stored_admission, mode, result)
            .await
    }

    async fn finish_admission(
        &self,
        module_id: ModuleId,
        can_restore: bool,
        allow_stored_admission: bool,
        mode: ReconcileMode,
        result: Result<ReconcileOutcome, RegistryError<R::Error>>,
    ) -> Result<ReconcileOutcome, RegistryError<R::Error>> {
        let completed_enable = matches!(&result, Ok(ReconcileOutcome::Enabled));
        let can_restore = can_restore && !matches!(&result, Ok(ReconcileOutcome::Disabled));
        let compensation = self
            .align_admission_with_current_intent(
                module_id,
                can_restore,
                completed_enable,
                allow_stored_admission,
                mode,
            )
            .await;
        match (result, compensation) {
            (Ok(outcome), Ok(())) => Ok(outcome),
            (Err(error), Ok(())) | (Ok(_), Err(error)) => Err(error),
            (Err(operation), Err(compensation)) => {
                if matches!(&operation, RegistryError::SnapshotRevisionExhausted)
                    && matches!(&compensation, RegistryError::SnapshotRevisionExhausted)
                {
                    return Err(operation);
                }
                Err(RegistryError::Compensation {
                    operation: Box::new(operation),
                    compensation: Box::new(compensation),
                })
            }
        }
    }

    async fn enable_transition(
        &self,
        module_id: ModuleId,
        revision: ModuleRevision,
        current: Option<InstanceStateRecord>,
        can_restore: &mut bool,
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
        if self
            .first_unavailable_dependency(module_id)
            .await?
            .is_some()
        {
            return self.fail_dependency_loss(&starting).await;
        }
        *can_restore = true;
        if !self.revision_is_current(module_id, revision).await? {
            self.discard_stale(module_id, revision, Some(&starting))
                .await?;
            return Ok(ReconcileOutcome::StaleDiscarded);
        }
        self.publish(module_id, true, false)?;
        if self
            .first_unavailable_dependency(module_id)
            .await?
            .is_some()
        {
            self.publish(module_id, false, false)?;
            *can_restore = false;
            return self.fail_dependency_loss(&starting).await;
        }
        if !self.revision_is_current(module_id, revision).await? {
            self.publish(module_id, false, false)?;
            self.discard_stale(module_id, revision, Some(&starting))
                .await?;
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
                self.publish(module_id, false, false)?;
                ReconcileOutcome::StaleDiscarded
            }
        })
    }

    async fn disable_transition(
        &self,
        desired: &DesiredStateRecord,
        current: Option<InstanceStateRecord>,
        mode: ReconcileMode,
        can_restore: &mut bool,
        allow_stored_admission: &mut bool,
    ) -> Result<ReconcileOutcome, RegistryError<R::Error>> {
        let module_id = desired.module_id;
        let revision = desired.revision;
        let disable_policy = self.catalog.effective_disable_policy(module_id);
        let drain_deadline = self.drain_deadline(desired, current.as_ref())?;
        let stored_window_open =
            drain_deadline.is_some_and(|deadline| SystemTime::now() < deadline);
        if current.as_ref().is_some_and(|instance| {
            instance.state == ModuleState::Disabled && instance.applied_revision == Some(revision)
        }) || (current
            .as_ref()
            .is_none_or(|instance| instance.state == ModuleState::Disabled)
            && !stored_window_open)
        {
            self.publish(module_id, false, false)?;
            if !matches!(disable_policy, DisablePolicy::Immediate) {
                if mode == ReconcileMode::Step {
                    if !self.snapshots.is_idle(module_id) {
                        return Ok(ReconcileOutcome::Pending);
                    }
                } else {
                    self.snapshots.wait_until_idle(module_id).await;
                }
            }
            if !self.revision_is_current(module_id, revision).await? {
                self.discard_stale(module_id, revision, current.as_ref())
                    .await?;
                return Ok(ReconcileOutcome::StaleDiscarded);
            }
            let completed = self
                .persist_state(
                    module_id,
                    revision,
                    current.as_ref().map(|state| state.transition_revision),
                    ModuleState::Disabled,
                    Some(revision),
                    ModuleEventType::TransitionCompleted,
                    current.as_ref().map(|state| state.state),
                    None,
                    None,
                )
                .await?;
            return match completed {
                CasOutcome::Applied(_) => {
                    if !self.revision_is_current(module_id, revision).await? {
                        Ok(ReconcileOutcome::StaleDiscarded)
                    } else {
                        self.publish(module_id, false, false)?;
                        Ok(ReconcileOutcome::Disabled)
                    }
                }
                CasOutcome::Stale { .. } => Ok(ReconcileOutcome::StaleDiscarded),
            };
        }
        let observation = self
            .drain_observations
            .lock()
            .expect("drain observations")
            .get(&module_id)
            .copied()
            .filter(|observation| {
                observation.revision == revision && observation.deadline == drain_deadline
            });
        let stored_complete = mode == ReconcileMode::Step
            && observation.is_some_and(|observation| observation.stored_complete);
        let resumed = mode == ReconcileMode::Step
            && observation.is_some()
            && current.as_ref().is_some_and(|instance| {
                instance.state == ModuleState::Draining
                    && instance.transition_revision == revision
                    && instance.drain_deadline == drain_deadline
            });
        let draining = if resumed {
            current.clone().expect("a resumed drain has an instance")
        } else {
            let outcome = self
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
            let CasOutcome::Applied(draining) = outcome else {
                return Ok(ReconcileOutcome::StaleDiscarded);
            };
            draining
        };
        *can_restore = true;
        if self.first_enabled_dependent(module_id).await?.is_some() {
            let failed = self
                .persist_failure(
                    &draining,
                    LifecycleFailure {
                        code: "active_dependent",
                    },
                )
                .await?;
            return Ok(if failed {
                ReconcileOutcome::Failed
            } else {
                ReconcileOutcome::StaleDiscarded
            });
        }
        if !self.revision_is_current(module_id, revision).await? {
            self.discard_stale(module_id, revision, Some(&draining))
                .await?;
            return Ok(ReconcileOutcome::StaleDiscarded);
        }
        self.publish(
            module_id,
            false,
            !stored_complete && drain_deadline.is_some_and(|deadline| SystemTime::now() < deadline),
        )?;
        if !self.revision_is_current(module_id, revision).await? {
            self.discard_stale(module_id, revision, Some(&draining))
                .await?;
            return Ok(ReconcileOutcome::StaleDiscarded);
        }
        if !matches!(disable_policy, DisablePolicy::Immediate) {
            if !resumed
                && !matches!(
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
                )
            {
                return Ok(ReconcileOutcome::StaleDiscarded);
            }
            if mode == ReconcileMode::Step && !resumed {
                // Keep only completed local observations, never a request-owned
                // future. Recovery after a failed/unknown start writes its own
                // DrainStarted evidence before a later completion.
                self.drain_observations
                    .lock()
                    .expect("drain observations")
                    .insert(
                        module_id,
                        DrainObservation {
                            revision,
                            deadline: drain_deadline,
                            stored_complete,
                        },
                    );
            }
            if matches!(
                disable_policy,
                DisablePolicy::DrainStoredTransactions { .. }
            ) && !stored_complete
            {
                let remaining_duration = drain_deadline
                    .and_then(|deadline| deadline.duration_since(SystemTime::now()).ok())
                    .unwrap_or(Duration::ZERO);
                let progress = if mode == ReconcileMode::Step {
                    self.lifecycle
                        .poll_stored_transactions(module_id, revision, remaining_duration)
                        .await
                } else {
                    self.lifecycle
                        .drain_stored_transactions(module_id, revision, remaining_duration)
                        .await
                        .and_then(|complete| {
                            if complete {
                                Ok(DrainProgress::Complete)
                            } else {
                                Err(LifecycleFailure {
                                    code: "drain_deadline_elapsed",
                                })
                            }
                        })
                };
                match progress {
                    Ok(DrainProgress::Complete) => {
                        self.drain_observations
                            .lock()
                            .expect("drain observations")
                            .insert(
                                module_id,
                                DrainObservation {
                                    revision,
                                    deadline: drain_deadline,
                                    stored_complete: true,
                                },
                            );
                    }
                    Ok(DrainProgress::Pending) => return Ok(ReconcileOutcome::Pending),
                    Err(failure) => {
                        let failed = self.persist_failure(&draining, failure).await?;
                        return Ok(if failed {
                            ReconcileOutcome::Failed
                        } else {
                            ReconcileOutcome::StaleDiscarded
                        });
                    }
                }
            }
            // Stop both new and stored-transaction admissions before waiting,
            // so later requests cannot keep extending the drain.
            *allow_stored_admission = false;
            self.publish(module_id, false, false)?;
            if mode == ReconcileMode::Step {
                if !self.snapshots.is_idle(module_id) {
                    return Ok(ReconcileOutcome::Pending);
                }
            } else {
                self.snapshots.wait_until_idle(module_id).await;
            }
            if !self.revision_is_current(module_id, revision).await? {
                self.discard_stale(module_id, revision, Some(&draining))
                    .await?;
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
                self.discard_stale(module_id, revision, Some(&draining))
                    .await?;
                return Ok(ReconcileOutcome::StaleDiscarded);
            }
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
                    self.publish(module_id, false, false)?;
                    return Ok(ReconcileOutcome::StaleDiscarded);
                }
                self.publish(module_id, false, false)?;
                Ok(ReconcileOutcome::Disabled)
            }
            CasOutcome::Stale { .. } => {
                self.publish(module_id, false, false)?;
                Ok(ReconcileOutcome::StaleDiscarded)
            }
        }
    }

    /// Reconcile admission after every terminal path, including failed or
    /// unknown writes. Admission follows the committed instance state and the
    /// newest durable intent; module services stay constructed throughout.
    async fn align_admission_with_current_intent(
        &self,
        module_id: ModuleId,
        can_restore: bool,
        completed_enable: bool,
        allow_stored_admission: bool,
        mode: ReconcileMode,
    ) -> Result<(), RegistryError<R::Error>> {
        let mut attempts = 0;
        loop {
            attempts += 1;
            if mode == ReconcileMode::Step && attempts > 2 {
                self.publish(module_id, false, false)?;
                return Err(RegistryError::SynchronizationChanged);
            }
            let desired = match self.repository.read_desired(module_id).await {
                Ok(Some(desired)) => desired,
                Ok(None) => {
                    self.publish(module_id, false, false)?;
                    return Err(RegistryError::MissingDesiredState(module_id));
                }
                Err(error) => {
                    self.publish(module_id, false, false)?;
                    return Err(RegistryError::Repository(error));
                }
            };
            let enabled = self
                .catalog
                .effective_enabled(module_id, desired.mode.is_enabled());
            let current = if can_restore && !completed_enable {
                match self
                    .repository
                    .read_instance(&self.instance_id, module_id)
                    .await
                {
                    Ok(state) => state,
                    Err(error) => {
                        self.publish(module_id, false, false)?;
                        return Err(RegistryError::Repository(error));
                    }
                }
            } else {
                None
            };
            let runtime_ready = if can_restore && !completed_enable {
                current.as_ref().is_some_and(|state| {
                    matches!(state.state, ModuleState::Enabled | ModuleState::Draining)
                })
            } else {
                can_restore
            };
            let dependencies_ready = if runtime_ready && enabled {
                match self.first_unavailable_dependency(module_id).await {
                    Ok(dependency) => dependency.is_none(),
                    Err(error) => {
                        self.publish(module_id, false, false)?;
                        return Err(error);
                    }
                }
            } else {
                false
            };
            self.publish(
                module_id,
                runtime_ready && enabled && dependencies_ready,
                runtime_ready
                    && !enabled
                    && allow_stored_admission
                    && self
                        .drain_deadline(&desired, current.as_ref())?
                        .is_some_and(|deadline| SystemTime::now() < deadline),
            )?;
            match self.revision_is_current(module_id, desired.revision).await {
                Ok(true) => return Ok(()),
                Ok(false) => {}
                Err(error) => {
                    self.publish(module_id, false, false)?;
                    return Err(error);
                }
            }
        }
    }

    pub(super) fn drain_deadline(
        &self,
        desired: &DesiredStateRecord,
        current: Option<&InstanceStateRecord>,
    ) -> Result<Option<SystemTime>, RegistryError<R::Error>> {
        if desired.mode.is_enabled()
            || !matches!(
                self.catalog.effective_disable_policy(desired.module_id),
                DisablePolicy::DrainStoredTransactions { .. }
            )
        {
            return Ok(None);
        }
        let Some(deadline) = self.catalog.stored_transaction_deadline(desired) else {
            self.publish(desired.module_id, false, false)?;
            return Err(RegistryError::DrainDeadlineOverflow(desired.module_id));
        };
        Ok(Some(
            current
                .filter(|instance| instance.transition_revision == desired.revision)
                .and_then(|instance| instance.drain_deadline)
                .map_or(deadline, |persisted| persisted.min(deadline)),
        ))
    }
}
