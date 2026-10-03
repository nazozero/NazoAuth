use std::time::{Duration, SystemTime};

use crate::{
    CasOutcome, DisablePolicy, InstanceStateRecord, LifecycleFailure, ModuleEventType, ModuleId,
    ModuleLifecycle, ModuleRevision, ModuleState, ModuleStateRepository, ReconcileOutcome,
    RegistryError,
};

use super::RuntimeModuleRegistry;

impl<R, L> RuntimeModuleRegistry<R, L>
where
    R: ModuleStateRepository,
    L: ModuleLifecycle,
{
    pub(super) async fn enable(
        &self,
        module_id: ModuleId,
        revision: ModuleRevision,
        current: Option<InstanceStateRecord>,
    ) -> Result<ReconcileOutcome, RegistryError<R::Error>> {
        let mut initialized = false;
        let result = self
            .enable_transition(module_id, revision, current, &mut initialized)
            .await;
        self.finish_admission(module_id, initialized, result).await
    }

    pub(super) async fn disable(
        &self,
        module_id: ModuleId,
        revision: ModuleRevision,
        current: Option<InstanceStateRecord>,
    ) -> Result<ReconcileOutcome, RegistryError<R::Error>> {
        let mut initialized = current.as_ref().is_some_and(|state| {
            matches!(state.state, ModuleState::Enabled | ModuleState::Draining)
        });
        let result = self
            .disable_transition(module_id, revision, current, &mut initialized)
            .await;
        self.finish_admission(module_id, initialized, result).await
    }

    async fn finish_admission(
        &self,
        module_id: ModuleId,
        initialized: bool,
        result: Result<ReconcileOutcome, RegistryError<R::Error>>,
    ) -> Result<ReconcileOutcome, RegistryError<R::Error>> {
        let completed_enable = matches!(&result, Ok(ReconcileOutcome::Enabled));
        let compensation = self
            .align_admission_with_current_intent(module_id, initialized, completed_enable)
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
        initialized: &mut bool,
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
            return self.fail_dependency_loss(&starting, false).await;
        }
        if let Err(failure) = self.lifecycle.initialize(module_id).await {
            return Ok(if self.persist_failure(&starting, failure).await? {
                ReconcileOutcome::Failed
            } else {
                ReconcileOutcome::StaleDiscarded
            });
        }
        *initialized = true;
        if self
            .first_unavailable_dependency(module_id)
            .await?
            .is_some()
        {
            *initialized = false;
            return self.fail_dependency_loss(&starting, true).await;
        }
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
            *initialized = false;
            return self.fail_dependency_loss(&starting, true).await;
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
        module_id: ModuleId,
        revision: ModuleRevision,
        current: Option<InstanceStateRecord>,
        initialized: &mut bool,
    ) -> Result<ReconcileOutcome, RegistryError<R::Error>> {
        let disable_policy = self
            .catalog
            .effective_disable_policy(module_id)
            .ok_or(RegistryError::MissingCatalogSpec(module_id))?;
        if current
            .as_ref()
            .is_none_or(|instance| instance.state == ModuleState::Disabled)
        {
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
        let prior_generation = self.snapshot().revision;
        let drain_deadline = match disable_policy {
            DisablePolicy::DrainStoredTransactions { max_duration } => current
                .as_ref()
                .filter(|instance| {
                    instance.state == ModuleState::Draining
                        && instance.transition_revision == revision
                })
                .and_then(|instance| instance.drain_deadline)
                .or_else(|| SystemTime::now().checked_add(max_duration)),
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
        self.publish(module_id, false, true)?;
        if !self.revision_is_current(module_id, revision).await? {
            self.discard_stale(module_id, revision, Some(&draining))
                .await?;
            return Ok(ReconcileOutcome::StaleDiscarded);
        }
        if !matches!(disable_policy, DisablePolicy::Immediate) {
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
            if matches!(
                disable_policy,
                DisablePolicy::DrainStoredTransactions { .. }
            ) {
                let remaining_duration = drain_deadline
                    .and_then(|deadline| deadline.duration_since(SystemTime::now()).ok())
                    .unwrap_or(Duration::ZERO);
                match self
                    .lifecycle
                    .drain_stored_transactions(module_id, revision, remaining_duration)
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
                        *initialized = false;
                        let failed = self.persist_failure(&draining, failure).await?;
                        return Ok(if failed {
                            ReconcileOutcome::Failed
                        } else {
                            ReconcileOutcome::StaleDiscarded
                        });
                    }
                }
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
        *initialized = false;
        if let Err(failure) = self.lifecycle.stop(module_id).await {
            let failed = self.persist_failure(&draining, failure).await?;
            return Ok(if failed {
                ReconcileOutcome::Failed
            } else {
                ReconcileOutcome::StaleDiscarded
            });
        }
        if !self.revision_is_current(module_id, revision).await? {
            self.discard_stale(module_id, revision, Some(&draining))
                .await?;
            // `stop` already ran, so admission cannot be restored safely.
            // Remove the obsolete draining marker; the newer revision will
            // initialize and republish the module if it resolves to enabled.
            self.publish(module_id, false, false)?;
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
    /// unknown writes. A stopped/uncertain lifecycle cannot be reopened merely
    /// because the newest durable intent is enabled.
    async fn align_admission_with_current_intent(
        &self,
        module_id: ModuleId,
        initialized: bool,
        completed_enable: bool,
    ) -> Result<(), RegistryError<R::Error>> {
        loop {
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
            let runtime_ready = if initialized && !completed_enable {
                match self
                    .repository
                    .read_instance(&self.instance_id, module_id)
                    .await
                {
                    Ok(state) => state.is_some_and(|state| {
                        matches!(state.state, ModuleState::Enabled | ModuleState::Draining)
                    }),
                    Err(error) => {
                        self.publish(module_id, false, false)?;
                        return Err(RegistryError::Repository(error));
                    }
                }
            } else {
                initialized
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
                runtime_ready && !enabled && self.catalog.is_available(module_id),
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
}
