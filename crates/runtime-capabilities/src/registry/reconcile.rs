use std::collections::BTreeMap;

use crate::{
    ModuleId, ModuleLifecycle, ModuleReconcileState, ModuleState, ModuleStateRepository,
    ReconcileOutcome, RegistryError,
};

use super::RuntimeModuleRegistry;

impl<R, L> RuntimeModuleRegistry<R, L>
where
    R: ModuleStateRepository,
    L: ModuleLifecycle,
{
    /// Poll durable state once for this instance. The snapshot only eliminates
    /// settled work; every transition still reads and fences its current state.
    pub async fn reconcile_all(
        &self,
    ) -> Result<
        Vec<(ModuleId, Result<ReconcileOutcome, RegistryError<R::Error>>)>,
        RegistryError<R::Error>,
    > {
        let states = self
            .repository
            .read_reconcile_state(&self.instance_id)
            .await
            .map_err(RegistryError::Repository)?
            .into_iter()
            .map(|state| (state.desired.module_id, state))
            .collect::<BTreeMap<_, _>>();
        let mut outcomes = Vec::with_capacity(ModuleId::ALL.len());
        for module_id in ModuleId::ALL {
            let outcome = if self.is_settled(module_id, &states) {
                Ok(ReconcileOutcome::NoChange)
            } else {
                self.reconcile_once(module_id).await
            };
            outcomes.push((module_id, outcome));
        }
        Ok(outcomes)
    }

    fn is_settled(
        &self,
        module_id: ModuleId,
        states: &BTreeMap<ModuleId, ModuleReconcileState>,
    ) -> bool {
        let Some(state) = states.get(&module_id) else {
            return false;
        };
        let enabled = state.desired.mode.is_enabled();
        if !state.instance.as_ref().is_some_and(|instance| {
            instance.applied_revision == Some(state.desired.revision)
                && ((enabled && instance.state == ModuleState::Enabled)
                    || (!enabled && instance.state == ModuleState::Disabled))
        }) {
            return false;
        }
        // Re-read the in-process admission snapshot after any earlier transition
        // in this pass. Desired mode alone never proves dependency readiness.
        let snapshot = self.snapshot();
        if enabled {
            self.catalog.spec(module_id).is_some_and(|spec| {
                spec.dependencies.iter().all(|dependency| {
                    states
                        .get(dependency)
                        .is_some_and(|state| state.desired.mode.is_enabled())
                        && snapshot.admits(*dependency)
                })
            })
        } else {
            self.catalog
                .specs()
                .values()
                .filter(|candidate| candidate.dependencies.contains(&module_id))
                .all(|dependent| {
                    states
                        .get(&dependent.id)
                        .is_some_and(|state| !state.desired.mode.is_enabled())
                        && !snapshot.admits(dependent.id)
                })
        }
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
        let enabled = desired.mode.is_enabled();
        let current = self
            .repository
            .read_instance(&self.instance_id, module_id)
            .await
            .map_err(RegistryError::Repository)?;
        if enabled {
            if let Some(dependency) = self.first_unavailable_dependency(module_id).await? {
                if self.snapshot().admits(module_id) {
                    self.publish(module_id, false, false)?;
                }
                if let Some(current) = current.as_ref()
                    && current.transition_revision == desired.revision
                {
                    return self.fail_dependency_loss(current, true).await;
                }
                return Err(RegistryError::DependencyUnavailable {
                    module_id,
                    dependency,
                });
            }
        } else if let Some(dependent) = self.first_enabled_dependent(module_id).await? {
            return Err(RegistryError::ActiveDependent {
                module_id,
                dependent,
            });
        }
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
}
