use std::{collections::BTreeMap, sync::Arc, time::SystemTime};

use crate::{
    CasOutcome, DesiredMode, DesiredStateRecord, DisablePolicy, InstanceStateRecord, ModuleCatalog,
    ModuleEventPage, ModuleId, ModuleLifecycle, ModuleRevision, ModuleState, ModuleStateRepository,
    RegistryError, RuntimeModuleRegistry,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeModuleView {
    pub module_id: ModuleId,
    pub desired_state: DesiredMode,
    pub resolved_enabled: bool,
    pub actual_state: ModuleState,
    pub revision: Option<ModuleRevision>,
    pub transition_revision: Option<ModuleRevision>,
    pub applied_revision: Option<ModuleRevision>,
    pub dependencies: Vec<ModuleId>,
    pub dependents: Vec<ModuleId>,
    pub allowed_actions: Vec<DesiredMode>,
    pub disable_policy: DisablePolicy,
    pub drain_deadline: Option<SystemTime>,
    pub failure_code: Option<String>,
    pub updated_at: SystemTime,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DesiredStateUpdate {
    pub module_id: ModuleId,
    pub desired_state: DesiredMode,
    pub expected_revision: Option<ModuleRevision>,
    pub actor_id: String,
    pub reason: String,
    pub changed_at: SystemTime,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DesiredStateUpdateOutcome {
    Accepted {
        desired: DesiredStateRecord,
        actual_state: ModuleState,
    },
    Stale {
        current_revision: Option<ModuleRevision>,
    },
}

#[derive(Debug)]
pub enum RuntimeModuleManagementError<E> {
    Repository(E),
    Registry(RegistryError<E>),
    MissingCatalogSpec(ModuleId),
    MissingDesiredState(ModuleId),
}

pub struct RuntimeModuleManagement<R, L> {
    repository: Arc<R>,
    registry: Arc<RuntimeModuleRegistry<R, L>>,
    catalog: ModuleCatalog,
    instance_id: Box<str>,
}

impl<R, L> RuntimeModuleManagement<R, L>
where
    R: ModuleStateRepository,
    L: ModuleLifecycle,
{
    #[must_use]
    pub fn new(
        repository: Arc<R>,
        registry: Arc<RuntimeModuleRegistry<R, L>>,
        catalog: ModuleCatalog,
        instance_id: impl Into<Box<str>>,
    ) -> Self {
        Self {
            repository,
            registry,
            catalog,
            instance_id: instance_id.into(),
        }
    }

    pub async fn list(
        &self,
    ) -> Result<Vec<RuntimeModuleView>, RuntimeModuleManagementError<R::Error>> {
        let states = self
            .repository
            .read_reconcile_state(&self.instance_id)
            .await
            .map_err(RuntimeModuleManagementError::Repository)?
            .into_iter()
            .map(|state| (state.desired.module_id, state))
            .collect::<BTreeMap<_, _>>();
        let snapshot = self.registry.snapshot();
        ModuleId::ALL
            .into_iter()
            .map(|module_id| {
                self.module_view(
                    module_id,
                    states.get(&module_id).map(|state| &state.desired),
                    states
                        .get(&module_id)
                        .and_then(|state| state.instance.as_ref()),
                    &snapshot,
                )
            })
            .collect()
    }

    pub async fn events(
        &self,
        offset: i64,
        limit: i64,
    ) -> Result<ModuleEventPage, RuntimeModuleManagementError<R::Error>> {
        self.repository
            .page_events(offset, limit)
            .await
            .map_err(RuntimeModuleManagementError::Repository)
    }

    pub async fn update_desired(
        &self,
        update: DesiredStateUpdate,
    ) -> Result<DesiredStateUpdateOutcome, RuntimeModuleManagementError<R::Error>> {
        let outcome = self
            .registry
            .set_desired_mode(
                update.module_id,
                update.desired_state,
                update.expected_revision,
                Some(update.actor_id),
                Some(update.reason),
                update.changed_at,
            )
            .await
            .map_err(RuntimeModuleManagementError::Registry)?;
        let desired = match outcome {
            CasOutcome::Applied(desired) => desired,
            CasOutcome::Stale { current } => {
                return Ok(DesiredStateUpdateOutcome::Stale {
                    current_revision: current.map(|record| record.revision),
                });
            }
        };
        let actual_state = self
            .repository
            .read_instance(&self.instance_id, update.module_id)
            .await
            .map_err(RuntimeModuleManagementError::Repository)?
            .map_or(ModuleState::Disabled, |record| {
                if self.catalog.is_available(update.module_id) {
                    record.state
                } else {
                    ModuleState::Disabled
                }
            });
        Ok(DesiredStateUpdateOutcome::Accepted {
            desired,
            actual_state,
        })
    }

    fn module_view(
        &self,
        module_id: ModuleId,
        desired: Option<&DesiredStateRecord>,
        instance: Option<&InstanceStateRecord>,
        snapshot: &crate::ActiveModuleSnapshot,
    ) -> Result<RuntimeModuleView, RuntimeModuleManagementError<R::Error>> {
        let spec = self
            .catalog
            .spec(module_id)
            .ok_or(RuntimeModuleManagementError::MissingCatalogSpec(module_id))?;
        let desired =
            desired.ok_or(RuntimeModuleManagementError::MissingDesiredState(module_id))?;
        let desired_state = desired.mode;
        let actual_state = if !self.catalog.is_available(module_id) {
            ModuleState::Disabled
        } else {
            instance.map_or_else(
                || {
                    if snapshot.admits(module_id) {
                        ModuleState::Enabled
                    } else {
                        ModuleState::Disabled
                    }
                },
                |record| record.state,
            )
        };
        let dependents = self
            .catalog
            .specs()
            .values()
            .filter(|candidate| candidate.dependencies.contains(&module_id))
            .map(|candidate| candidate.id)
            .collect();
        let updated_at = instance
            .map(|record| record.updated_at)
            .unwrap_or(desired.updated_at);
        Ok(RuntimeModuleView {
            module_id,
            desired_state,
            resolved_enabled: self
                .catalog
                .effective_enabled(module_id, desired_state.is_enabled()),
            actual_state,
            revision: Some(desired.revision),
            transition_revision: instance.map(|record| record.transition_revision),
            applied_revision: instance.and_then(|record| record.applied_revision),
            dependencies: spec.dependencies.iter().copied().collect(),
            dependents,
            allowed_actions: self.allowed_actions(module_id, desired_state, snapshot),
            disable_policy: self
                .catalog
                .effective_disable_policy(module_id)
                .ok_or(RuntimeModuleManagementError::MissingCatalogSpec(module_id))?,
            drain_deadline: instance.and_then(|record| record.drain_deadline),
            failure_code: if !self.catalog.is_available(module_id) {
                Some("service_not_constructed".to_owned())
            } else {
                instance.and_then(|record| record.error_code.clone())
            },
            updated_at,
        })
    }

    fn allowed_actions(
        &self,
        module_id: ModuleId,
        mode: DesiredMode,
        snapshot: &crate::ActiveModuleSnapshot,
    ) -> Vec<DesiredMode> {
        let mut actions = Vec::with_capacity(2);
        if self.catalog.is_available(module_id)
            && mode != DesiredMode::Enabled
            && self.catalog.spec(module_id).is_some_and(|spec| {
                spec.dependencies
                    .iter()
                    .all(|dependency| snapshot.admits(*dependency))
            })
        {
            actions.push(DesiredMode::Enabled);
        }
        if mode != DesiredMode::Disabled
            && !matches!(
                self.catalog.effective_disable_policy(module_id),
                Some(DisablePolicy::NotRuntimeDisableable) | None
            )
            && !self.catalog.specs().values().any(|candidate| {
                candidate.dependencies.contains(&module_id)
                    && self.catalog.is_available(candidate.id)
                    && (snapshot.admits(candidate.id) || snapshot.draining.contains(&candidate.id))
            })
        {
            actions.push(DesiredMode::Disabled);
        }
        actions
    }
}

#[cfg(test)]
#[path = "../tests/unit/management.rs"]
mod tests;
