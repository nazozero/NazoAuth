use crate::{
    ActiveModuleSnapshot, DesiredStateRecord, InstanceStateRecord, LifecycleFailure, ModuleId,
    ModuleLifecycle, ModuleState, ModuleStateRepository, ReconcileOutcome, RegistryError,
};

use super::RuntimeModuleRegistry;

impl<R, L> RuntimeModuleRegistry<R, L>
where
    R: ModuleStateRepository,
    L: ModuleLifecycle + ?Sized,
{
    pub(super) async fn first_unavailable_dependency(
        &self,
        module_id: ModuleId,
    ) -> Result<Option<ModuleId>, RegistryError<R::Error>> {
        let spec = self.catalog.spec(module_id);
        if spec.dependencies.is_empty() {
            return Ok(None);
        }
        let snapshot = self.snapshot();
        let desired = self
            .repository
            .read_all_desired()
            .await
            .map_err(RegistryError::Repository)?;
        for dependency in &spec.dependencies {
            let desired = desired
                .iter()
                .find(|record| record.module_id == *dependency)
                .ok_or(RegistryError::MissingDesiredState(*dependency))?;
            if !self
                .catalog
                .effective_enabled(*dependency, desired.mode.is_enabled())
                || !snapshot.admits(*dependency)
            {
                return Ok(Some(*dependency));
            }
        }
        Ok(None)
    }

    pub(super) async fn first_enabled_dependent(
        &self,
        module_id: ModuleId,
    ) -> Result<Option<ModuleId>, RegistryError<R::Error>> {
        let dependents = self
            .catalog
            .specs()
            .values()
            .filter(|candidate| candidate.dependencies.contains(&module_id))
            .map(|candidate| candidate.id)
            .collect::<Vec<_>>();
        if dependents.is_empty() {
            return Ok(None);
        }
        let snapshot = self.snapshot();
        let desired = self
            .repository
            .read_all_desired()
            .await
            .map_err(RegistryError::Repository)?;
        for dependent in dependents {
            let desired = desired
                .iter()
                .find(|record| record.module_id == dependent)
                .ok_or(RegistryError::MissingDesiredState(dependent))?;
            if self.dependent_has_work(desired, &snapshot).await? {
                return Ok(Some(dependent));
            }
        }
        Ok(None)
    }

    /// Closing admission is not proof that a dependent finished. A cold or
    /// budgeted step may still have a live global window or local execution.
    pub(super) async fn dependent_has_work(
        &self,
        desired: &DesiredStateRecord,
        snapshot: &ActiveModuleSnapshot,
    ) -> Result<bool, RegistryError<R::Error>> {
        let module_id = desired.module_id;
        if !self.catalog.is_available(module_id) {
            return Ok(false);
        }
        if desired.mode.is_enabled()
            || snapshot.admits(module_id)
            || snapshot.draining.contains(&module_id)
            || !self.snapshots.is_idle(module_id)
        {
            return Ok(true);
        }
        let pending = self
            .synchronization
            .lock()
            .expect("synchronization state")
            .pending
            .contains(&module_id);
        if !pending
            && self
                .drain_deadline(desired, None)?
                .is_none_or(|deadline| web_time::SystemTime::now() >= deadline)
        {
            return Ok(false);
        }
        let instance = self
            .repository
            .read_instance(&self.instance_id, module_id)
            .await
            .map_err(RegistryError::Repository)?;
        Ok(!instance.is_some_and(|instance| {
            instance.state == ModuleState::Disabled
                && instance.applied_revision == Some(desired.revision)
                && instance.transition_revision == desired.revision
        }))
    }

    pub(super) async fn fail_dependency_loss(
        &self,
        current: &InstanceStateRecord,
    ) -> Result<ReconcileOutcome, RegistryError<R::Error>> {
        self.publish(current.module_id, false, false)?;
        let failed = self
            .persist_failure(
                current,
                LifecycleFailure {
                    code: "dependency_unavailable",
                },
            )
            .await?;
        Ok(if failed {
            ReconcileOutcome::Failed
        } else {
            ReconcileOutcome::StaleDiscarded
        })
    }
}
