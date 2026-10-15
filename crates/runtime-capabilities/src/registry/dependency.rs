use crate::{
    InstanceStateRecord, LifecycleFailure, ModuleId, ModuleLifecycle, ModuleStateRepository,
    ReconcileOutcome, RegistryError,
};

use super::RuntimeModuleRegistry;

impl<R, L> RuntimeModuleRegistry<R, L>
where
    R: ModuleStateRepository,
    L: ModuleLifecycle,
{
    pub(super) async fn first_unavailable_dependency(
        &self,
        module_id: ModuleId,
    ) -> Result<Option<ModuleId>, RegistryError<R::Error>> {
        let spec = self
            .catalog
            .spec(module_id)
            .ok_or(RegistryError::MissingCatalogSpec(module_id))?;
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
            if self
                .catalog
                .effective_enabled(dependent, desired.mode.is_enabled())
                || snapshot.admits(dependent)
                || snapshot.draining.contains(&dependent)
            {
                return Ok(Some(dependent));
            }
        }
        Ok(None)
    }

    pub(super) async fn fail_dependency_loss(
        &self,
        current: &InstanceStateRecord,
        initialized: bool,
    ) -> Result<ReconcileOutcome, RegistryError<R::Error>> {
        self.publish(current.module_id, false, false)?;
        let failure = if initialized {
            self.lifecycle
                .stop(current.module_id)
                .await
                .err()
                .unwrap_or(LifecycleFailure {
                    code: "dependency_unavailable",
                })
        } else {
            LifecycleFailure {
                code: "dependency_unavailable",
            }
        };
        let failed = self.persist_failure(current, failure).await?;
        Ok(if failed {
            ReconcileOutcome::Failed
        } else {
            ReconcileOutcome::StaleDiscarded
        })
    }
}
