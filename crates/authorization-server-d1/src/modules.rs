//! Worker module availability is fixed by the deployed profile. Runtime changes
//! require a new deployment; this adapter does not emulate native lifecycle work.
use crate::{D1Provider, db::DbError};
use futures_util::future::BoxFuture;
use nazo_identity::ports::RepositoryError;
use nazo_persistence::RuntimeModuleStore;
use nazo_runtime_modules::{
    CasOutcome, DesiredMode, DesiredRevisionGuard, DesiredStateChange, DesiredStateRecord,
    InstanceStateMutation, InstanceStateObservation, InstanceStateRecord, ModuleEventPage,
    ModuleId, ModuleReconcileState, ModuleRevision,
};
use serde::Deserialize;
use serde_json::json;

#[derive(Deserialize)]
struct ModuleRow {
    module_id: ModuleId,
    enabled: i64,
}
impl ModuleRow {
    fn into_domain(self) -> DesiredStateRecord {
        DesiredStateRecord {
            module_id: self.module_id,
            mode: if self.enabled != 0 {
                DesiredMode::Enabled
            } else {
                DesiredMode::Disabled
            },
            revision: ModuleRevision::new(1),
            actor_id: None,
            reason: Some("deployment profile".into()),
            updated_at: web_time::UNIX_EPOCH,
        }
    }
}
impl RuntimeModuleStore for D1Provider {
    fn read_desired(
        &self,
        module_id: ModuleId,
    ) -> BoxFuture<'_, Result<Option<DesiredStateRecord>, RepositoryError>> {
        Box::pin(async move {
            Ok(self.database.query::<ModuleRow>("SELECT module_id,enabled FROM nazo_modules WHERE tenant_id=?1 AND module_id=?2",vec![json!(self.tenant_id),json!(module_id)]).await?.into_iter().next().map(ModuleRow::into_domain))
        })
    }
    fn read_all_desired(&self) -> BoxFuture<'_, Result<Vec<DesiredStateRecord>, RepositoryError>> {
        Box::pin(async move {
            Ok(self
                .database
                .query::<ModuleRow>(
                    "SELECT module_id,enabled FROM nazo_modules WHERE tenant_id=?1",
                    vec![json!(self.tenant_id)],
                )
                .await?
                .into_iter()
                .map(ModuleRow::into_domain)
                .collect())
        })
    }
    fn read_reconcile_state<'a>(
        &'a self,
        _instance_id: &'a str,
    ) -> BoxFuture<'a, Result<Vec<ModuleReconcileState>, RepositoryError>> {
        Box::pin(async move {
            let desired = self.read_all_desired().await?;
            if desired.len() != ModuleId::ALL.len() {
                return Err(DbError::CorruptData.into());
            }
            Ok(desired
                .into_iter()
                .map(|desired| ModuleReconcileState {
                    desired,
                    instance: None,
                })
                .collect())
        })
    }
    fn compare_and_set_desired(
        &self,
        _change: DesiredStateChange,
    ) -> BoxFuture<'_, Result<CasOutcome<DesiredStateRecord>, RepositoryError>> {
        Box::pin(async { Err(RepositoryError::Unavailable) })
    }
    fn compare_and_set_desired_guarded(
        &self,
        _change: DesiredStateChange,
        _required_revisions: Vec<DesiredRevisionGuard>,
    ) -> BoxFuture<'_, Result<CasOutcome<DesiredStateRecord>, RepositoryError>> {
        Box::pin(async { Err(RepositoryError::Unavailable) })
    }
    fn read_instance<'a>(
        &'a self,
        _instance_id: &'a str,
        _module_id: ModuleId,
    ) -> BoxFuture<'a, Result<Option<InstanceStateRecord>, RepositoryError>> {
        Box::pin(async { Ok(None) })
    }
    fn read_all_instances<'a>(
        &'a self,
        _instance_id: &'a str,
    ) -> BoxFuture<'a, Result<Vec<InstanceStateRecord>, RepositoryError>> {
        Box::pin(async { Ok(Vec::new()) })
    }
    fn page_events(
        &self,
        _offset: i64,
        _limit: i64,
    ) -> BoxFuture<'_, Result<ModuleEventPage, RepositoryError>> {
        Box::pin(async { Err(RepositoryError::Unavailable) })
    }
    fn compare_and_set_instance(
        &self,
        _mutation: InstanceStateMutation,
    ) -> BoxFuture<'_, Result<CasOutcome<InstanceStateRecord>, RepositoryError>> {
        Box::pin(async { Err(RepositoryError::Unavailable) })
    }
    fn record_instance_observation(
        &self,
        _observation: InstanceStateObservation,
    ) -> BoxFuture<'_, Result<(), RepositoryError>> {
        Box::pin(async { Err(RepositoryError::Unavailable) })
    }
    fn validate_revision(
        &self,
        module_id: ModuleId,
        expected: ModuleRevision,
    ) -> BoxFuture<'_, Result<bool, RepositoryError>> {
        Box::pin(async move {
            Ok(self
                .read_desired(module_id)
                .await?
                .is_some_and(|state| state.revision == expected))
        })
    }
}
