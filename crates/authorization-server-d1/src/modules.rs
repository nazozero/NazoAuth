//! Durable module intent and instance observations. The shared registry owns
//! dependency policy, admission and lifecycle; this adapter owns atomic evidence.
mod mutations;
mod records;

use crate::{D1Provider, db::DbError};
use futures_util::future::BoxFuture;
use nazo_identity::ports::RepositoryError;
use nazo_persistence::RuntimeModuleStore;
use nazo_runtime_modules::{
    CasOutcome, DesiredRevisionGuard, DesiredStateChange, DesiredStateRecord,
    InstanceStateMutation, InstanceStateObservation, InstanceStateRecord, ModuleEventPage,
    ModuleId, ModuleReconcileState, ModuleRevision,
};
use records::{DesiredRow, EventRow, InstanceRow, bounded, invalid};
use serde::{Deserialize, de::DeserializeOwned};
use serde_json::json;

pub(super) const DESIRED_JSON: &str = "json_object(
    'module_id',d.module_id,'mode',d.mode,'revision',d.revision,
    'actor_id',d.actor_id,'reason',d.reason,'updated_at',d.updated_at)";
pub(super) const INSTANCE_JSON: &str = "json_object(
    'instance_id',i.instance_id,'module_id',i.module_id,'state',i.state,
    'transition_revision',i.transition_revision,'applied_revision',i.applied_revision,
    'drain_deadline',i.drain_deadline,'error_code',i.error_code,'updated_at',i.updated_at)";

#[derive(Deserialize)]
struct RecordRow {
    record: String,
}

#[derive(Deserialize)]
struct ReconcileRow {
    desired: String,
    instance: Option<String>,
}

#[derive(Deserialize)]
struct PageRow {
    total: i64,
    record: Option<String>,
}

pub(super) fn decode<T: DeserializeOwned>(record: &str) -> Result<T, RepositoryError> {
    serde_json::from_str(record).map_err(|_| DbError::CorruptData.into())
}

impl RuntimeModuleStore for D1Provider {
    fn read_desired(
        &self,
        module_id: ModuleId,
    ) -> BoxFuture<'_, Result<Option<DesiredStateRecord>, RepositoryError>> {
        Box::pin(async move {
            self.database
                .query::<RecordRow>(
                    &format!(
                        "SELECT {DESIRED_JSON} AS record FROM nazo_module_desired d
                        WHERE tenant_id=?1 AND module_id=?2"
                    ),
                    vec![json!(self.tenant_id), json!(module_id)],
                )
                .await?
                .into_iter()
                .next()
                .map(|row| decode::<DesiredRow>(&row.record)?.into_record())
                .transpose()
        })
    }

    fn read_all_desired(&self) -> BoxFuture<'_, Result<Vec<DesiredStateRecord>, RepositoryError>> {
        Box::pin(async move {
            self.database
                .query::<RecordRow>(
                    &format!(
                        "SELECT {DESIRED_JSON} AS record FROM nazo_module_desired d
                        WHERE tenant_id=?1 ORDER BY module_id"
                    ),
                    vec![json!(self.tenant_id)],
                )
                .await?
                .into_iter()
                .map(|row| decode::<DesiredRow>(&row.record)?.into_record())
                .collect()
        })
    }

    fn read_reconcile_state<'a>(
        &'a self,
        instance_id: &'a str,
    ) -> BoxFuture<'a, Result<Vec<ModuleReconcileState>, RepositoryError>> {
        Box::pin(async move {
            bounded(instance_id, 255, "runtime instance id is out of bounds")?;
            // One statement snapshot includes every desired row, even when
            // this isolate has never persisted an instance observation.
            let rows = self
                .database
                .query::<ReconcileRow>(
                    &format!(
                        "SELECT {DESIRED_JSON} AS desired,
                    CASE WHEN i.instance_id IS NULL THEN NULL ELSE {INSTANCE_JSON} END AS instance
                 FROM nazo_module_desired d LEFT JOIN nazo_module_instances i
                   ON i.tenant_id=d.tenant_id AND i.module_id=d.module_id AND i.instance_id=?2
                 WHERE d.tenant_id=?1 ORDER BY d.module_id"
                    ),
                    vec![json!(self.tenant_id), json!(instance_id)],
                )
                .await?;
            if rows.len() != ModuleId::ALL.len() {
                return Err(invalid("runtime desired state is incomplete"));
            }
            rows.into_iter()
                .map(|row| {
                    Ok(ModuleReconcileState {
                        desired: decode::<DesiredRow>(&row.desired)?.into_record()?,
                        instance: row
                            .instance
                            .map(|record| decode::<InstanceRow>(&record)?.into_record())
                            .transpose()?,
                    })
                })
                .collect()
        })
    }

    fn compare_and_set_desired(
        &self,
        change: DesiredStateChange,
    ) -> BoxFuture<'_, Result<CasOutcome<DesiredStateRecord>, RepositoryError>> {
        Box::pin(mutations::desired(self, change, Vec::new()))
    }

    fn compare_and_set_desired_guarded(
        &self,
        change: DesiredStateChange,
        required_revisions: Vec<DesiredRevisionGuard>,
    ) -> BoxFuture<'_, Result<CasOutcome<DesiredStateRecord>, RepositoryError>> {
        Box::pin(mutations::desired(self, change, required_revisions))
    }

    fn read_instance<'a>(
        &'a self,
        instance_id: &'a str,
        module_id: ModuleId,
    ) -> BoxFuture<'a, Result<Option<InstanceStateRecord>, RepositoryError>> {
        Box::pin(async move {
            bounded(instance_id, 255, "runtime instance id is out of bounds")?;
            self.database
                .query::<RecordRow>(
                    &format!(
                        "SELECT {INSTANCE_JSON} AS record FROM nazo_module_instances i
                        WHERE tenant_id=?1 AND instance_id=?2 AND module_id=?3"
                    ),
                    vec![json!(self.tenant_id), json!(instance_id), json!(module_id)],
                )
                .await?
                .into_iter()
                .next()
                .map(|row| decode::<InstanceRow>(&row.record)?.into_record())
                .transpose()
        })
    }

    fn read_all_instances<'a>(
        &'a self,
        instance_id: &'a str,
    ) -> BoxFuture<'a, Result<Vec<InstanceStateRecord>, RepositoryError>> {
        Box::pin(async move {
            bounded(instance_id, 255, "runtime instance id is out of bounds")?;
            self.database
                .query::<RecordRow>(
                    &format!(
                        "SELECT {INSTANCE_JSON} AS record FROM nazo_module_instances i
                        WHERE tenant_id=?1 AND instance_id=?2 ORDER BY module_id"
                    ),
                    vec![json!(self.tenant_id), json!(instance_id)],
                )
                .await?
                .into_iter()
                .map(|row| decode::<InstanceRow>(&row.record)?.into_record())
                .collect()
        })
    }

    fn page_events(
        &self,
        offset: i64,
        limit: i64,
    ) -> BoxFuture<'_, Result<ModuleEventPage, RepositoryError>> {
        Box::pin(async move {
            if offset < 0 || !(1..=100).contains(&limit) {
                return Err(invalid("runtime event pagination is out of bounds"));
            }
            // Count and page share one snapshot; concurrent mutations cannot
            // make a page's total describe a different event stream.
            let rows = self.database.query::<PageRow>(
                "SELECT totals.total,events.record FROM
                    (SELECT count(*) AS total FROM nazo_module_events WHERE tenant_id=?1) totals
                 LEFT JOIN (SELECT record,occurred_at,event_id FROM nazo_module_events
                    WHERE tenant_id=?1 ORDER BY occurred_at DESC,event_id DESC LIMIT ?3 OFFSET ?2) events ON true
                 ORDER BY events.occurred_at DESC,events.event_id DESC",
                vec![json!(self.tenant_id),json!(offset),json!(limit)],
            ).await?;
            let total = rows.first().ok_or(DbError::CorruptData)?.total;
            let events = rows
                .into_iter()
                .filter_map(|row| row.record)
                .map(|record| decode::<EventRow>(&record)?.into_record())
                .collect::<Result<_, _>>()?;
            Ok(ModuleEventPage { total, events })
        })
    }

    fn compare_and_set_instance(
        &self,
        mutation: InstanceStateMutation,
    ) -> BoxFuture<'_, Result<CasOutcome<InstanceStateRecord>, RepositoryError>> {
        Box::pin(mutations::instance(self, mutation))
    }

    fn record_instance_observation(
        &self,
        observation: InstanceStateObservation,
    ) -> BoxFuture<'_, Result<(), RepositoryError>> {
        Box::pin(mutations::observation(self, observation))
    }

    fn validate_revision(
        &self,
        module_id: ModuleId,
        expected: ModuleRevision,
    ) -> BoxFuture<'_, Result<bool, RepositoryError>> {
        Box::pin(async move {
            #[derive(Deserialize)]
            struct Revision {
                revision: i64,
            }
            let expected = records::revision(expected)?;
            Ok(self
                .database
                .query::<Revision>(
                    "SELECT revision FROM nazo_module_desired WHERE tenant_id=?1 AND module_id=?2",
                    vec![json!(self.tenant_id), json!(module_id)],
                )
                .await?
                .first()
                .is_some_and(|row| row.revision == expected))
        })
    }
}

#[cfg(test)]
#[path = "../tests/unit/modules.rs"]
mod tests;
