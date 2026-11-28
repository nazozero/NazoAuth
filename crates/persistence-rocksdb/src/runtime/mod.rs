//! Transactional module intent, observations and their immutable events.
mod records;

use futures_util::future::BoxFuture;
use nazo_identity::ports::RepositoryError;
use nazo_persistence::RuntimeModuleStore;
use nazo_runtime_modules::*;
use rocksdb::{Transaction, TransactionDB};
use uuid::Uuid;

use crate::{
    RocksDb,
    db::{decode, key, map_error, put, read, read_snapshot, read_tx},
};
use records::{DesiredRow, EventRow, InstanceRow, bounded, invalid};

const DESIRED: u8 = 0x80;
const INSTANCE: u8 = 0x81;
const EVENT: u8 = 0x82;
const EVENT_ID: u8 = 0x83;
const EVENT_COUNT: u8 = 0x84;

fn desired_key(tenant: Uuid, module: ModuleId) -> Vec<u8> {
    key(
        DESIRED,
        tenant,
        &serde_json::to_vec(&module).expect("closed module enum"),
    )
}

fn instance_key(tenant: Uuid, instance: &str, module: ModuleId) -> Vec<u8> {
    let mut id = instance.as_bytes().to_vec();
    id.push(0);
    id.extend_from_slice(&serde_json::to_vec(&module).expect("closed module enum"));
    key(INSTANCE, tenant, &id)
}

fn append_event(
    tx: &Transaction<'_, TransactionDB>,
    tenant: Uuid,
    event: &ModuleEventRecord,
) -> Result<(), RepositoryError> {
    let row = EventRow::from_record(event)?;
    let id =
        Uuid::parse_str(&event.event_id).map_err(|_| invalid("invalid module event identity"))?;
    let id_key = key(EVENT_ID, Uuid::nil(), id.as_bytes());
    if tx
        .get_pinned_for_update(&id_key, true)
        .map_err(map_error)?
        .is_some()
    {
        return Err(RepositoryError::Conflict);
    }
    let count_key = key(EVENT_COUNT, tenant, &[]);
    let count = read_tx::<i64>(tx, &count_key, true)?
        .unwrap_or(0)
        .checked_add(1)
        .ok_or_else(|| invalid("module event sequence overflow"))?;
    let mut order = ((row.occurred_at as u64) ^ (1 << 63))
        .to_be_bytes()
        .to_vec();
    order.extend_from_slice(id.as_bytes());
    put(tx, &key(EVENT, tenant, &order), &row)?;
    put(tx, &id_key, &())?;
    put(tx, &count_key, &count)
}

pub(crate) fn ensure_defaults_in_tx(
    tx: &Transaction<'_, TransactionDB>,
    tenant: Uuid,
) -> Result<(), RepositoryError> {
    let now = std::time::SystemTime::now();
    let system_tenant = tenant
        == nazo_identity::TenantContext::default_system()
            .tenant_id
            .as_uuid();
    let reason = if system_tenant {
        "clean install baseline"
    } else {
        "tenant capability defaults"
    };
    for module in ModuleId::ALL {
        let record_key = desired_key(tenant, module);
        if read_tx::<DesiredRow>(tx, &record_key, true)?.is_some() {
            continue;
        }
        let mode = match module {
            ModuleId::HttpMessageSignatures => DesiredMode::Disabled,
            ModuleId::DynamicClientRegistration
            | ModuleId::AuthorizationDetails
            | ModuleId::ScimSecurityEvents
            | ModuleId::Openid4vciIssuer
            | ModuleId::Openid4vpVerifier
            | ModuleId::NativeSso
                if system_tenant =>
            {
                DesiredMode::Disabled
            }
            _ => DesiredMode::Enabled,
        };
        let record = DesiredStateRecord {
            module_id: module,
            mode,
            revision: ModuleRevision::new(1),
            actor_id: None,
            reason: Some(reason.into()),
            updated_at: now,
        };
        put(tx, &record_key, &DesiredRow::from_record(&record)?)?;
        append_event(
            tx,
            tenant,
            &ModuleEventRecord {
                event_id: Uuid::now_v7().to_string(),
                module_id: module,
                event_type: ModuleEventType::DesiredStateChanged,
                revision: record.revision,
                instance_id: None,
                actor_id: None,
                reason: record.reason,
                before: None,
                after: Some(ModuleEventState::Desired(mode.into())),
                outcome_code: None,
                occurred_at: now,
            },
        )?;
    }
    Ok(())
}

impl RuntimeModuleStore for RocksDb {
    fn read_desired(
        &self,
        module_id: ModuleId,
    ) -> BoxFuture<'_, Result<Option<DesiredStateRecord>, RepositoryError>> {
        Box::pin(self.run(move |store| {
            read::<DesiredRow>(&store.db, &desired_key(store.tenant_id, module_id))?
                .map(DesiredRow::into_record)
                .transpose()
        }))
    }

    fn read_all_desired(&self) -> BoxFuture<'_, Result<Vec<DesiredStateRecord>, RepositoryError>> {
        Box::pin(self.run(|store| {
            let snapshot = store.db.snapshot();
            ModuleId::ALL
                .into_iter()
                .map(|module| {
                    read_snapshot::<DesiredRow>(&snapshot, &desired_key(store.tenant_id, module))?
                        .ok_or_else(|| invalid("runtime desired state is incomplete"))?
                        .into_record()
                })
                .collect()
        }))
    }

    fn read_reconcile_state<'a>(
        &'a self,
        instance_id: &'a str,
    ) -> BoxFuture<'a, Result<Vec<ModuleReconcileState>, RepositoryError>> {
        let instance_id = instance_id.to_owned();
        Box::pin(self.run(move |store| {
            bounded(&instance_id, 255, "runtime instance id is out of bounds")?;
            let snapshot = store.db.snapshot();
            ModuleId::ALL
                .into_iter()
                .map(|module| {
                    Ok(ModuleReconcileState {
                        desired: read_snapshot::<DesiredRow>(
                            &snapshot,
                            &desired_key(store.tenant_id, module),
                        )?
                        .ok_or_else(|| invalid("runtime desired state is incomplete"))?
                        .into_record()?,
                        instance: read_snapshot::<InstanceRow>(
                            &snapshot,
                            &instance_key(store.tenant_id, &instance_id, module),
                        )?
                        .map(InstanceRow::into_record)
                        .transpose()?,
                    })
                })
                .collect()
        }))
    }

    fn compare_and_set_desired(
        &self,
        change: DesiredStateChange,
    ) -> BoxFuture<'_, Result<CasOutcome<DesiredStateRecord>, RepositoryError>> {
        self.compare_and_set_desired_guarded(change, Vec::new())
    }

    fn compare_and_set_desired_guarded(
        &self,
        change: DesiredStateChange,
        guards: Vec<DesiredRevisionGuard>,
    ) -> BoxFuture<'_, Result<CasOutcome<DesiredStateRecord>, RepositoryError>> {
        Box::pin(self.run(move |store| {
            let next_row = DesiredRow::from_record(&change.next)?;
            let tx = store.transaction();
            let mut keys: Vec<_> = guards
                .iter()
                .map(|guard| desired_key(store.tenant_id, guard.module_id))
                .collect();
            let target = desired_key(store.tenant_id, change.next.module_id);
            keys.push(target.clone());
            keys.sort_unstable();
            keys.dedup();
            for key in keys {
                tx.get_pinned_for_update(key, true).map_err(map_error)?;
            }
            let current = read_tx::<DesiredRow>(&tx, &target, true)?
                .ok_or_else(|| invalid("runtime desired state is missing"))?
                .into_record()?;
            let mut matches = change.expected_revision == Some(current.revision);
            for guard in guards {
                let row = read_tx::<DesiredRow>(
                    &tx,
                    &desired_key(store.tenant_id, guard.module_id),
                    true,
                )?;
                matches &= row.as_ref().map(|row| row.revision as u64)
                    == guard.expected_revision.map(ModuleRevision::get);
            }
            if !matches {
                return Ok(CasOutcome::Stale {
                    current: Some(current),
                });
            }
            let noop = current.mode == change.next.mode;
            if !noop && current.revision.get().checked_add(1) != Some(change.next.revision.get()) {
                return Err(invalid("runtime desired revision must advance by one"));
            }
            let event = ModuleEventRecord {
                event_id: Uuid::now_v7().to_string(),
                module_id: change.next.module_id,
                event_type: ModuleEventType::DesiredStateChanged,
                revision: if noop {
                    current.revision
                } else {
                    change.next.revision
                },
                instance_id: None,
                actor_id: change.next.actor_id.clone(),
                reason: change.next.reason.clone(),
                before: Some(ModuleEventState::Desired(current.mode.into())),
                after: Some(ModuleEventState::Desired(change.next.mode.into())),
                outcome_code: noop.then(|| "noop".into()),
                occurred_at: change.next.updated_at,
            };
            if !noop {
                put(&tx, &target, &next_row)?;
            }
            append_event(&tx, store.tenant_id, &event)?;
            tx.commit().map_err(map_error)?;
            Ok(CasOutcome::Applied(if noop {
                current
            } else {
                change.next
            }))
        }))
    }

    fn read_instance<'a>(
        &'a self,
        instance_id: &'a str,
        module_id: ModuleId,
    ) -> BoxFuture<'a, Result<Option<InstanceStateRecord>, RepositoryError>> {
        let instance_id = instance_id.to_owned();
        Box::pin(self.run(move |store| {
            read::<InstanceRow>(
                &store.db,
                &instance_key(store.tenant_id, &instance_id, module_id),
            )?
            .map(InstanceRow::into_record)
            .transpose()
        }))
    }

    fn read_all_instances<'a>(
        &'a self,
        instance_id: &'a str,
    ) -> BoxFuture<'a, Result<Vec<InstanceStateRecord>, RepositoryError>> {
        let instance_id = instance_id.to_owned();
        Box::pin(self.run(move |store| {
            let snapshot = store.db.snapshot();
            ModuleId::ALL
                .into_iter()
                .filter_map(|module| {
                    read_snapshot::<InstanceRow>(
                        &snapshot,
                        &instance_key(store.tenant_id, &instance_id, module),
                    )
                    .transpose()
                    .map(|result| result.and_then(InstanceRow::into_record))
                })
                .collect()
        }))
    }

    fn page_events(
        &self,
        offset: i64,
        limit: i64,
    ) -> BoxFuture<'_, Result<ModuleEventPage, RepositoryError>> {
        Box::pin(self.run(move |store| {
            if offset < 0 || !(1..=100).contains(&limit) {
                return Err(invalid("runtime event pagination is out of bounds"));
            }
            let snapshot = store.db.snapshot();
            let prefix = key(EVENT, store.tenant_id, &[]);
            let mut end = prefix.clone();
            end.extend_from_slice(&[0xff; 24]);
            let mut iter = snapshot.raw_iterator();
            iter.seek_for_prev(end);
            let mut events = Vec::with_capacity(limit as usize);
            let mut seen = 0;
            while iter.valid()
                && iter.key().is_some_and(|key| key.starts_with(&prefix))
                && events.len() < limit as usize
            {
                if seen >= offset {
                    events.push(
                        decode::<EventRow>(iter.value().expect("valid iterator"))?.into_record()?,
                    );
                }
                seen += 1;
                iter.prev();
            }
            iter.status().map_err(map_error)?;
            Ok(ModuleEventPage {
                total: read_snapshot(&snapshot, &key(EVENT_COUNT, store.tenant_id, &[]))?
                    .unwrap_or(0),
                events,
            })
        }))
    }

    fn compare_and_set_instance(
        &self,
        mut mutation: InstanceStateMutation,
    ) -> BoxFuture<'_, Result<CasOutcome<InstanceStateRecord>, RepositoryError>> {
        Box::pin(self.run(move |store| {
            let next = &mutation.change.next;
            let event = &mutation.event;
            if !matches!(
                event.event_type,
                ModuleEventType::TransitionStarted
                    | ModuleEventType::TransitionCompleted
                    | ModuleEventType::TransitionFailed
                    | ModuleEventType::DrainStarted
                    | ModuleEventType::DrainCompleted
            ) || event.module_id != next.module_id
                || event.instance_id.as_deref() != Some(&next.instance_id)
                || event.revision != next.transition_revision
                || event.after != Some(ModuleEventState::Actual(next.state))
                || matches!(event.before, Some(ModuleEventState::Desired(_)))
                || mutation
                    .change
                    .expected_revision
                    .is_some_and(|expected| next.transition_revision < expected)
            {
                return Err(invalid(
                    "runtime event does not match its revision-bound mutation",
                ));
            }
            let row = InstanceRow::from_record(next)?;
            let tx = store.transaction();
            let desired =
                read_tx::<DesiredRow>(&tx, &desired_key(store.tenant_id, next.module_id), false)?;
            let record_key = instance_key(store.tenant_id, &next.instance_id, next.module_id);
            let current = read_tx::<InstanceRow>(&tx, &record_key, true)?
                .map(InstanceRow::into_record)
                .transpose()?;
            let matches = desired
                .is_some_and(|desired| desired.revision as u64 == next.transition_revision.get())
                && current.as_ref().map(|row| row.transition_revision)
                    == mutation.change.expected_revision;
            if matches {
                put(&tx, &record_key, &row)?;
            } else {
                mutation.event.event_type = ModuleEventType::StaleTransitionDiscarded;
            }
            append_event(&tx, store.tenant_id, &mutation.event)?;
            tx.commit().map_err(map_error)?;
            Ok(if matches {
                CasOutcome::Applied(mutation.change.next)
            } else {
                CasOutcome::Stale { current }
            })
        }))
    }

    fn record_instance_observation(
        &self,
        observation: InstanceStateObservation,
    ) -> BoxFuture<'_, Result<(), RepositoryError>> {
        Box::pin(self.run(move |store| {
            let event = observation.event;
            if event.event_type != ModuleEventType::StaleTransitionDiscarded
                || event.instance_id.as_ref().is_none_or(String::is_empty)
                || event.before != event.after
                || matches!(event.before, Some(ModuleEventState::Desired(_)))
            {
                return Err(invalid(
                    "runtime observation must describe unchanged actual state and discarded work",
                ));
            }
            let tx = store.transaction();
            append_event(&tx, store.tenant_id, &event)?;
            tx.commit().map_err(map_error)
        }))
    }

    fn validate_revision(
        &self,
        module_id: ModuleId,
        expected: ModuleRevision,
    ) -> BoxFuture<'_, Result<bool, RepositoryError>> {
        Box::pin(self.run(move |store| {
            Ok(
                read::<DesiredRow>(&store.db, &desired_key(store.tenant_id, module_id))?
                    .is_some_and(|row| row.revision as u64 == expected.get()),
            )
        }))
    }
}

#[cfg(test)]
#[path = "../../tests/unit/runtime.rs"]
mod tests;
