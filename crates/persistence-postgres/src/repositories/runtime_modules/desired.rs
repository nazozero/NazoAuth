use chrono::{DateTime, Utc};
use diesel::{
    BoolExpressionMethods, ExpressionMethods, JoinOnDsl, OptionalExtension, QueryDsl,
    SelectableHelper,
};
use diesel_async::{AsyncConnection, RunQueryDsl};
use nazo_identity::ports::RepositoryError;
use nazo_runtime_modules::{
    CasOutcome, DesiredMode, DesiredRevisionGuard, DesiredStateChange, DesiredStateRecord,
    HistoricalDesiredMode, ModuleId, ModuleReconcileState, ModuleRevision,
};

use crate::{
    repositories::audit::{append_runtime_event, desired_mode, map_error, module_id, revision},
    rows::runtime::{DesiredStateRow, InstanceStateRow},
    schema::{runtime_module_desired_states, runtime_module_instance_states},
};

use super::{
    RuntimeModuleRepository, events,
    mapping::{self, parse_optional_uuid},
    transaction::RuntimeTransactionError,
};

pub(super) async fn read_desired(
    repository: &RuntimeModuleRepository,
    requested_module_id: ModuleId,
) -> Result<Option<DesiredStateRecord>, RepositoryError> {
    let mut connection = repository.connection().await?;
    runtime_module_desired_states::table
        .find((repository.tenant_id(), module_id(requested_module_id)))
        .select(DesiredStateRow::as_select())
        .first::<DesiredStateRow>(&mut connection)
        .await
        .optional()
        .map_err(map_error)?
        .map(mapping::desired_from_row)
        .transpose()
}

pub(super) async fn read_all_desired(
    repository: &RuntimeModuleRepository,
) -> Result<Vec<DesiredStateRecord>, RepositoryError> {
    let mut connection = repository.connection().await?;
    runtime_module_desired_states::table
        .filter(runtime_module_desired_states::tenant_id.eq(repository.tenant_id()))
        .select(DesiredStateRow::as_select())
        .load::<DesiredStateRow>(&mut connection)
        .await
        .map_err(map_error)?
        .into_iter()
        .map(mapping::desired_from_row)
        .collect()
}

pub(super) async fn read_reconcile_state(
    repository: &RuntimeModuleRepository,
    instance_id: &str,
) -> Result<Vec<ModuleReconcileState>, RepositoryError> {
    let mut connection = repository.connection().await?;
    runtime_module_desired_states::table
        .left_join(
            runtime_module_instance_states::table.on(runtime_module_instance_states::tenant_id
                .eq(runtime_module_desired_states::tenant_id)
                .and(
                    runtime_module_instance_states::module_id
                        .eq(runtime_module_desired_states::module_id),
                )
                .and(runtime_module_instance_states::instance_id.eq(instance_id))),
        )
        .filter(runtime_module_desired_states::tenant_id.eq(repository.tenant_id()))
        .select((
            DesiredStateRow::as_select(),
            Option::<InstanceStateRow>::as_select(),
        ))
        .load::<(DesiredStateRow, Option<InstanceStateRow>)>(&mut connection)
        .await
        .map_err(map_error)?
        .into_iter()
        .map(|(desired, instance)| {
            Ok(ModuleReconcileState {
                desired: mapping::desired_from_row(desired)?,
                instance: instance.map(mapping::instance_from_row).transpose()?,
            })
        })
        .collect()
}

pub(super) async fn compare_and_set_desired(
    repository: &RuntimeModuleRepository,
    change: DesiredStateChange,
    required_revisions: Vec<DesiredRevisionGuard>,
) -> Result<CasOutcome<DesiredStateRecord>, RepositoryError> {
    let expected_next = next_desired_revision(change.expected_revision)?;
    let connection = repository.connection().await?;
    {
        let mut guard = crate::pool::DiscardOnDrop(Some(connection));
        let result = guard
            .connection()
            .transaction::<CasOutcome<DesiredStateRecord>, RuntimeTransactionError, _>(
                async |connection| {
                    // Desired rows are created with the tenant. Lock the target and
                    // its policy guards in one database order before inspecting them.
                    let rows = runtime_module_desired_states::table
                        .filter(runtime_module_desired_states::tenant_id.eq(repository.tenant_id()))
                        .filter(
                            runtime_module_desired_states::module_id.eq_any(
                                std::iter::once(module_id(change.next.module_id)).chain(
                                    required_revisions
                                        .iter()
                                        .map(|guard| module_id(guard.module_id)),
                                ),
                            ),
                        )
                        .order(runtime_module_desired_states::module_id.asc())
                        .select(DesiredStateRow::as_select())
                        .for_update()
                        .load::<DesiredStateRow>(connection)
                        .await?;
                    let mut guards_match = true;
                    for guard in &required_revisions {
                        let guarded_revision = rows
                            .iter()
                            .find(|row| row.module_id == module_id(guard.module_id))
                            .map(|row| mapping::parse_revision(row.revision))
                            .transpose()
                            .map_err(RuntimeTransactionError::Repository)?;
                        if guarded_revision != guard.expected_revision {
                            guards_match = false;
                            break;
                        }
                    }
                    let current = rows
                        .into_iter()
                        .find(|row| row.module_id == module_id(change.next.module_id))
                        .ok_or_else(|| {
                            RuntimeTransactionError::Repository(RepositoryError::Consistency(
                                "runtime desired state is missing".to_owned(),
                            ))
                        })?;
                    let current = mapping::desired_from_row(current)
                        .map_err(RuntimeTransactionError::Repository)?;
                    if Some(current.revision) != change.expected_revision || !guards_match {
                        return Ok(CasOutcome::Stale {
                            current: Some(current),
                        });
                    }

                    if current.mode == change.next.mode {
                        let event = events::desired_event(
                            &change.next,
                            match current.mode {
                                DesiredMode::Enabled => HistoricalDesiredMode::Enabled,
                                DesiredMode::Disabled => HistoricalDesiredMode::Disabled,
                            },
                            current.revision,
                            Some("noop".to_owned()),
                        );
                        append_runtime_event(connection, repository.tenant_id(), &event)
                            .await
                            .map_err(RuntimeTransactionError::Repository)?;
                        return Ok(CasOutcome::Applied(current));
                    }

                    if change.next.revision.get() != expected_next {
                        return Err(RuntimeTransactionError::Repository(
                            RepositoryError::Consistency(format!(
                                "desired revision must advance to {expected_next}"
                            )),
                        ));
                    }
                    let actor_id = parse_optional_uuid(change.next.actor_id.as_deref(), "actor")?;
                    let updated_at = DateTime::<Utc>::from(change.next.updated_at);
                    diesel::update(
                        runtime_module_desired_states::table
                            .find((repository.tenant_id(), module_id(change.next.module_id))),
                    )
                    .set((
                        runtime_module_desired_states::desired_mode
                            .eq(desired_mode(change.next.mode)),
                        runtime_module_desired_states::revision.eq(revision(change.next.revision)
                            .map_err(RuntimeTransactionError::Repository)?),
                        runtime_module_desired_states::actor_id.eq(actor_id),
                        runtime_module_desired_states::reason.eq(change.next.reason.as_deref()),
                        runtime_module_desired_states::updated_at.eq(updated_at),
                    ))
                    .execute(connection)
                    .await?;
                    let event = events::desired_event(
                        &change.next,
                        match current.mode {
                            DesiredMode::Enabled => HistoricalDesiredMode::Enabled,
                            DesiredMode::Disabled => HistoricalDesiredMode::Disabled,
                        },
                        change.next.revision,
                        None,
                    );
                    append_runtime_event(connection, repository.tenant_id(), &event)
                        .await
                        .map_err(RuntimeTransactionError::Repository)?;
                    Ok(CasOutcome::Applied(change.next))
                },
            )
            .await;
        if result.is_ok() {
            guard.return_to_pool();
        }
        result
    }
    .map_err(RuntimeTransactionError::into_repository)
}

pub(super) async fn validate_revision(
    repository: &RuntimeModuleRepository,
    requested_module_id: ModuleId,
    expected: ModuleRevision,
) -> Result<bool, RepositoryError> {
    let mut connection = repository.connection().await?;
    let current = runtime_module_desired_states::table
        .find((repository.tenant_id(), module_id(requested_module_id)))
        .select(runtime_module_desired_states::revision)
        .first::<i64>(&mut connection)
        .await
        .optional()
        .map_err(map_error)?
        .map(mapping::parse_revision)
        .transpose()?;
    Ok(current == Some(expected))
}

pub(super) fn next_desired_revision(
    expected_revision: Option<ModuleRevision>,
) -> Result<u64, RepositoryError> {
    match expected_revision {
        None => Ok(1),
        Some(revision) => revision.get().checked_add(1).ok_or_else(|| {
            RepositoryError::Consistency("desired revision space is exhausted".to_owned())
        }),
    }
}
