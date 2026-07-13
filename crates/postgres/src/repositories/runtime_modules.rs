use chrono::{DateTime, Utc};
use diesel::{ExpressionMethods, OptionalExtension, QueryDsl, SelectableHelper};
use diesel_async::{AsyncConnection, AsyncPgConnection, RunQueryDsl};
use nazo_identity::ports::RepositoryError;
use nazo_runtime_modules::{
    CasOutcome, DesiredMode, DesiredStateChange, DesiredStateRecord, InstanceStateMutation,
    InstanceStateRecord, ModuleEventRecord, ModuleEventState, ModuleEventType, ModuleId,
    ModuleRevision, ModuleState, ModuleStateRepository,
};
use uuid::Uuid;

use crate::{
    DbPool,
    repositories::audit::{
        actual_state, append_runtime_event, desired_mode, map_error, module_id, revision,
    },
    rows::runtime::{DesiredStateRow, InstanceStateRow},
    schema::{runtime_module_desired_states, runtime_module_instance_states},
};

#[derive(Clone)]
pub struct RuntimeModuleRepository {
    pool: DbPool,
}

impl RuntimeModuleRepository {
    #[must_use]
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }

    async fn connection(&self) -> Result<crate::DbConnection, RepositoryError> {
        self.pool
            .get()
            .await
            .map_err(|_| RepositoryError::Unavailable)
    }
}

impl ModuleStateRepository for RuntimeModuleRepository {
    type Error = RepositoryError;

    async fn read_desired(
        &self,
        requested_module_id: ModuleId,
    ) -> Result<Option<DesiredStateRecord>, Self::Error> {
        let mut connection = self.connection().await?;
        runtime_module_desired_states::table
            .find(module_id(requested_module_id))
            .select(DesiredStateRow::as_select())
            .first::<DesiredStateRow>(&mut connection)
            .await
            .optional()
            .map_err(map_error)?
            .map(desired_from_row)
            .transpose()
    }

    async fn compare_and_set_desired(
        &self,
        change: DesiredStateChange,
    ) -> Result<CasOutcome<DesiredStateRecord>, Self::Error> {
        let mut connection = self.connection().await?;
        connection
            .transaction::<CasOutcome<DesiredStateRecord>, RuntimeTransactionError, _>(
                async |connection| {
                    lock_key(connection, module_id(change.next.module_id)).await?;
                    let current = runtime_module_desired_states::table
                        .find(module_id(change.next.module_id))
                        .select(DesiredStateRow::as_select())
                        .for_update()
                        .first::<DesiredStateRow>(connection)
                        .await
                        .optional()?
                        .map(desired_from_row)
                        .transpose()
                        .map_err(RuntimeTransactionError::Repository)?;
                    if current.as_ref().map(|record| record.revision) != change.expected_revision {
                        return Ok(CasOutcome::Stale { current });
                    }

                    if let Some(current) = current.as_ref()
                        && current.mode == change.next.mode
                    {
                        let event = desired_event(
                            &change.next,
                            current.mode,
                            current.revision,
                            Some("noop".to_owned()),
                        );
                        append_runtime_event(connection, &event)
                            .await
                            .map_err(RuntimeTransactionError::Repository)?;
                        return Ok(CasOutcome::Applied(current.clone()));
                    }

                    let expected_next = change
                        .expected_revision
                        .map_or(1, |value| value.get().saturating_add(1));
                    if change.next.revision.get() != expected_next {
                        return Err(RuntimeTransactionError::Repository(
                            RepositoryError::Consistency(format!(
                                "desired revision must advance to {expected_next}"
                            )),
                        ));
                    }
                    let actor_id = parse_optional_uuid(change.next.actor_id.as_deref(), "actor")?;
                    let updated_at = DateTime::<Utc>::from(change.next.updated_at);
                    if current.is_some() {
                        diesel::update(
                            runtime_module_desired_states::table
                                .find(module_id(change.next.module_id)),
                        )
                        .set((
                            runtime_module_desired_states::desired_mode
                                .eq(desired_mode(change.next.mode)),
                            runtime_module_desired_states::revision
                                .eq(revision(change.next.revision)
                                    .map_err(RuntimeTransactionError::Repository)?),
                            runtime_module_desired_states::actor_id.eq(actor_id),
                            runtime_module_desired_states::reason.eq(change.next.reason.as_deref()),
                            runtime_module_desired_states::updated_at.eq(updated_at),
                        ))
                        .execute(connection)
                        .await?;
                    } else {
                        diesel::insert_into(runtime_module_desired_states::table)
                            .values((
                                runtime_module_desired_states::module_id
                                    .eq(module_id(change.next.module_id)),
                                runtime_module_desired_states::desired_mode
                                    .eq(desired_mode(change.next.mode)),
                                runtime_module_desired_states::revision
                                    .eq(revision(change.next.revision)
                                        .map_err(RuntimeTransactionError::Repository)?),
                                runtime_module_desired_states::actor_id.eq(actor_id),
                                runtime_module_desired_states::reason
                                    .eq(change.next.reason.as_deref()),
                                runtime_module_desired_states::updated_at.eq(updated_at),
                            ))
                            .execute(connection)
                            .await?;
                    }
                    let event = desired_event(
                        &change.next,
                        current
                            .as_ref()
                            .map_or(DesiredMode::Inherit, |record| record.mode),
                        change.next.revision,
                        None,
                    );
                    append_runtime_event(connection, &event)
                        .await
                        .map_err(RuntimeTransactionError::Repository)?;
                    Ok(CasOutcome::Applied(change.next))
                },
            )
            .await
            .map_err(RuntimeTransactionError::into_repository)
    }

    async fn read_instance(
        &self,
        requested_instance_id: &str,
        requested_module_id: ModuleId,
    ) -> Result<Option<InstanceStateRecord>, Self::Error> {
        let mut connection = self.connection().await?;
        runtime_module_instance_states::table
            .find((requested_instance_id, module_id(requested_module_id)))
            .select(InstanceStateRow::as_select())
            .first::<InstanceStateRow>(&mut connection)
            .await
            .optional()
            .map_err(map_error)?
            .map(instance_from_row)
            .transpose()
    }

    async fn compare_and_set_instance(
        &self,
        required_desired_revision: ModuleRevision,
        mutation: InstanceStateMutation,
    ) -> Result<CasOutcome<InstanceStateRecord>, Self::Error> {
        validate_instance_mutation(required_desired_revision, &mutation)?;
        let mut connection = self.connection().await?;
        connection
            .transaction::<CasOutcome<InstanceStateRecord>, RuntimeTransactionError, _>(
                async |connection| {
                    let change = mutation.change;
                    let key = format!(
                        "{}:{}",
                        change.next.instance_id,
                        module_id(change.next.module_id)
                    );
                    lock_key(connection, &key).await?;
                    let durable_desired_revision = runtime_module_desired_states::table
                        .find(module_id(change.next.module_id))
                        .select(runtime_module_desired_states::revision)
                        .for_update()
                        .first::<i64>(connection)
                        .await
                        .optional()?;
                    if durable_desired_revision
                        != Some(
                            revision(required_desired_revision)
                                .map_err(RuntimeTransactionError::Repository)?,
                        )
                    {
                        let current = load_instance(connection, &change.next).await?;
                        append_runtime_event(connection, &mutation.stale_event)
                            .await
                            .map_err(RuntimeTransactionError::Repository)?;
                        return Ok(CasOutcome::Stale { current });
                    }
                    let current = runtime_module_instance_states::table
                        .find((
                            change.next.instance_id.as_str(),
                            module_id(change.next.module_id),
                        ))
                        .select(InstanceStateRow::as_select())
                        .for_update()
                        .first::<InstanceStateRow>(connection)
                        .await
                        .optional()?
                        .map(instance_from_row)
                        .transpose()
                        .map_err(RuntimeTransactionError::Repository)?;
                    if current.as_ref().map(|record| record.transition_revision)
                        != change.expected_revision
                    {
                        append_runtime_event(connection, &mutation.stale_event)
                            .await
                            .map_err(RuntimeTransactionError::Repository)?;
                        return Ok(CasOutcome::Stale { current });
                    }
                    if change
                        .expected_revision
                        .is_some_and(|expected| change.next.transition_revision < expected)
                    {
                        return Err(RuntimeTransactionError::Repository(
                            RepositoryError::Consistency(
                                "instance transition revision cannot move backwards".to_owned(),
                            ),
                        ));
                    }
                    let transition_revision = revision(change.next.transition_revision)
                        .map_err(RuntimeTransactionError::Repository)?;
                    let applied_revision = change
                        .next
                        .applied_revision
                        .map(revision)
                        .transpose()
                        .map_err(RuntimeTransactionError::Repository)?;
                    let updated_at = DateTime::<Utc>::from(change.next.updated_at);
                    let drain_deadline = change.next.drain_deadline.map(DateTime::<Utc>::from);
                    if let Some(expected) = change.expected_revision {
                        let updated = diesel::update(
                            runtime_module_instance_states::table
                                .find((
                                    change.next.instance_id.as_str(),
                                    module_id(change.next.module_id),
                                ))
                                .filter(
                                    runtime_module_instance_states::transition_revision
                                        .eq(revision(expected)
                                            .map_err(RuntimeTransactionError::Repository)?),
                                ),
                        )
                        .set((
                            runtime_module_instance_states::actual_state
                                .eq(actual_state(change.next.state)),
                            runtime_module_instance_states::transition_revision
                                .eq(transition_revision),
                            runtime_module_instance_states::applied_revision.eq(applied_revision),
                            runtime_module_instance_states::drain_deadline.eq(drain_deadline),
                            runtime_module_instance_states::error_code
                                .eq(change.next.error_code.as_deref()),
                            runtime_module_instance_states::updated_at.eq(updated_at),
                        ))
                        .execute(connection)
                        .await?;
                        if updated != 1 {
                            let current = load_instance(connection, &change.next).await?;
                            append_runtime_event(connection, &mutation.stale_event)
                                .await
                                .map_err(RuntimeTransactionError::Repository)?;
                            return Ok(CasOutcome::Stale { current });
                        }
                    } else {
                        diesel::insert_into(runtime_module_instance_states::table)
                            .values((
                                runtime_module_instance_states::instance_id
                                    .eq(change.next.instance_id.as_str()),
                                runtime_module_instance_states::module_id
                                    .eq(module_id(change.next.module_id)),
                                runtime_module_instance_states::actual_state
                                    .eq(actual_state(change.next.state)),
                                runtime_module_instance_states::transition_revision
                                    .eq(transition_revision),
                                runtime_module_instance_states::applied_revision
                                    .eq(applied_revision),
                                runtime_module_instance_states::drain_deadline.eq(drain_deadline),
                                runtime_module_instance_states::error_code
                                    .eq(change.next.error_code.as_deref()),
                                runtime_module_instance_states::updated_at.eq(updated_at),
                            ))
                            .execute(connection)
                            .await?;
                    }
                    append_runtime_event(connection, &mutation.applied_event)
                        .await
                        .map_err(RuntimeTransactionError::Repository)?;
                    Ok(CasOutcome::Applied(change.next))
                },
            )
            .await
            .map_err(RuntimeTransactionError::into_repository)
    }

    async fn validate_revision(
        &self,
        requested_module_id: ModuleId,
        expected: ModuleRevision,
    ) -> Result<bool, Self::Error> {
        Ok(self
            .read_desired(requested_module_id)
            .await?
            .is_some_and(|record| record.revision == expected))
    }
}

fn validate_instance_mutation(
    required_desired_revision: ModuleRevision,
    mutation: &InstanceStateMutation,
) -> Result<(), RepositoryError> {
    let next = &mutation.change.next;
    if next.transition_revision != required_desired_revision {
        return Err(RepositoryError::Consistency(
            "instance transition must be bound to the required desired revision".to_owned(),
        ));
    }
    let applied = &mutation.applied_event;
    let stale = &mutation.stale_event;
    if !matches!(
        applied.event_type,
        ModuleEventType::TransitionStarted
            | ModuleEventType::TransitionCompleted
            | ModuleEventType::TransitionFailed
            | ModuleEventType::DrainStarted
            | ModuleEventType::DrainCompleted
    ) {
        return Err(RepositoryError::Consistency(
            "actual-state mutation requires a transition or drain event".to_owned(),
        ));
    }
    if stale.event_type != ModuleEventType::StaleTransitionDiscarded {
        return Err(RepositoryError::Consistency(
            "actual-state mutation requires a stale-transition event".to_owned(),
        ));
    }
    for event in [applied, stale] {
        if event.module_id != next.module_id
            || event.instance_id.as_deref() != Some(next.instance_id.as_str())
            || event.revision != next.transition_revision
        {
            return Err(RepositoryError::Consistency(
                "actual-state event does not match its revision-bound mutation".to_owned(),
            ));
        }
    }
    if applied.after != Some(ModuleEventState::Actual(next.state)) {
        return Err(RepositoryError::Consistency(
            "applied actual-state event must describe the committed state".to_owned(),
        ));
    }
    Ok(())
}

async fn load_instance(
    connection: &mut AsyncPgConnection,
    next: &InstanceStateRecord,
) -> Result<Option<InstanceStateRecord>, RuntimeTransactionError> {
    runtime_module_instance_states::table
        .find((next.instance_id.as_str(), module_id(next.module_id)))
        .select(InstanceStateRow::as_select())
        .first::<InstanceStateRow>(connection)
        .await
        .optional()?
        .map(instance_from_row)
        .transpose()
        .map_err(RuntimeTransactionError::Repository)
}

async fn lock_key(
    connection: &mut AsyncPgConnection,
    key: &str,
) -> Result<(), diesel::result::Error> {
    diesel::sql_query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind::<diesel::sql_types::Text, _>(key)
        .execute(connection)
        .await?;
    Ok(())
}

fn desired_event(
    next: &DesiredStateRecord,
    before: DesiredMode,
    revision: ModuleRevision,
    outcome_code: Option<String>,
) -> ModuleEventRecord {
    ModuleEventRecord {
        event_id: Uuid::now_v7().to_string(),
        module_id: next.module_id,
        event_type: ModuleEventType::DesiredStateChanged,
        revision,
        instance_id: None,
        actor_id: next.actor_id.clone(),
        reason: next.reason.clone(),
        before: Some(ModuleEventState::Desired(before)),
        after: Some(ModuleEventState::Desired(next.mode)),
        outcome_code,
        occurred_at: next.updated_at,
    }
}

fn desired_from_row(row: DesiredStateRow) -> Result<DesiredStateRecord, RepositoryError> {
    Ok(DesiredStateRecord {
        module_id: parse_module_id(&row.module_id)?,
        mode: parse_desired_mode(&row.desired_mode)?,
        revision: parse_revision(row.revision)?,
        actor_id: row.actor_id.map(|value| value.to_string()),
        reason: row.reason,
        updated_at: row.updated_at.into(),
    })
}

fn instance_from_row(row: InstanceStateRow) -> Result<InstanceStateRecord, RepositoryError> {
    Ok(InstanceStateRecord {
        instance_id: row.instance_id,
        module_id: parse_module_id(&row.module_id)?,
        state: parse_actual_state(&row.actual_state)?,
        transition_revision: parse_revision(row.transition_revision)?,
        applied_revision: row.applied_revision.map(parse_revision).transpose()?,
        drain_deadline: row.drain_deadline.map(Into::into),
        error_code: row.error_code,
        updated_at: row.updated_at.into(),
    })
}

fn parse_optional_uuid(
    value: Option<&str>,
    field: &str,
) -> Result<Option<Uuid>, RuntimeTransactionError> {
    value.map(Uuid::parse_str).transpose().map_err(|error| {
        RuntimeTransactionError::Repository(RepositoryError::Consistency(format!(
            "invalid runtime {field} id: {error}"
        )))
    })
}

fn parse_revision(value: i64) -> Result<ModuleRevision, RepositoryError> {
    u64::try_from(value)
        .map(ModuleRevision::new)
        .map_err(|_| RepositoryError::Consistency("negative runtime revision".to_owned()))
}

fn parse_desired_mode(value: &str) -> Result<DesiredMode, RepositoryError> {
    match value {
        "inherit" => Ok(DesiredMode::Inherit),
        "enabled" => Ok(DesiredMode::Enabled),
        "disabled" => Ok(DesiredMode::Disabled),
        _ => Err(RepositoryError::Consistency(format!(
            "unknown runtime desired mode: {value}"
        ))),
    }
}

fn parse_actual_state(value: &str) -> Result<ModuleState, RepositoryError> {
    match value {
        "disabled" => Ok(ModuleState::Disabled),
        "starting" => Ok(ModuleState::Starting),
        "enabled" => Ok(ModuleState::Enabled),
        "draining" => Ok(ModuleState::Draining),
        "failed" => Ok(ModuleState::Failed),
        _ => Err(RepositoryError::Consistency(format!(
            "unknown runtime actual state: {value}"
        ))),
    }
}

fn parse_module_id(value: &str) -> Result<ModuleId, RepositoryError> {
    match value {
        "device_authorization" => Ok(ModuleId::DeviceAuthorization),
        "token_exchange" => Ok(ModuleId::TokenExchange),
        "jwt_bearer_grant" => Ok(ModuleId::JwtBearerGrant),
        "ciba" => Ok(ModuleId::Ciba),
        "dynamic_client_registration" => Ok(ModuleId::DynamicClientRegistration),
        "request_objects" => Ok(ModuleId::RequestObjects),
        "jarm" => Ok(ModuleId::Jarm),
        "authorization_details" => Ok(ModuleId::AuthorizationDetails),
        "http_message_signatures" => Ok(ModuleId::HttpMessageSignatures),
        "scim" => Ok(ModuleId::Scim),
        "native_sso" => Ok(ModuleId::NativeSso),
        "frontchannel_logout" => Ok(ModuleId::FrontchannelLogout),
        "session_management" => Ok(ModuleId::SessionManagement),
        _ => Err(RepositoryError::Consistency(format!(
            "unknown runtime module id: {value}"
        ))),
    }
}

#[derive(Debug)]
enum RuntimeTransactionError {
    Diesel(diesel::result::Error),
    Repository(RepositoryError),
}

impl RuntimeTransactionError {
    fn into_repository(self) -> RepositoryError {
        match self {
            Self::Diesel(error) => map_error(error),
            Self::Repository(error) => error,
        }
    }
}

impl From<diesel::result::Error> for RuntimeTransactionError {
    fn from(error: diesel::result::Error) -> Self {
        Self::Diesel(error)
    }
}
