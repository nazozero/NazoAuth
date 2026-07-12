use chrono::{DateTime, Utc};
use diesel::ExpressionMethods;
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use nazo_identity::ports::RepositoryError;
use nazo_runtime_modules::{ModuleEventRecord, ModuleEventState, ModuleEventType};
use uuid::Uuid;

use crate::schema::runtime_module_state_events;

pub(super) async fn append_runtime_event(
    connection: &mut AsyncPgConnection,
    event: &ModuleEventRecord,
) -> Result<(), RepositoryError> {
    let event_id = Uuid::parse_str(&event.event_id).map_err(|error| {
        RepositoryError::Unexpected(format!("invalid runtime event id: {error}"))
    })?;
    let actor_id = event
        .actor_id
        .as_deref()
        .map(Uuid::parse_str)
        .transpose()
        .map_err(|error| {
            RepositoryError::Unexpected(format!("invalid runtime actor id: {error}"))
        })?;
    diesel::insert_into(runtime_module_state_events::table)
        .values((
            runtime_module_state_events::event_id.eq(event_id),
            runtime_module_state_events::module_id.eq(module_id(event.module_id)),
            runtime_module_state_events::event_type.eq(event_type(event.event_type)),
            runtime_module_state_events::revision.eq(revision(event.revision)?),
            runtime_module_state_events::instance_id.eq(event.instance_id.as_deref()),
            runtime_module_state_events::actor_id.eq(actor_id),
            runtime_module_state_events::reason.eq(event.reason.as_deref()),
            runtime_module_state_events::before_state.eq(event.before.map(event_state)),
            runtime_module_state_events::after_state.eq(event.after.map(event_state)),
            runtime_module_state_events::outcome_code.eq(event.outcome_code.as_deref()),
            runtime_module_state_events::occurred_at.eq(DateTime::<Utc>::from(event.occurred_at)),
        ))
        .execute(connection)
        .await
        .map_err(map_error)?;
    Ok(())
}

pub(super) const fn module_id(value: nazo_runtime_modules::ModuleId) -> &'static str {
    use nazo_runtime_modules::ModuleId;
    match value {
        ModuleId::DeviceAuthorization => "device_authorization",
        ModuleId::TokenExchange => "token_exchange",
        ModuleId::JwtBearerGrant => "jwt_bearer_grant",
        ModuleId::Ciba => "ciba",
        ModuleId::DynamicClientRegistration => "dynamic_client_registration",
        ModuleId::RequestObjects => "request_objects",
        ModuleId::Jarm => "jarm",
        ModuleId::AuthorizationDetails => "authorization_details",
        ModuleId::HttpMessageSignatures => "http_message_signatures",
        ModuleId::Scim => "scim",
        ModuleId::NativeSso => "native_sso",
        ModuleId::FrontchannelLogout => "frontchannel_logout",
        ModuleId::SessionManagement => "session_management",
    }
}

pub(super) const fn desired_mode(value: nazo_runtime_modules::DesiredMode) -> &'static str {
    use nazo_runtime_modules::DesiredMode;
    match value {
        DesiredMode::Inherit => "inherit",
        DesiredMode::Enabled => "enabled",
        DesiredMode::Disabled => "disabled",
    }
}

pub(super) const fn actual_state(value: nazo_runtime_modules::ModuleState) -> &'static str {
    use nazo_runtime_modules::ModuleState;
    match value {
        ModuleState::Disabled => "disabled",
        ModuleState::Starting => "starting",
        ModuleState::Enabled => "enabled",
        ModuleState::Draining => "draining",
        ModuleState::Failed => "failed",
    }
}

const fn event_type(value: ModuleEventType) -> &'static str {
    match value {
        ModuleEventType::DesiredStateChanged => "desired_state_changed",
        ModuleEventType::TransitionStarted => "transition_started",
        ModuleEventType::TransitionCompleted => "transition_completed",
        ModuleEventType::TransitionFailed => "transition_failed",
        ModuleEventType::DrainStarted => "drain_started",
        ModuleEventType::DrainCompleted => "drain_completed",
        ModuleEventType::StaleTransitionDiscarded => "stale_transition_discarded",
    }
}

const fn event_state(value: ModuleEventState) -> &'static str {
    match value {
        ModuleEventState::Desired(mode) => desired_mode(mode),
        ModuleEventState::Actual(state) => actual_state(state),
    }
}

pub(super) fn revision(
    value: nazo_runtime_modules::ModuleRevision,
) -> Result<i64, RepositoryError> {
    i64::try_from(value.get()).map_err(|_| {
        RepositoryError::Unexpected("runtime revision exceeds PostgreSQL BIGINT".to_owned())
    })
}

pub(super) fn map_error(error: diesel::result::Error) -> RepositoryError {
    RepositoryError::Unexpected(error.to_string())
}
