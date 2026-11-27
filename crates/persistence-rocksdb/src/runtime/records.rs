use std::time::Duration;

use nazo_identity::ports::RepositoryError;
use nazo_runtime_modules::{
    DesiredMode, DesiredStateRecord, HistoricalDesiredMode, InstanceStateRecord, ModuleEventRecord,
    ModuleEventState, ModuleEventType, ModuleId, ModuleRevision, ModuleState,
};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

pub(super) const MAX_EXACT_INTEGER: i64 = i64::MAX;

pub(super) fn invalid(message: &str) -> RepositoryError {
    RepositoryError::Consistency(message.to_owned())
}

pub(super) fn revision(value: ModuleRevision) -> Result<i64, RepositoryError> {
    i64::try_from(value.get())
        .ok()
        .filter(|value| (0..=MAX_EXACT_INTEGER).contains(value))
        .ok_or_else(|| invalid("runtime revision exceeds the database range"))
}

pub(super) fn time(value: SystemTime) -> Result<i64, RepositoryError> {
    let value = match value.duration_since(UNIX_EPOCH) {
        Ok(duration) => i64::try_from(duration.as_micros()).ok(),
        Err(error) => i64::try_from(error.duration().as_micros())
            .ok()
            .and_then(i64::checked_neg),
    };
    value
        .filter(|value| (-MAX_EXACT_INTEGER..=MAX_EXACT_INTEGER).contains(value))
        .ok_or_else(|| invalid("runtime timestamp exceeds the database range"))
}

fn stored_time(value: i64) -> Result<SystemTime, RepositoryError> {
    if !(-MAX_EXACT_INTEGER..=MAX_EXACT_INTEGER).contains(&value) {
        return Err(invalid("runtime timestamp is invalid"));
    }
    let duration = Duration::from_micros(value.unsigned_abs());
    if value >= 0 {
        UNIX_EPOCH.checked_add(duration)
    } else {
        UNIX_EPOCH.checked_sub(duration)
    }
    .ok_or_else(|| invalid("runtime timestamp is invalid"))
}

fn stored_revision(value: i64) -> Result<ModuleRevision, RepositoryError> {
    if !(0..=MAX_EXACT_INTEGER).contains(&value) {
        return Err(invalid("runtime revision is invalid"));
    }
    Ok(ModuleRevision::new(value as u64))
}

fn optional_id(value: Option<&str>) -> Result<Option<String>, RepositoryError> {
    value
        .map(|value| {
            uuid::Uuid::parse_str(value)
                .map(|value| value.to_string())
                .map_err(|_| invalid("runtime actor id is invalid"))
        })
        .transpose()
}

pub(super) fn bounded(value: &str, limit: usize, label: &str) -> Result<(), RepositoryError> {
    let length = value.chars().count();
    if value.trim().is_empty() || length > limit {
        return Err(invalid(label));
    }
    Ok(())
}

fn optional_text(value: Option<&str>, limit: usize) -> Result<(), RepositoryError> {
    if let Some(value) = value {
        bounded(value, limit, "runtime event text is out of bounds")?;
    }
    Ok(())
}

#[derive(Clone, Deserialize, Serialize)]
pub(super) struct DesiredRow {
    pub module_id: ModuleId,
    pub mode: DesiredMode,
    pub revision: i64,
    pub actor_id: Option<String>,
    pub reason: Option<String>,
    pub updated_at: i64,
}

impl DesiredRow {
    pub fn from_record(value: &DesiredStateRecord) -> Result<Self, RepositoryError> {
        optional_text(value.reason.as_deref(), 500)?;
        Ok(Self {
            module_id: value.module_id,
            mode: value.mode,
            revision: revision(value.revision)?,
            actor_id: optional_id(value.actor_id.as_deref())?,
            reason: value.reason.clone(),
            updated_at: time(value.updated_at)?,
        })
    }

    pub fn into_record(self) -> Result<DesiredStateRecord, RepositoryError> {
        if self.revision == 0 {
            return Err(invalid("runtime desired revision must be positive"));
        }
        optional_text(self.reason.as_deref(), 500)?;
        Ok(DesiredStateRecord {
            module_id: self.module_id,
            mode: self.mode,
            revision: stored_revision(self.revision)?,
            actor_id: optional_id(self.actor_id.as_deref())?,
            reason: self.reason,
            updated_at: stored_time(self.updated_at)?,
        })
    }
}

#[derive(Clone, Deserialize, Serialize)]
pub(super) struct InstanceRow {
    pub instance_id: String,
    pub module_id: ModuleId,
    pub state: ModuleState,
    pub transition_revision: i64,
    pub applied_revision: Option<i64>,
    pub drain_deadline: Option<i64>,
    pub error_code: Option<String>,
    pub updated_at: i64,
}

impl InstanceRow {
    pub fn from_record(value: &InstanceStateRecord) -> Result<Self, RepositoryError> {
        bounded(
            &value.instance_id,
            255,
            "runtime instance id is out of bounds",
        )?;
        optional_text(value.error_code.as_deref(), 128)?;
        let transition_revision = revision(value.transition_revision)?;
        let applied_revision = value.applied_revision.map(revision).transpose()?;
        if applied_revision.is_some_and(|applied| applied > transition_revision) {
            return Err(invalid("runtime applied revision is invalid"));
        }
        Ok(Self {
            instance_id: value.instance_id.clone(),
            module_id: value.module_id,
            state: value.state,
            transition_revision,
            applied_revision,
            drain_deadline: value.drain_deadline.map(time).transpose()?,
            error_code: value.error_code.clone(),
            updated_at: time(value.updated_at)?,
        })
    }

    pub fn into_record(self) -> Result<InstanceStateRecord, RepositoryError> {
        let record = InstanceStateRecord {
            instance_id: self.instance_id,
            module_id: self.module_id,
            state: self.state,
            transition_revision: stored_revision(self.transition_revision)?,
            applied_revision: self.applied_revision.map(stored_revision).transpose()?,
            drain_deadline: self.drain_deadline.map(stored_time).transpose()?,
            error_code: self.error_code,
            updated_at: stored_time(self.updated_at)?,
        };
        Self::from_record(&record)?;
        Ok(record)
    }
}

#[derive(Clone, Deserialize, Serialize)]
pub(super) struct EventRow {
    pub event_id: String,
    pub module_id: ModuleId,
    pub event_type: String,
    pub revision: i64,
    pub instance_id: Option<String>,
    pub actor_id: Option<String>,
    pub reason: Option<String>,
    pub before_state: Option<String>,
    pub after_state: Option<String>,
    pub outcome_code: Option<String>,
    pub occurred_at: i64,
}

impl EventRow {
    pub fn from_record(value: &ModuleEventRecord) -> Result<Self, RepositoryError> {
        let row = Self {
            event_id: uuid::Uuid::parse_str(&value.event_id)
                .map_err(|_| invalid("runtime event id is invalid"))?
                .to_string(),
            module_id: value.module_id,
            event_type: event_type(value.event_type).to_owned(),
            revision: revision(value.revision)?,
            instance_id: value.instance_id.clone(),
            actor_id: optional_id(value.actor_id.as_deref())?,
            reason: value.reason.clone(),
            before_state: value.before.map(event_state).map(str::to_owned),
            after_state: value.after.map(event_state).map(str::to_owned),
            outcome_code: value.outcome_code.clone(),
            occurred_at: time(value.occurred_at)?,
        };
        row.clone().into_record()?;
        Ok(row)
    }

    pub fn into_record(self) -> Result<ModuleEventRecord, RepositoryError> {
        optional_text(self.instance_id.as_deref(), 255)?;
        optional_text(self.reason.as_deref(), 500)?;
        optional_text(self.outcome_code.as_deref(), 128)?;
        let event_type = ModuleEventType::ALL
            .into_iter()
            .find(|kind| event_type(*kind) == self.event_type)
            .ok_or_else(|| invalid("runtime event type is invalid"))?;
        Ok(ModuleEventRecord {
            event_id: uuid::Uuid::parse_str(&self.event_id)
                .map_err(|_| invalid("runtime event id is invalid"))?
                .to_string(),
            module_id: self.module_id,
            event_type,
            revision: stored_revision(self.revision)?,
            instance_id: self.instance_id,
            actor_id: optional_id(self.actor_id.as_deref())?,
            reason: self.reason,
            before: self
                .before_state
                .as_deref()
                .map(|state| parse_event_state(event_type, state))
                .transpose()?,
            after: self
                .after_state
                .as_deref()
                .map(|state| parse_event_state(event_type, state))
                .transpose()?,
            outcome_code: self.outcome_code,
            occurred_at: stored_time(self.occurred_at)?,
        })
    }
}

pub(super) const fn event_type(value: ModuleEventType) -> &'static str {
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

fn event_state(value: ModuleEventState) -> &'static str {
    match value {
        ModuleEventState::Desired(HistoricalDesiredMode::Inherit) => "inherit",
        ModuleEventState::Desired(HistoricalDesiredMode::Enabled)
        | ModuleEventState::Actual(ModuleState::Enabled) => "enabled",
        ModuleEventState::Desired(HistoricalDesiredMode::Disabled)
        | ModuleEventState::Actual(ModuleState::Disabled) => "disabled",
        ModuleEventState::Actual(ModuleState::Starting) => "starting",
        ModuleEventState::Actual(ModuleState::Draining) => "draining",
        ModuleEventState::Actual(ModuleState::Failed) => "failed",
    }
}

fn parse_event_state(
    kind: ModuleEventType,
    value: &str,
) -> Result<ModuleEventState, RepositoryError> {
    if kind == ModuleEventType::DesiredStateChanged {
        return Ok(ModuleEventState::Desired(match value {
            "inherit" => HistoricalDesiredMode::Inherit,
            "enabled" => HistoricalDesiredMode::Enabled,
            "disabled" => HistoricalDesiredMode::Disabled,
            _ => return Err(invalid("runtime desired event state is invalid")),
        }));
    }
    serde_json::from_value::<ModuleState>(serde_json::Value::String(value.to_owned()))
        .map(ModuleEventState::Actual)
        .map_err(|_| invalid("runtime actual event state is invalid"))
}
