//! Controller slot registry lifecycle (D01/D02): admission, rotation,
//! revocation, and the per-deployment advisory lock that serializes them.

use chrono::{DateTime, Duration, Utc};
use diesel::QueryableByName;
use diesel::result::Error as QueryError;
use diesel::sql_query;
use diesel::sql_types::{BigInt, Binary, Nullable, SmallInt, Timestamptz, Varchar};
use diesel::{ExpressionMethods as _, OptionalExtension, QueryDsl as _};
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use uuid::Uuid;

use nazo_persistence::control_plane as contract;

use crate::get_conn;

use super::ControllerRegistryRepository;

pub use contract::{
    AdmittedController, CONTROLLER_KEY_TTL_SECONDS, ControllerSlotStatus, ControllerSlotSummary,
    MAX_ACTIVE_CONTROLLER_SLOTS, NewControllerSlot, RotateControllerKey, StoredControllerSlot,
};

/// Advisory-lock seed namespace for the per-deployment identity lock. Slot
/// mutations AND Recovery Root/challenge mutations share this single lock so
/// a break-glass recovery cannot interleave its active-slot re-check and
/// batch revoke with a concurrent bind/rotate commit (P0-5): one deployment,
/// one identity, one lock order.
pub const DEPLOYMENT_IDENTITY_LOCK_SEED: i64 = 0x4E5A_4354_5200_0001;

/// Legal slot indices; the migration pins this range with a CHECK constraint.
const SLOT_INDEX_RANGE: [i16; 3] = [0, 1, 2];

fn parse_slot_status(value: &str) -> Option<ControllerSlotStatus> {
    match value {
        "active" => Some(ControllerSlotStatus::Active),
        "revoked" => Some(ControllerSlotStatus::Revoked),
        _ => None,
    }
}

/// Typed registry failures.  Transport failures are infrastructure faults;
/// everything else is an authoritative operation outcome.
#[derive(Debug)]
pub enum ControllerRegistryError {
    /// A fourth active slot was requested; carries non-secret summaries of the
    /// current active set (`CONTROLLER_SLOT_LIMIT`, 04 D02).  No partial row
    /// survives.
    SlotLimit(Vec<ControllerSlotSummary>),
    /// No slot with this exact controller id under this deployment.
    UnknownController,
    /// The target slot is already revoked; revoke refuses and rotate is impossible.
    AlreadyRevoked,
    /// Another slot of this deployment already holds this key material.
    DuplicateKid,
    /// Malformed deployment/controller/kid/key shape rejected before storage.
    InvalidIdentity(&'static str),
    /// Infrastructure failure; nothing about outcomes can be inferred from it.
    Transport(anyhow::Error),
}

impl std::fmt::Display for ControllerRegistryError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SlotLimit(_) => write!(formatter, "CONTROLLER_SLOT_LIMIT"),
            Self::UnknownController => write!(formatter, "unknown controller slot"),
            Self::AlreadyRevoked => write!(formatter, "controller slot already revoked"),
            Self::DuplicateKid => write!(formatter, "controller kid already registered"),
            Self::InvalidIdentity(reason) => write!(formatter, "{reason}"),
            Self::Transport(error) => write!(formatter, "{error:#}"),
        }
    }
}

impl std::error::Error for ControllerRegistryError {}

impl From<QueryError> for ControllerRegistryError {
    fn from(error: QueryError) -> Self {
        Self::Transport(anyhow::Error::from(error))
    }
}

fn transport<E>(error: E) -> ControllerRegistryError
where
    E: Into<anyhow::Error>,
{
    ControllerRegistryError::Transport(error.into())
}

#[derive(QueryableByName)]
struct SlotRow {
    #[diesel(sql_type = Varchar)]
    deployment_id: String,
    #[diesel(sql_type = Varchar)]
    controller_id: String,
    #[diesel(sql_type = Varchar)]
    label: String,
    #[diesel(sql_type = Varchar)]
    kid: String,
    #[diesel(sql_type = Binary)]
    public_key: Vec<u8>,
    #[diesel(sql_type = SmallInt)]
    slot_index: i16,
    #[diesel(sql_type = Timestamptz)]
    issued_at: DateTime<Utc>,
    #[diesel(sql_type = Timestamptz)]
    expires_at: DateTime<Utc>,
    #[diesel(sql_type = Varchar)]
    status: String,
    #[diesel(sql_type = Nullable<Timestamptz>)]
    revoked_at: Option<DateTime<Utc>>,
    #[diesel(sql_type = Timestamptz)]
    created_at: DateTime<Utc>,
    #[diesel(sql_type = Timestamptz)]
    updated_at: DateTime<Utc>,
}

impl TryFrom<SlotRow> for StoredControllerSlot {
    type Error = anyhow::Error;

    fn try_from(row: SlotRow) -> Result<Self, Self::Error> {
        Ok(Self {
            deployment_id: row.deployment_id,
            controller_id: row.controller_id,
            label: row.label,
            kid: row.kid,
            public_key: row.public_key,
            slot_index: row.slot_index,
            issued_at: row.issued_at,
            expires_at: row.expires_at,
            status: parse_slot_status(&row.status)
                .ok_or_else(|| anyhow::anyhow!("stored controller slot has unknown status"))?,
            revoked_at: row.revoked_at,
            created_at: row.created_at,
            updated_at: row.updated_at,
        })
    }
}

#[derive(QueryableByName)]
struct AdmittedRow {
    #[diesel(sql_type = Varchar)]
    controller_id: String,
    #[diesel(sql_type = Varchar)]
    kid: String,
    #[diesel(sql_type = Binary)]
    public_key: Vec<u8>,
    #[diesel(sql_type = Timestamptz)]
    expires_at: DateTime<Utc>,
}

impl From<AdmittedRow> for AdmittedController {
    fn from(row: AdmittedRow) -> Self {
        Self {
            controller_id: row.controller_id,
            kid: row.kid,
            public_key: row.public_key,
            expires_at: row.expires_at,
        }
    }
}

macro_rules! slot_columns {
    () => {
        "deployment_id, controller_id, label, kid, public_key, \
         slot_index, issued_at, expires_at, status, revoked_at, \
         created_at, updated_at"
    };
}

/// Validate identifier shapes before anything reaches SQL.
///
/// * `deployment_id` mirrors the operator protocol's file-safe identifier rule.
/// * `controller_id` is the authoritative format defined by D01: a canonical
///   lowercase RFC 9562 UUIDv7 string assigned by NazoAuth when the slot is
///   created and kept stable across rotations.  It therefore survives key
///   rotation (unlike the `kid`, which changes with key material), fits every
///   bounded-text/file-safety rule of the control operation journal, and this
///   definition resolves the E03 open question about the snapshot field.
pub(crate) fn validate_deployment_id(value: &str) -> Result<(), ControllerRegistryError> {
    nazo_operator_protocol::validate_file_identifier_value(value).map_err(|_| {
        ControllerRegistryError::InvalidIdentity(
            "deployment_id is not a valid file-safe identifier",
        )
    })
}

pub(crate) fn validate_kid(value: &str) -> Result<(), ControllerRegistryError> {
    if value.len() != 43
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(ControllerRegistryError::InvalidIdentity(
            "kid must be unpadded base64url SHA-256 of the public key",
        ));
    }
    Ok(())
}

pub(super) async fn lock_deployment_slots(
    connection: &mut AsyncPgConnection,
    deployment_id: &str,
) -> Result<(), ControllerRegistryError> {
    sql_query("SELECT pg_advisory_xact_lock(hashtextextended($1, $2))")
        .bind::<Varchar, _>(deployment_id)
        .bind::<BigInt, _>(DEPLOYMENT_IDENTITY_LOCK_SEED)
        .execute(connection)
        .await?;
    Ok(())
}

async fn active_slots_on_connection(
    connection: &mut AsyncPgConnection,
    deployment_id: &str,
) -> Result<Vec<StoredControllerSlot>, ControllerRegistryError> {
    let rows = sql_query(format!(
        "SELECT {} FROM controller_registry_slots \
         WHERE deployment_id = $1 AND status = 'active' \
         ORDER BY slot_index, controller_id",
        slot_columns!()
    ))
    .bind::<Varchar, _>(deployment_id)
    .load::<SlotRow>(connection)
    .await
    .map_err(transport)?;
    rows.into_iter()
        .map(StoredControllerSlot::try_from)
        .collect::<Result<Vec<_>, _>>()
        .map_err(transport)
}

fn lowest_free_slot_index(active: &[StoredControllerSlot]) -> Option<i16> {
    SLOT_INDEX_RANGE
        .into_iter()
        .find(|index| !active.iter().any(|slot| slot.slot_index == *index))
}

/// Insert one new active slot under the held advisory lock, picking the lowest
/// free index.  The partial unique active-slot index is the hard backstop for
/// any path that could bypass the lock.
pub(crate) async fn insert_slot_on_connection(
    connection: &mut AsyncPgConnection,
    slot: &NewControllerSlot,
    now: DateTime<Utc>,
) -> Result<StoredControllerSlot, ControllerRegistryError> {
    let active = active_slots_on_connection(connection, &slot.deployment_id).await?;
    let Some(slot_index) = lowest_free_slot_index(&active) else {
        return Err(ControllerRegistryError::SlotLimit(
            active.iter().map(StoredControllerSlot::summary).collect(),
        ));
    };
    let controller_id = Uuid::now_v7().to_string();
    let mut rows = sql_query(format!(
        "INSERT INTO controller_registry_slots
            (deployment_id, controller_id, label, kid, public_key, slot_index,
             issued_at, expires_at, status, revoked_at, created_at, updated_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'active', NULL, $7, $7)
         RETURNING {}",
        slot_columns!()
    ))
    .bind::<Varchar, _>(&slot.deployment_id)
    .bind::<Varchar, _>(&controller_id)
    .bind::<Varchar, _>(&slot.label)
    .bind::<Varchar, _>(&slot.kid)
    .bind::<Binary, _>(&slot.public_key[..])
    .bind::<SmallInt, _>(slot_index)
    .bind::<Timestamptz, _>(now)
    .bind::<Timestamptz, _>(now + Duration::seconds(CONTROLLER_KEY_TTL_SECONDS))
    .load::<SlotRow>(connection)
    .await
    .map_err(map_slot_conflict)?;
    rows.pop()
        .expect("one fully received inserted slot row")
        .try_into()
        .map_err(transport)
}

// The caller holds the deployment identity lock. A conditional UPDATE has
// already rejected this target; only distinguish absence from terminal revoke.
async fn written_slot_or_rejection(
    connection: &mut AsyncPgConnection,
    mut rows: Vec<SlotRow>,
    deployment_id: &str,
    controller_id: &str,
) -> Result<StoredControllerSlot, ControllerRegistryError> {
    if let Some(row) = rows.pop() {
        return row.try_into().map_err(transport);
    }
    use crate::schema::controller_registry_slots as slots;
    let present = diesel::select(diesel::dsl::exists(
        slots::table
            .filter(slots::deployment_id.eq(deployment_id))
            .filter(slots::controller_id.eq(controller_id)),
    ))
    .get_result::<bool>(connection)
    .await?;
    Err(if present {
        ControllerRegistryError::AlreadyRevoked
    } else {
        ControllerRegistryError::UnknownController
    })
}

fn map_slot_conflict(error: QueryError) -> ControllerRegistryError {
    match &error {
        QueryError::DatabaseError(diesel::result::DatabaseErrorKind::UniqueViolation, info)
            if info.constraint_name() == Some("ux_controller_registry_slots_deployment_kid") =>
        {
            ControllerRegistryError::DuplicateKid
        }
        _ => transport(error),
    }
}

pub(super) async fn rotate_slot_on_connection(
    connection: &mut AsyncPgConnection,
    rotation: &RotateControllerKey,
    now: DateTime<Utc>,
) -> Result<StoredControllerSlot, ControllerRegistryError> {
    let rows = sql_query(format!(
        "UPDATE controller_registry_slots
         SET label = $3, kid = $4, public_key = $5,
             issued_at = $6, expires_at = $7,
             updated_at = $6
         WHERE deployment_id = $1 AND controller_id = $2 AND status = 'active'
         RETURNING {}",
        slot_columns!()
    ))
    .bind::<Varchar, _>(&rotation.deployment_id)
    .bind::<Varchar, _>(&rotation.controller_id)
    .bind::<Varchar, _>(&rotation.label)
    .bind::<Varchar, _>(&rotation.kid)
    .bind::<Binary, _>(&rotation.public_key[..])
    .bind::<Timestamptz, _>(now)
    .bind::<Timestamptz, _>(now + Duration::seconds(CONTROLLER_KEY_TTL_SECONDS))
    .load::<SlotRow>(connection)
    .await
    .map_err(map_slot_conflict)?;
    written_slot_or_rejection(
        connection,
        rows,
        &rotation.deployment_id,
        &rotation.controller_id,
    )
    .await
}

pub(super) async fn revoke_slot_on_connection(
    connection: &mut AsyncPgConnection,
    deployment_id: &str,
    controller_id: &str,
    now: DateTime<Utc>,
) -> Result<StoredControllerSlot, ControllerRegistryError> {
    let rows = sql_query(format!(
        "UPDATE controller_registry_slots
         SET status = 'revoked', revoked_at = $3, updated_at = $3
         WHERE deployment_id = $1 AND controller_id = $2 AND status = 'active'
         RETURNING {}",
        slot_columns!()
    ))
    .bind::<Varchar, _>(deployment_id)
    .bind::<Varchar, _>(controller_id)
    .bind::<Timestamptz, _>(now)
    .load::<SlotRow>(connection)
    .await?;
    written_slot_or_rejection(connection, rows, deployment_id, controller_id).await
}

impl ControllerRegistryRepository {
    /// Every slot of one deployment ordered by assignment, including revoked
    /// rows: history is part of the authority answer ("does this key exist and
    /// what happened to it").
    pub async fn list_slots(
        &self,
        deployment_id: &str,
    ) -> Result<Vec<StoredControllerSlot>, ControllerRegistryError> {
        validate_deployment_id(deployment_id)?;
        let mut connection = get_conn(&self.pool).await.map_err(transport)?;
        let rows = sql_query(format!(
            "SELECT {} FROM controller_registry_slots \
             WHERE deployment_id = $1 ORDER BY slot_index, controller_id",
            slot_columns!()
        ))
        .bind::<Varchar, _>(deployment_id)
        .load::<SlotRow>(&mut connection)
        .await
        .map_err(transport)?;
        rows.into_iter()
            .map(StoredControllerSlot::try_from)
            .collect::<Result<Vec<_>, _>>()
            .map_err(transport)
    }

    /// E04 verification-order lookup ("by deployment id, find the controller
    /// kids/public keys"): every slot that would admit a new operation right
    /// now.  Expired-but-not-yet-replaced keys are absent because admission
    /// requires `expires_at > now`.
    pub async fn admitted_controllers(
        &self,
        deployment_id: &str,
        now: DateTime<Utc>,
    ) -> Result<Vec<AdmittedController>, ControllerRegistryError> {
        validate_deployment_id(deployment_id)?;
        let mut connection = get_conn(&self.pool).await.map_err(transport)?;
        let rows = sql_query(
            "SELECT controller_id, kid, public_key, expires_at
             FROM controller_registry_slots
             WHERE deployment_id = $1 AND status = 'active' AND expires_at > $2
             ORDER BY slot_index",
        )
        .bind::<Varchar, _>(deployment_id)
        .bind::<Timestamptz, _>(now)
        .load::<AdmittedRow>(&mut connection)
        .await
        .map_err(transport)?;
        Ok(rows.into_iter().map(AdmittedController::from).collect())
    }

    /// Single-kid admission lookup used to verify one presented envelope key.
    /// Returns `None` for unknown, revoked, and expired keys alike; callers map
    /// the outcome onto the single controller-key authorization rejection.
    pub async fn admitted_controller_by_kid(
        &self,
        deployment_id: &str,
        kid: &str,
        now: DateTime<Utc>,
    ) -> Result<Option<AdmittedController>, ControllerRegistryError> {
        validate_deployment_id(deployment_id)?;
        validate_kid(kid)?;
        let mut connection = get_conn(&self.pool).await.map_err(transport)?;
        let row = sql_query(
            "SELECT controller_id, kid, public_key, expires_at
             FROM controller_registry_slots
             WHERE deployment_id = $1 AND kid = $2
               AND status = 'active' AND expires_at > $3",
        )
        .bind::<Varchar, _>(deployment_id)
        .bind::<Varchar, _>(kid)
        .bind::<Timestamptz, _>(now)
        .get_result::<AdmittedRow>(&mut connection)
        .await
        .optional()
        .map_err(transport)?;
        Ok(row.map(AdmittedController::from))
    }
}

pub(super) fn contract_registry_error(
    error: ControllerRegistryError,
) -> contract::ControllerRegistryError {
    match error {
        ControllerRegistryError::SlotLimit(summaries) => {
            contract::ControllerRegistryError::SlotLimit(summaries)
        }
        ControllerRegistryError::UnknownController => {
            contract::ControllerRegistryError::UnknownController
        }
        ControllerRegistryError::AlreadyRevoked => {
            contract::ControllerRegistryError::AlreadyRevoked
        }
        ControllerRegistryError::DuplicateKid => contract::ControllerRegistryError::DuplicateKid,
        ControllerRegistryError::InvalidIdentity(reason) => {
            contract::ControllerRegistryError::InvalidIdentity(reason)
        }
        ControllerRegistryError::Transport(error) => {
            contract::ControllerRegistryError::Transport(error)
        }
    }
}

#[cfg(test)]
#[path = "../../../tests/unit/repositories/controller_registry/slots.rs"]
mod tests;
