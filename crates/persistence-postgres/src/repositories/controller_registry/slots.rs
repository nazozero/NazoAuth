//! Controller slot registry lifecycle (D01/D02): admission, rotation,
//! revocation, and the per-deployment advisory lock that serializes them.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Duration, Utc};
use diesel::OptionalExtension;
use diesel::QueryableByName;
use diesel::result::Error as QueryError;
use diesel::sql_query;
use diesel::sql_types::{BigInt, Binary, Nullable, SmallInt, Timestamptz, Varchar};
use diesel_async::{AsyncConnection as _, AsyncPgConnection, RunQueryDsl};
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

use nazo_persistence::control_plane as contract;

use crate::get_conn;

use super::ControllerRegistryRepository;

/// Fixed controller key lifetime in seconds: exactly 30 days (04 §2).  Not a
/// configuration item, never derived from a natural month, never renewed in
/// place.
pub const CONTROLLER_KEY_TTL_SECONDS: i64 = contract::CONTROLLER_KEY_TTL_SECONDS;

/// Maximum number of concurrently non-revoked controller slots per deployment.
pub const MAX_ACTIVE_CONTROLLER_SLOTS: usize = contract::MAX_ACTIVE_CONTROLLER_SLOTS;

/// Advisory-lock seed namespace for the per-deployment identity lock. Slot
/// mutations AND Recovery Root/challenge mutations share this single lock so
/// a break-glass recovery cannot interleave its active-slot re-check and
/// batch revoke with a concurrent bind/rotate commit (P0-5): one deployment,
/// one identity, one lock order.
pub const DEPLOYMENT_IDENTITY_LOCK_SEED: i64 = 0x4E5A_4354_5200_0001;

/// Legal slot indices; the migration pins this range with a CHECK constraint.
const SLOT_INDEX_RANGE: [i16; 3] = [0, 1, 2];

/// Status catalog of a stored controller slot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ControllerSlotStatus {
    /// Enrolled and eligible for admission until `expires_at`.
    Active,
    /// Terminal state; can never admit operations again.
    Revoked,
}

impl ControllerSlotStatus {
    const ACTIVE: &'static str = "active";
    const REVOKED: &'static str = "revoked";

    fn from_str(value: &str) -> Option<Self> {
        match value {
            Self::ACTIVE => Some(Self::Active),
            Self::REVOKED => Some(Self::Revoked),
            _ => None,
        }
    }
}

/// One authoritative controller slot (public material only).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoredControllerSlot {
    pub deployment_id: String,
    /// Server-assigned canonical UUIDv7; stable across rotations.
    pub controller_id: String,
    pub label: String,
    pub kid: String,
    /// Raw Ed25519 public key bytes (32).
    pub public_key: Vec<u8>,
    pub slot_index: i16,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub status: ControllerSlotStatus,
    pub revoked_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl StoredControllerSlot {
    /// Non-secret summary for human-facing surfaces.  Never carries public key
    /// bytes.
    #[must_use]
    pub fn summary(&self) -> ControllerSlotSummary {
        ControllerSlotSummary {
            controller_id: self.controller_id.clone(),
            label: self.label.clone(),
            kid: self.kid.clone(),
            slot_index: self.slot_index,
            issued_at: self.issued_at,
            expires_at: self.expires_at,
            status: self.status,
        }
    }
}

/// Non-secret slot summary used in limit errors and approval screens.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ControllerSlotSummary {
    pub controller_id: String,
    pub label: String,
    pub kid: String,
    pub slot_index: i16,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub status: ControllerSlotStatus,
}

/// A controller slot that would admit a new application-level operation at the
/// instant of the lookup: exists, non-revoked, and unexpired.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdmittedController {
    pub controller_id: String,
    pub kid: String,
    /// Raw Ed25519 public key bytes used to verify operation signatures.
    pub public_key: Vec<u8>,
    pub expires_at: DateTime<Utc>,
}

/// Server-side input for enrolling one new controller slot.  Bind and add
/// share this shape; the distinction lives in the approval action only.  The
/// `controller_id` is assigned by the server, never by callers.
#[derive(Clone, Debug)]
pub struct NewControllerSlot {
    pub deployment_id: String,
    pub label: String,
    /// Unpadded base64url SHA-256 of `public_key`.
    pub kid: String,
    /// Raw Ed25519 public key bytes (32); private halves are not representable here.
    pub public_key: [u8; 32],
}

/// Atomic same-`controller_id` key replacement (rotate).  The active-slot
/// count is unchanged by construction.
#[derive(Clone, Debug)]
pub struct RotateControllerKey {
    pub deployment_id: String,
    pub controller_id: String,
    pub label: String,
    pub kid: String,
    pub public_key: [u8; 32],
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
    #[diesel(sql_type = Nullable<Timestamptz>)]
    last_used_at: Option<DateTime<Utc>>,
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
            last_used_at: row.last_used_at,
            status: ControllerSlotStatus::from_str(&row.status)
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

impl TryFrom<AdmittedRow> for AdmittedController {
    type Error = anyhow::Error;

    fn try_from(row: AdmittedRow) -> Result<Self, Self::Error> {
        Ok(Self {
            controller_id: row.controller_id,
            kid: row.kid,
            public_key: row.public_key,
            expires_at: row.expires_at,
        })
    }
}

#[derive(QueryableByName)]
struct CountRow {
    #[diesel(sql_type = BigInt)]
    count: i64,
}

macro_rules! slot_columns {
    () => {
        "deployment_id, controller_id, label, kid, public_key, \
         slot_index, issued_at, expires_at, last_used_at, status, revoked_at, \
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

pub(super) fn validate_controller_id(value: &str) -> Result<(), ControllerRegistryError> {
    nazo_operator_protocol::validate_controller_id(value).map_err(|_| {
        ControllerRegistryError::InvalidIdentity(
            "controller_id must be a canonical lowercase UUIDv7",
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

pub(crate) fn validate_label(value: &str) -> Result<(), ControllerRegistryError> {
    if value.is_empty() || value.len() > 128 || value.chars().any(char::is_control) {
        return Err(ControllerRegistryError::InvalidIdentity(
            "controller label must be 1..=128 bounded text",
        ));
    }
    Ok(())
}

/// Registry self-consistency: `kid` must be exactly `base64url(SHA-256(key))`.
pub(crate) fn validate_kid_binding(
    kid: &str,
    public_key: &[u8; 32],
) -> Result<(), ControllerRegistryError> {
    if kid != URL_SAFE_NO_PAD.encode(Sha256::digest(public_key)) {
        return Err(ControllerRegistryError::InvalidIdentity(
            "kid does not match the controller public key material",
        ));
    }
    Ok(())
}

pub(super) fn validate_slot_input(
    deployment_id: &str,
    label: &str,
    kid: &str,
    public_key: &[u8; 32],
) -> Result<(), ControllerRegistryError> {
    validate_deployment_id(deployment_id)?;
    validate_label(label)?;
    validate_kid(kid)?;
    validate_kid_binding(kid, public_key)
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

async fn load_slot_for_update(
    connection: &mut AsyncPgConnection,
    deployment_id: &str,
    controller_id: &str,
) -> Result<StoredControllerSlot, ControllerRegistryError> {
    let row = sql_query(format!(
        "SELECT {} FROM controller_registry_slots \
         WHERE deployment_id = $1 AND controller_id = $2 FOR UPDATE",
        slot_columns!()
    ))
    .bind::<Varchar, _>(deployment_id)
    .bind::<Varchar, _>(controller_id)
    .get_result::<SlotRow>(connection)
    .await
    .optional()
    .map_err(transport)?
    .map(StoredControllerSlot::try_from)
    .transpose()
    .map_err(transport)?;
    row.ok_or(ControllerRegistryError::UnknownController)
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

async fn read_slot_row(
    connection: &mut AsyncPgConnection,
    deployment_id: &str,
    controller_id: &str,
) -> Result<StoredControllerSlot, ControllerRegistryError> {
    sql_query(format!(
        "SELECT {} FROM controller_registry_slots \
         WHERE deployment_id = $1 AND controller_id = $2",
        slot_columns!()
    ))
    .bind::<Varchar, _>(deployment_id)
    .bind::<Varchar, _>(controller_id)
    .get_result::<SlotRow>(connection)
    .await?
    .try_into()
    .map_err(transport)
}

/// Insert one new active slot under the held advisory lock, picking the lowest
/// free index.  The partial unique active-slot index is the hard backstop for
/// any path that could bypass the lock.
pub(crate) async fn insert_slot_on_connection(
    connection: &mut AsyncPgConnection,
    slot: &NewControllerSlot,
    now: DateTime<Utc>,
) -> Result<StoredControllerSlot, ControllerRegistryError> {
    lock_deployment_slots(connection, &slot.deployment_id).await?;
    let active = active_slots_on_connection(connection, &slot.deployment_id).await?;
    let Some(slot_index) = lowest_free_slot_index(&active) else {
        return Err(ControllerRegistryError::SlotLimit(
            active.iter().map(StoredControllerSlot::summary).collect(),
        ));
    };
    let controller_id = Uuid::now_v7().to_string();
    let inserted = sql_query(
        "INSERT INTO controller_registry_slots
            (deployment_id, controller_id, label, kid, public_key, slot_index,
             issued_at, expires_at, last_used_at, status, revoked_at, created_at, updated_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NULL, 'active', NULL, $7, $7)",
    )
    .bind::<Varchar, _>(&slot.deployment_id)
    .bind::<Varchar, _>(&controller_id)
    .bind::<Varchar, _>(&slot.label)
    .bind::<Varchar, _>(&slot.kid)
    .bind::<Binary, _>(&slot.public_key[..])
    .bind::<SmallInt, _>(slot_index)
    .bind::<Timestamptz, _>(now)
    .bind::<Timestamptz, _>(now + Duration::seconds(CONTROLLER_KEY_TTL_SECONDS))
    .execute(connection)
    .await;
    if let Err(error) = inserted {
        // Under the per-deployment advisory lock the only reachable unique
        // violation on this path is the per-deployment kid backstop.
        return Err(map_insert_conflict(error));
    }
    read_slot_row(connection, &slot.deployment_id, &controller_id).await
}

fn map_insert_conflict(error: QueryError) -> ControllerRegistryError {
    match &error {
        QueryError::DatabaseError(kind, _) => {
            if matches!(kind, diesel::result::DatabaseErrorKind::UniqueViolation) {
                ControllerRegistryError::DuplicateKid
            } else {
                transport(error)
            }
        }
        _ => transport(error),
    }
}

pub(super) async fn rotate_slot_on_connection(
    connection: &mut AsyncPgConnection,
    rotation: &RotateControllerKey,
    now: DateTime<Utc>,
) -> Result<StoredControllerSlot, ControllerRegistryError> {
    lock_deployment_slots(connection, &rotation.deployment_id).await?;
    let current =
        load_slot_for_update(connection, &rotation.deployment_id, &rotation.controller_id).await?;
    if current.status == ControllerSlotStatus::Revoked {
        return Err(ControllerRegistryError::AlreadyRevoked);
    }
    let conflict = sql_query(
        "SELECT count(*) AS count FROM controller_registry_slots
         WHERE deployment_id = $1 AND kid = $2 AND controller_id <> $3",
    )
    .bind::<Varchar, _>(&rotation.deployment_id)
    .bind::<Varchar, _>(&rotation.kid)
    .bind::<Varchar, _>(&rotation.controller_id)
    .get_result::<CountRow>(connection)
    .await?;
    if conflict.count > 0 {
        return Err(ControllerRegistryError::DuplicateKid);
    }
    sql_query(
        "UPDATE controller_registry_slots
         SET label = $3, kid = $4, public_key = $5,
             issued_at = $6, expires_at = $7,
             last_used_at = NULL, updated_at = $6
         WHERE deployment_id = $1 AND controller_id = $2",
    )
    .bind::<Varchar, _>(&rotation.deployment_id)
    .bind::<Varchar, _>(&rotation.controller_id)
    .bind::<Varchar, _>(&rotation.label)
    .bind::<Varchar, _>(&rotation.kid)
    .bind::<Binary, _>(&rotation.public_key[..])
    .bind::<Timestamptz, _>(now)
    .bind::<Timestamptz, _>(now + Duration::seconds(CONTROLLER_KEY_TTL_SECONDS))
    .execute(connection)
    .await?;
    load_slot_for_update(connection, &rotation.deployment_id, &rotation.controller_id).await
}

pub(super) async fn revoke_slot_on_connection(
    connection: &mut AsyncPgConnection,
    deployment_id: &str,
    controller_id: &str,
    now: DateTime<Utc>,
) -> Result<StoredControllerSlot, ControllerRegistryError> {
    lock_deployment_slots(connection, deployment_id).await?;
    let current = load_slot_for_update(connection, deployment_id, controller_id).await?;
    if current.status == ControllerSlotStatus::Revoked {
        return Err(ControllerRegistryError::AlreadyRevoked);
    }
    sql_query(
        "UPDATE controller_registry_slots
         SET status = 'revoked', revoked_at = $3, updated_at = $3
         WHERE deployment_id = $1 AND controller_id = $2",
    )
    .bind::<Varchar, _>(deployment_id)
    .bind::<Varchar, _>(controller_id)
    .bind::<Timestamptz, _>(now)
    .execute(connection)
    .await?;
    load_slot_for_update(connection, deployment_id, controller_id).await
}

impl ControllerRegistryRepository {
    /// Enroll one new controller slot (bind or add).  Assigns the authoritative
    /// `controller_id`, computes the fixed 30-day expiry server-side, picks the
    /// lowest free slot index, and refuses a fourth concurrent active slot with
    /// [`ControllerRegistryError::SlotLimit`] carrying the non-secret active
    /// summaries.  No partial row survives any rejection.
    pub async fn create_slot(
        &self,
        slot: NewControllerSlot,
        now: DateTime<Utc>,
    ) -> Result<StoredControllerSlot, ControllerRegistryError> {
        validate_slot_input(
            &slot.deployment_id,
            &slot.label,
            &slot.kid,
            &slot.public_key,
        )?;
        let mut connection = get_conn(&self.pool).await.map_err(transport)?;
        connection
            .transaction::<_, ControllerRegistryError, _>(async move |connection| {
                insert_slot_on_connection(connection, &slot, now).await
            })
            .await
    }

    /// Atomically replace the key material of one existing active slot without
    /// changing the deployment's active-slot count.  Rotation of a revoked slot
    /// is refused, the old key stops admitting at commit time, and the
    /// replacement gets a fresh fixed 30-day window computed server-side.
    pub async fn rotate_slot(
        &self,
        rotation: RotateControllerKey,
        now: DateTime<Utc>,
    ) -> Result<StoredControllerSlot, ControllerRegistryError> {
        validate_controller_id(&rotation.controller_id)?;
        validate_slot_input(
            &rotation.deployment_id,
            &rotation.label,
            &rotation.kid,
            &rotation.public_key,
        )?;
        let mut connection = get_conn(&self.pool).await.map_err(transport)?;
        connection
            .transaction::<_, ControllerRegistryError, _>(async move |connection| {
                rotate_slot_on_connection(connection, &rotation, now).await
            })
            .await
    }

    /// Revoke one slot by exact controller id.  Terminal: a second call fails
    /// with [`ControllerRegistryError::AlreadyRevoked`] so no caller can
    /// mistake an already-dead key for a fresh revocation.
    pub async fn revoke_slot(
        &self,
        deployment_id: &str,
        controller_id: &str,
        now: DateTime<Utc>,
    ) -> Result<StoredControllerSlot, ControllerRegistryError> {
        validate_deployment_id(deployment_id)?;
        validate_controller_id(controller_id)?;
        let deployment_id = deployment_id.to_owned();
        let controller_id = controller_id.to_owned();
        let mut connection = get_conn(&self.pool).await.map_err(transport)?;
        connection
            .transaction::<_, ControllerRegistryError, _>(async move |connection| {
                revoke_slot_on_connection(connection, &deployment_id, &controller_id, now).await
            })
            .await
    }

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
        rows.into_iter()
            .map(AdmittedController::try_from)
            .collect::<Result<Vec<_>, _>>()
            .map_err(transport)
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
        .map_err(transport)?
        .map(AdmittedController::try_from)
        .transpose()
        .map_err(transport)?;
        Ok(row)
    }
}

fn contract_status(status: ControllerSlotStatus) -> contract::ControllerSlotStatus {
    match status {
        ControllerSlotStatus::Active => contract::ControllerSlotStatus::Active,
        ControllerSlotStatus::Revoked => contract::ControllerSlotStatus::Revoked,
    }
}

pub(crate) fn contract_slot(slot: StoredControllerSlot) -> contract::StoredControllerSlot {
    contract::StoredControllerSlot {
        deployment_id: slot.deployment_id,
        controller_id: slot.controller_id,
        label: slot.label,
        kid: slot.kid,
        public_key: slot.public_key,
        slot_index: slot.slot_index,
        issued_at: slot.issued_at,
        expires_at: slot.expires_at,
        last_used_at: slot.last_used_at,
        status: contract_status(slot.status),
        revoked_at: slot.revoked_at,
        created_at: slot.created_at,
        updated_at: slot.updated_at,
    }
}

fn contract_summary(summary: ControllerSlotSummary) -> contract::ControllerSlotSummary {
    contract::ControllerSlotSummary {
        controller_id: summary.controller_id,
        label: summary.label,
        kid: summary.kid,
        slot_index: summary.slot_index,
        issued_at: summary.issued_at,
        expires_at: summary.expires_at,
        status: contract_status(summary.status),
    }
}

pub(super) fn contract_admitted(controller: AdmittedController) -> contract::AdmittedController {
    contract::AdmittedController {
        controller_id: controller.controller_id,
        kid: controller.kid,
        public_key: controller.public_key,
        expires_at: controller.expires_at,
    }
}

pub(super) fn contract_registry_error(
    error: ControllerRegistryError,
) -> contract::ControllerRegistryError {
    match error {
        ControllerRegistryError::SlotLimit(summaries) => {
            contract::ControllerRegistryError::SlotLimit(
                summaries.into_iter().map(contract_summary).collect(),
            )
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
