//! Fresh-2FA identity approvals (D05): single-use tokens bound to an exact
//! `(deployment_id, action, action_sha256)` triple and consumed inside the
//! transaction that performs the approved mutation.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Duration, Utc};
use diesel::OptionalExtension;
use diesel::QueryableByName;
use diesel::sql_query;
use diesel::sql_types::{Nullable, Timestamptz, Uuid as DieselUuid, Varchar};
use diesel_async::{AsyncConnection as _, AsyncPgConnection, RunQueryDsl};
use uuid::Uuid;

use nazo_persistence::control_plane as contract;

use crate::get_conn;

use super::ControllerRegistryRepository;

pub use contract::{
    ControllerIdentityAction, IDENTITY_APPROVAL_TTL_SECONDS, IssuedIdentityApproval,
};

#[derive(Debug)]
pub enum IdentityApprovalError {
    /// The plaintext token does not correspond to any issued approval.
    UnknownToken,
    /// The token matches an approval that was already consumed: replay.
    Replayed,
    /// The token matches an unconsumed approval whose window has passed.
    Expired,
    /// The token is valid but was issued for a different deployment, action,
    /// or exact action digest; nothing may be committed with it.
    ActionMismatch,
    /// Infrastructure failure.
    Transport(anyhow::Error),
}

impl std::fmt::Display for IdentityApprovalError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownToken => write!(formatter, "unknown approval token"),
            Self::Replayed => write!(formatter, "approval token already consumed"),
            Self::Expired => write!(formatter, "approval token expired"),
            Self::ActionMismatch => write!(formatter, "approval does not cover this action"),
            Self::Transport(error) => write!(formatter, "{error:#}"),
        }
    }
}

impl std::error::Error for IdentityApprovalError {}

impl From<diesel::result::Error> for IdentityApprovalError {
    fn from(error: diesel::result::Error) -> Self {
        approval_transport(error)
    }
}

fn approval_transport<E>(error: E) -> IdentityApprovalError
where
    E: Into<anyhow::Error>,
{
    IdentityApprovalError::Transport(error.into())
}

#[derive(QueryableByName)]
struct IssuedApprovalRow {
    #[diesel(sql_type = Timestamptz)]
    expires_at: DateTime<Utc>,
}

#[derive(QueryableByName)]
struct ApprovalRow {
    #[diesel(sql_type = Timestamptz)]
    expires_at: DateTime<Utc>,
    #[diesel(sql_type = Nullable<Timestamptz>)]
    consumed_at: Option<DateTime<Utc>>,
    #[diesel(sql_type = Varchar)]
    deployment_id: String,
    #[diesel(sql_type = Varchar)]
    action: String,
    #[diesel(sql_type = Varchar)]
    action_sha256: String,
}

/// Hash one plaintext approval token for storage/lookup.  Tokens are random
/// 32-byte values; only their BLAKE3 digest is ever persisted, mirroring every
/// other one-time token in this schema.  Plaintext tokens are never logged.
pub(super) fn approval_token_digest(token: &str) -> String {
    blake3::hash(token.as_bytes()).to_hex().to_string()
}

/// Consume an approval row inside an open transaction.  Enforces single use,
/// the fixed expiry window, and the exact `(deployment_id, action,
/// action_sha256)` binding; sets `consumed_at` only when everything matches.
/// A later failure of the authorized mutation rolls the consumption back too.
pub(crate) async fn consume_approval_on_connection(
    connection: &mut AsyncPgConnection,
    token_hash: &str,
    expected_deployment_id: &str,
    expected_action: ControllerIdentityAction,
    expected_action_sha256: &str,
    now: DateTime<Utc>,
) -> Result<(), IdentityApprovalError> {
    let row = sql_query(
        "SELECT expires_at, consumed_at, deployment_id, action, action_sha256
         FROM controller_identity_approvals
         WHERE token_hash = $1
         FOR UPDATE",
    )
    .bind::<Varchar, _>(token_hash)
    .get_result::<ApprovalRow>(connection)
    .await
    .optional()
    .map_err(approval_transport)?;
    let Some(row) = row else {
        return Err(IdentityApprovalError::UnknownToken);
    };
    if row.consumed_at.is_some() {
        return Err(IdentityApprovalError::Replayed);
    }
    if row.expires_at <= now {
        return Err(IdentityApprovalError::Expired);
    }
    if row.deployment_id != expected_deployment_id
        || row.action != expected_action.as_str()
        || row.action_sha256 != expected_action_sha256
    {
        return Err(IdentityApprovalError::ActionMismatch);
    }
    sql_query("UPDATE controller_identity_approvals SET consumed_at = $2 WHERE token_hash = $1")
        .bind::<Varchar, _>(token_hash)
        .bind::<Timestamptz, _>(now)
        .execute(connection)
        .await
        .map_err(approval_transport)?;
    Ok(())
}

impl ControllerRegistryRepository {
    pub(crate) async fn issue_identity_approval_owned(
        &self,
        deployment_id: &str,
        action: ControllerIdentityAction,
        action_sha256: &str,
        now: DateTime<Utc>,
        audit: contract::AdminIdentityAudit,
    ) -> Result<IssuedIdentityApproval, IdentityApprovalError> {
        let token = URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>());
        let token_hash = approval_token_digest(&token);
        let approval_id = Uuid::now_v7();
        let expires_at = now + Duration::seconds(IDENTITY_APPROVAL_TTL_SECONDS);
        let mut guard = crate::pool::DiscardOnDrop(Some(
            get_conn(&self.pool).await.map_err(approval_transport)?,
        ));
        let result = guard
            .connection()
            .transaction::<_, IdentityApprovalError, _>(async move |connection| {
                super::slots::lock_deployment_slots(connection, deployment_id)
                    .await
                    .map_err(approval_transport)?;
                super::required::authorize_actor(connection, &audit)
                    .await
                    .map_err(approval_transport)?;

                let mut rows = sql_query(
                    "INSERT INTO controller_identity_approvals
                (approval_id, deployment_id, action, action_sha256,
                 admin_user_id, token_hash, expires_at, consumed_at, created_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, NULL, $8)
             RETURNING expires_at",
                )
                .bind::<DieselUuid, _>(approval_id)
                .bind::<Varchar, _>(deployment_id)
                .bind::<Varchar, _>(action.as_str())
                .bind::<Varchar, _>(action_sha256)
                .bind::<DieselUuid, _>(audit.actor_user_id)
                .bind::<Varchar, _>(&token_hash)
                .bind::<Timestamptz, _>(expires_at)
                .bind::<Timestamptz, _>(now)
                .load::<IssuedApprovalRow>(connection)
                .await
                .map_err(approval_transport)?;
                // Drain the INSERT result before publishing the approval; PostgreSQL
                // stores timestamps at microsecond precision.
                let row = rows.pop().expect("one fully received approval row");
                let issued = IssuedIdentityApproval {
                    approval_id,
                    action,
                    action_sha256: action_sha256.to_owned(),
                    token,
                    expires_at: row.expires_at,
                };

                let event = if action == ControllerIdentityAction::RecoveryRootRotate {
                    "controller_recovery_root_rotation_approved"
                } else {
                    "controller_identity_approval_issued"
                };
                super::required::append_outcome(
                    connection,
                    event,
                    &audit,
                    serde_json::json!({
                        "approval_id": issued.approval_id,
                        "deployment_id": deployment_id,
                        "action": issued.action.as_str(),
                        "action_sha256": issued.action_sha256,
                        "expires_at": issued.expires_at.to_rfc3339(),
                    }),
                )
                .await
                .map_err(approval_transport)?;

                Ok(issued)
            })
            .await;
        if result.is_ok() {
            guard.return_to_pool();
        }
        result
    }
}

pub(crate) fn contract_approval_error(
    error: IdentityApprovalError,
) -> contract::IdentityApprovalError {
    match error {
        IdentityApprovalError::UnknownToken => contract::IdentityApprovalError::UnknownToken,
        IdentityApprovalError::Replayed => contract::IdentityApprovalError::Replayed,
        IdentityApprovalError::Expired => contract::IdentityApprovalError::Expired,
        IdentityApprovalError::ActionMismatch => contract::IdentityApprovalError::ActionMismatch,
        IdentityApprovalError::Transport(error) => {
            contract::IdentityApprovalError::Transport(error)
        }
    }
}

#[cfg(test)]
#[path = "../../../tests/unit/repositories/controller_registry/approvals.rs"]
mod tests;
