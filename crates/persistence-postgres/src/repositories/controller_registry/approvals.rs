//! Fresh-2FA identity approvals (D05): single-use tokens bound to an exact
//! `(deployment_id, action, action_sha256)` triple and consumed inside the
//! transaction that performs the approved mutation.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Duration, Utc};
use diesel::OptionalExtension;
use diesel::QueryableByName;
use diesel::sql_query;
use diesel::sql_types::{Nullable, Timestamptz, Uuid as DieselUuid, Varchar};
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use uuid::Uuid;

use nazo_persistence::control_plane as contract;

use crate::get_conn;

use super::ControllerRegistryRepository;
use super::slots::validate_deployment_id;

/// Fresh-2FA approval lifetime in seconds: a fixed 10-minute ceiling (04 §3).
pub const IDENTITY_APPROVAL_TTL_SECONDS: i64 = contract::IDENTITY_APPROVAL_TTL_SECONDS;

/// Closed catalog of controller identity actions requiring fresh 2FA approval
/// (bind/add/rotate/revoke plus the recovery-root rotation of 04A D12, which
/// reuses this exact approval machinery with its own action value).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ControllerIdentityAction {
    Bind,
    Add,
    Rotate,
    Revoke,
    RecoveryRootRotate,
}

impl ControllerIdentityAction {
    const BIND: &'static str = "bind";
    const ADD: &'static str = "add";
    const ROTATE: &'static str = "rotate";
    const REVOKE: &'static str = "revoke";
    const RECOVERY_ROOT_ROTATE: &'static str = "recovery-root-rotate";

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Bind => Self::BIND,
            Self::Add => Self::ADD,
            Self::Rotate => Self::ROTATE,
            Self::Revoke => Self::REVOKE,
            Self::RecoveryRootRotate => Self::RECOVERY_ROOT_ROTATE,
        }
    }

    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            Self::BIND => Some(Self::Bind),
            Self::ADD => Some(Self::Add),
            Self::ROTATE => Some(Self::Rotate),
            Self::REVOKE => Some(Self::Revoke),
            Self::RECOVERY_ROOT_ROTATE => Some(Self::RecoveryRootRotate),
            _ => None,
        }
    }
}

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

fn approval_transport<E>(error: E) -> IdentityApprovalError
where
    E: Into<anyhow::Error>,
{
    IdentityApprovalError::Transport(error.into())
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

/// One issued approval as returned to the administrator.  The plaintext token
/// exists exactly once — in this return value — and is never logged or stored.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IssuedIdentityApproval {
    pub approval_id: Uuid,
    pub action: ControllerIdentityAction,
    /// Digest the approval is bound to; recomputed and re-checked at commit.
    pub action_sha256: String,
    pub token: String,
    pub expires_at: DateTime<Utc>,
}

impl ControllerRegistryRepository {
    /// Issue one single-use approval bound to `(deployment_id, action,
    /// action_sha256)` and to the approving administrator.  Freshness of the
    /// administrator's MFA is enforced at the HTTP boundary before this call;
    /// here the record itself gets its fixed 10-minute life.
    pub async fn issue_identity_approval(
        &self,
        deployment_id: &str,
        action: ControllerIdentityAction,
        action_sha256: &str,
        admin_user_id: Uuid,
        now: DateTime<Utc>,
    ) -> Result<IssuedIdentityApproval, IdentityApprovalError> {
        if validate_deployment_id(deployment_id).is_err() {
            return Err(approval_transport(anyhow::anyhow!(
                "approval deployment_id is invalid"
            )));
        }
        if action_sha256.len() != 64
            || !action_sha256
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(approval_transport(anyhow::anyhow!(
                "approval action digest is not lowercase sha256 hex"
            )));
        }
        let token = URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>());
        let token_hash = approval_token_digest(&token);
        let approval_id = Uuid::now_v7();
        let expires_at = now + Duration::seconds(IDENTITY_APPROVAL_TTL_SECONDS);
        let mut connection = get_conn(&self.pool).await.map_err(approval_transport)?;
        sql_query(
            "INSERT INTO controller_identity_approvals
                (approval_id, deployment_id, action, action_sha256,
                 admin_user_id, token_hash, expires_at, consumed_at, created_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, NULL, $8)",
        )
        .bind::<DieselUuid, _>(approval_id)
        .bind::<Varchar, _>(deployment_id)
        .bind::<Varchar, _>(action.as_str())
        .bind::<Varchar, _>(action_sha256)
        .bind::<DieselUuid, _>(admin_user_id)
        .bind::<Varchar, _>(&token_hash)
        .bind::<Timestamptz, _>(expires_at)
        .bind::<Timestamptz, _>(now)
        .execute(&mut connection)
        .await
        .map_err(approval_transport)?;
        Ok(IssuedIdentityApproval {
            approval_id,
            action,
            action_sha256: action_sha256.to_owned(),
            token,
            expires_at,
        })
    }
}

pub(super) fn contract_action(
    action: contract::ControllerIdentityAction,
) -> ControllerIdentityAction {
    match action {
        contract::ControllerIdentityAction::Bind => ControllerIdentityAction::Bind,
        contract::ControllerIdentityAction::Add => ControllerIdentityAction::Add,
        contract::ControllerIdentityAction::Rotate => ControllerIdentityAction::Rotate,
        contract::ControllerIdentityAction::Revoke => ControllerIdentityAction::Revoke,
        contract::ControllerIdentityAction::RecoveryRootRotate => {
            ControllerIdentityAction::RecoveryRootRotate
        }
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

pub(crate) fn contract_approval(
    approval: IssuedIdentityApproval,
) -> contract::IssuedIdentityApproval {
    contract::IssuedIdentityApproval {
        approval_id: approval.approval_id,
        action: match approval.action {
            ControllerIdentityAction::Bind => contract::ControllerIdentityAction::Bind,
            ControllerIdentityAction::Add => contract::ControllerIdentityAction::Add,
            ControllerIdentityAction::Rotate => contract::ControllerIdentityAction::Rotate,
            ControllerIdentityAction::Revoke => contract::ControllerIdentityAction::Revoke,
            ControllerIdentityAction::RecoveryRootRotate => {
                contract::ControllerIdentityAction::RecoveryRootRotate
            }
        },
        action_sha256: approval.action_sha256,
        token: approval.token,
        expires_at: approval.expires_at,
    }
}

#[cfg(test)]
#[path = "../../../tests/unit/repositories/controller_registry/approvals.rs"]
mod tests;
