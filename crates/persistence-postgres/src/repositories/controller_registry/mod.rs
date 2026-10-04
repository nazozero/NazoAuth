//! Authoritative per-deployment Controller Public Key registry (D01/D02) and
//! single-use fresh-2FA identity approvals (D05).
//!
//! Storage ownership follows the dominant pattern for deployment-scoped
//! authoritative state in this workspace: PostgreSQL tables behind a Diesel
//! migration (`20260824000100_controller_registry`).  Unlike the E03 control
//! operation journal — which deliberately lives outside the database because
//! `migrate-apply` must work before any database exists — enrollment state is
//! written through the admin plane, whose approval flow already requires the
//! application database, and every lifecycle mutation must consume its fresh
//! 2FA approval in the *same* transaction that mutates the registry.
//!
//! Hard invariants enforced here (mirrored by CHECK/unique constraints in the
//! migration):
//!
//! * fixed 30-day TTL: `expires_at` is always computed server-side as
//!   `issued_at + CONTROLLER_KEY_TTL_SECONDS`; caller-supplied expiry is not a
//!   concept;
//! * at most [`MAX_ACTIVE_CONTROLLER_SLOTS`] concurrently non-revoked slots
//!   per deployment, serialized per deployment by an advisory transaction lock
//!   with the partial unique index as the race backstop;
//! * revocation is terminal: no code path moves a revoked slot back to
//!   `active`, rotation of a revoked slot is refused, and a second revoke is
//!   an explicit error instead of a silent success;
//! * admission ([`Self::admitted_controller_by_kid`] /
//!   [`Self::admitted_controllers`]) accepts only `active` slots with
//!   `expires_at > now`: an expired key fails new-operation admission exactly
//!   at the boundary, while already-accepted operations are unaffected (the
//!   control operation journal owns post-accept authorization);
//! * `kid` binding is validated server-side: `kid` must equal
//!   `base64url(SHA-256(public_key))`, so the registry can never store a key
//!   whose id does not match its material.
//!
//! Only public key material is ever persisted or returned; summaries shown on
//! limit errors carry identifiers and timestamps but never key bytes.

mod approvals;
pub(crate) mod required;
mod slots;

pub use approvals::{
    ControllerIdentityAction, IDENTITY_APPROVAL_TTL_SECONDS, IdentityApprovalError,
    IssuedIdentityApproval,
};
use approvals::{approval_token_digest, contract_action};
pub(crate) use approvals::{
    consume_approval_on_connection, contract_approval, contract_approval_error,
};
pub use slots::{
    AdmittedController, CONTROLLER_KEY_TTL_SECONDS, ControllerRegistryError, ControllerSlotStatus,
    ControllerSlotSummary, DEPLOYMENT_IDENTITY_LOCK_SEED, MAX_ACTIVE_CONTROLLER_SLOTS,
    NewControllerSlot, RotateControllerKey, StoredControllerSlot,
};
use slots::{
    contract_admitted, contract_registry_error, lock_deployment_slots, revoke_slot_on_connection,
    rotate_slot_on_connection, validate_controller_id, validate_slot_input,
};
pub(crate) use slots::{
    contract_slot, insert_slot_on_connection, validate_deployment_id, validate_kid,
    validate_kid_binding, validate_label,
};

use chrono::{DateTime, Utc};
use diesel::result::Error as QueryError;
use diesel_async::AsyncConnection as _;
use uuid::Uuid;

use nazo_persistence::control_plane as contract;

use crate::{DbPool, get_conn};

use super::recovery_root::{
    NewRecoveryRoot, RecoveryRootError, enroll_initial_root_on_connection,
    read_root_on_connection_for_registry,
};

/// P0-3 failure text: a bind that carries an initial Recovery Root refuses to
/// run when a root already exists (first binding initializes; it never
/// overwrites). The transaction rolls the slot back with it.
const ROOT_ALREADY_PRESENT: &str =
    "recovery root already present; bind only initializes a deployment without one";

/// Failure of an approval-gated commit.  Either the approval boundary rejected
/// redemption before anything happened, or the registry mutation failed after
/// consumption — the transaction rolls both back, leaving the approval
/// unconsumed and the registry untouched.
#[derive(Debug)]
pub enum CommitWithApprovalError {
    Approval(IdentityApprovalError),
    Mutation(ControllerRegistryError),
    Transport(anyhow::Error),
}

impl CommitWithApprovalError {
    fn transport<E>(error: E) -> Self
    where
        E: Into<anyhow::Error>,
    {
        Self::Transport(error.into())
    }

    fn approval<E>(error: E) -> Self
    where
        E: Into<IdentityApprovalError>,
    {
        Self::Approval(error.into())
    }
}

impl std::fmt::Display for CommitWithApprovalError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Approval(error) => write!(formatter, "{error}"),
            Self::Mutation(error) => write!(formatter, "{error}"),
            Self::Transport(error) => write!(formatter, "{error:#}"),
        }
    }
}

impl std::error::Error for CommitWithApprovalError {}

impl From<QueryError> for CommitWithApprovalError {
    fn from(error: QueryError) -> Self {
        Self::Transport(anyhow::Error::from(error))
    }
}

impl From<ControllerRegistryError> for CommitWithApprovalError {
    fn from(error: ControllerRegistryError) -> Self {
        Self::Mutation(error)
    }
}

impl From<IdentityApprovalError> for CommitWithApprovalError {
    fn from(error: IdentityApprovalError) -> Self {
        Self::Approval(error)
    }
}

/// P0-3: map a recovery-plane error raised inside the bind transaction.
/// Transport stays transport (outcomes cannot be inferred); every other
/// recovery failure is an authoritative failure of the whole first binding —
/// the transaction rolls the slot back with it. The mapped variant carries
/// the recovery error's stable operator message in its anyhow chain so the
/// diagnostic is not lost, while the retry semantics stay honest: the
/// approval rolled back unconsumed and identical inputs may resubmit.
fn map_recovery_error(error: RecoveryRootError) -> CommitWithApprovalError {
    match error {
        RecoveryRootError::Transport(inner) => CommitWithApprovalError::Transport(inner),
        other => CommitWithApprovalError::Transport(anyhow::anyhow!(
            "initial recovery root enrollment failed and the first binding rolled back: {other}"
        )),
    }
}

/// Repository facade over the controller registry tables.  All validity times
/// come from the caller-supplied server clock; nothing derives authorization
/// from client input.
#[derive(Clone)]
pub struct ControllerRegistryRepository {
    pool: DbPool,
}

impl ControllerRegistryRepository {
    #[must_use]
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }

    /// Consume one approval and enroll a new slot in the same transaction.
    /// Replay/expiry/binding-mismatch aborts the whole transaction, so a
    /// consumed approval can never exist without its mutation having committed,
    /// and no slot can exist without its approval having been consumed.
    pub async fn commit_slot_creation(
        &self,
        approval_token: &str,
        expected_action: ControllerIdentityAction,
        expected_action_sha256: &str,
        slot: NewControllerSlot,
        initial_root: Option<NewRecoveryRoot>,
        now: DateTime<Utc>,
    ) -> Result<StoredControllerSlot, CommitWithApprovalError> {
        self.commit_slot_creation_owned(contract::SlotCreationCommand {approval_token:approval_token.to_owned(),action:contract::ControllerIdentityAction::parse(expected_action.as_str()).expect("closed identity action"),action_sha256:expected_action_sha256.to_owned(),slot:contract::NewControllerSlot{deployment_id:slot.deployment_id,label:slot.label,kid:slot.kid,public_key:slot.public_key},initial_root:initial_root.map(|root|contract::NewRecoveryRoot{deployment_id:root.deployment_id,kid:root.kid,public_key:root.public_key}),now},None).await
    }

    async fn commit_slot_creation_owned(&self,command:contract::SlotCreationCommand,audit:Option<contract::AdminIdentityAudit>) -> Result<StoredControllerSlot,CommitWithApprovalError> {
        let contract::SlotCreationCommand { approval_token, action, action_sha256, slot, initial_root, now } = command;
        let expected_action=contract_action(action);let expected_action_sha256=action_sha256.as_str();let approval_token=approval_token.as_str();
        let slot=NewControllerSlot {deployment_id:slot.deployment_id,label:slot.label,kid:slot.kid,public_key:slot.public_key};
        let initial_root=initial_root.map(|root|NewRecoveryRoot {deployment_id:root.deployment_id,kid:root.kid,public_key:root.public_key});

        validate_slot_input(
            &slot.deployment_id,
            &slot.label,
            &slot.kid,
            &slot.public_key,
        )?;
        let token_hash = approval_token_digest(approval_token);
        let expected_action_sha256 = expected_action_sha256.to_owned();
        let mut guard = crate::pool::DiscardOnDrop(Some(get_conn(&self.pool)
            .await.map_err(CommitWithApprovalError::transport)?));
        let result = guard.connection()
            .transaction::<_, CommitWithApprovalError, _>(async move |connection| {
                if let Some(audit) = &audit {
                    lock_deployment_slots(connection,&slot.deployment_id).await?;
                    required::authorize_actor(connection,audit).await.map_err(CommitWithApprovalError::transport)?;
                }
                consume_approval_on_connection(
                    connection,
                    &token_hash,
                    &slot.deployment_id,
                    expected_action,
                    &expected_action_sha256,
                    now,
                )
                .await?;
                // P0-3: the shared identity lock is held from BEFORE the root
                // existence check through the commit, so a concurrent
                // bind/rotate/revoke can never interleave here.
                lock_deployment_slots(connection, &slot.deployment_id).await?;
                if initial_root.is_some() {
                    let existing =
                        read_root_on_connection_for_registry(connection, &slot.deployment_id)
                            .await
                            .map_err(map_recovery_error)?;
                    if existing.is_some() {
                        return Err(CommitWithApprovalError::Mutation(
                            ControllerRegistryError::InvalidIdentity(ROOT_ALREADY_PRESENT),
                        ));
                    }
                }
                let stored = insert_slot_on_connection(connection, &slot, now)
                    .await
                    .map_err(CommitWithApprovalError::Mutation)?;
                // Same-transaction enrollment: any failure rolls the slot
                // back too, so a first binding can never exist without its
                // Recovery Root (and vice versa).
                if let Some(root) = &initial_root {
                    enroll_initial_root_on_connection(connection, root, now)
                        .await
                        .map_err(map_recovery_error)?;
                }
                if let Some(audit) = &audit { required::append_slot(connection,"controller_slot_created",audit,&stored).await.map_err(CommitWithApprovalError::transport)?; }
                Ok(stored)
            })
            .await;
        if result.is_ok() { guard.return_to_pool(); }
        result
    }

    /// Consume one approval and rotate an existing slot in the same
    /// transaction.
    pub async fn commit_slot_rotation(
        &self,
        approval_token: &str,
        expected_deployment_id: &str,
        expected_action_sha256: &str,
        rotation: RotateControllerKey,
        now: DateTime<Utc>,
    ) -> Result<StoredControllerSlot, CommitWithApprovalError> {
        self.commit_slot_rotation_owned(contract::SlotRotationCommand {approval_token:approval_token.to_owned(),deployment_id:expected_deployment_id.to_owned(),action_sha256:expected_action_sha256.to_owned(),rotation:contract::RotateControllerKey{deployment_id:rotation.deployment_id,controller_id:rotation.controller_id,label:rotation.label,kid:rotation.kid,public_key:rotation.public_key},now},None).await
    }

    async fn commit_slot_rotation_owned(&self,command:contract::SlotRotationCommand,audit:Option<contract::AdminIdentityAudit>) -> Result<StoredControllerSlot,CommitWithApprovalError> {
        let contract::SlotRotationCommand {approval_token,deployment_id,action_sha256,rotation,now}=command;
        let approval_token=approval_token.as_str();let expected_deployment_id=deployment_id.as_str();let expected_action_sha256=action_sha256.as_str();
        let rotation=RotateControllerKey{deployment_id:rotation.deployment_id,controller_id:rotation.controller_id,label:rotation.label,kid:rotation.kid,public_key:rotation.public_key};

        validate_controller_id(&rotation.controller_id)?;
        validate_slot_input(
            &rotation.deployment_id,
            &rotation.label,
            &rotation.kid,
            &rotation.public_key,
        )?;
        if rotation.deployment_id != expected_deployment_id {
            return Err(CommitWithApprovalError::approval(
                IdentityApprovalError::ActionMismatch,
            ));
        }
        let token_hash = approval_token_digest(approval_token);
        let expected_action_sha256 = expected_action_sha256.to_owned();
        let mut guard = crate::pool::DiscardOnDrop(Some(get_conn(&self.pool)
            .await.map_err(CommitWithApprovalError::transport)?));
        let result = guard.connection()
            .transaction::<_, CommitWithApprovalError, _>(async move |connection| {
                if let Some(audit) = &audit {
                    lock_deployment_slots(connection,&rotation.deployment_id).await?;
                    required::authorize_actor(connection,audit).await.map_err(CommitWithApprovalError::transport)?;
                }
                consume_approval_on_connection(
                    connection,
                    &token_hash,
                    &rotation.deployment_id,
                    ControllerIdentityAction::Rotate,
                    &expected_action_sha256,
                    now,
                )
                .await?;
                let stored = rotate_slot_on_connection(connection, &rotation, now).await.map_err(CommitWithApprovalError::Mutation)?;
                if let Some(audit) = &audit { required::append_slot(connection,"controller_slot_rotated",audit,&stored).await.map_err(CommitWithApprovalError::transport)?; }
                Ok(stored)
            })
            .await;
        if result.is_ok() { guard.return_to_pool(); }
        result
    }

    /// Consume one approval and revoke an existing slot in the same
    /// transaction.
    pub async fn commit_slot_revocation(
        &self,
        approval_token: &str,
        expected_deployment_id: &str,
        expected_action_sha256: &str,
        controller_id: &str,
        now: DateTime<Utc>,
    ) -> Result<StoredControllerSlot, CommitWithApprovalError> {
        self.commit_slot_revocation_owned(contract::SlotRevocationCommand{approval_token:approval_token.to_owned(),deployment_id:expected_deployment_id.to_owned(),action_sha256:expected_action_sha256.to_owned(),controller_id:controller_id.to_owned(),now},None).await
    }

    async fn commit_slot_revocation_owned(&self,command:contract::SlotRevocationCommand,audit:Option<contract::AdminIdentityAudit>) -> Result<StoredControllerSlot,CommitWithApprovalError> {
        let contract::SlotRevocationCommand {approval_token,deployment_id,action_sha256,controller_id,now}=command;
        let approval_token=approval_token.as_str();let expected_deployment_id=deployment_id.as_str();let expected_action_sha256=action_sha256.as_str();let controller_id=controller_id.as_str();

        validate_deployment_id(expected_deployment_id)?;
        validate_controller_id(controller_id)?;
        let token_hash = approval_token_digest(approval_token);
        let expected_deployment_id = expected_deployment_id.to_owned();
        let controller_id = controller_id.to_owned();
        let expected_action_sha256 = expected_action_sha256.to_owned();
        let mut guard = crate::pool::DiscardOnDrop(Some(get_conn(&self.pool)
            .await.map_err(CommitWithApprovalError::transport)?));
        let result = guard.connection()
            .transaction::<_, CommitWithApprovalError, _>(async move |connection| {
                if let Some(audit) = &audit {
                    lock_deployment_slots(connection,&expected_deployment_id).await?;
                    required::authorize_actor(connection,audit).await.map_err(CommitWithApprovalError::transport)?;
                }
                consume_approval_on_connection(
                    connection,
                    &token_hash,
                    &expected_deployment_id,
                    ControllerIdentityAction::Revoke,
                    &expected_action_sha256,
                    now,
                )
                .await?;
                let stored = revoke_slot_on_connection(connection, &expected_deployment_id, &controller_id, now).await.map_err(CommitWithApprovalError::Mutation)?;
                if let Some(audit) = &audit { required::append_slot(connection,"controller_slot_revoked",audit,&stored).await.map_err(CommitWithApprovalError::transport)?; }
                Ok(stored)
            })
            .await;
        if result.is_ok() { guard.return_to_pool(); }
        result
    }
}

fn contract_commit_error(error: CommitWithApprovalError) -> contract::CommitWithApprovalError {
    match error {
        CommitWithApprovalError::Approval(error) => {
            contract::CommitWithApprovalError::Approval(contract_approval_error(error))
        }
        CommitWithApprovalError::Mutation(error) => {
            contract::CommitWithApprovalError::Mutation(contract_registry_error(error))
        }
        CommitWithApprovalError::Transport(error) => {
            contract::CommitWithApprovalError::Transport(error)
        }
    }
}

impl contract::ControllerRegistryPort for ControllerRegistryRepository {
    fn issue_identity_approval_with_required_audit(&self, command:contract::IdentityApprovalCommand, audit:contract::AdminIdentityAudit) -> futures_util::future::BoxFuture<'_,Result<contract::IssuedIdentityApproval,contract::IdentityApprovalError>> {
        Box::pin(async move { self.issue_identity_approval_owned(&command.deployment_id,contract_action(command.action),&command.action_sha256,audit.actor_user_id,command.now,Some(audit)).await.map(contract_approval).map_err(contract_approval_error) })
    }
    fn commit_slot_creation_with_required_audit(&self,command:contract::SlotCreationCommand,audit:contract::AdminIdentityAudit) -> futures_util::future::BoxFuture<'_,Result<contract::StoredControllerSlot,contract::CommitWithApprovalError>> {
        Box::pin(async move { self.commit_slot_creation_owned(command,Some(audit)).await.map(contract_slot).map_err(contract_commit_error) })
    }
    fn commit_slot_rotation_with_required_audit(&self,command:contract::SlotRotationCommand,audit:contract::AdminIdentityAudit) -> futures_util::future::BoxFuture<'_,Result<contract::StoredControllerSlot,contract::CommitWithApprovalError>> {
        Box::pin(async move { self.commit_slot_rotation_owned(command,Some(audit)).await.map(contract_slot).map_err(contract_commit_error) })
    }
    fn commit_slot_revocation_with_required_audit(&self,command:contract::SlotRevocationCommand,audit:contract::AdminIdentityAudit) -> futures_util::future::BoxFuture<'_,Result<contract::StoredControllerSlot,contract::CommitWithApprovalError>> {
        Box::pin(async move { self.commit_slot_revocation_owned(command,Some(audit)).await.map(contract_slot).map_err(contract_commit_error) })
    }

    fn issue_identity_approval<'a>(
        &'a self,
        deployment_id: &'a str,
        action: contract::ControllerIdentityAction,
        action_sha256: &'a str,
        admin_user_id: Uuid,
        now: DateTime<Utc>,
    ) -> futures_util::future::BoxFuture<
        'a,
        Result<contract::IssuedIdentityApproval, contract::IdentityApprovalError>,
    > {
        Box::pin(async move {
            ControllerRegistryRepository::issue_identity_approval(
                self,
                deployment_id,
                contract_action(action),
                action_sha256,
                admin_user_id,
                now,
            )
            .await
            .map(contract_approval)
            .map_err(contract_approval_error)
        })
    }

    fn commit_slot_creation<'a>(
        &'a self,
        approval_token: &'a str,
        expected_action: contract::ControllerIdentityAction,
        expected_action_sha256: &'a str,
        slot: contract::NewControllerSlot,
        initial_root: Option<contract::NewRecoveryRoot>,
        now: DateTime<Utc>,
    ) -> futures_util::future::BoxFuture<
        'a,
        Result<contract::StoredControllerSlot, contract::CommitWithApprovalError>,
    > {
        Box::pin(async move {
            ControllerRegistryRepository::commit_slot_creation(
                self,
                approval_token,
                contract_action(expected_action),
                expected_action_sha256,
                NewControllerSlot {
                    deployment_id: slot.deployment_id,
                    label: slot.label,
                    kid: slot.kid,
                    public_key: slot.public_key,
                },
                initial_root.map(|root| NewRecoveryRoot {
                    deployment_id: root.deployment_id,
                    kid: root.kid,
                    public_key: root.public_key,
                }),
                now,
            )
            .await
            .map(contract_slot)
            .map_err(contract_commit_error)
        })
    }

    fn commit_slot_rotation<'a>(
        &'a self,
        approval_token: &'a str,
        expected_deployment_id: &'a str,
        expected_action_sha256: &'a str,
        rotation: contract::RotateControllerKey,
        now: DateTime<Utc>,
    ) -> futures_util::future::BoxFuture<
        'a,
        Result<contract::StoredControllerSlot, contract::CommitWithApprovalError>,
    > {
        Box::pin(async move {
            ControllerRegistryRepository::commit_slot_rotation(
                self,
                approval_token,
                expected_deployment_id,
                expected_action_sha256,
                RotateControllerKey {
                    deployment_id: rotation.deployment_id,
                    controller_id: rotation.controller_id,
                    label: rotation.label,
                    kid: rotation.kid,
                    public_key: rotation.public_key,
                },
                now,
            )
            .await
            .map(contract_slot)
            .map_err(contract_commit_error)
        })
    }

    fn commit_slot_revocation<'a>(
        &'a self,
        approval_token: &'a str,
        expected_deployment_id: &'a str,
        expected_action_sha256: &'a str,
        controller_id: &'a str,
        now: DateTime<Utc>,
    ) -> futures_util::future::BoxFuture<
        'a,
        Result<contract::StoredControllerSlot, contract::CommitWithApprovalError>,
    > {
        Box::pin(async move {
            ControllerRegistryRepository::commit_slot_revocation(
                self,
                approval_token,
                expected_deployment_id,
                expected_action_sha256,
                controller_id,
                now,
            )
            .await
            .map(contract_slot)
            .map_err(contract_commit_error)
        })
    }

    fn list_slots<'a>(
        &'a self,
        deployment_id: &'a str,
    ) -> futures_util::future::BoxFuture<
        'a,
        Result<Vec<contract::StoredControllerSlot>, contract::ControllerRegistryError>,
    > {
        Box::pin(async move {
            ControllerRegistryRepository::list_slots(self, deployment_id)
                .await
                .map(|slots| slots.into_iter().map(contract_slot).collect())
                .map_err(contract_registry_error)
        })
    }

    fn admitted_controllers<'a>(
        &'a self,
        deployment_id: &'a str,
        now: DateTime<Utc>,
    ) -> futures_util::future::BoxFuture<
        'a,
        Result<Vec<contract::AdmittedController>, contract::ControllerRegistryError>,
    > {
        Box::pin(async move {
            ControllerRegistryRepository::admitted_controllers(self, deployment_id, now)
                .await
                .map(|items| items.into_iter().map(contract_admitted).collect())
                .map_err(contract_registry_error)
        })
    }

    fn admitted_controller_by_kid<'a>(
        &'a self,
        deployment_id: &'a str,
        kid: &'a str,
        now: DateTime<Utc>,
    ) -> futures_util::future::BoxFuture<
        'a,
        Result<Option<contract::AdmittedController>, contract::ControllerRegistryError>,
    > {
        Box::pin(async move {
            ControllerRegistryRepository::admitted_controller_by_kid(self, deployment_id, kid, now)
                .await
                .map(|item| item.map(contract_admitted))
                .map_err(contract_registry_error)
        })
    }
}
