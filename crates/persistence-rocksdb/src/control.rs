//! Deployment identity and recovery share one lock. Approvals, authority
//! changes, and required outcomes are committed by that transaction owner.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use futures_util::future::BoxFuture;
use jiff::{SignedDuration, Timestamp};
use nazo_identity::ports::RepositoryError;
use nazo_persistence::control_plane::*;
use rocksdb::{Direction, IteratorMode, Transaction, TransactionDB};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

use crate::{
    RocksDb,
    db::{decode, key, map_error, put, put_expiring, read, read_snapshot, read_tx},
};

const DEPLOYMENT: u8 = 0x66;
const SLOT: u8 = 0x67;
const KID: u8 = 0x68;
const APPROVAL: u8 = 0x69;
const ROOT_HISTORY: u8 = 0x6a;
const CHALLENGE: u8 = 0x6b;
const ALLOCATION: u8 = 0x6c;

#[derive(Default, Serialize, Deserialize)]
struct Deployment {
    active_slots: Vec<String>,
    root: Option<Root>,
    pending: Option<Uuid>,
}

#[derive(Clone, Serialize, Deserialize)]
struct Slot {
    controller_id: String,
    label: String,
    kid: String,
    public_key: [u8; 32],
    slot_index: i16,
    issued_at: Timestamp,
    expires_at: Timestamp,
    revoked_at: Option<Timestamp>,
    created_at: Timestamp,
    updated_at: Timestamp,
}

impl Slot {
    fn into_domain(self, deployment_id: String) -> StoredControllerSlot {
        StoredControllerSlot {
            deployment_id,
            controller_id: self.controller_id,
            label: self.label,
            kid: self.kid,
            public_key: self.public_key.to_vec(),
            slot_index: self.slot_index,
            issued_at: self.issued_at,
            expires_at: self.expires_at,
            status: if self.revoked_at.is_some() {
                ControllerSlotStatus::Revoked
            } else {
                ControllerSlotStatus::Active
            },
            revoked_at: self.revoked_at,
            created_at: self.created_at,
            updated_at: self.updated_at,
        }
    }
    fn admitted(self, now: Timestamp) -> Option<AdmittedController> {
        (self.revoked_at.is_none() && self.expires_at > now).then(|| AdmittedController {
            controller_id: self.controller_id,
            kid: self.kid,
            public_key: self.public_key.to_vec(),
            expires_at: self.expires_at,
        })
    }
}

#[derive(Clone, Serialize, Deserialize)]
struct Root {
    kid: String,
    public_key: [u8; 32],
    generation: i32,
    created_at: Timestamp,
    updated_at: Timestamp,
}

impl Root {
    fn into_domain(self, deployment_id: String) -> StoredRecoveryRoot {
        StoredRecoveryRoot {
            deployment_id,
            recovery_kid: self.kid,
            recovery_public_key: self.public_key.to_vec(),
            kdf: nazo_operator_protocol::RECOVERY_KDF_ID.into(),
            generation: self.generation,
            created_at: self.created_at,
            updated_at: self.updated_at,
        }
    }
}

#[derive(Serialize, Deserialize)]
struct Approval {
    deployment_id: String,
    action: String,
    action_sha256: String,
    expires_at: Timestamp,
    consumed: bool,
}

#[derive(Serialize, Deserialize)]
struct Challenge {
    nonce: [u8; 32],
    allocation_nonce: [u8; 32],
    controller_label: String,
    controller_kid: String,
    controller_public_key: [u8; 32],
    recovery_kid: String,
    recovery_public_key: [u8; 32],
    expires_at: Timestamp,
    attempts: i32,
    consumed: bool,
    accepted_signature_sha256: Option<[u8; 32]>,
    receipt: Option<(Slot, i32)>,
}

impl Challenge {
    fn proposal(&self, deployment_id: &str) -> nazo_operator_protocol::RecoveryProposal {
        nazo_operator_protocol::RecoveryProposal {
            deployment_id: deployment_id.into(),
            controller_label: self.controller_label.clone(),
            controller_kid: self.controller_kid.clone(),
            controller_public_key: self.controller_public_key,
            recovery_kid: self.recovery_kid.clone(),
            recovery_public_key: self.recovery_public_key,
        }
    }
    fn same_allocation(&self, candidate: &NewRecoveryChallenge) -> bool {
        self.allocation_nonce == candidate.allocation_nonce
            && self.controller_label == candidate.controller_label
            && self.controller_kid == candidate.controller_kid
            && self.controller_public_key == candidate.controller_public_key
            && self.recovery_kid == candidate.recovery_kid
            && self.recovery_public_key == candidate.recovery_public_key
    }
}

fn scoped_key(table: u8, deployment: &str, id: &[u8]) -> Vec<u8> {
    let mut storage_key = key(table, Uuid::nil(), deployment.as_bytes());
    storage_key.push(0);
    storage_key.extend_from_slice(id);
    storage_key
}

fn deployment_key(deployment: &str) -> Vec<u8> {
    scoped_key(DEPLOYMENT, deployment, &[])
}

fn lock_deployment(
    tx: &Transaction<'_, TransactionDB>,
    deployment: &str,
) -> Result<Deployment, RepositoryError> {
    Ok(read_tx(tx, &deployment_key(deployment), true)?.unwrap_or_default())
}

fn validate_deployment(deployment: &str) -> Result<(), ControllerRegistryError> {
    nazo_operator_protocol::validate_file_identifier_value(deployment)
        .map_err(|_| ControllerRegistryError::InvalidIdentity("invalid deployment identifier"))
}

fn validate_key(kid: &str, public_key: &[u8; 32]) -> Result<(), ControllerRegistryError> {
    let public = nazo_crypto::ed25519::VerifyingKey::from_bytes(public_key)
        .map_err(|_| ControllerRegistryError::InvalidIdentity("invalid controller public key"))?;
    if nazo_operator_protocol::controller_key_id(&public) != kid {
        return Err(ControllerRegistryError::InvalidIdentity(
            "key identifier does not match public key",
        ));
    }
    Ok(())
}

fn registry_error(error: RepositoryError) -> ControllerRegistryError {
    ControllerRegistryError::Transport(error.into())
}
fn approval_error(error: RepositoryError) -> IdentityApprovalError {
    IdentityApprovalError::Transport(error.into())
}
fn commit_error(error: RepositoryError) -> CommitWithApprovalError {
    CommitWithApprovalError::Transport(error.into())
}
fn recovery_error(error: RepositoryError) -> RecoveryRootError {
    RecoveryRootError::Transport(error.into())
}
fn rotation_error(error: RepositoryError) -> RecoveryRotationError {
    RecoveryRotationError::Transport(error.into())
}

fn append_admin(
    tx: &Transaction<'_, TransactionDB>,
    event_type: &str,
    audit: &AdminIdentityAudit,
    mut fields: serde_json::Value,
) -> Result<(), RepositoryError> {
    let payload = fields
        .as_object_mut()
        .expect("identity outcome is an object");
    payload.extend([
        (
            "schema_version".into(),
            serde_json::json!(nazo_persistence::SECURITY_AUDIT_SCHEMA_VERSION),
        ),
        ("event_category".into(), serde_json::json!("administration")),
        (
            "tenant_id".into(),
            serde_json::json!(audit.tenant.tenant_id.as_uuid()),
        ),
        (
            "realm_id".into(),
            serde_json::json!(audit.tenant.realm_id.as_uuid()),
        ),
        (
            "organization_id".into(),
            serde_json::json!(audit.tenant.organization_id.as_uuid()),
        ),
        (
            "actor_user_id".into(),
            serde_json::json!(audit.actor_user_id),
        ),
        (
            "source_ip_hash".into(),
            serde_json::json!(audit.source_ip_hash),
        ),
        ("outcome".into(), serde_json::json!("success")),
    ]);
    crate::audit::append_in_tx(
        tx,
        &nazo_persistence::SecurityAuditEvent {
            event_id: Uuid::now_v7(),
            event_type: event_type.into(),
            event_category: "administration".into(),
            payload: fields,
            occurred_at: Timestamp::now(),
        },
    )
}

fn append_slot(
    tx: &Transaction<'_, TransactionDB>,
    event_type: &str,
    audit: &AdminIdentityAudit,
    deployment: &str,
    slot: &Slot,
) -> Result<(), RepositoryError> {
    append_admin(
        tx,
        event_type,
        audit,
        serde_json::json!({
            "deployment_id": deployment,
            "controller_id": slot.controller_id,
            "kid": slot.kid,
            "slot_index": slot.slot_index,
            "expires_at": slot.expires_at,
        }),
    )
}

fn consume_approval(
    tx: &Transaction<'_, TransactionDB>,
    token: &str,
    deployment: &str,
    action: ControllerIdentityAction,
    action_hash: &str,
    now: Timestamp,
) -> Result<(), IdentityApprovalError> {
    let storage_key = key(
        APPROVAL,
        Uuid::nil(),
        blake3::hash(token.as_bytes()).as_bytes(),
    );
    let mut approval: Approval = read_tx(tx, &storage_key, true)
        .map_err(approval_error)?
        .ok_or(IdentityApprovalError::UnknownToken)?;
    if approval.consumed {
        return Err(IdentityApprovalError::Replayed);
    }
    if approval.expires_at <= now {
        return Err(IdentityApprovalError::Expired);
    }
    if approval.deployment_id != deployment
        || approval.action != action.as_str()
        || approval.action_sha256 != action_hash
    {
        return Err(IdentityApprovalError::ActionMismatch);
    }
    approval.consumed = true;
    put_expiring(tx, &storage_key, &approval, approval.expires_at).map_err(approval_error)
}

fn active_slots(
    tx: &Transaction<'_, TransactionDB>,
    deployment: &str,
    state: &Deployment,
) -> Result<Vec<Slot>, RepositoryError> {
    state
        .active_slots
        .iter()
        .map(|id| {
            read_tx(tx, &scoped_key(SLOT, deployment, id.as_bytes()), false)?.ok_or_else(|| {
                RepositoryError::Consistency("missing active controller slot".into())
            })
        })
        .collect()
}

fn insert_slot(
    tx: &Transaction<'_, TransactionDB>,
    state: &mut Deployment,
    candidate: &NewControllerSlot,
    now: Timestamp,
) -> Result<Slot, ControllerRegistryError> {
    validate_deployment(&candidate.deployment_id)?;
    validate_key(&candidate.kid, &candidate.public_key)?;
    let active = active_slots(tx, &candidate.deployment_id, state).map_err(registry_error)?;
    let slot_index = (0..MAX_ACTIVE_CONTROLLER_SLOTS as i16)
        .find(|index| !active.iter().any(|slot| slot.slot_index == *index))
        .ok_or_else(|| {
            ControllerRegistryError::SlotLimit(
                active
                    .into_iter()
                    .map(|slot| slot.into_domain(candidate.deployment_id.clone()).summary())
                    .collect(),
            )
        })?;
    let kid_key = scoped_key(KID, &candidate.deployment_id, candidate.kid.as_bytes());
    if read_tx::<String>(tx, &kid_key, true)
        .map_err(registry_error)?
        .is_some()
    {
        return Err(ControllerRegistryError::DuplicateKid);
    }
    let slot = Slot {
        controller_id: Uuid::now_v7().to_string(),
        label: candidate.label.clone(),
        kid: candidate.kid.clone(),
        public_key: candidate.public_key,
        slot_index,
        issued_at: now,
        expires_at: now + SignedDuration::from_secs(CONTROLLER_KEY_TTL_SECONDS),
        revoked_at: None,
        created_at: now,
        updated_at: now,
    };
    put(
        tx,
        &scoped_key(
            SLOT,
            &candidate.deployment_id,
            slot.controller_id.as_bytes(),
        ),
        &slot,
    )
    .map_err(registry_error)?;
    put(tx, &kid_key, &slot.controller_id).map_err(registry_error)?;
    state.active_slots.push(slot.controller_id.clone());
    Ok(slot)
}

fn rotate_slot(
    tx: &Transaction<'_, TransactionDB>,
    candidate: &RotateControllerKey,
    now: Timestamp,
) -> Result<Slot, ControllerRegistryError> {
    validate_key(&candidate.kid, &candidate.public_key)?;
    let storage_key = scoped_key(
        SLOT,
        &candidate.deployment_id,
        candidate.controller_id.as_bytes(),
    );
    let mut slot: Slot = read_tx(tx, &storage_key, true)
        .map_err(registry_error)?
        .ok_or(ControllerRegistryError::UnknownController)?;
    if slot.revoked_at.is_some() {
        return Err(ControllerRegistryError::AlreadyRevoked);
    }
    let kid_key = scoped_key(KID, &candidate.deployment_id, candidate.kid.as_bytes());
    if read_tx::<String>(tx, &kid_key, true)
        .map_err(registry_error)?
        .is_some_and(|id| id != candidate.controller_id)
    {
        return Err(ControllerRegistryError::DuplicateKid);
    }
    tx.delete(scoped_key(
        KID,
        &candidate.deployment_id,
        slot.kid.as_bytes(),
    ))
    .map_err(map_error)
    .map_err(registry_error)?;
    slot.label.clone_from(&candidate.label);
    slot.kid.clone_from(&candidate.kid);
    slot.public_key = candidate.public_key;
    slot.issued_at = now;
    slot.expires_at = now + SignedDuration::from_secs(CONTROLLER_KEY_TTL_SECONDS);
    slot.updated_at = now;
    put(tx, &storage_key, &slot).map_err(registry_error)?;
    put(tx, &kid_key, &slot.controller_id).map_err(registry_error)?;
    Ok(slot)
}

fn replace_root(
    tx: &Transaction<'_, TransactionDB>,
    state: &mut Deployment,
    candidate: &NewRecoveryRoot,
    now: Timestamp,
) -> Result<Root, RecoveryRootError> {
    validate_key(&candidate.kid, &candidate.public_key).map_err(|_| {
        RecoveryRootError::InvalidIdentity("invalid recovery public key or identifier")
    })?;
    let history_key = scoped_key(
        ROOT_HISTORY,
        &candidate.deployment_id,
        &candidate.public_key,
    );
    if read_tx::<bool>(tx, &history_key, true)
        .map_err(recovery_error)?
        .is_some()
    {
        return Err(RecoveryRootError::InvalidIdentity(
            "recovery key was already used for this deployment",
        ));
    }
    let generation = state
        .root
        .as_ref()
        .map_or(Some(1), |root| root.generation.checked_add(1))
        .ok_or_else(|| {
            recovery_error(RepositoryError::Consistency(
                "recovery generation exhausted".into(),
            ))
        })?;
    let root = Root {
        kid: candidate.kid.clone(),
        public_key: candidate.public_key,
        generation,
        created_at: state.root.as_ref().map_or(now, |root| root.created_at),
        updated_at: now,
    };
    put(tx, &history_key, &true).map_err(recovery_error)?;
    if let Some(id) = state.pending.take() {
        let challenge_key = scoped_key(CHALLENGE, &candidate.deployment_id, id.as_bytes());
        if let Some(mut challenge) =
            read_tx::<Challenge>(tx, &challenge_key, true).map_err(recovery_error)?
        {
            challenge.consumed = true;
            put(tx, &challenge_key, &challenge).map_err(recovery_error)?;
        }
    }
    state.root = Some(root.clone());
    Ok(root)
}

impl ControllerRegistryPort for RocksDb {
    fn renew_controller_key(
        &self,
        deployment_id: String,
        controller_id: String,
        previous_kid: String,
        public_key: [u8; 32],
        now: Timestamp,
    ) -> BoxFuture<'_, Result<Option<String>, ControllerRegistryError>> {
        Box::pin(async move {
            self.run(move |db| {
                Ok((|| {
                    validate_deployment(&deployment_id)?;
                    let public = nazo_crypto::ed25519::VerifyingKey::from_bytes(&public_key)
                        .map_err(|_| {
                            ControllerRegistryError::InvalidIdentity("invalid renewal public key")
                        })?;
                    let kid = nazo_operator_protocol::controller_key_id(&public);
                    if kid == previous_kid {
                        return Err(ControllerRegistryError::InvalidIdentity(
                            "renewal must replace signing key",
                        ));
                    }
                    let tx = db.transaction();
                    let state = lock_deployment(&tx, &deployment_id).map_err(registry_error)?;
                    let Some(slot) = active_slots(&tx, &deployment_id, &state)
                        .map_err(registry_error)?
                        .into_iter()
                        .find(|slot| slot.controller_id == controller_id)
                    else {
                        return Ok(None);
                    };
                    if slot.kid == kid {
                        return Ok(Some(kid));
                    }
                    if slot.kid != previous_kid
                        || slot.expires_at > now + SignedDuration::from_hours(7 * 24)
                    {
                        return Ok(None);
                    }
                    rotate_slot(
                        &tx,
                        &RotateControllerKey {
                            deployment_id: deployment_id.clone(),
                            controller_id: controller_id.clone(),
                            label: slot.label,
                            kid: kid.clone(),
                            public_key,
                        },
                        now,
                    )?;
                    let audit_tenant = nazo_identity::TenantContext::default_system()
                        .tenant_id
                        .as_uuid();
                    crate::audit::append_in_tx(
                        &tx,
                        &nazo_persistence::SecurityAuditEvent {
                            event_id: Uuid::now_v7(),
                            event_type: "controller_key_renewed".into(),
                            event_category: "administration".into(),
                            occurred_at: now,
                            payload: serde_json::json!({
                                "schema_version": nazo_persistence::SECURITY_AUDIT_SCHEMA_VERSION,
                                "event_category": "administration",
                                "tenant_id": audit_tenant,
                                "deployment_id": deployment_id,
                                "controller_id": controller_id,
                                "previous_kid": previous_kid,
                                "kid": kid,
                                "authority": "host_operator",
                                "outcome": "success"
                            }),
                        },
                    )
                    .map_err(registry_error)?;
                    tx.commit().map_err(map_error).map_err(registry_error)?;
                    Ok(Some(kid))
                })())
            })
            .await
            .map_err(registry_error)?
        })
    }

    fn issue_identity_approval_with_required_audit(
        &self,
        command: IdentityApprovalCommand,
        audit: AdminIdentityAudit,
    ) -> BoxFuture<'_, Result<IssuedIdentityApproval, IdentityApprovalError>> {
        Box::pin(async move {
            self.run(move |db| {
                let tx = db.transaction();
                lock_deployment(&tx, &command.deployment_id)?;
                crate::users::authorize_admin_tx(&tx, &audit)?;
                let token = URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>());
                let approval_id = Uuid::now_v7();
                let expires_at =
                    command.now + SignedDuration::from_secs(IDENTITY_APPROVAL_TTL_SECONDS);
                let approval = Approval {
                    deployment_id: command.deployment_id.clone(),
                    action: command.action.as_str().into(),
                    action_sha256: command.action_sha256.clone(),
                    expires_at,
                    consumed: false,
                };
                put_expiring(
                    &tx,
                    &key(
                        APPROVAL,
                        Uuid::nil(),
                        blake3::hash(token.as_bytes()).as_bytes(),
                    ),
                    &approval,
                    expires_at,
                )?;
                append_admin(
                    &tx,
                    if command.action == ControllerIdentityAction::RecoveryRootRotate {
                        "controller_recovery_root_rotation_approved"
                    } else {
                        "controller_identity_approval_issued"
                    },
                    &audit,
                    serde_json::json!({
                        "approval_id": approval_id,
                        "deployment_id": command.deployment_id,
                        "action": command.action.as_str(),
                        "action_sha256": command.action_sha256,
                        "expires_at": expires_at,
                    }),
                )?;
                tx.commit().map_err(map_error)?;
                Ok(IssuedIdentityApproval {
                    approval_id,
                    action: command.action,
                    action_sha256: command.action_sha256,
                    token,
                    expires_at,
                })
            })
            .await
            .map_err(approval_error)
        })
    }

    fn commit_slot_creation_with_required_audit(
        &self,
        command: SlotCreationCommand,
        audit: AdminIdentityAudit,
    ) -> BoxFuture<'_, Result<StoredControllerSlot, CommitWithApprovalError>> {
        Box::pin(async move {
            self.run(move |db| {
                Ok((|| {
                    let tx = db.transaction();
                    let mut state =
                        lock_deployment(&tx, &command.slot.deployment_id).map_err(commit_error)?;
                    crate::users::authorize_admin_tx(&tx, &audit).map_err(commit_error)?;
                    consume_approval(
                        &tx,
                        &command.approval_token,
                        &command.slot.deployment_id,
                        command.action,
                        &command.action_sha256,
                        command.now,
                    )
                    .map_err(CommitWithApprovalError::Approval)?;
                    if let Some(root) = &command.initial_root {
                        if state.root.is_some() || root.deployment_id != command.slot.deployment_id
                        {
                            return Err(CommitWithApprovalError::Mutation(
                                ControllerRegistryError::InvalidIdentity(
                                    "initial recovery root must belong to an unbound deployment",
                                ),
                            ));
                        }
                        replace_root(&tx, &mut state, root, command.now)
                            .map_err(|error| CommitWithApprovalError::Transport(error.into()))?;
                    }
                    let slot = insert_slot(&tx, &mut state, &command.slot, command.now)
                        .map_err(CommitWithApprovalError::Mutation)?;
                    append_slot(
                        &tx,
                        "controller_slot_created",
                        &audit,
                        &command.slot.deployment_id,
                        &slot,
                    )
                    .map_err(commit_error)?;
                    put(&tx, &deployment_key(&command.slot.deployment_id), &state)
                        .map_err(commit_error)?;
                    tx.commit().map_err(map_error).map_err(commit_error)?;
                    Ok(slot.into_domain(command.slot.deployment_id))
                })())
            })
            .await
            .map_err(commit_error)?
        })
    }

    fn commit_slot_rotation_with_required_audit(
        &self,
        command: SlotRotationCommand,
        audit: AdminIdentityAudit,
    ) -> BoxFuture<'_, Result<StoredControllerSlot, CommitWithApprovalError>> {
        Box::pin(async move {
            self.run(move |db| {
                Ok((|| {
                    let tx = db.transaction();
                    lock_deployment(&tx, &command.rotation.deployment_id).map_err(commit_error)?;
                    crate::users::authorize_admin_tx(&tx, &audit).map_err(commit_error)?;
                    consume_approval(
                        &tx,
                        &command.approval_token,
                        &command.rotation.deployment_id,
                        ControllerIdentityAction::Rotate,
                        &command.action_sha256,
                        command.now,
                    )
                    .map_err(CommitWithApprovalError::Approval)?;
                    let slot = rotate_slot(&tx, &command.rotation, command.now)
                        .map_err(CommitWithApprovalError::Mutation)?;
                    append_slot(
                        &tx,
                        "controller_slot_rotated",
                        &audit,
                        &command.rotation.deployment_id,
                        &slot,
                    )
                    .map_err(commit_error)?;
                    tx.commit().map_err(map_error).map_err(commit_error)?;
                    Ok(slot.into_domain(command.rotation.deployment_id))
                })())
            })
            .await
            .map_err(commit_error)?
        })
    }

    fn commit_slot_revocation_with_required_audit(
        &self,
        command: SlotRevocationCommand,
        audit: AdminIdentityAudit,
    ) -> BoxFuture<'_, Result<StoredControllerSlot, CommitWithApprovalError>> {
        Box::pin(async move {
            self.run(move |db| {
                Ok((|| {
                    let tx = db.transaction();
                    let mut state =
                        lock_deployment(&tx, &command.deployment_id).map_err(commit_error)?;
                    crate::users::authorize_admin_tx(&tx, &audit).map_err(commit_error)?;
                    consume_approval(
                        &tx,
                        &command.approval_token,
                        &command.deployment_id,
                        ControllerIdentityAction::Revoke,
                        &command.action_sha256,
                        command.now,
                    )
                    .map_err(CommitWithApprovalError::Approval)?;
                    let storage_key = scoped_key(
                        SLOT,
                        &command.deployment_id,
                        command.controller_id.as_bytes(),
                    );
                    let mut slot: Slot = read_tx(&tx, &storage_key, true)
                        .map_err(commit_error)?
                        .ok_or(CommitWithApprovalError::Mutation(
                            ControllerRegistryError::UnknownController,
                        ))?;
                    if slot.revoked_at.is_some() {
                        return Err(CommitWithApprovalError::Mutation(
                            ControllerRegistryError::AlreadyRevoked,
                        ));
                    }
                    slot.revoked_at = Some(command.now);
                    slot.updated_at = command.now;
                    state.active_slots.retain(|id| *id != command.controller_id);
                    put(&tx, &storage_key, &slot).map_err(commit_error)?;
                    put(&tx, &deployment_key(&command.deployment_id), &state)
                        .map_err(commit_error)?;
                    append_slot(
                        &tx,
                        "controller_slot_revoked",
                        &audit,
                        &command.deployment_id,
                        &slot,
                    )
                    .map_err(commit_error)?;
                    tx.commit().map_err(map_error).map_err(commit_error)?;
                    Ok(slot.into_domain(command.deployment_id))
                })())
            })
            .await
            .map_err(commit_error)?
        })
    }

    fn list_slots<'a>(
        &'a self,
        deployment_id: &'a str,
    ) -> BoxFuture<'a, Result<Vec<StoredControllerSlot>, ControllerRegistryError>> {
        let deployment = deployment_id.to_owned();
        Box::pin(async move {
            validate_deployment(&deployment)?;
            self.run(move |db| {
                let prefix = scoped_key(SLOT, &deployment, &[]);
                let mut slots = Vec::new();
                for row in db
                    .db
                    .iterator(IteratorMode::From(&prefix, Direction::Forward))
                {
                    let (storage_key, value) = row.map_err(map_error)?;
                    if !storage_key.starts_with(&prefix) {
                        break;
                    }
                    slots.push(decode::<Slot>(&value)?.into_domain(deployment.clone()));
                }
                slots.sort_by(|a, b| {
                    (a.slot_index, &a.controller_id).cmp(&(b.slot_index, &b.controller_id))
                });
                Ok(slots)
            })
            .await
            .map_err(registry_error)
        })
    }

    fn admitted_controllers<'a>(
        &'a self,
        deployment_id: &'a str,
        now: Timestamp,
    ) -> BoxFuture<'a, Result<Vec<AdmittedController>, ControllerRegistryError>> {
        let deployment = deployment_id.to_owned();
        Box::pin(async move {
            validate_deployment(&deployment)?;
            self.run(move |db| {
                let snapshot = db.db.snapshot();
                let state: Deployment =
                    read_snapshot(&snapshot, &deployment_key(&deployment))?.unwrap_or_default();
                let mut slots = Vec::new();
                for id in state.active_slots {
                    let slot: Slot =
                        read_snapshot(&snapshot, &scoped_key(SLOT, &deployment, id.as_bytes()))?
                            .ok_or_else(|| {
                                RepositoryError::Consistency(
                                    "missing active controller slot".into(),
                                )
                            })?;
                    slots.push(slot);
                }
                slots.sort_by_key(|slot| slot.slot_index);
                Ok(slots
                    .into_iter()
                    .filter_map(|slot| slot.admitted(now))
                    .collect())
            })
            .await
            .map_err(registry_error)
        })
    }

    fn admitted_controller_by_kid<'a>(
        &'a self,
        deployment_id: &'a str,
        kid: &'a str,
        now: Timestamp,
    ) -> BoxFuture<'a, Result<Option<AdmittedController>, ControllerRegistryError>> {
        let deployment = deployment_id.to_owned();
        let kid = kid.to_owned();
        Box::pin(async move {
            validate_deployment(&deployment)?;
            self.run(move |db| {
                let snapshot = db.db.snapshot();
                let Some(id) = read_snapshot::<String>(
                    &snapshot,
                    &scoped_key(KID, &deployment, kid.as_bytes()),
                )?
                else {
                    return Ok(None);
                };
                let slot: Slot =
                    read_snapshot(&snapshot, &scoped_key(SLOT, &deployment, id.as_bytes()))?
                        .ok_or_else(|| {
                            RepositoryError::Consistency("missing indexed controller slot".into())
                        })?;
                Ok(slot.admitted(now))
            })
            .await
            .map_err(registry_error)
        })
    }
}

impl RecoveryRootPort for RocksDb {
    fn issue_rotation_approval_with_required_audit(
        &self,
        command: RecoveryApprovalCommand,
        audit: AdminIdentityAudit,
    ) -> BoxFuture<'_, Result<IssuedIdentityApproval, RecoveryRotationError>> {
        Box::pin(async move {
            self.issue_identity_approval_with_required_audit(
                IdentityApprovalCommand {
                    deployment_id: command.deployment_id,
                    action: ControllerIdentityAction::RecoveryRootRotate,
                    action_sha256: command.action_sha256,
                    now: command.now,
                },
                audit,
            )
            .await
            .map_err(RecoveryRotationError::Approval)
        })
    }

    fn commit_rotation_with_required_audit(
        &self,
        command: RecoveryRotationCommand,
        audit: AdminIdentityAudit,
    ) -> BoxFuture<'_, Result<StoredRecoveryRoot, RecoveryRotationError>> {
        Box::pin(async move {
            self.run(move |db| {
                Ok((|| {
                    let tx = db.transaction();
                    let mut state = lock_deployment(&tx, &command.root.deployment_id)
                        .map_err(rotation_error)?;
                    crate::users::authorize_admin_tx(&tx, &audit).map_err(rotation_error)?;
                    consume_approval(
                        &tx,
                        &command.approval_token,
                        &command.root.deployment_id,
                        ControllerIdentityAction::RecoveryRootRotate,
                        &command.action_sha256,
                        command.now,
                    )
                    .map_err(RecoveryRotationError::Approval)?;
                    let root = replace_root(&tx, &mut state, &command.root, command.now)
                        .map_err(RecoveryRotationError::Mutation)?;
                    append_admin(
                        &tx,
                        "controller_recovery_root_rotated",
                        &audit,
                        serde_json::json!({
                            "deployment_id": command.root.deployment_id,
                            "generation": root.generation,
                            "recovery_kid": root.kid,
                            "kdf": nazo_operator_protocol::RECOVERY_KDF_ID,
                        }),
                    )
                    .map_err(rotation_error)?;
                    put(&tx, &deployment_key(&command.root.deployment_id), &state)
                        .map_err(rotation_error)?;
                    tx.commit().map_err(map_error).map_err(rotation_error)?;
                    Ok(root.into_domain(command.root.deployment_id))
                })())
            })
            .await
            .map_err(rotation_error)?
        })
    }

    fn current_root<'a>(
        &'a self,
        deployment_id: &'a str,
    ) -> BoxFuture<'a, Result<Option<StoredRecoveryRoot>, RecoveryRootError>> {
        let deployment = deployment_id.to_owned();
        Box::pin(async move {
            validate_deployment(&deployment)
                .map_err(|_| RecoveryRootError::InvalidIdentity("invalid deployment identifier"))?;
            self.run(move |db| {
                Ok(read::<Deployment>(&db.db, &deployment_key(&deployment))?
                    .and_then(|state| state.root)
                    .map(|root| root.into_domain(deployment)))
            })
            .await
            .map_err(recovery_error)
        })
    }

    fn issue_recovery_challenge(
        &self,
        candidate: NewRecoveryChallenge,
        now: Timestamp,
    ) -> BoxFuture<'_, Result<IssuedRecoveryChallenge, RecoveryRootError>> {
        Box::pin(async move {
            self.run(move |db| {
                Ok((|| {
                    let tx = db.transaction();
                    let mut state =
                        lock_deployment(&tx, &candidate.deployment_id).map_err(recovery_error)?;
                    let root = state.root.as_ref().ok_or(RecoveryRootError::RootMissing)?;
                    let proposal = nazo_operator_protocol::RecoveryProposal {
                        deployment_id: candidate.deployment_id.clone(),
                        controller_label: candidate.controller_label.clone(),
                        controller_kid: candidate.controller_kid.clone(),
                        controller_public_key: candidate.controller_public_key,
                        recovery_kid: candidate.recovery_kid.clone(),
                        recovery_public_key: candidate.recovery_public_key,
                    };
                    if !proposal.verify_allocation_signature(
                        &candidate.allocation_nonce,
                        &root.public_key,
                        &candidate.allocation_signature,
                    ) {
                        return Err(RecoveryRootError::InvalidAllocationProof);
                    }
                    let admitted: Vec<_> = active_slots(&tx, &candidate.deployment_id, &state)
                        .map_err(recovery_error)?
                        .into_iter()
                        .filter_map(|slot| slot.admitted(now))
                        .map(|slot| AdmittedControllerSummary {
                            controller_id: slot.controller_id,
                            kid: slot.kid,
                            expires_at: slot.expires_at,
                        })
                        .collect();
                    if !admitted.is_empty() {
                        return Err(RecoveryRootError::ControllersStillAdmitted(admitted));
                    }
                    let allocation_key = scoped_key(
                        ALLOCATION,
                        &candidate.deployment_id,
                        &candidate.allocation_nonce,
                    );
                    if let Some(id) =
                        read_tx::<Uuid>(&tx, &allocation_key, true).map_err(recovery_error)?
                    {
                        let prior: Challenge = read_tx(
                            &tx,
                            &scoped_key(CHALLENGE, &candidate.deployment_id, id.as_bytes()),
                            false,
                        )
                        .map_err(recovery_error)?
                        .ok_or_else(|| {
                            recovery_error(RepositoryError::Consistency(
                                "missing recovery allocation".into(),
                            ))
                        })?;
                        if prior.consumed || prior.expires_at <= now {
                            return Err(RecoveryRootError::AllocationProofReplayed);
                        }
                        if prior.same_allocation(&candidate) {
                            return Ok(IssuedRecoveryChallenge {
                                challenge_id: id,
                                deployment_id: candidate.deployment_id,
                                nonce: prior.nonce,
                                expires_at: prior.expires_at,
                            });
                        }
                        return Err(RecoveryRootError::ChallengePending);
                    }
                    if let Some(id) = state.pending {
                        let pending_key =
                            scoped_key(CHALLENGE, &candidate.deployment_id, id.as_bytes());
                        let mut pending: Challenge = read_tx(&tx, &pending_key, true)
                            .map_err(recovery_error)?
                            .ok_or_else(|| {
                                recovery_error(RepositoryError::Consistency(
                                    "missing pending recovery challenge".into(),
                                ))
                            })?;
                        if !pending.consumed && pending.expires_at > now {
                            return Err(RecoveryRootError::ChallengePending);
                        }
                        pending.consumed = true;
                        put(&tx, &pending_key, &pending).map_err(recovery_error)?;
                    }
                    let id = Uuid::now_v7();
                    let challenge = Challenge {
                        nonce: rand::random(),
                        allocation_nonce: candidate.allocation_nonce,
                        controller_label: candidate.controller_label,
                        controller_kid: candidate.controller_kid,
                        controller_public_key: candidate.controller_public_key,
                        recovery_kid: candidate.recovery_kid,
                        recovery_public_key: candidate.recovery_public_key,
                        expires_at: now + SignedDuration::from_secs(RECOVERY_CHALLENGE_TTL_SECONDS),
                        attempts: 0,
                        consumed: false,
                        accepted_signature_sha256: None,
                        receipt: None,
                    };
                    state.pending = Some(id);
                    put(
                        &tx,
                        &scoped_key(CHALLENGE, &candidate.deployment_id, id.as_bytes()),
                        &challenge,
                    )
                    .map_err(recovery_error)?;
                    put(&tx, &allocation_key, &id).map_err(recovery_error)?;
                    put(&tx, &deployment_key(&candidate.deployment_id), &state)
                        .map_err(recovery_error)?;
                    tx.commit().map_err(map_error).map_err(recovery_error)?;
                    Ok(IssuedRecoveryChallenge {
                        challenge_id: id,
                        deployment_id: candidate.deployment_id,
                        nonce: challenge.nonce,
                        expires_at: challenge.expires_at,
                    })
                })())
            })
            .await
            .map_err(recovery_error)?
        })
    }

    fn submit_recovery_challenge(
        &self,
        submission: RecoverySubmission,
        now: Timestamp,
    ) -> BoxFuture<'_, Result<RecoveredSlotCommit, RecoveryRootError>> {
        Box::pin(async move {
            self.run(move |db| {
                Ok((|| {
                    validate_deployment(&submission.deployment_id).map_err(|_| {
                        RecoveryRootError::InvalidIdentity("invalid deployment identifier")
                    })?;
                    let tx = db.transaction();
                    let mut state =
                        lock_deployment(&tx, &submission.deployment_id).map_err(recovery_error)?;
                    let storage_key = scoped_key(
                        CHALLENGE,
                        &submission.deployment_id,
                        submission.challenge_id.as_bytes(),
                    );
                    let mut challenge: Challenge = read_tx(&tx, &storage_key, true)
                        .map_err(recovery_error)?
                        .ok_or(RecoveryRootError::ChallengeUnknown)?;
                    let signature_digest: [u8; 32] = Sha256::digest(submission.signature).into();
                    if challenge.consumed {
                        if challenge.attempts >= MAX_RECOVERY_CHALLENGE_ATTEMPTS
                            && challenge.accepted_signature_sha256.is_none()
                        {
                            return Err(RecoveryRootError::ChallengeExhausted);
                        }
                        if challenge.nonce != submission.nonce
                            || challenge.accepted_signature_sha256 != Some(signature_digest)
                        {
                            return Err(RecoveryRootError::ChallengeReplayed);
                        }
                        let (slot, generation) = challenge.receipt.ok_or_else(|| {
                            recovery_error(RepositoryError::Consistency(
                                "recovery receipt is incomplete".into(),
                            ))
                        })?;
                        return Ok(RecoveredSlotCommit {
                            slot: slot.into_domain(submission.deployment_id),
                            recovery_generation: generation,
                        });
                    }
                    if challenge.expires_at <= now {
                        return Err(RecoveryRootError::ChallengeExpired);
                    }
                    let proposal = challenge.proposal(&submission.deployment_id);
                    let invalid = if challenge.nonce != submission.nonce {
                        Some(RecoveryRootError::NonceMismatch)
                    } else {
                        let root = state.root.as_ref().ok_or(RecoveryRootError::RootMissing)?;
                        (!proposal.verify_challenge_signature(
                            &submission.challenge_id.to_string(),
                            &submission.nonce,
                            &root.public_key,
                            &submission.signature,
                        ))
                        .then_some(RecoveryRootError::InvalidSignature)
                    };
                    if let Some(error) = invalid {
                        challenge.attempts += 1;
                        if challenge.attempts >= MAX_RECOVERY_CHALLENGE_ATTEMPTS {
                            challenge.consumed = true;
                            state.pending = None;
                        }
                        put(&tx, &storage_key, &challenge).map_err(recovery_error)?;
                        put(&tx, &deployment_key(&submission.deployment_id), &state)
                            .map_err(recovery_error)?;
                        tx.commit().map_err(map_error).map_err(recovery_error)?;
                        return Err(error);
                    }
                    let slots = active_slots(&tx, &submission.deployment_id, &state)
                        .map_err(recovery_error)?;
                    if slots
                        .iter()
                        .any(|slot| slot.expires_at > now && slot.revoked_at.is_none())
                    {
                        return Err(RecoveryRootError::ControllersStillAdmitted(Vec::new()));
                    }
                    for mut slot in slots {
                        slot.revoked_at = Some(now);
                        slot.updated_at = now;
                        put(
                            &tx,
                            &scoped_key(
                                SLOT,
                                &submission.deployment_id,
                                slot.controller_id.as_bytes(),
                            ),
                            &slot,
                        )
                        .map_err(recovery_error)?;
                    }
                    state.active_slots.clear();
                    let slot = insert_slot(
                        &tx,
                        &mut state,
                        &NewControllerSlot {
                            deployment_id: submission.deployment_id.clone(),
                            label: proposal.controller_label,
                            kid: proposal.controller_kid,
                            public_key: proposal.controller_public_key,
                        },
                        now,
                    )
                    .map_err(|error| match error {
                        ControllerRegistryError::DuplicateKid => {
                            RecoveryRootError::InvalidIdentity(
                                "controller key is already registered",
                            )
                        }
                        ControllerRegistryError::InvalidIdentity(reason) => {
                            RecoveryRootError::InvalidIdentity(reason)
                        }
                        other => RecoveryRootError::Transport(other.into()),
                    })?;
                    let root = replace_root(
                        &tx,
                        &mut state,
                        &NewRecoveryRoot {
                            deployment_id: submission.deployment_id.clone(),
                            kid: proposal.recovery_kid,
                            public_key: proposal.recovery_public_key,
                        },
                        now,
                    )?;
                    challenge.consumed = true;
                    challenge.accepted_signature_sha256 = Some(signature_digest);
                    challenge.receipt = Some((slot.clone(), root.generation));
                    put(&tx, &storage_key, &challenge).map_err(recovery_error)?;
                    put(&tx, &deployment_key(&submission.deployment_id), &state)
                        .map_err(recovery_error)?;
                    tx.commit().map_err(map_error).map_err(recovery_error)?;
                    Ok(RecoveredSlotCommit {
                        slot: slot.into_domain(submission.deployment_id),
                        recovery_generation: root.generation,
                    })
                })())
            })
            .await
            .map_err(recovery_error)?
        })
    }
}

#[cfg(test)]
#[path = "../tests/unit/control.rs"]
mod tests;
