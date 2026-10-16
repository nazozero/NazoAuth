//! Controller identity approvals and changes.
//!
//! The HTTP boundary owns fresh-MFA admission. This service validates the
//! proposed identity and binds its sorted-key JSON digest to one approval.
//! Persistence atomically consumes that approval, mutates the registry and
//! records the required audit event. Controller keys expire after thirty days,
//! with at most three active slots per deployment.

use std::{collections::BTreeMap, sync::Arc};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Duration, Utc};
use serde::Deserialize;
use sha2::{Digest as _, Sha256};

pub use nazo_persistence::control_plane::{
    CONTROLLER_KEY_TTL_SECONDS, IDENTITY_APPROVAL_TTL_SECONDS, MAX_ACTIVE_CONTROLLER_SLOTS,
};

use nazo_persistence::control_plane::{
    CommitWithApprovalError, ControllerIdentityAction, ControllerRegistryError,
    ControllerRegistryPort, ControllerSlotSummary, IdentityApprovalError, IssuedIdentityApproval,
    NewControllerSlot, NewRecoveryRoot, RotateControllerKey, StoredControllerSlot,
};

/// Fixed 7-day pre-expiry warning threshold (04 §2).
pub const EXPIRY_WARNING_DAYS: i64 = 7;
/// Fixed 24-hour urgent pre-expiry warning threshold (04 §2).
pub const EXPIRY_URGENT_HOURS: i64 = 24;

/// Pre-expiry warning level of a controller slot at time `now`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ControllerKeyWarning {
    /// Fewer than 24 hours remain.
    Urgent,
    /// Fewer than 7 days remain.
    Expiring,
}

/// Pure policy predicate shared by status surfaces (D09 consumes the render).
#[must_use]
pub fn expiry_warning(
    now: DateTime<Utc>,
    expires_at: DateTime<Utc>,
) -> Option<ControllerKeyWarning> {
    let remaining = expires_at - now;
    if remaining <= Duration::hours(EXPIRY_URGENT_HOURS) {
        Some(ControllerKeyWarning::Urgent)
    } else if remaining <= Duration::days(EXPIRY_WARNING_DAYS) {
        Some(ControllerKeyWarning::Expiring)
    } else {
        None
    }
}

/// One pending controller identity change offered for fresh-2FA approval.
///
/// Unknown members are rejected so an approval never silently covers more
/// than the administrator saw.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct SlotChangeRequest {
    pub deployment_id: String,
    pub label: String,
    /// Unpadded base64url encoding of the raw 32-byte Ed25519 public key.
    pub public_key: String,
    /// Unpadded base64url SHA-256 of the public key bytes.
    pub kid: String,
    /// P0-3 atomic first binding: the replacement Recovery Public Key that
    /// the SAME transaction must enroll as generation 1. Only `bind` may
    /// carry it — a fresh install can never be left without a Recovery Root.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovery_public_key: Option<String>,
    /// Unpadded base64url SHA-256 of `recovery_public_key`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovery_kid: Option<String>,
}

/// Rotation keeps the same `controller_id` and replaces its key material.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RotateRequest {
    pub deployment_id: String,
    pub controller_id: String,
    pub label: String,
    pub public_key: String,
    pub kid: String,
}

/// Revocation requires the exact controller id; label matching is refused.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RevokeRequest {
    pub deployment_id: String,
    pub controller_id: String,
}

/// The exact payload an approval covers.  The digest input is compact JSON
/// with sorted keys (`serde_json`'s default map), so both the issuing screen
/// and the committing call derive identical digests from identical payloads.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IdentityChange {
    Bind(SlotChangeRequest),
    Add(SlotChangeRequest),
    Rotate(RotateRequest),
    Revoke(RevokeRequest),
}

impl IdentityChange {
    #[must_use]
    pub fn action(&self) -> ControllerIdentityAction {
        match self {
            Self::Bind(_) => ControllerIdentityAction::Bind,
            Self::Add(_) => ControllerIdentityAction::Add,
            Self::Rotate(_) => ControllerIdentityAction::Rotate,
            Self::Revoke(_) => ControllerIdentityAction::Revoke,
        }
    }

    #[must_use]
    pub fn deployment_id(&self) -> &str {
        match self {
            Self::Bind(request) | Self::Add(request) => &request.deployment_id,
            Self::Rotate(request) => &request.deployment_id,
            Self::Revoke(request) => &request.deployment_id,
        }
    }

    fn validate(&self) -> Result<(), ControllerRegistryServiceError> {
        match self {
            Self::Bind(request) => request.validate(true).map(|_| ()),
            Self::Add(request) => request.validate(false).map(|_| ()),
            Self::Rotate(request) => request.validate().map(|_| ()),
            Self::Revoke(request) => request.validate(),
        }
    }

    /// Lowercase hex SHA-256 of sorted-key compact JSON, preserving the
    /// approval binding without allocating owned JSON strings or a byte buffer.
    #[must_use]
    pub fn action_sha256(&self) -> String {
        let mut fields = BTreeMap::from([
            ("action", self.action().as_str()),
            ("deployment_id", self.deployment_id()),
        ]);
        match self {
            Self::Bind(request) | Self::Add(request) => {
                fields.extend([
                    ("kid", request.kid.as_str()),
                    ("label", request.label.as_str()),
                    ("public_key", request.public_key.as_str()),
                ]);
                if matches!(self, Self::Bind(_)) {
                    if let Some(kid) = &request.recovery_kid {
                        fields.insert("recovery_kid", kid);
                    }
                    if let Some(key) = &request.recovery_public_key {
                        fields.insert("recovery_public_key", key);
                    }
                }
            }
            Self::Rotate(request) => fields.extend([
                ("controller_id", request.controller_id.as_str()),
                ("kid", request.kid.as_str()),
                ("label", request.label.as_str()),
                ("public_key", request.public_key.as_str()),
            ]),
            Self::Revoke(request) => {
                fields.insert("controller_id", &request.controller_id);
            }
        }
        struct DigestWriter(Sha256);
        impl std::io::Write for DigestWriter {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                self.0.update(bytes);
                Ok(bytes.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let mut digest = DigestWriter(Sha256::new());
        serde_json::to_writer(&mut digest, &fields).expect("string map serialization cannot fail");
        hex::encode(digest.0.finalize())
    }
}

impl SlotChangeRequest {
    fn validate(
        &self,
        bind: bool,
    ) -> Result<([u8; 32], Option<[u8; 32]>), ControllerRegistryServiceError> {
        if !bind && (self.recovery_public_key.is_some() || self.recovery_kid.is_some()) {
            return Err(ControllerRegistryServiceError::Invalid(
                "add 不允许携带 recovery 字段；Recovery Root 只随首次 bind 建立.",
            ));
        }
        let key = validate_slot_request(
            &self.deployment_id,
            &self.label,
            &self.kid,
            &self.public_key,
        )?;
        let recovery_key = if bind {
            let (Some(public_key), Some(kid)) = (
                self.recovery_public_key.as_deref(),
                self.recovery_kid.as_deref(),
            ) else {
                return Err(ControllerRegistryServiceError::Invalid(
                    "bind 必须携带 recovery_public_key/recovery_kid，首次绑定与 Recovery Root 是一个原子事务.",
                ));
            };
            Some(validate_recovery_binding(public_key, kid)?)
        } else {
            None
        };
        Ok((key, recovery_key))
    }
}

impl RotateRequest {
    fn validate(&self) -> Result<[u8; 32], ControllerRegistryServiceError> {
        validate_controller_id(&self.controller_id)?;
        validate_slot_request(
            &self.deployment_id,
            &self.label,
            &self.kid,
            &self.public_key,
        )
    }
}

impl RevokeRequest {
    fn validate(&self) -> Result<(), ControllerRegistryServiceError> {
        validate_deployment(&self.deployment_id)?;
        validate_controller_id(&self.controller_id)
    }
}

fn validate_deployment(value: &str) -> Result<(), ControllerRegistryServiceError> {
    nazo_operator_protocol::validate_file_identifier_value(value).map_err(|_| {
        ControllerRegistryServiceError::Invalid("deployment_id 不是合法的文件安全标识符.")
    })
}

fn validate_controller_id(value: &str) -> Result<(), ControllerRegistryServiceError> {
    nazo_operator_protocol::validate_controller_id(value).map_err(|_| {
        ControllerRegistryServiceError::Invalid("controller_id 必须是规范的小写 UUIDv7.")
    })
}

/// Decode and fully bind one slot change request: identifier shapes, bounded
/// label, 32-byte key material, and `kid == base64url(SHA-256(key))`.  The
/// server never trusts a `kid` that does not match its key bytes.
fn validate_slot_request(
    deployment_id: &str,
    label: &str,
    kid: &str,
    public_key_text: &str,
) -> Result<[u8; 32], ControllerRegistryServiceError> {
    validate_deployment(deployment_id)?;
    if label.is_empty() || label.len() > 128 || label.chars().any(char::is_control) {
        return Err(ControllerRegistryServiceError::Invalid(
            "label 必须为 1..=128 个受限文本字符.",
        ));
    }
    let public_key = decode_public_key(public_key_text)?;
    let derived_kid = URL_SAFE_NO_PAD.encode(Sha256::digest(public_key));
    if derived_kid != kid {
        return Err(ControllerRegistryServiceError::Invalid(
            "kid 与公钥材料不匹配.",
        ));
    }
    Ok(public_key)
}

/// Typed service failures; the HTTP boundary maps these onto the admin error
/// conventions without losing the distinction between operator mistakes and
/// infrastructure faults.
#[derive(Debug)]
pub enum ControllerRegistryServiceError {
    /// Malformed request; nothing was persisted or approved.
    Invalid(&'static str),
    /// Fourth active slot requested; carries non-secret active summaries.
    SlotLimit(Vec<ControllerSlotSummary>),
    UnknownController,
    AlreadyRevoked,
    DuplicateKid,
    ApprovalRejected(IdentityApprovalError),
    Transport(anyhow::Error),
}

impl From<CommitWithApprovalError> for ControllerRegistryServiceError {
    fn from(error: CommitWithApprovalError) -> Self {
        match error {
            CommitWithApprovalError::Approval(inner) => Self::ApprovalRejected(inner),
            CommitWithApprovalError::Mutation(ControllerRegistryError::SlotLimit(summaries)) => {
                Self::SlotLimit(summaries)
            }
            CommitWithApprovalError::Mutation(ControllerRegistryError::UnknownController) => {
                Self::UnknownController
            }
            CommitWithApprovalError::Mutation(ControllerRegistryError::AlreadyRevoked) => {
                Self::AlreadyRevoked
            }
            CommitWithApprovalError::Mutation(ControllerRegistryError::DuplicateKid) => {
                Self::DuplicateKid
            }
            CommitWithApprovalError::Mutation(ControllerRegistryError::InvalidIdentity(reason)) => {
                Self::Invalid(reason)
            }
            CommitWithApprovalError::Mutation(ControllerRegistryError::Transport(inner))
            | CommitWithApprovalError::Transport(inner) => Self::Transport(inner),
        }
    }
}

impl From<ControllerRegistryError> for ControllerRegistryServiceError {
    fn from(error: ControllerRegistryError) -> Self {
        match error {
            ControllerRegistryError::SlotLimit(summaries) => Self::SlotLimit(summaries),
            ControllerRegistryError::UnknownController => Self::UnknownController,
            ControllerRegistryError::AlreadyRevoked => Self::AlreadyRevoked,
            ControllerRegistryError::DuplicateKid => Self::DuplicateKid,
            ControllerRegistryError::InvalidIdentity(reason) => Self::Invalid(reason),
            ControllerRegistryError::Transport(inner) => Self::Transport(inner),
        }
    }
}

/// Service facade over the registry repository.  Cheap to clone.
#[derive(Clone)]
pub struct ControllerRegistryService {
    repository: Arc<dyn ControllerRegistryPort>,
    deployment_id: String,
}

fn ensure_local_deployment(
    local_deployment_id: &str,
    caller_deployment_id: &str,
) -> Result<(), ControllerRegistryServiceError> {
    if caller_deployment_id != local_deployment_id {
        return Err(ControllerRegistryServiceError::Invalid(
            "deployment_id 与当前部署不匹配.",
        ));
    }
    Ok(())
}

impl ControllerRegistryService {
    #[must_use]
    pub fn new(repository: Arc<dyn ControllerRegistryPort>, deployment_id: &str) -> Self {
        Self {
            repository,
            deployment_id: deployment_id.to_owned(),
        }
    }

    fn ensure_local_deployment(
        &self,
        deployment_id: &str,
    ) -> Result<(), ControllerRegistryServiceError> {
        ensure_local_deployment(&self.deployment_id, deployment_id)
    }

    /// Issue an approval for this exact payload after the HTTP boundary's
    /// fresh-MFA check. Approval and required audit share one transaction.
    pub async fn issue_approval_with_required_audit(
        &self,
        audit: nazo_persistence::control_plane::AdminIdentityAudit,
        change: &IdentityChange,
        now: DateTime<Utc>,
    ) -> Result<IssuedIdentityApproval, ControllerRegistryServiceError> {
        self.ensure_local_deployment(change.deployment_id())?;
        change.validate()?;
        self.repository
            .issue_identity_approval_with_required_audit(
                nazo_persistence::control_plane::IdentityApprovalCommand {
                    deployment_id: change.deployment_id().to_owned(),
                    action: change.action(),
                    action_sha256: change.action_sha256(),
                    now,
                },
                audit,
            )
            .await
            .map_err(|error| ControllerRegistryServiceError::Transport(error.into()))
    }

    /// Consume an approval and commit its exact identity change with required
    /// audit. Each request is decoded once, then moved into the storage command.
    pub async fn commit_with_required_audit(
        &self,
        approval_token: String,
        change: IdentityChange,
        now: DateTime<Utc>,
        audit: nazo_persistence::control_plane::AdminIdentityAudit,
    ) -> Result<StoredControllerSlot, ControllerRegistryServiceError> {
        self.ensure_local_deployment(change.deployment_id())?;
        let action = change.action();
        let action_sha256 = change.action_sha256();
        let committed = match change {
            IdentityChange::Bind(request) | IdentityChange::Add(request) => {
                let (public_key, recovery_key) =
                    request.validate(action == ControllerIdentityAction::Bind)?;
                let initial_root = recovery_key.map(|public_key| NewRecoveryRoot {
                    deployment_id: request.deployment_id.clone(),
                    kid: request.recovery_kid.expect("validated bind recovery key"),
                    public_key,
                });
                self.repository
                    .commit_slot_creation_with_required_audit(
                        nazo_persistence::control_plane::SlotCreationCommand {
                            approval_token,
                            action,
                            action_sha256,
                            slot: NewControllerSlot {
                                deployment_id: request.deployment_id,
                                label: request.label,
                                kid: request.kid,
                                public_key,
                            },
                            initial_root,
                            now,
                        },
                        audit,
                    )
                    .await
            }
            IdentityChange::Rotate(request) => {
                let public_key = request.validate()?;
                self.repository
                    .commit_slot_rotation_with_required_audit(
                        nazo_persistence::control_plane::SlotRotationCommand {
                            approval_token,
                            deployment_id: request.deployment_id.clone(),
                            action_sha256,
                            rotation: RotateControllerKey {
                                deployment_id: request.deployment_id,
                                controller_id: request.controller_id,
                                label: request.label,
                                kid: request.kid,
                                public_key,
                            },
                            now,
                        },
                        audit,
                    )
                    .await
            }
            IdentityChange::Revoke(request) => {
                request.validate()?;
                self.repository
                    .commit_slot_revocation_with_required_audit(
                        nazo_persistence::control_plane::SlotRevocationCommand {
                            approval_token,
                            deployment_id: request.deployment_id,
                            action_sha256,
                            controller_id: request.controller_id,
                            now,
                        },
                        audit,
                    )
                    .await
            }
        }?;
        Ok(committed)
    }

    /// Authoritative answer to "which controllers exist for this deployment
    /// and when do they expire".  Includes revoked history rows.
    pub async fn list_slots(
        &self,
        deployment_id: &str,
    ) -> Result<Vec<StoredControllerSlot>, ControllerRegistryServiceError> {
        self.ensure_local_deployment(deployment_id)?;
        Ok(self.repository.list_slots(deployment_id).await?)
    }
}

fn decode_public_key(text: &str) -> Result<[u8; 32], ControllerRegistryServiceError> {
    let mut key = [0; 32];
    if matches!(URL_SAFE_NO_PAD.decode_slice(text, &mut key), Ok(32)) {
        Ok(key)
    } else {
        Err(ControllerRegistryServiceError::Invalid(
            "public_key 必须是 32 字节 Ed25519 公钥的未填充 base64url 编码.",
        ))
    }
}

/// P0-3: shape + binding check for the recovery material a bind carries.
fn validate_recovery_binding(
    recovery_public_key: &str,
    recovery_kid: &str,
) -> Result<[u8; 32], ControllerRegistryServiceError> {
    let key = decode_public_key(recovery_public_key)?;
    let digest = URL_SAFE_NO_PAD.encode(Sha256::digest(key));
    if digest != recovery_kid {
        return Err(ControllerRegistryServiceError::Invalid(
            "recovery_kid 与 recovery_public_key 不匹配.",
        ));
    }
    Ok(key)
}

#[cfg(test)]
#[path = "../tests/unit/controller_registry.rs"]
mod tests;
