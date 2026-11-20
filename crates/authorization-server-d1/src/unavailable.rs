//! Explicit unavailable capabilities outside the initial Workers deployment profile.
//! No unsupported read is represented as an empty successful result.

pub(crate) struct Unavailable;

impl nazo_identity::ports::AvatarUploadStatePort for Unavailable {
    fn create<'a>(
        &'a self,
        _authorization: &'a nazo_identity::ports::AvatarUploadAuthorization,
        _ttl_seconds: u64,
    ) -> nazo_identity::ports::RepositoryFuture<'a, ()> {
        Box::pin(async { Err(nazo_identity::ports::RepositoryError::Unavailable) })
    }

    fn claim<'a>(
        &'a self,
        _user_id: nazo_identity::UserId,
        _upload_id: &'a str,
        _lease_until: jiff::Timestamp,
    ) -> nazo_identity::ports::RepositoryFuture<'a, nazo_identity::ports::AvatarUploadClaim> {
        Box::pin(async { Err(nazo_identity::ports::RepositoryError::Unavailable) })
    }

    fn record_candidate<'a>(
        &'a self,
        _user_id: nazo_identity::UserId,
        _upload_id: &'a str,
        _ownership_token: &'a str,
        _staged_version: &'a str,
        _final_object_id: &'a str,
    ) -> nazo_identity::ports::RepositoryFuture<'a, bool> {
        Box::pin(async { Err(nazo_identity::ports::RepositoryError::Unavailable) })
    }

    fn complete<'a>(
        &'a self,
        _user_id: nazo_identity::UserId,
        _upload_id: &'a str,
        _ownership_token: &'a str,
        _final_object_id: &'a str,
    ) -> nazo_identity::ports::RepositoryFuture<'a, bool> {
        Box::pin(async { Err(nazo_identity::ports::RepositoryError::Unavailable) })
    }

    fn release<'a>(
        &'a self,
        _user_id: nazo_identity::UserId,
        _upload_id: &'a str,
        _ownership_token: &'a str,
    ) -> nazo_identity::ports::RepositoryFuture<'a, bool> {
        Box::pin(async { Err(nazo_identity::ports::RepositoryError::Unavailable) })
    }
}

impl nazo_persistence::TenantDirectoryStore for Unavailable {
    fn current_revision(
        &self,
    ) -> futures_util::future::BoxFuture<'_, Result<u64, nazo_identity::ports::RepositoryError>>
    {
        Box::pin(async { Err(nazo_identity::ports::RepositoryError::Unavailable) })
    }

    fn load_active(
        &self,
    ) -> futures_util::future::BoxFuture<
        '_,
        Result<nazo_identity::TenantDirectorySnapshot, nazo_identity::ports::RepositoryError>,
    > {
        Box::pin(async { Err(nazo_identity::ports::RepositoryError::Unavailable) })
    }

    fn find_active_binding(
        &self,
        _tenant_id: nazo_identity::TenantId,
    ) -> futures_util::future::BoxFuture<
        '_,
        Result<
            Option<nazo_identity::TenantDirectoryBinding>,
            nazo_identity::ports::RepositoryError,
        >,
    > {
        Box::pin(async { Err(nazo_identity::ports::RepositoryError::Unavailable) })
    }
}

impl nazo_persistence::ControllerRegistryPort for Unavailable {
    fn renew_controller_key(
        &self,
        _deployment_id: String,
        _controller_id: String,
        _previous_kid: String,
        _public_key: [u8; 32],
        _now: jiff::Timestamp,
    ) -> futures_util::future::BoxFuture<
        '_,
        Result<Option<String>, nazo_persistence::ControllerRegistryError>,
    > {
        Box::pin(async {
            Err(nazo_persistence::ControllerRegistryError::Transport(
                anyhow::anyhow!("capability is unavailable in the Workers profile"),
            ))
        })
    }

    fn issue_identity_approval_with_required_audit(
        &self,
        _command: nazo_persistence::IdentityApprovalCommand,
        _audit: nazo_persistence::AdminIdentityAudit,
    ) -> futures_util::future::BoxFuture<
        '_,
        Result<nazo_persistence::IssuedIdentityApproval, nazo_persistence::IdentityApprovalError>,
    > {
        Box::pin(async {
            Err(nazo_persistence::IdentityApprovalError::Transport(
                anyhow::anyhow!("capability is unavailable in the Workers profile"),
            ))
        })
    }

    fn commit_slot_creation_with_required_audit(
        &self,
        _command: nazo_persistence::SlotCreationCommand,
        _audit: nazo_persistence::AdminIdentityAudit,
    ) -> futures_util::future::BoxFuture<
        '_,
        Result<nazo_persistence::StoredControllerSlot, nazo_persistence::CommitWithApprovalError>,
    > {
        Box::pin(async {
            Err(nazo_persistence::CommitWithApprovalError::Transport(
                anyhow::anyhow!("capability is unavailable in the Workers profile"),
            ))
        })
    }

    fn commit_slot_rotation_with_required_audit(
        &self,
        _command: nazo_persistence::SlotRotationCommand,
        _audit: nazo_persistence::AdminIdentityAudit,
    ) -> futures_util::future::BoxFuture<
        '_,
        Result<nazo_persistence::StoredControllerSlot, nazo_persistence::CommitWithApprovalError>,
    > {
        Box::pin(async {
            Err(nazo_persistence::CommitWithApprovalError::Transport(
                anyhow::anyhow!("capability is unavailable in the Workers profile"),
            ))
        })
    }

    fn commit_slot_revocation_with_required_audit(
        &self,
        _command: nazo_persistence::SlotRevocationCommand,
        _audit: nazo_persistence::AdminIdentityAudit,
    ) -> futures_util::future::BoxFuture<
        '_,
        Result<nazo_persistence::StoredControllerSlot, nazo_persistence::CommitWithApprovalError>,
    > {
        Box::pin(async {
            Err(nazo_persistence::CommitWithApprovalError::Transport(
                anyhow::anyhow!("capability is unavailable in the Workers profile"),
            ))
        })
    }

    fn list_slots<'a>(
        &'a self,
        _deployment_id: &'a str,
    ) -> futures_util::future::BoxFuture<
        'a,
        Result<
            Vec<nazo_persistence::StoredControllerSlot>,
            nazo_persistence::ControllerRegistryError,
        >,
    > {
        Box::pin(async {
            Err(nazo_persistence::ControllerRegistryError::Transport(
                anyhow::anyhow!("capability is unavailable in the Workers profile"),
            ))
        })
    }

    fn admitted_controllers<'a>(
        &'a self,
        _deployment_id: &'a str,
        _now: jiff::Timestamp,
    ) -> futures_util::future::BoxFuture<
        'a,
        Result<
            Vec<nazo_persistence::AdmittedController>,
            nazo_persistence::ControllerRegistryError,
        >,
    > {
        Box::pin(async {
            Err(nazo_persistence::ControllerRegistryError::Transport(
                anyhow::anyhow!("capability is unavailable in the Workers profile"),
            ))
        })
    }

    fn admitted_controller_by_kid<'a>(
        &'a self,
        _deployment_id: &'a str,
        _kid: &'a str,
        _now: jiff::Timestamp,
    ) -> futures_util::future::BoxFuture<
        'a,
        Result<
            Option<nazo_persistence::AdmittedController>,
            nazo_persistence::ControllerRegistryError,
        >,
    > {
        Box::pin(async {
            Err(nazo_persistence::ControllerRegistryError::Transport(
                anyhow::anyhow!("capability is unavailable in the Workers profile"),
            ))
        })
    }
}

impl nazo_persistence::RecoveryRootPort for Unavailable {
    fn issue_rotation_approval_with_required_audit(
        &self,
        _command: nazo_persistence::RecoveryApprovalCommand,
        _audit: nazo_persistence::AdminIdentityAudit,
    ) -> futures_util::future::BoxFuture<
        '_,
        Result<nazo_persistence::IssuedIdentityApproval, nazo_persistence::RecoveryRotationError>,
    > {
        Box::pin(async {
            Err(nazo_persistence::RecoveryRotationError::Transport(
                anyhow::anyhow!("capability is unavailable in the Workers profile"),
            ))
        })
    }

    fn commit_rotation_with_required_audit(
        &self,
        _command: nazo_persistence::RecoveryRotationCommand,
        _audit: nazo_persistence::AdminIdentityAudit,
    ) -> futures_util::future::BoxFuture<
        '_,
        Result<nazo_persistence::StoredRecoveryRoot, nazo_persistence::RecoveryRotationError>,
    > {
        Box::pin(async {
            Err(nazo_persistence::RecoveryRotationError::Transport(
                anyhow::anyhow!("capability is unavailable in the Workers profile"),
            ))
        })
    }

    fn current_root<'a>(
        &'a self,
        _deployment_id: &'a str,
    ) -> futures_util::future::BoxFuture<
        'a,
        Result<Option<nazo_persistence::StoredRecoveryRoot>, nazo_persistence::RecoveryRootError>,
    > {
        Box::pin(async {
            Err(nazo_persistence::RecoveryRootError::Transport(
                anyhow::anyhow!("capability is unavailable in the Workers profile"),
            ))
        })
    }

    fn issue_recovery_challenge(
        &self,
        _challenge: nazo_persistence::NewRecoveryChallenge,
        _now: jiff::Timestamp,
    ) -> futures_util::future::BoxFuture<
        '_,
        Result<nazo_persistence::IssuedRecoveryChallenge, nazo_persistence::RecoveryRootError>,
    > {
        Box::pin(async {
            Err(nazo_persistence::RecoveryRootError::Transport(
                anyhow::anyhow!("capability is unavailable in the Workers profile"),
            ))
        })
    }

    fn submit_recovery_challenge(
        &self,
        _submission: nazo_persistence::RecoverySubmission,
        _now: jiff::Timestamp,
    ) -> futures_util::future::BoxFuture<
        '_,
        Result<nazo_persistence::RecoveredSlotCommit, nazo_persistence::RecoveryRootError>,
    > {
        Box::pin(async {
            Err(nazo_persistence::RecoveryRootError::Transport(
                anyhow::anyhow!("capability is unavailable in the Workers profile"),
            ))
        })
    }
}

impl nazo_oauth_server::ports::transient_state::TenantDirectoryCachePort for Unavailable {
    fn load(
        &self,
    ) -> nazo_oauth_server::ports::transient_state::TransientStateFuture<
        '_,
        Option<std::sync::Arc<nazo_identity::TenantDirectorySnapshot>>,
    > {
        Box::pin(async {
            Err(nazo_oauth_server::ports::transient_state::TransientStateError::Unavailable)
        })
    }

    fn publish_authoritative<'a>(
        &'a self,
        _snapshot: &'a nazo_identity::TenantDirectorySnapshot,
    ) -> nazo_oauth_server::ports::transient_state::TransientStateFuture<'a, bool> {
        Box::pin(async {
            Err(nazo_oauth_server::ports::transient_state::TransientStateError::Unavailable)
        })
    }
}
