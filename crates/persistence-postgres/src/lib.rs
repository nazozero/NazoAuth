#![forbid(unsafe_code)]

//! PostgreSQL repository adapters for NazoAuth.
//!
//! Persistence records and Diesel schema are intentionally private:
//!
//! ```compile_fail
//! use nazo_postgres::schema::users;
//! ```
//!
//! ```compile_fail
//! use nazo_postgres::rows::identity::UserRow;
//! ```

mod convert;
mod pool;
mod repositories;
pub(crate) mod rows;
pub(crate) mod schema;
mod tenant_resource_executor;

pub use pool::{
    DbConnection, DbPool, DbPoolMetrics, configure_runtime_role, create_pool, db_pool_metrics,
    get_conn, health_check, run_pending_migrations,
};
pub use repositories::{
    AccessRequestRepository, ActiveTenantBoundaryRepository, AdminProvisionError,
    AdminProvisionReceipt, AdminProvisionRepository, AdminProvisionRequest, AdmittedController,
    AdmittedControllerSummary, AuditLedgerRepository, AuditRepository, AuthorizationFlowRepository,
    AuthorizationRepository, CONTROLLER_KEY_TTL_SECONDS, CommitWithApprovalError,
    ControllerIdentityAction, ControllerRegistryError, ControllerRegistryRepository,
    ControllerSlotStatus, ControllerSlotSummary, DEPLOYMENT_IDENTITY_LOCK_SEED,
    FederationRepository, GrantAuthorization, GrantRepository, IDENTITY_APPROVAL_TTL_SECONDS,
    IdentityApprovalError, IssuedIdentityApproval, IssuedRecoveryChallenge,
    MAX_ACTIVE_CONTROLLER_SLOTS, MAX_RECOVERY_CHALLENGE_ATTEMPTS, MAX_SECURITY_AUDIT_PAYLOAD_BYTES,
    ManagedCredentialDataset, ManagedCredentialDatasetWrite, MfaRepository,
    MtlsTrustAnchorRepository, NewControllerSlot, NewRecoveryChallenge, NewRecoveryRoot,
    NewStoredOpenid4vcTrustPolicy, NewTenantResourceBinding, OAuthClientRepository,
    Openid4vcTrustPolicyClientBind, Openid4vcTrustPolicyForClient, Openid4vcTrustPolicyRevoke,
    Openid4vcTrustPolicyWrite, Openid4vciDatasetRepository, Openid4vciRepository,
    Openid4vpRepository, OperatorManagedTrustAnchor, PasskeyRepository,
    RECOVERY_CHALLENGE_TTL_SECONDS, RecoveredSlotCommit, RecoveryInvalidation, RecoveryRootError,
    RecoveryRootRepository, RecoveryRootSummary, RecoveryRotationError, RecoverySubmission,
    RotateControllerKey, RuntimeModuleEventPage, RuntimeModuleRepository, ScimEventRepository,
    ScimRepository, SecurityAuditAnchorHealth, SecurityAuditEvent, SecurityAuditPendingDelivery,
    SecurityStateMaintenanceRepository, SigningKeysetRepository, StoredControllerSlot,
    StoredOpenid4vcTrustPolicy, StoredRecoveryRoot, TenantBoundaryDefinition,
    TenantDirectoryControlRepository, TenantDirectoryRepository, TenantProvisioningRequest,
    TenantResourceBinding, TenantResourceBindingDeactivate, TenantResourceRepository,
    TenantResourceState, TenantResourceStateCas, TenantRuntimeStatus, TokenIssuanceRepository,
    TokenRepository, UserInsert, UserRepository, active_public_client_id_on_connection,
    append_fresh_security_audit_on_connection, deactivate_client_on_connection,
    delete_operator_managed_dataset_on_connection, disable_user_on_connection,
    insert_client_on_connection, insert_operator_managed_trust_anchor_on_connection,
    insert_user_on_connection, protect_dataset_claims,
    revoke_operator_managed_trust_anchor_on_connection, unprotect_dataset_claims,
    upsert_operator_managed_dataset_on_connection,
};
pub use tenant_resource_executor::PostgresTenantResourceExecutor;

#[derive(Clone)]
pub struct PostgresHealthCheck {
    pool: DbPool,
}

impl PostgresHealthCheck {
    #[must_use]
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }
}

impl nazo_persistence::DatabaseHealthPort for PostgresHealthCheck {
    fn check(
        &self,
    ) -> futures_util::future::BoxFuture<'_, Result<(), nazo_persistence::DatabaseHealthError>>
    {
        Box::pin(async {
            health_check(&self.pool)
                .await
                .map_err(|_| nazo_persistence::DatabaseHealthError)
        })
    }
}

#[derive(Clone)]
pub struct PostgresPoolMetrics {
    pool: DbPool,
}

impl PostgresPoolMetrics {
    #[must_use]
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }
}

impl nazo_persistence::DatabasePoolMetricsPort for PostgresPoolMetrics {
    fn snapshot(&self) -> nazo_persistence::DatabasePoolMetrics {
        let metrics = db_pool_metrics();
        let status = self.pool.status();
        nazo_persistence::DatabasePoolMetrics {
            acquire_count: metrics.acquire_count,
            wait_nanos_total: metrics.wait_nanos_total,
            wait_nanos_max: metrics.wait_nanos_max,
            connections: Some(status.size as u64),
            idle_connections: Some(status.available as u64),
            waiting_acquisitions: Some(status.waiting as u64),
        }
    }
}

impl nazo_persistence::SecurityAuditLedger for AuditLedgerRepository {
    fn check_available(
        &self,
        require_least_privilege: bool,
    ) -> futures_util::future::BoxFuture<'_, Result<(), nazo_identity::ports::RepositoryError>>
    {
        Box::pin(async move {
            self.check_available_with_policy(require_least_privilege)
                .await
        })
    }

    fn anchor_health(
        &self,
    ) -> futures_util::future::BoxFuture<
        '_,
        Result<nazo_persistence::SecurityAuditAnchorHealth, nazo_identity::ports::RepositoryError>,
    > {
        Box::pin(async move { AuditLedgerRepository::anchor_health(self).await })
    }

    fn append(
        &self,
        event: nazo_persistence::SecurityAuditEvent,
    ) -> futures_util::future::BoxFuture<'_, Result<(), nazo_identity::ports::RepositoryError>>
    {
        Box::pin(async move { AuditLedgerRepository::append(self, event).await })
    }

    fn append_batch<'a>(
        &'a self,
        events: &'a [nazo_persistence::SecurityAuditEvent],
    ) -> futures_util::future::BoxFuture<'a, Result<(), nazo_identity::ports::RepositoryError>>
    {
        Box::pin(async move { AuditLedgerRepository::append_batch(self, events).await })
    }
}

impl nazo_persistence::SecurityAuditExporter for AuditLedgerRepository {
    fn check_available(
        &self,
    ) -> futures_util::future::BoxFuture<'_, Result<(), nazo_identity::ports::RepositoryError>>
    {
        Box::pin(async move { self.check_exporter_available().await })
    }

    fn anchor_health(
        &self,
    ) -> futures_util::future::BoxFuture<
        '_,
        Result<nazo_persistence::SecurityAuditAnchorHealth, nazo_identity::ports::RepositoryError>,
    > {
        Box::pin(async move { AuditLedgerRepository::anchor_health(self).await })
    }

    fn observe_anchor<'a>(
        &'a self,
        deployment_id: &'a str,
    ) -> futures_util::future::BoxFuture<'a, Result<(), nazo_identity::ports::RepositoryError>>
    {
        Box::pin(async move { AuditLedgerRepository::observe_anchor(self, deployment_id).await })
    }

    fn record_genesis<'a>(
        &'a self,
        deployment_id: &'a str,
        head_hash: &'a [u8],
    ) -> futures_util::future::BoxFuture<'a, Result<(), nazo_identity::ports::RepositoryError>>
    {
        Box::pin(async move {
            AuditLedgerRepository::record_genesis(self, deployment_id, head_hash).await
        })
    }

    fn claim_batch<'a>(
        &'a self,
        deployment_id: &'a str,
        limit: i64,
        max_envelope_bytes: i64,
        lock_timeout_seconds: i32,
    ) -> futures_util::future::BoxFuture<
        'a,
        Result<nazo_persistence::SecurityAuditBatchClaim, nazo_identity::ports::RepositoryError>,
    > {
        Box::pin(async move {
            AuditLedgerRepository::claim_batch(
                self,
                deployment_id,
                limit,
                max_envelope_bytes,
                lock_timeout_seconds,
            )
            .await
        })
    }

    fn ack_batch<'a>(
        &'a self,
        ack: nazo_persistence::SecurityAuditBatchAck,
    ) -> futures_util::future::BoxFuture<'a, Result<(), nazo_identity::ports::RepositoryError>>
    {
        Box::pin(async move { AuditLedgerRepository::ack_batch(self, ack).await })
    }

    fn fail_batch<'a>(
        &'a self,
        generation: i64,
        available_at: chrono::DateTime<chrono::Utc>,
        last_error: &'a str,
        blocked: bool,
    ) -> futures_util::future::BoxFuture<'a, Result<(), nazo_identity::ports::RepositoryError>>
    {
        Box::pin(async move {
            AuditLedgerRepository::fail_batch(self, generation, available_at, last_error, blocked)
                .await
        })
    }
}
