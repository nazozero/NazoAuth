use crate::{
    DbPool, get_conn,
    pool::DiscardOnDrop,
    schema::{user_mfa_backup_codes, user_mfa_remembered_devices, user_totp_credentials, users},
};
use diesel::{ExpressionMethods, QueryDsl, dsl::now};
use diesel_async::RunQueryDsl;
use nazo_identity::{
    IdentitySecurityEvent, IdentitySecurityEventType, IdentitySecurityOutcome,
    IdentitySecurityReason, TenantId, UserId, ports::RepositoryError,
};

mod backup_codes;
mod ports;
mod remembered_devices;
mod totp;

#[derive(Clone)]
pub struct MfaRepository {
    pool: DbPool,
    totp_keys: Option<crate::MfaTotpKeyRing>,
}

impl MfaRepository {
    #[must_use]
    pub fn new(pool: DbPool) -> Self {
        Self {
            pool,
            totp_keys: None,
        }
    }

    #[must_use]
    pub fn with_totp_key_ring(pool: DbPool, totp_keys: Option<crate::MfaTotpKeyRing>) -> Self {
        Self { pool, totp_keys }
    }

    pub async fn clear_mfa_state_if_current(
        &self,
        tenant_id: TenantId,
        user_id: UserId,
        credential_id: uuid::Uuid,
    ) -> Result<bool, RepositoryError> {
        self.clear_mfa_state_owned(tenant_id, user_id, credential_id, None)
            .await
    }

    pub async fn clear_mfa_state_if_current_with_required_audit(
        &self,
        tenant_id: TenantId,
        user_id: UserId,
        credential_id: uuid::Uuid,
        source_ip_hash: String,
    ) -> Result<bool, RepositoryError> {
        self.clear_mfa_state_owned(tenant_id, user_id, credential_id, Some(source_ip_hash))
            .await
    }

    async fn clear_mfa_state_owned(
        &self,
        tenant_id: TenantId,
        user_id: UserId,
        credential_id: uuid::Uuid,
        source_ip_hash: Option<String>,
    ) -> Result<bool, RepositoryError> {
        let mut guard = DiscardOnDrop(Some(
            get_conn(&self.pool)
                .await
                .map_err(|_| RepositoryError::Unavailable)?,
        ));
        let result = guard
            .connection()
            .build_transaction()
            .read_committed()
            .run::<_, diesel::result::Error, _>(async move |connection| {
                let cleared = diesel::delete(
                    user_totp_credentials::table
                        .filter(user_totp_credentials::tenant_id.eq(tenant_id.as_uuid()))
                        .filter(user_totp_credentials::user_id.eq(user_id.as_uuid()))
                        .filter(user_totp_credentials::id.eq(credential_id))
                        .filter(user_totp_credentials::confirmed_at.is_not_null()),
                )
                .execute(connection)
                .await?;
                if cleared == 0 {
                    return Ok(false);
                }
                diesel::delete(
                    user_mfa_backup_codes::table
                        .filter(user_mfa_backup_codes::tenant_id.eq(tenant_id.as_uuid()))
                        .filter(user_mfa_backup_codes::user_id.eq(user_id.as_uuid())),
                )
                .execute(connection)
                .await?;
                diesel::delete(
                    user_mfa_remembered_devices::table
                        .filter(user_mfa_remembered_devices::tenant_id.eq(tenant_id.as_uuid()))
                        .filter(user_mfa_remembered_devices::user_id.eq(user_id.as_uuid())),
                )
                .execute(connection)
                .await?;
                // Keep the established generation/dependent/user lock order.
                // The final active-account write holds its lock through audit
                // and ACK; a retired account rolls back every preceding delete.
                let updated = diesel::update(
                    users::table
                        .find(user_id.as_uuid())
                        .filter(users::tenant_id.eq(tenant_id.as_uuid()))
                        .filter(users::is_active.eq(true)),
                )
                .set((users::mfa_enabled.eq(false), users::updated_at.eq(now)))
                .execute(connection)
                .await?;
                if updated != 1 {
                    return Err(diesel::result::Error::RollbackTransaction);
                }
                if let Some(source_ip_hash) = source_ip_hash {
                    crate::repositories::audit_ledger::append_fresh_security_audit_on_connection(
                        connection,
                        &nazo_persistence::SecurityAuditEvent {
                            event_id: uuid::Uuid::now_v7(),
                            event_type: "mfa_disabled".to_owned(),
                            event_category: "authentication".to_owned(),
                            payload: serde_json::json!({
                                "schema_version": nazo_persistence::SECURITY_AUDIT_SCHEMA_VERSION,
                                "event_category": "authentication",
                                "tenant_id": tenant_id.as_uuid(), "user_id": user_id.as_uuid(),
                                "credential_id": credential_id, "outcome": "success",
                                "source_ip_hash": source_ip_hash,
                            }),
                            occurred_at: chrono::Utc::now(),
                        },
                    )
                    .await?;
                }
                Ok(true)
            })
            .await
            .map_err(|error| RepositoryError::Unexpected(error.to_string()));
        if result.is_ok() {
            guard.return_to_pool();
        }
        result
    }
}

fn mfa_event(
    tenant_id: TenantId,
    user_id: UserId,
    event_type: IdentitySecurityEventType,
    outcome: IdentitySecurityOutcome,
    reason: IdentitySecurityReason,
) -> IdentitySecurityEvent {
    IdentitySecurityEvent {
        tenant_id,
        event_type,
        outcome,
        actor_id: Some(user_id),
        target_user_id: Some(user_id),
        reason,
        occurred_at: std::time::SystemTime::now(),
    }
}

enum MfaAuditError {
    Diesel(diesel::result::Error),
    Repository(RepositoryError),
}

impl From<diesel::result::Error> for MfaAuditError {
    fn from(error: diesel::result::Error) -> Self {
        Self::Diesel(error)
    }
}

impl MfaAuditError {
    fn into_repository(self) -> RepositoryError {
        match self {
            Self::Diesel(error) => map_mfa_error(error),
            Self::Repository(error) => error,
        }
    }
}

pub(super) fn map_mfa_error(error: diesel::result::Error) -> RepositoryError {
    match error {
        diesel::result::Error::NotFound
        | diesel::result::Error::RollbackTransaction
        | diesel::result::Error::DatabaseError(
            diesel::result::DatabaseErrorKind::UniqueViolation,
            _,
        ) => RepositoryError::Conflict,
        other => RepositoryError::Unexpected(other.to_string()),
    }
}

#[cfg(test)]
#[path = "../../../tests/unit/repositories/mfa.rs"]
mod tests;

/// Canonical successful MFA mutation outcome on the existing accepting owner.
async fn append_required_mfa_outcome(
    connection: &mut diesel_async::AsyncPgConnection,
    tenant_id: TenantId,
    user_id: UserId,
    credential_id: uuid::Uuid,
    event_type: &'static str,
    source_ip_hash: String,
) -> Result<(), diesel::result::Error> {
    crate::repositories::audit_ledger::append_fresh_security_audit_on_connection(
        connection,
        &nazo_persistence::SecurityAuditEvent {
            event_id: uuid::Uuid::now_v7(),
            event_type: event_type.to_owned(),
            event_category: "authentication".to_owned(),
            payload: serde_json::json!({
                "schema_version": nazo_persistence::SECURITY_AUDIT_SCHEMA_VERSION,
                "event_category": "authentication", "tenant_id": tenant_id.as_uuid(),
                "user_id": user_id.as_uuid(), "actor_id": user_id.as_uuid(),
                "target_user_id": user_id.as_uuid(), "credential_id": credential_id,
                "outcome": "success", "source_ip_hash": source_ip_hash,
            }),
            occurred_at: chrono::Utc::now(),
        },
    )
    .await
}
