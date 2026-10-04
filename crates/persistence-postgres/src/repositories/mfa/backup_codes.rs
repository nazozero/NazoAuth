use super::{MfaAuditError, MfaRepository, mfa_event};
use crate::{
    get_conn, pool::DiscardOnDrop, repositories::audit::insert_identity_security_event,
    schema::user_mfa_backup_codes,
};
use diesel::{ExpressionMethods, OptionalExtension, QueryDsl};
use diesel_async::{AsyncConnection, RunQueryDsl};
use nazo_identity::{
    IdentitySecurityEventType, IdentitySecurityOutcome, IdentitySecurityReason, TenantId, UserId,
    mfa::MFA_BACKUP_CODE_COUNT,
    ports::{BackupCodeCandidate, EncodedSecretHash, RepositoryError},
};

impl MfaRepository {
    pub async fn backup_code_candidates(
        &self,
        tenant_id: TenantId,
        user_id: UserId,
    ) -> Result<Vec<BackupCodeCandidate>, RepositoryError> {
        let mut connection = get_conn(&self.pool)
            .await
            .map_err(|_| RepositoryError::Unavailable)?;
        let rows = user_mfa_backup_codes::table
            .filter(user_mfa_backup_codes::tenant_id.eq(tenant_id.as_uuid()))
            .filter(user_mfa_backup_codes::user_id.eq(user_id.as_uuid()))
            .filter(user_mfa_backup_codes::used_at.is_null())
            .select((user_mfa_backup_codes::id, user_mfa_backup_codes::code_hash))
            .limit(i64::try_from(MFA_BACKUP_CODE_COUNT + 1).expect("backup-code limit fits i64"))
            .load::<(uuid::Uuid, String)>(&mut connection)
            .await
            .map_err(|error| RepositoryError::Unexpected(error.to_string()))?;
        if rows.len() > MFA_BACKUP_CODE_COUNT {
            return Err(RepositoryError::Consistency(
                "persisted backup-code count exceeds the supported maximum".to_owned(),
            ));
        }
        rows.into_iter()
            .map(|(id, hash)| {
                EncodedSecretHash::new(hash)
                    .map(|hash| BackupCodeCandidate { id, hash })
                    .map_err(|_| {
                        RepositoryError::Consistency(
                            "persisted backup-code hash is empty".to_owned(),
                        )
                    })
            })
            .collect()
    }

    pub async fn consume_backup_code_candidate(
        &self,
        tenant_id: TenantId,
        user_id: UserId,
        candidate_id: uuid::Uuid,
    ) -> Result<Option<uuid::Uuid>, RepositoryError> {
        let mut connection = get_conn(&self.pool)
            .await
            .map_err(|_| RepositoryError::Unavailable)?;
        connection
            .transaction::<Option<uuid::Uuid>, MfaAuditError, _>(async |connection| {
                #[derive(diesel::QueryableByName)]
                struct Generation { #[diesel(sql_type = diesel::sql_types::Uuid)] id: uuid::Uuid }
                let generation = diesel::sql_query("UPDATE user_mfa_backup_codes AS backup SET used_at=CURRENT_TIMESTAMP FROM user_totp_credentials AS totp WHERE backup.id=$1 AND backup.tenant_id=$2 AND backup.user_id=$3 AND backup.used_at IS NULL AND totp.tenant_id=backup.tenant_id AND totp.user_id=backup.user_id AND totp.confirmed_at IS NOT NULL RETURNING totp.id")
                    .bind::<diesel::sql_types::Uuid,_>(candidate_id).bind::<diesel::sql_types::Uuid,_>(tenant_id.as_uuid()).bind::<diesel::sql_types::Uuid,_>(user_id.as_uuid())
                    .get_result::<Generation>(connection).await.optional()?.map(|row| row.id);
                let changed = generation.is_some();
                insert_identity_security_event(
                    connection,
                    &mfa_event(
                        tenant_id,
                        user_id,
                        IdentitySecurityEventType::MfaBackupCodeAttempt,
                        if changed {
                            IdentitySecurityOutcome::Success
                        } else {
                            IdentitySecurityOutcome::Replay
                        },
                        if changed {
                            IdentitySecurityReason::BackupCodeAccepted
                        } else {
                            IdentitySecurityReason::BackupCodeReplay
                        },
                    ),
                )
                .await
                .map_err(MfaAuditError::Repository)?;
                Ok(generation)
            })
            .await
            .map_err(MfaAuditError::into_repository)
    }

    pub async fn record_invalid_backup_code_attempt(
        &self,
        tenant_id: TenantId,
        user_id: UserId,
    ) -> Result<(), RepositoryError> {
        let mut connection = get_conn(&self.pool)
            .await
            .map_err(|_| RepositoryError::Unavailable)?;
        insert_identity_security_event(
            &mut connection,
            &mfa_event(
                tenant_id,
                user_id,
                IdentitySecurityEventType::MfaBackupCodeAttempt,
                IdentitySecurityOutcome::InvalidCredential,
                IdentitySecurityReason::BackupCodeInvalid,
            ),
        )
        .await
    }
    pub async fn replace_backup_code_hashes(
        &self,
        tenant_id: TenantId,
        user_id: UserId,
        credential_id: uuid::Uuid,
        hashes: Vec<String>,
    ) -> Result<bool, RepositoryError> {
        self.replace_backup_code_hashes_owned(tenant_id, user_id, credential_id, hashes, None)
            .await
    }

    pub async fn replace_backup_code_hashes_with_required_audit(
        &self,
        tenant_id: TenantId,
        user_id: UserId,
        credential_id: uuid::Uuid,
        hashes: Vec<String>,
        source_ip_hash: String,
    ) -> Result<bool, RepositoryError> {
        self.replace_backup_code_hashes_owned(
            tenant_id,
            user_id,
            credential_id,
            hashes,
            Some(source_ip_hash),
        )
        .await
    }

    async fn replace_backup_code_hashes_owned(
        &self,
        tenant_id: TenantId,
        user_id: UserId,
        credential_id: uuid::Uuid,
        hashes: Vec<String>,
        source_ip_hash: Option<String>,
    ) -> Result<bool, RepositoryError> {
        validate_backup_hash_count(&hashes)?;
        let connection = get_conn(&self.pool)
            .await
            .map_err(|_| RepositoryError::Unavailable)?;
        let mut guard = DiscardOnDrop(Some(connection));
        let result = guard
            .connection()
            .transaction::<_, diesel::result::Error, _>(async move |connection| {
                let generation = crate::schema::user_totp_credentials::table
                    .filter(crate::schema::user_totp_credentials::tenant_id.eq(tenant_id.as_uuid()))
                    .filter(crate::schema::user_totp_credentials::user_id.eq(user_id.as_uuid()))
                    .filter(crate::schema::user_totp_credentials::id.eq(credential_id))
                    .filter(crate::schema::user_totp_credentials::confirmed_at.is_not_null())
                    .for_update()
                    .select(crate::schema::user_totp_credentials::id)
                    .first::<uuid::Uuid>(connection)
                    .await
                    .optional()?;
                if generation.is_none() {
                    return Ok(false);
                }
                diesel::delete(
                    user_mfa_backup_codes::table
                        .filter(user_mfa_backup_codes::tenant_id.eq(tenant_id.as_uuid()))
                        .filter(user_mfa_backup_codes::user_id.eq(user_id.as_uuid())),
                )
                .execute(connection)
                .await?;
                if !hashes.is_empty() {
                    let codes = hashes
                        .into_iter()
                        .map(|hash| {
                            (
                                user_mfa_backup_codes::tenant_id.eq(tenant_id.as_uuid()),
                                user_mfa_backup_codes::user_id.eq(user_id.as_uuid()),
                                user_mfa_backup_codes::code_hash.eq(hash),
                            )
                        })
                        .collect::<Vec<_>>();
                    diesel::insert_into(user_mfa_backup_codes::table)
                        .values(&codes)
                        .execute(connection)
                        .await?;
                }
                if let Some(source_ip_hash) = source_ip_hash {
                    // Preserve generation -> dependent -> self-principal lock
                    // order, matching confirmation and disable accepting owners.
                    let active = crate::schema::users::table
                        .find(user_id.as_uuid())
                        .filter(crate::schema::users::tenant_id.eq(tenant_id.as_uuid()))
                        .filter(crate::schema::users::is_active.eq(true))
                        .filter(crate::schema::users::mfa_enabled.eq(true))
                        .for_update()
                        .select(crate::schema::users::id)
                        .first::<uuid::Uuid>(connection)
                        .await
                        .optional()?;
                    if active.is_none() {
                        return Err(diesel::result::Error::RollbackTransaction);
                    }
                    super::append_required_mfa_outcome(
                        connection,
                        tenant_id,
                        user_id,
                        credential_id,
                        "mfa_backup_codes_regenerated",
                        source_ip_hash,
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

pub(super) fn validate_backup_hash_count(hashes: &[String]) -> Result<(), RepositoryError> {
    if hashes.len() > MFA_BACKUP_CODE_COUNT {
        Err(RepositoryError::Conflict)
    } else {
        Ok(())
    }
}
