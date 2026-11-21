//! MFA persistence: shared TOTP policy, encrypted seeds and atomic one-use proofs.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use jiff::Timestamp;
use nazo_identity::{
    TenantId, UserId,
    mfa::{MFA_BACKUP_CODE_COUNT, verified_totp_step},
    ports::{
        BackupCodeCandidate, EncodedSecretHash, MfaRepositoryPort, RememberedMfaDevicePort,
        RepositoryError, RepositoryFuture, TotpEnrollmentCheck, TotpVerificationOutcome,
    },
};
use nazo_persistence::SecurityAuditEvent;
use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::{
    D1Provider,
    db::{DbError, Statement},
    persistence::{NOW, encode},
};

const KEY_ID: &str = "d1-data-key-v1";
const MAX_CAS_ATTEMPTS: usize = 8;
const CURRENT: &str = "EXISTS(SELECT 1 FROM nazo_mfa_totp AS totp JOIN nazo_users AS account ON account.tenant_id=totp.tenant_id AND account.id=totp.user_id WHERE totp.tenant_id=?1 AND totp.user_id=?2 AND totp.id=?3 AND totp.confirmed_at IS NOT NULL AND account.active=1)";

#[derive(Deserialize)]
struct TotpRow {
    id: Uuid,
    secret_ciphertext: String,
    secret_key_id: String,
    confirmed_at: Option<i64>,
    last_used_step: Option<i64>,
    version: Uuid,
    active: i64,
}

#[derive(Deserialize)]
struct IdRow {
    id: Uuid,
}

#[derive(Deserialize)]
struct BackupRow {
    id: Uuid,
    code_hash: String,
}

impl D1Provider {
    fn totp_key(&self) -> Result<Zeroizing<[u8; 32]>, RepositoryError> {
        let root = self.data_encryption_key.as_ref().ok_or_else(|| {
            RepositoryError::Consistency("MFA TOTP encryption key is not configured".into())
        })?;
        Ok(Zeroizing::new(blake3::derive_key(
            "NazoAuth D1 TOTP seed encryption v1",
            root.as_ref().as_ref(),
        )))
    }

    fn totp_aad(&self, user: UserId) -> Vec<u8> {
        // The envelope binds the seed to its tenant, account and key purpose.
        let mut aad = Vec::with_capacity(80);
        aad.extend_from_slice(b"nazo-totp-seed-v1");
        aad.extend_from_slice(self.tenant_id.as_bytes());
        aad.extend_from_slice(user.as_uuid().as_bytes());
        aad.extend_from_slice(&(KEY_ID.len() as u64).to_be_bytes());
        aad.extend_from_slice(KEY_ID.as_bytes());
        aad
    }

    fn protect_totp(&self, user: UserId, secret: &str) -> Result<String, RepositoryError> {
        if secret.trim().len() < 16 || secret.len() > 128 {
            return Err(RepositoryError::Consistency(
                "invalid TOTP seed length".into(),
            ));
        }
        let nonce = rand::random::<[u8; 12]>();
        let mut prefix = [1_u8; 13];
        prefix[1..].copy_from_slice(&nonce);
        let protected = nazo_crypto::aead::encrypt_prefixed(
            &*self.totp_key()?,
            &nonce,
            &self.totp_aad(user),
            secret.as_bytes(),
            &prefix,
        )
        .map_err(|_| RepositoryError::Consistency("TOTP seed encryption failed".into()))?;
        Ok(URL_SAFE_NO_PAD.encode(protected))
    }

    fn verified_step(
        &self,
        user: UserId,
        row: &TotpRow,
        code: &str,
        timestamp: i64,
        last_step: Option<i64>,
    ) -> Result<Option<i64>, RepositoryError> {
        let key = self.totp_key()?;
        if row.secret_key_id != KEY_ID {
            return Err(RepositoryError::Consistency(
                "unknown TOTP key version".into(),
            ));
        }
        let mut protected = Zeroizing::new(
            URL_SAFE_NO_PAD
                .decode(&row.secret_ciphertext)
                .map_err(|_| DbError::CorruptData)?,
        );
        if protected.len() < 30 || protected[0] != 1 {
            return Err(DbError::CorruptData.into());
        }
        let plaintext = nazo_crypto::aead::decrypt_nonce_prefixed(
            &key,
            &self.totp_aad(user),
            &mut protected[1..],
        )
        .map_err(|_| RepositoryError::Consistency("TOTP seed authentication failed".into()))?;
        let secret = std::str::from_utf8(plaintext).map_err(|_| DbError::CorruptData)?;
        Ok(verified_totp_step(secret, code, timestamp, last_step))
    }

    async fn totp_row(&self, user: UserId) -> Result<Option<TotpRow>, RepositoryError> {
        Ok(self.database.query(
            "SELECT totp.id,secret_ciphertext,secret_key_id,confirmed_at,last_used_step,version,account.active FROM nazo_mfa_totp AS totp JOIN nazo_users AS account ON account.tenant_id=totp.tenant_id AND account.id=totp.user_id WHERE totp.tenant_id=?1 AND totp.user_id=?2",
            vec![json!(self.tenant_id), json!(user)],
        ).await?.into_iter().next())
    }

    fn mfa_attempt(
        &self,
        user: UserId,
        backup: bool,
        outcome: &str,
        reason: &str,
    ) -> SecurityAuditEvent {
        SecurityAuditEvent {
            event_id: Uuid::new_v4(),
            event_type: if backup {
                "mfa_backup_code_attempt"
            } else {
                "mfa_totp_attempt"
            }
            .into(),
            event_category: "mfa".into(),
            occurred_at: Timestamp::now(),
            payload: json!({
                "schema_version": nazo_persistence::SECURITY_AUDIT_SCHEMA_VERSION,
                "event_category": "mfa", "tenant_id": self.tenant_id,
                "user_id": user, "actor_id": user, "target_user_id": user,
                "outcome": outcome, "reason_code": reason,
            }),
        }
    }

    fn mfa_outcome(&self, user: UserId, id: Uuid, event: &str, source: &str) -> SecurityAuditEvent {
        SecurityAuditEvent {
            event_id: Uuid::new_v4(),
            event_type: event.into(),
            event_category: "authentication".into(),
            occurred_at: Timestamp::now(),
            payload: json!({
                "schema_version": nazo_persistence::SECURITY_AUDIT_SCHEMA_VERSION,
                "event_category": "authentication", "tenant_id": self.tenant_id,
                "user_id": user, "actor_id": user, "target_user_id": user,
                "credential_id": id, "outcome": "success", "source_ip_hash": source,
            }),
        }
    }

    fn audit_when(
        &self,
        event: &SecurityAuditEvent,
        predicate: &str,
        tail: Vec<Value>,
    ) -> Result<Vec<Statement>, RepositoryError> {
        let mut params = self.audit_statement(event)?.params.to_vec();
        params.extend(tail);
        let params: std::sync::Arc<[Value]> = params.into();
        Ok(vec![Statement::new(format!(
                "INSERT INTO nazo_audit(tenant_id,event_id,event_type,category,occurred_at,payload) SELECT ?1,?2,?3,?4,?5,?6 WHERE {predicate}"
            ),params.clone()),
            // A suppressed Required INSERT is a failed transaction, never an
            // acknowledgement. Compare the complete canonical event while the
            // authority predicate still describes this exact transition.
            Statement::new(format!("SELECT CASE WHEN (
                ({predicate}) AND EXISTS(SELECT 1 FROM nazo_audit WHERE tenant_id=?1 AND event_id=?2 AND event_type=?3 AND category=?4 AND occurred_at=?5 AND payload=?6))
                OR (NOT ({predicate}) AND NOT EXISTS(SELECT 1 FROM nazo_audit WHERE event_id=?2))
                THEN 1 ELSE json_extract('MFA Required audit was not accepted','$') END"),params),
        ])
    }

    fn generation_audit(
        &self,
        event: &SecurityAuditEvent,
        user: UserId,
        id: Uuid,
        version: Option<Uuid>,
    ) -> Result<Vec<Statement>, RepositoryError> {
        self.audit_when(event,
            "EXISTS(SELECT 1 FROM nazo_mfa_totp AS totp JOIN nazo_users AS account ON account.tenant_id=totp.tenant_id AND account.id=totp.user_id WHERE totp.tenant_id=?1 AND totp.user_id=?7 AND totp.id=?8 AND totp.confirmed_at IS NOT NULL AND (?9 IS NULL OR totp.version=?9) AND account.active=1)",
            vec![json!(user), json!(id), json!(version)],
        )
    }

    async fn record_mfa_attempt(
        &self,
        user: UserId,
        backup: bool,
        outcome: &str,
        reason: &str,
    ) -> Result<(), RepositoryError> {
        let mut statements = self.audit_when(
            &self.mfa_attempt(user, backup, outcome, reason),
            "EXISTS(SELECT 1 FROM nazo_users WHERE tenant_id=?1 AND id=?7)",
            vec![json!(user)],
        )?;
        statements[0].sql.push_str(" RETURNING sequence");
        if self.database.batch(statements).await?[0].rows.len() != 1 {
            return Err(RepositoryError::Consistency(
                "MFA audit account does not exist".into(),
            ));
        }
        Ok(())
    }

    fn backup_statements(
        &self,
        user: UserId,
        id: Uuid,
        hashes: Vec<EncodedSecretHash>,
        version: Option<Uuid>,
    ) -> Result<Vec<Statement>, RepositoryError> {
        let codes = hashes
            .into_iter()
            .map(|hash| json!({"id": Uuid::new_v4(), "hash": hash.into_persistence_value()}))
            .collect::<Vec<_>>();
        let guard = format!(
            "{CURRENT} AND (?5 IS NULL OR EXISTS(SELECT 1 FROM nazo_mfa_totp WHERE tenant_id=?1 AND user_id=?2 AND id=?3 AND version=?5))"
        );
        let params: std::sync::Arc<[Value]> = vec![
            json!(self.tenant_id),
            json!(user),
            json!(id),
            json!(encode(&codes)?),
            json!(version),
        ]
        .into();
        Ok(vec![
            Statement::new(
                format!(
                    "DELETE FROM nazo_mfa_backup_codes WHERE tenant_id=?1 AND user_id=?2 AND {guard}"
                ),
                params.clone(),
            ),
            Statement::new(
                format!(
                    "INSERT INTO nazo_mfa_backup_codes(tenant_id,user_id,id,credential_id,code_hash) SELECT ?1,?2,json_extract(value,'$.id'),?3,json_extract(value,'$.hash') FROM json_each(?4) WHERE {guard}"
                ),
                params.clone(),
            ),
            Statement::new(format!("SELECT CASE WHEN NOT ({guard}) OR (
                (SELECT count(*) FROM nazo_mfa_backup_codes WHERE tenant_id=?1 AND user_id=?2)=json_array_length(?4)
                AND NOT EXISTS(SELECT 1 FROM json_each(?4) expected WHERE NOT EXISTS(SELECT 1 FROM nazo_mfa_backup_codes WHERE tenant_id=?1 AND user_id=?2 AND credential_id=?3 AND id=json_extract(expected.value,'$.id') AND code_hash=json_extract(expected.value,'$.hash'))))
                THEN 1 ELSE json_extract('MFA backup replacement was not accepted','$') END"),params),
        ])
    }

    fn totp_update_guard(
        &self,
        user: UserId,
        row: &TotpRow,
        step: i64,
        version: Uuid,
        confirmation: bool,
    ) -> Statement {
        let previous = if confirmation {
            "confirmed_at IS NULL"
        } else {
            "confirmed_at IS NOT NULL AND (last_used_step IS NULL OR last_used_step<?5)"
        };
        Statement::new(format!("SELECT CASE WHEN changes()=1 THEN
            CASE WHEN EXISTS(SELECT 1 FROM nazo_mfa_totp WHERE tenant_id=?1 AND user_id=?2 AND id=?3 AND version=?6 AND confirmed_at IS NOT NULL AND last_used_step=?5 AND secret_ciphertext=?7 AND secret_key_id=?8)
              THEN 1 ELSE json_extract('MFA TOTP projection was not accepted','$') END
            ELSE CASE WHEN NOT EXISTS(SELECT 1 FROM nazo_mfa_totp WHERE tenant_id=?1 AND user_id=?2 AND id=?3 AND version=?4 AND {previous} AND EXISTS(SELECT 1 FROM nazo_users WHERE tenant_id=?1 AND id=?2 AND active=1))
              THEN 1 ELSE json_extract('MFA TOTP mutation was ignored','$') END END"),
            vec![json!(self.tenant_id),json!(user),json!(row.id),json!(row.version),json!(step),json!(version),json!(row.secret_ciphertext),json!(row.secret_key_id)])
    }

    fn totp_commit_guard(
        &self,
        user: UserId,
        row: &TotpRow,
        step: i64,
        version: Uuid,
        event: Uuid,
        confirmation: bool,
    ) -> Statement {
        Statement::new("SELECT CASE WHEN
            (NOT EXISTS(SELECT 1 FROM nazo_audit WHERE tenant_id=?1 AND event_id=?8) AND NOT EXISTS(SELECT 1 FROM nazo_mfa_totp WHERE tenant_id=?1 AND user_id=?2 AND version=?4))
            OR (EXISTS(SELECT 1 FROM nazo_audit WHERE tenant_id=?1 AND event_id=?8)
                AND EXISTS(SELECT 1 FROM nazo_mfa_totp t JOIN nazo_users u ON u.tenant_id=t.tenant_id AND u.id=t.user_id WHERE t.tenant_id=?1 AND t.user_id=?2 AND t.id=?3 AND t.version=?4 AND t.last_used_step=?5 AND t.secret_ciphertext=?6 AND t.secret_key_id=?7 AND t.confirmed_at IS NOT NULL AND u.active=1 AND (?9=0 OR u.mfa_enabled=1)))
            THEN 1 ELSE json_extract('MFA TOTP commit effects were not accepted','$') END",
            vec![json!(self.tenant_id),json!(user),json!(row.id),json!(version),json!(step),json!(row.secret_ciphertext),json!(row.secret_key_id),json!(event),json!(confirmation)])
    }

    async fn confirm_totp(
        &self,
        tenant: TenantId,
        user: UserId,
        code: &str,
        timestamp: i64,
        hashes: Vec<EncodedSecretHash>,
        source: Option<String>,
    ) -> Result<TotpVerificationOutcome, RepositoryError> {
        self.require_tenant(tenant.as_uuid())?;
        self.totp_key()?;
        if hashes.len() != MFA_BACKUP_CODE_COUNT {
            return Err(RepositoryError::Conflict);
        }
        for _ in 0..MAX_CAS_ATTEMPTS {
            let Some(row) = self
                .totp_row(user)
                .await?
                .filter(|row| row.confirmed_at.is_none())
            else {
                self.record_mfa_attempt(user, false, "replay", "totp_replay")
                    .await?;
                return Ok(TotpVerificationOutcome::Replay);
            };
            if row.active != 1 {
                return Err(RepositoryError::Conflict);
            }
            let Some(step) = self.verified_step(user, &row, code, timestamp, None)? else {
                self.record_mfa_attempt(user, false, "invalid_credential", "totp_invalid")
                    .await?;
                return Ok(TotpVerificationOutcome::Invalid);
            };
            let version = Uuid::new_v4();
            let params = vec![
                json!(self.tenant_id),
                json!(user),
                json!(row.id),
                json!(row.version),
                json!(step),
                json!(version),
            ];
            let mut statements = vec![Statement::new(
                format!(
                    "UPDATE nazo_mfa_totp SET confirmed_at={NOW},last_used_step=?5,version=?6 WHERE tenant_id=?1 AND user_id=?2 AND id=?3 AND version=?4 AND confirmed_at IS NULL AND EXISTS(SELECT 1 FROM nazo_users WHERE tenant_id=?1 AND id=?2 AND active=1) RETURNING id"
                ),
                params,
            )];
            statements.push(self.totp_update_guard(user, &row, step, version, true));
            let accepted = self.mfa_attempt(user, false, "success", "totp_accepted");
            statements.extend(self.generation_audit(&accepted, user, row.id, Some(version))?);
            if let Some(source) = &source {
                statements.extend(self.generation_audit(
                    &self.mfa_outcome(user, row.id, "mfa_totp_enabled", source),
                    user,
                    row.id,
                    Some(version),
                )?);
            }
            let mut backups =
                self.backup_statements(user, row.id, hashes.clone(), Some(version))?;
            let backup_guard = backups.pop().ok_or(DbError::CorruptData)?;
            statements.extend(backups);
            statements.push(Statement::new(
                format!("UPDATE nazo_users SET mfa_enabled=1,updated_at={NOW} WHERE tenant_id=?1 AND id=?2 AND active=1 AND EXISTS(SELECT 1 FROM nazo_mfa_totp WHERE tenant_id=?1 AND user_id=?2 AND id=?3 AND version=?4 AND confirmed_at IS NOT NULL)"),
                vec![json!(self.tenant_id), json!(user), json!(row.id), json!(version)],
            ));
            statements.push(backup_guard);
            statements.push(self.totp_commit_guard(
                user,
                &row,
                step,
                version,
                accepted.event_id,
                true,
            ));
            if !self.database.batch(statements).await?[0].rows.is_empty() {
                return Ok(TotpVerificationOutcome::Accepted(row.id));
            }
            // A replaced pending seed is verified again; an old read cannot
            // confirm a different generation or consume a newly issued seed.
        }
        Err(RepositoryError::Conflict)
    }

    async fn replace_backup_hashes(
        &self,
        tenant: TenantId,
        user: UserId,
        id: Uuid,
        hashes: Vec<EncodedSecretHash>,
        source: Option<String>,
    ) -> Result<bool, RepositoryError> {
        self.require_tenant(tenant.as_uuid())?;
        if hashes.len() > MFA_BACKUP_CODE_COUNT {
            return Err(RepositoryError::Conflict);
        }
        let mut statements = vec![Statement::new(
            format!("SELECT ?3 AS id WHERE {CURRENT}"),
            vec![json!(self.tenant_id), json!(user), json!(id)],
        )];
        let mut backups = self.backup_statements(user, id, hashes, None)?;
        let backup_guard = backups.pop().ok_or(DbError::CorruptData)?;
        statements.extend(backups);
        if let Some(source) = source {
            statements.extend(self.generation_audit(
                &self.mfa_outcome(user, id, "mfa_backup_codes_regenerated", &source),
                user,
                id,
                None,
            )?);
        }
        statements.push(backup_guard);
        Ok(!self.database.batch(statements).await?[0].rows.is_empty())
    }

    async fn clear_mfa(
        &self,
        tenant: TenantId,
        user: UserId,
        id: Uuid,
        source: Option<String>,
    ) -> Result<bool, RepositoryError> {
        self.require_tenant(tenant.as_uuid())?;
        let params: std::sync::Arc<[Value]> =
            vec![json!(self.tenant_id), json!(user), json!(id)].into();
        let mut statements = Vec::new();
        if let Some(source) = source {
            statements.extend(self.generation_audit(
                &self.mfa_outcome(user, id, "mfa_disabled", &source),
                user,
                id,
                None,
            )?);
        }
        statements.push(Statement::new(format!("UPDATE nazo_users SET mfa_enabled=0,updated_at={NOW} WHERE tenant_id=?1 AND id=?2 AND {CURRENT}"), params.clone()));
        statements.push(Statement::new(format!("SELECT CASE WHEN ({CURRENT} AND changes()=1 AND EXISTS(SELECT 1 FROM nazo_users WHERE tenant_id=?1 AND id=?2 AND mfa_enabled=0)) OR (NOT ({CURRENT}) AND changes()=0)
            THEN 1 ELSE json_extract('MFA account disable was not accepted','$') END"),params.clone()));
        // Foreign keys retire backup codes and remembered devices for this
        // exact generation in the same transaction as the account and audit.
        let deletion = statements.len();
        statements.push(Statement::new(format!("DELETE FROM nazo_mfa_totp WHERE tenant_id=?1 AND user_id=?2 AND id=?3 AND {CURRENT} RETURNING id"), params.clone()));
        statements.push(Statement::new(format!("SELECT CASE WHEN
            (changes()=1 AND NOT EXISTS(SELECT 1 FROM nazo_mfa_totp WHERE tenant_id=?1 AND user_id=?2 AND id=?3)
                AND NOT EXISTS(SELECT 1 FROM nazo_mfa_backup_codes WHERE tenant_id=?1 AND user_id=?2 AND credential_id=?3)
                AND NOT EXISTS(SELECT 1 FROM nazo_mfa_devices WHERE tenant_id=?1 AND user_id=?2 AND credential_id=?3)
                AND EXISTS(SELECT 1 FROM nazo_users WHERE tenant_id=?1 AND id=?2 AND mfa_enabled=0))
            OR (changes()=0 AND NOT ({CURRENT}))
            THEN 1 ELSE json_extract('MFA disable retirement was not accepted','$') END"),params));
        Ok(!self
            .database
            .batch(statements)
            .await?
            .get(deletion)
            .ok_or(DbError::Unavailable)?
            .rows
            .is_empty())
    }
}

impl MfaRepositoryPort for D1Provider {
    fn check_totp_enrollment<'a>(
        &'a self,
        tenant: TenantId,
        user: UserId,
        code: &'a str,
        timestamp: i64,
    ) -> RepositoryFuture<'a, TotpEnrollmentCheck> {
        Box::pin(async move {
            self.require_tenant(tenant.as_uuid())?;
            self.totp_key()?;
            let Some(row) = self.totp_row(user).await? else {
                return Ok(TotpEnrollmentCheck::Missing);
            };
            if row.confirmed_at.is_some() {
                return Ok(TotpEnrollmentCheck::AlreadyConfirmed);
            }
            Ok(
                if self
                    .verified_step(user, &row, code, timestamp, row.last_used_step)?
                    .is_some()
                {
                    TotpEnrollmentCheck::ValidCode
                } else {
                    TotpEnrollmentCheck::InvalidCode
                },
            )
        })
    }

    fn begin_totp_enrollment<'a>(
        &'a self,
        tenant: TenantId,
        user: UserId,
        secret: &'a str,
    ) -> RepositoryFuture<'a, bool> {
        Box::pin(async move {
            self.require_tenant(tenant.as_uuid())?;
            let protected = self.protect_totp(user, secret)?;
            let params: std::sync::Arc<[Value]> = vec![
                json!(self.tenant_id),
                json!(user),
                json!(Uuid::new_v4()),
                json!(protected),
                json!(KEY_ID),
                json!(Uuid::new_v4()),
            ]
            .into();
            let result=self.database.batch(vec![Statement::new(
                "INSERT INTO nazo_mfa_totp(tenant_id,user_id,id,secret_ciphertext,secret_key_id,version) SELECT ?1,?2,?3,?4,?5,?6 WHERE EXISTS(SELECT 1 FROM nazo_users WHERE tenant_id=?1 AND id=?2 AND active=1) ON CONFLICT(tenant_id,user_id) DO UPDATE SET secret_ciphertext=excluded.secret_ciphertext,secret_key_id=excluded.secret_key_id,last_used_step=NULL,version=excluded.version WHERE nazo_mfa_totp.confirmed_at IS NULL RETURNING id",
                params.clone()),
                Statement::new("SELECT CASE WHEN
                    (changes()=1 AND EXISTS(SELECT 1 FROM nazo_mfa_totp WHERE tenant_id=?1 AND user_id=?2 AND secret_ciphertext=?4 AND secret_key_id=?5 AND version=?6 AND confirmed_at IS NULL AND last_used_step IS NULL))
                    OR (changes()=0 AND (NOT EXISTS(SELECT 1 FROM nazo_users WHERE tenant_id=?1 AND id=?2 AND active=1) OR EXISTS(SELECT 1 FROM nazo_mfa_totp WHERE tenant_id=?1 AND user_id=?2 AND confirmed_at IS NOT NULL)))
                    THEN 1 ELSE json_extract('MFA pending enrollment was not accepted','$') END",params),
            ]).await?;
            Ok(!result[0].rows.is_empty())
        })
    }

    fn verify_and_confirm_totp<'a>(
        &'a self,
        tenant: TenantId,
        user: UserId,
        code: &'a str,
        timestamp: i64,
        hashes: Vec<EncodedSecretHash>,
    ) -> RepositoryFuture<'a, TotpVerificationOutcome> {
        Box::pin(self.confirm_totp(tenant, user, code, timestamp, hashes, None))
    }

    fn verify_and_confirm_totp_with_required_audit<'a>(
        &'a self,
        tenant: TenantId,
        user: UserId,
        code: &'a str,
        timestamp: i64,
        hashes: Vec<EncodedSecretHash>,
        source: String,
    ) -> RepositoryFuture<'a, TotpVerificationOutcome> {
        Box::pin(self.confirm_totp(tenant, user, code, timestamp, hashes, Some(source)))
    }

    fn record_invalid_totp_attempt(
        &self,
        tenant: TenantId,
        user: UserId,
    ) -> RepositoryFuture<'_, ()> {
        Box::pin(async move {
            self.require_tenant(tenant.as_uuid())?;
            self.record_mfa_attempt(user, false, "invalid_credential", "totp_invalid")
                .await
        })
    }

    fn verify_and_consume_totp<'a>(
        &'a self,
        tenant: TenantId,
        user: UserId,
        code: &'a str,
        timestamp: i64,
    ) -> RepositoryFuture<'a, TotpVerificationOutcome> {
        Box::pin(async move {
            self.require_tenant(tenant.as_uuid())?;
            self.totp_key()?;
            for _ in 0..MAX_CAS_ATTEMPTS {
                let Some(row) = self
                    .totp_row(user)
                    .await?
                    .filter(|row| row.confirmed_at.is_some())
                else {
                    self.record_mfa_attempt(user, false, "invalid_credential", "totp_invalid")
                        .await?;
                    return Ok(TotpVerificationOutcome::Invalid);
                };
                if row.active != 1 {
                    return Err(RepositoryError::Conflict);
                }
                let Some(step) = self.verified_step(user, &row, code, timestamp, None)? else {
                    self.record_mfa_attempt(user, false, "invalid_credential", "totp_invalid")
                        .await?;
                    return Ok(TotpVerificationOutcome::Invalid);
                };
                if row.last_used_step.is_some_and(|last| step <= last) {
                    self.record_mfa_attempt(user, false, "replay", "totp_replay")
                        .await?;
                    return Ok(TotpVerificationOutcome::Replay);
                }
                let version = Uuid::new_v4();
                let mut statements = vec![
                    Statement::new(
                        format!(
                            "UPDATE nazo_mfa_totp SET last_used_step=?5,version=?6 WHERE tenant_id=?1 AND user_id=?2 AND id=?3 AND version=?4 AND (last_used_step IS NULL OR last_used_step<?5) AND {CURRENT} RETURNING id"
                        ),
                        vec![
                            json!(self.tenant_id),
                            json!(user),
                            json!(row.id),
                            json!(row.version),
                            json!(step),
                            json!(version),
                        ],
                    ),
                    self.totp_update_guard(user, &row, step, version, false),
                ];
                let accepted = self.mfa_attempt(user, false, "success", "totp_accepted");
                statements.extend(self.generation_audit(&accepted, user, row.id, Some(version))?);
                statements.push(self.totp_commit_guard(
                    user,
                    &row,
                    step,
                    version,
                    accepted.event_id,
                    false,
                ));
                if !self.database.batch(statements).await?[0].rows.is_empty() {
                    return Ok(TotpVerificationOutcome::Accepted(row.id));
                }
            }
            Err(RepositoryError::Conflict)
        })
    }

    fn backup_code_candidates(
        &self,
        tenant: TenantId,
        user: UserId,
    ) -> RepositoryFuture<'_, Vec<BackupCodeCandidate>> {
        Box::pin(async move {
            self.require_tenant(tenant.as_uuid())?;
            let rows = self.database.query::<BackupRow>(
                "SELECT id,code_hash FROM nazo_mfa_backup_codes WHERE tenant_id=?1 AND user_id=?2 ORDER BY id LIMIT ?3",
                vec![json!(self.tenant_id), json!(user), json!(MFA_BACKUP_CODE_COUNT + 1)],
            ).await?;
            if rows.len() > MFA_BACKUP_CODE_COUNT {
                return Err(RepositoryError::Consistency(
                    "persisted backup-code count exceeds its bound".into(),
                ));
            }
            rows.into_iter()
                .map(|row| {
                    Ok(BackupCodeCandidate {
                        id: row.id,
                        hash: EncodedSecretHash::new(row.code_hash)
                            .map_err(|_| DbError::CorruptData)?,
                    })
                })
                .collect()
        })
    }

    fn consume_backup_code_candidate(
        &self,
        tenant: TenantId,
        user: UserId,
        candidate: Uuid,
    ) -> RepositoryFuture<'_, Option<Uuid>> {
        Box::pin(async move {
            self.require_tenant(tenant.as_uuid())?;
            let predicate = "EXISTS(SELECT 1 FROM nazo_mfa_backup_codes AS backup JOIN nazo_mfa_totp AS totp ON totp.tenant_id=backup.tenant_id AND totp.user_id=backup.user_id AND totp.id=backup.credential_id JOIN nazo_users AS account ON account.tenant_id=totp.tenant_id AND account.id=totp.user_id WHERE backup.tenant_id=?1 AND backup.user_id=?7 AND backup.id=?8 AND totp.confirmed_at IS NOT NULL AND account.active=1)";
            let accepted = self.mfa_attempt(user, true, "success", "backup_code_accepted");
            let mut statements =
                self.audit_when(&accepted, predicate, vec![json!(user), json!(candidate)])?;
            statements.extend(self.audit_when(&self.mfa_attempt(user, true, "replay", "backup_code_replay"), &format!("NOT {predicate} AND EXISTS(SELECT 1 FROM nazo_users WHERE tenant_id=?1 AND id=?7)"), vec![json!(user), json!(candidate)])?);
            let deletion = statements.len();
            let params: std::sync::Arc<[Value]> = vec![
                json!(self.tenant_id),
                json!(user),
                json!(candidate),
                json!(accepted.event_id),
            ]
            .into();
            statements.push(Statement::new("DELETE FROM nazo_mfa_backup_codes WHERE tenant_id=?1 AND user_id=?2 AND id=?3 AND EXISTS(SELECT 1 FROM nazo_audit WHERE tenant_id=?1 AND event_id=?4) RETURNING credential_id AS id",params.clone()));
            statements.push(Statement::new("SELECT CASE WHEN
                (EXISTS(SELECT 1 FROM nazo_audit WHERE tenant_id=?1 AND event_id=?4) AND changes()=1 AND NOT EXISTS(SELECT 1 FROM nazo_mfa_backup_codes WHERE tenant_id=?1 AND user_id=?2 AND id=?3))
                OR (NOT EXISTS(SELECT 1 FROM nazo_audit WHERE tenant_id=?1 AND event_id=?4) AND changes()=0)
                THEN 1 ELSE json_extract('MFA backup consumption was not accepted','$') END",params));
            self.database
                .batch(statements)
                .await?
                .into_iter()
                .nth(deletion)
                .ok_or(DbError::Unavailable)?
                .rows
                .into_iter()
                .next()
                .map(|value| {
                    serde_json::from_value::<IdRow>(value)
                        .map(|row| row.id)
                        .map_err(|_| DbError::CorruptData.into())
                })
                .transpose()
        })
    }

    fn record_invalid_backup_code_attempt(
        &self,
        tenant: TenantId,
        user: UserId,
    ) -> RepositoryFuture<'_, ()> {
        Box::pin(async move {
            self.require_tenant(tenant.as_uuid())?;
            self.record_mfa_attempt(user, true, "invalid_credential", "backup_code_invalid")
                .await
        })
    }

    fn replace_backup_code_hashes<'a>(
        &'a self,
        tenant: TenantId,
        user: UserId,
        id: Uuid,
        hashes: Vec<EncodedSecretHash>,
    ) -> RepositoryFuture<'a, bool> {
        Box::pin(self.replace_backup_hashes(tenant, user, id, hashes, None))
    }

    fn replace_backup_code_hashes_with_required_audit<'a>(
        &'a self,
        tenant: TenantId,
        user: UserId,
        id: Uuid,
        hashes: Vec<EncodedSecretHash>,
        source: String,
    ) -> RepositoryFuture<'a, bool> {
        Box::pin(self.replace_backup_hashes(tenant, user, id, hashes, Some(source)))
    }

    fn clear_mfa_state_if_current<'a>(
        &'a self,
        tenant: TenantId,
        user: UserId,
        id: Uuid,
    ) -> RepositoryFuture<'a, bool> {
        Box::pin(self.clear_mfa(tenant, user, id, None))
    }

    fn clear_mfa_state_if_current_with_required_audit<'a>(
        &'a self,
        tenant: TenantId,
        user: UserId,
        id: Uuid,
        source: String,
    ) -> RepositoryFuture<'a, bool> {
        Box::pin(self.clear_mfa(tenant, user, id, Some(source)))
    }

    fn remember_device(
        &self,
        tenant: TenantId,
        user: UserId,
        id: Uuid,
        token_hash: String,
        user_agent_hash: Option<String>,
        expires_at: Timestamp,
    ) -> RepositoryFuture<'_, bool> {
        Box::pin(async move {
            self.require_tenant(tenant.as_uuid())?;
            let params: std::sync::Arc<[Value]> = vec![
                json!(self.tenant_id),
                json!(user),
                json!(id),
                json!(token_hash),
                json!(user_agent_hash),
                json!(expires_at.as_microsecond()),
            ]
            .into();
            let results = self.database.batch(vec![
                Statement::new(format!("DELETE FROM nazo_mfa_devices WHERE tenant_id=?1 AND user_id=?2 AND expires_at<={NOW} AND {CURRENT}"), params[..3].to_vec()),
                Statement::new(format!("SELECT CASE WHEN NOT ({CURRENT}) OR NOT EXISTS(SELECT 1 FROM nazo_mfa_devices WHERE tenant_id=?1 AND user_id=?2 AND expires_at<={NOW}) THEN 1 ELSE json_extract('MFA expired device cleanup was not accepted','$') END"),params[..3].to_vec()),
                Statement::new(format!("INSERT INTO nazo_mfa_devices(tenant_id,user_id,credential_id,token_hash,user_agent_hash,expires_at) SELECT ?1,?2,?3,?4,?5,?6 WHERE {CURRENT} RETURNING credential_id"), params.clone()),
                Statement::new(format!("SELECT CASE WHEN
                    (changes()=1 AND {CURRENT} AND EXISTS(SELECT 1 FROM nazo_mfa_devices WHERE tenant_id=?1 AND user_id=?2 AND credential_id=?3 AND token_hash=?4 AND user_agent_hash IS ?5 AND expires_at=?6))
                    OR (changes()=0 AND NOT ({CURRENT}))
                    THEN 1 ELSE json_extract('MFA remembered device was not accepted','$') END"),params),
            ]).await?;
            Ok(!results[2].rows.is_empty())
        })
    }
}

impl RememberedMfaDevicePort for D1Provider {
    fn is_valid<'a>(
        &'a self,
        tenant: TenantId,
        user: UserId,
        token_hash: &'a str,
        user_agent_hash: Option<&'a str>,
        at: Timestamp,
    ) -> RepositoryFuture<'a, bool> {
        Box::pin(async move {
            self.require_tenant(tenant.as_uuid())?;
            Ok(!self.database.query::<IdRow>(
                "SELECT totp.id FROM nazo_mfa_devices AS device JOIN nazo_mfa_totp AS totp ON totp.tenant_id=device.tenant_id AND totp.user_id=device.user_id AND totp.id=device.credential_id JOIN nazo_users AS account ON account.tenant_id=totp.tenant_id AND account.id=totp.user_id WHERE device.tenant_id=?1 AND device.user_id=?2 AND device.token_hash=?3 AND device.user_agent_hash IS ?4 AND device.expires_at>?5 AND totp.confirmed_at IS NOT NULL AND account.active=1 AND account.mfa_enabled=1",
                vec![json!(self.tenant_id), json!(user), json!(token_hash), json!(user_agent_hash), json!(at.as_microsecond())],
            ).await?.is_empty())
        })
    }
}
