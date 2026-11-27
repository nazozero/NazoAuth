//! Encrypted TOTP generations and one-use MFA proofs.
use crate::{
    MfaTotpKeyRing, RocksDb,
    audit::append_in_tx,
    db::{
        decode, delete_expiring, key, map_error, put, put_expiring, read, read_snapshot, read_tx,
    },
    users::{AccountMetadata, USER_CLAIMS, USER_METADATA, corrupt, read_principal_tx},
};
use jiff::Timestamp;
use nazo_identity::{
    SubjectClaims, TenantId, UserId,
    mfa::{MFA_BACKUP_CODE_COUNT, verified_totp_step},
    ports::{
        BackupCodeCandidate, EncodedSecretHash, MfaRepositoryPort, RememberedMfaDevicePort,
        RepositoryError, RepositoryFuture, TotpEnrollmentCheck, TotpVerificationOutcome,
    },
};
use nazo_persistence::SecurityAuditEvent;
use rocksdb::{Direction, IteratorMode, Transaction, TransactionDB};
use serde::{Deserialize, Serialize};
use serde_json::json;
use uuid::Uuid;
use zeroize::Zeroizing;

const TOTP: u8 = 0x45;
const BACKUP: u8 = 0x46;
pub(crate) const REMEMBERED: u8 = 0x47;
const KEY_STATE: u8 = 0x48;
const KEY_INDEX: u8 = 0x49;
#[derive(Serialize, Deserialize)]
struct Totp {
    id: Uuid,
    ciphertext: Vec<u8>,
    key_id: String,
    confirmed: bool,
    last_step: Option<i64>,
}
#[derive(Serialize, Deserialize)]
struct KeyState {
    current: String,
    previous: Option<String>,
}
#[derive(Serialize, Deserialize)]
struct Remembered {
    generation: Uuid,
    user_agent: Option<String>,
    expires: Timestamp,
}
fn totp_key(tenant: TenantId, user: UserId) -> Vec<u8> {
    key(TOTP, tenant.as_uuid(), user.as_uuid().as_bytes())
}
fn owned_key(table: u8, tenant: TenantId, user: UserId, suffix: &[u8]) -> Vec<u8> {
    let mut k = key(table, tenant.as_uuid(), user.as_uuid().as_bytes());
    k.extend_from_slice(suffix);
    k
}
fn key_index_prefix(key_id: &str) -> Vec<u8> {
    let mut k = key(KEY_INDEX, Uuid::nil(), &(key_id.len() as u16).to_be_bytes());
    k.extend_from_slice(key_id.as_bytes());
    k
}
fn key_index(key_id: &str, tenant: TenantId, user: UserId) -> Vec<u8> {
    let mut k = key_index_prefix(key_id);
    k.extend_from_slice(tenant.as_uuid().as_bytes());
    k.extend_from_slice(user.as_uuid().as_bytes());
    k
}
fn aad(tenant: TenantId, user: UserId, key_id: &str) -> Vec<u8> {
    let mut v = Vec::with_capacity(56 + key_id.len());
    v.extend_from_slice(b"nazo-totp-seed-v1");
    v.extend_from_slice(tenant.as_uuid().as_bytes());
    v.extend_from_slice(user.as_uuid().as_bytes());
    v.extend_from_slice(&(key_id.len() as u64).to_be_bytes());
    v.extend_from_slice(key_id.as_bytes());
    v
}
fn protect(
    keys: &MfaTotpKeyRing,
    tenant: TenantId,
    user: UserId,
    secret: &str,
) -> Result<(Vec<u8>, String), RepositoryError> {
    if secret.trim().len() < 16 || secret.len() > 128 {
        return Err(corrupt("invalid TOTP seed length"));
    }
    let nonce = rand::random::<[u8; 12]>();
    let mut prefix = [1; 13];
    prefix[1..].copy_from_slice(&nonce);
    let ciphertext = nazo_crypto::aead::encrypt_prefixed(
        keys.current().key(),
        &nonce,
        &aad(tenant, user, keys.current().id()),
        secret.as_bytes(),
        &prefix,
    )
    .map_err(|_| corrupt("TOTP encryption failed"))?;
    Ok((ciphertext, keys.current().id().to_owned()))
}
fn open<'a>(
    keys: &MfaTotpKeyRing,
    tenant: TenantId,
    user: UserId,
    ciphertext: &'a mut [u8],
    key_id: &str,
) -> Result<&'a str, RepositoryError> {
    let key = if keys.current().id() == key_id {
        keys.current()
    } else {
        keys.previous()
            .filter(|k| k.id() == key_id)
            .ok_or_else(|| corrupt("TOTP key unavailable"))?
    };
    if ciphertext.len() < 30 || ciphertext[0] != 1 {
        return Err(corrupt("invalid TOTP envelope"));
    }
    let plaintext = nazo_crypto::aead::decrypt_nonce_prefixed(
        key.key(),
        &aad(tenant, user, key_id),
        &mut ciphertext[1..],
    )
    .map_err(|_| corrupt("TOTP authentication failed"))?;
    std::str::from_utf8(plaintext).map_err(|_| corrupt("invalid TOTP seed"))
}
fn step(
    db: &RocksDb,
    tenant: TenantId,
    user: UserId,
    row: &Totp,
    code: &str,
    timestamp: i64,
) -> Result<Option<i64>, RepositoryError> {
    let keys = db
        .totp_keys
        .as_ref()
        .ok_or_else(|| corrupt("TOTP encryption key is not configured"))?;
    let mut bytes = Zeroizing::new(row.ciphertext.clone());
    let secret = open(keys, tenant, user, &mut bytes, &row.key_id)?;
    Ok(verified_totp_step(secret, code, timestamp, None))
}
fn active(
    tx: &Transaction<'_, TransactionDB>,
    tenant: TenantId,
    user: UserId,
) -> Result<(), RepositoryError> {
    read_principal_tx(tx, tenant.as_uuid(), user.as_uuid(), false)?
        .filter(|p| p.active)
        .ok_or(RepositoryError::Conflict)
        .map(|_| ())
}
fn attempt(
    tenant: TenantId,
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
            "event_category": "mfa",
            "tenant_id": tenant,
            "user_id": user,
            "actor_id": user,
            "target_user_id": user,
            "outcome": outcome,
            "reason_code": reason,
        }),
    }
}
fn lifecycle(
    tenant: TenantId,
    user: UserId,
    id: Uuid,
    event: &str,
    source: &str,
) -> SecurityAuditEvent {
    SecurityAuditEvent {
        event_id: Uuid::new_v4(),
        event_type: event.into(),
        event_category: "authentication".into(),
        occurred_at: Timestamp::now(),
        payload: json!({
            "schema_version": nazo_persistence::SECURITY_AUDIT_SCHEMA_VERSION,
            "event_category": "authentication",
            "tenant_id": tenant,
            "user_id": user,
            "actor_id": user,
            "target_user_id": user,
            "credential_id": id,
            "outcome": "success",
            "source_ip_hash": source,
        }),
    }
}
fn delete_backup(
    tx: &Transaction<'_, TransactionDB>,
    tenant: TenantId,
    user: UserId,
) -> Result<(), RepositoryError> {
    let prefix = owned_key(BACKUP, tenant, user, &[]);
    for result in tx.iterator(IteratorMode::From(&prefix, Direction::Forward)) {
        let (k, _) = result.map_err(map_error)?;
        if !k.starts_with(&prefix) {
            break;
        }
        tx.delete(k).map_err(map_error)?;
    }
    Ok(())
}
fn replace_backup(
    tx: &Transaction<'_, TransactionDB>,
    tenant: TenantId,
    user: UserId,
    hashes: Vec<EncodedSecretHash>,
) -> Result<(), RepositoryError> {
    if hashes.len() > MFA_BACKUP_CODE_COUNT {
        return Err(RepositoryError::Conflict);
    }
    delete_backup(tx, tenant, user)?;
    for hash in hashes {
        put(
            tx,
            &owned_key(BACKUP, tenant, user, Uuid::new_v4().as_bytes()),
            &hash.into_persistence_value(),
        )?;
    }
    Ok(())
}
fn set_enabled(
    tx: &Transaction<'_, TransactionDB>,
    tenant: TenantId,
    user: UserId,
    enabled: bool,
) -> Result<(), RepositoryError> {
    let claims_key = key(USER_CLAIMS, tenant.as_uuid(), user.as_uuid().as_bytes());
    let mut claims: SubjectClaims =
        read_tx(tx, &claims_key, true)?.ok_or_else(|| corrupt("MFA account claims missing"))?;
    let k = key(USER_METADATA, tenant.as_uuid(), user.as_uuid().as_bytes());
    let mut metadata: AccountMetadata =
        read_tx(tx, &k, true)?.ok_or_else(|| corrupt("MFA account metadata missing"))?;
    metadata.mfa_enabled = enabled;
    metadata.updated_at = Timestamp::now();
    claims.updated_at = metadata.updated_at.as_second();
    put(tx, &claims_key, &claims)?;
    put(tx, &k, &metadata)
}
impl RocksDb {
    #[must_use]
    pub fn with_totp_key_ring(mut self, keys: Option<MfaTotpKeyRing>) -> Self {
        self.totp_keys = keys.map(std::sync::Arc::new);
        self
    }
    pub async fn activate_totp_key(&self) -> Result<(), RepositoryError> {
        self.run(|db| {
            let Some(keys) = &db.totp_keys else {
                return Ok(());
            };
            let tx = db.transaction();
            let state_key = key(KEY_STATE, Uuid::nil(), &[]);
            let state = read_tx::<KeyState>(&tx, &state_key, true)?;
            let previous = keys.previous().map(|k| k.id());
            for result in tx.iterator(IteratorMode::From(&[TOTP], Direction::Forward)) {
                let (k, v) = result.map_err(map_error)?;
                if k.first() != Some(&TOTP) {
                    break;
                }
                let row: Totp = decode(&v)?;
                if row.key_id != keys.current().id() && Some(row.key_id.as_str()) != previous {
                    return Err(corrupt("retained TOTP envelopes require an absent key"));
                }
            }
            let mut next = KeyState {
                current: keys.current().id().into(),
                previous: None,
            };
            if let Some(state) = state {
                if state.current != keys.current().id() {
                    if previous != Some(state.current.as_str())
                        || state.previous.as_deref() == Some(keys.current().id())
                    {
                        return Err(corrupt("TOTP rotation must advance from the active key"));
                    }
                    next.previous = Some(state.current);
                } else {
                    next.previous = state.previous;
                }
            }
            put(&tx, &state_key, &next)?;
            tx.commit().map_err(map_error)
        })
        .await
    }
    pub async fn rewrap_totp_batch(&self) -> Result<u64, RepositoryError> {
        self.run(|db| {
            let Some(keys) = &db.totp_keys else {
                return Ok(0);
            };
            let Some(previous) = keys.previous() else {
                return Ok(0);
            };
            let tx = db.transaction();
            let state: KeyState = read_tx(&tx, &key(KEY_STATE, Uuid::nil(), &[]), false)?
                .ok_or_else(|| corrupt("TOTP write key is not activated"))?;
            if state.current != keys.current().id() {
                return Ok(0);
            }
            let prefix = key_index_prefix(previous.id());
            let mut count = 0;
            for result in tx
                .iterator(IteratorMode::From(&prefix, Direction::Forward))
                .take(256)
            {
                let (k, v) = result.map_err(map_error)?;
                if !k.starts_with(&prefix) {
                    break;
                }
                let (tenant, user): (TenantId, UserId) = decode(&v)?;
                let record_key = totp_key(tenant, user);
                let Some(mut row) = read_tx::<Totp>(&tx, &record_key, true)? else {
                    continue;
                };
                if row.key_id != previous.id() {
                    continue;
                }
                let mut plaintext = Zeroizing::new(row.ciphertext);
                let seed = open(keys, tenant, user, &mut plaintext, &row.key_id)?;
                let (ciphertext, key_id) = protect(keys, tenant, user, seed)?;
                row.ciphertext = ciphertext;
                row.key_id = key_id;
                put(&tx, &record_key, &row)?;
                tx.delete(k).map_err(map_error)?;
                put(&tx, &key_index(&row.key_id, tenant, user), &(tenant, user))?;
                count += 1;
            }
            tx.commit().map_err(map_error)?;
            Ok(count)
        })
        .await
    }
    async fn confirm_totp(
        &self,
        tenant: TenantId,
        user: UserId,
        code: String,
        timestamp: i64,
        hashes: Vec<EncodedSecretHash>,
        source: Option<String>,
    ) -> Result<TotpVerificationOutcome, RepositoryError> {
        self.run(move |db| {
            if hashes.len() != MFA_BACKUP_CODE_COUNT {
                return Err(RepositoryError::Conflict);
            }
            let tx = db.transaction();
            active(&tx, tenant, user)?;
            let key = totp_key(tenant, user);
            let row = read_tx::<Totp>(&tx, &key, true)?;
            let outcome = match row {
                Some(mut row) if !row.confirmed => {
                    match step(db, tenant, user, &row, &code, timestamp)? {
                        Some(step) => {
                            row.confirmed = true;
                            row.last_step = Some(step);
                            put(&tx, &key, &row)?;
                            replace_backup(&tx, tenant, user, hashes)?;
                            set_enabled(&tx, tenant, user, true)?;
                            if let Some(source) = source {
                                append_in_tx(
                                    &tx,
                                    &lifecycle(tenant, user, row.id, "mfa_totp_enabled", &source),
                                )?;
                            }
                            TotpVerificationOutcome::Accepted(row.id)
                        }
                        None => TotpVerificationOutcome::Invalid,
                    }
                }
                _ => TotpVerificationOutcome::Replay,
            };
            let (outcome_name, reason) = match outcome {
                TotpVerificationOutcome::Accepted(_) => ("success", "totp_accepted"),
                TotpVerificationOutcome::Invalid => ("invalid_credential", "totp_invalid"),
                TotpVerificationOutcome::Replay => ("replay", "totp_replay"),
            };
            append_in_tx(&tx, &attempt(tenant, user, false, outcome_name, reason))?;
            tx.commit().map_err(map_error)?;
            Ok(outcome)
        })
        .await
    }
    async fn replace_codes(
        &self,
        tenant: TenantId,
        user: UserId,
        id: Uuid,
        hashes: Vec<EncodedSecretHash>,
        source: Option<String>,
    ) -> Result<bool, RepositoryError> {
        self.run(move |db| {
            let tx = db.transaction();
            active(&tx, tenant, user)?;
            if !read_tx::<Totp>(&tx, &totp_key(tenant, user), true)?
                .is_some_and(|r| r.confirmed && r.id == id)
            {
                return Ok(false);
            }
            replace_backup(&tx, tenant, user, hashes)?;
            if let Some(source) = source {
                append_in_tx(
                    &tx,
                    &lifecycle(tenant, user, id, "mfa_backup_codes_regenerated", &source),
                )?;
            }
            tx.commit().map_err(map_error)?;
            Ok(true)
        })
        .await
    }
    async fn clear_mfa(
        &self,
        tenant: TenantId,
        user: UserId,
        id: Uuid,
        source: Option<String>,
    ) -> Result<bool, RepositoryError> {
        self.run(move |db| {
            let tx = db.transaction();
            active(&tx, tenant, user)?;
            let k = totp_key(tenant, user);
            let Some(row) = read_tx::<Totp>(&tx, &k, true)?.filter(|r| r.confirmed && r.id == id)
            else {
                return Ok(false);
            };
            tx.delete(&k).map_err(map_error)?;
            tx.delete(key_index(&row.key_id, tenant, user))
                .map_err(map_error)?;
            delete_backup(&tx, tenant, user)?;
            let prefix = owned_key(REMEMBERED, tenant, user, &[]);
            for result in tx.iterator(IteratorMode::From(&prefix, Direction::Forward)) {
                let (k, v) = result.map_err(map_error)?;
                if !k.starts_with(&prefix) {
                    break;
                }
                let row: Remembered = decode(&v)?;
                delete_expiring(&tx, &k, row.expires)?;
            }
            set_enabled(&tx, tenant, user, false)?;
            if let Some(source) = source {
                append_in_tx(&tx, &lifecycle(tenant, user, id, "mfa_disabled", &source))?;
            }
            tx.commit().map_err(map_error)?;
            Ok(true)
        })
        .await
    }
    async fn invalid_mfa(
        &self,
        tenant: TenantId,
        user: UserId,
        backup: bool,
    ) -> Result<(), RepositoryError> {
        self.run(move |db| {
            let tx = db.transaction();
            read_principal_tx(&tx, tenant.as_uuid(), user.as_uuid(), false)?
                .ok_or(RepositoryError::NotFound)?;
            append_in_tx(
                &tx,
                &attempt(
                    tenant,
                    user,
                    backup,
                    "invalid_credential",
                    if backup {
                        "backup_code_invalid"
                    } else {
                        "totp_invalid"
                    },
                ),
            )?;
            tx.commit().map_err(map_error)
        })
        .await
    }
}
impl MfaRepositoryPort for RocksDb {
    fn check_totp_enrollment<'a>(
        &'a self,
        tenant_id: TenantId,
        user_id: UserId,
        code: &'a str,
        timestamp: i64,
    ) -> RepositoryFuture<'a, TotpEnrollmentCheck> {
        let code = code.to_owned();
        Box::pin(self.run(move |db| {
            let Some(row) = read::<Totp>(&db.db, &totp_key(tenant_id, user_id))? else {
                return Ok(TotpEnrollmentCheck::Missing);
            };
            if row.confirmed {
                return Ok(TotpEnrollmentCheck::AlreadyConfirmed);
            }
            Ok(
                if step(db, tenant_id, user_id, &row, &code, timestamp)?
                    .is_some_and(|s| row.last_step.is_none_or(|last| s > last))
                {
                    TotpEnrollmentCheck::ValidCode
                } else {
                    TotpEnrollmentCheck::InvalidCode
                },
            )
        }))
    }
    fn begin_totp_enrollment<'a>(
        &'a self,
        tenant_id: TenantId,
        user_id: UserId,
        secret: &'a str,
    ) -> RepositoryFuture<'a, bool> {
        let secret = Zeroizing::new(secret.to_owned());
        Box::pin(self.run(move |db| {
            let keys = db
                .totp_keys
                .as_ref()
                .ok_or_else(|| corrupt("TOTP encryption key is not configured"))?;
            let tx = db.transaction();
            let state: KeyState = read_tx(&tx, &key(KEY_STATE, Uuid::nil(), &[]), false)?
                .ok_or_else(|| corrupt("TOTP write key is not activated"))?;
            if state.current != keys.current().id() {
                return Err(corrupt("stale TOTP writer key"));
            }
            active(&tx, tenant_id, user_id)?;
            let k = totp_key(tenant_id, user_id);
            let old = read_tx::<Totp>(&tx, &k, true)?;
            if old.as_ref().is_some_and(|r| r.confirmed) {
                return Ok(false);
            }
            if let Some(old) = old {
                tx.delete(key_index(&old.key_id, tenant_id, user_id))
                    .map_err(map_error)?;
            }
            let (ciphertext, key_id) = protect(keys, tenant_id, user_id, &secret)?;
            let row = Totp {
                id: Uuid::new_v4(),
                ciphertext,
                key_id,
                confirmed: false,
                last_step: None,
            };
            put(&tx, &k, &row)?;
            put(
                &tx,
                &key_index(&row.key_id, tenant_id, user_id),
                &(tenant_id, user_id),
            )?;
            tx.commit().map_err(map_error)?;
            Ok(true)
        }))
    }
    fn verify_and_confirm_totp<'a>(
        &'a self,
        tenant_id: TenantId,
        user_id: UserId,
        code: &'a str,
        timestamp: i64,
        hashes: Vec<EncodedSecretHash>,
    ) -> RepositoryFuture<'a, TotpVerificationOutcome> {
        Box::pin(self.confirm_totp(tenant_id, user_id, code.into(), timestamp, hashes, None))
    }
    fn verify_and_confirm_totp_with_required_audit<'a>(
        &'a self,
        tenant_id: TenantId,
        user_id: UserId,
        code: &'a str,
        timestamp: i64,
        hashes: Vec<EncodedSecretHash>,
        source_ip_hash: String,
    ) -> RepositoryFuture<'a, TotpVerificationOutcome> {
        Box::pin(self.confirm_totp(
            tenant_id,
            user_id,
            code.into(),
            timestamp,
            hashes,
            Some(source_ip_hash),
        ))
    }
    fn record_invalid_totp_attempt(
        &self,
        tenant_id: TenantId,
        user_id: UserId,
    ) -> RepositoryFuture<'_, ()> {
        Box::pin(self.invalid_mfa(tenant_id, user_id, false))
    }
    fn verify_and_consume_totp<'a>(
        &'a self,
        tenant_id: TenantId,
        user_id: UserId,
        code: &'a str,
        timestamp: i64,
    ) -> RepositoryFuture<'a, TotpVerificationOutcome> {
        let code = code.to_owned();
        Box::pin(self.run(move |db| {
            let tx = db.transaction();
            active(&tx, tenant_id, user_id)?;
            let key = totp_key(tenant_id, user_id);
            let outcome = match read_tx::<Totp>(&tx, &key, true)? {
                Some(mut row) if row.confirmed => {
                    match step(db, tenant_id, user_id, &row, &code, timestamp)? {
                        Some(s) if row.last_step.is_some_and(|last| s <= last) => {
                            TotpVerificationOutcome::Replay
                        }
                        Some(s) => {
                            row.last_step = Some(s);
                            put(&tx, &key, &row)?;
                            TotpVerificationOutcome::Accepted(row.id)
                        }
                        None => TotpVerificationOutcome::Invalid,
                    }
                }
                _ => TotpVerificationOutcome::Invalid,
            };
            let (outcome_name, reason) = match outcome {
                TotpVerificationOutcome::Accepted(_) => ("success", "totp_accepted"),
                TotpVerificationOutcome::Invalid => ("invalid_credential", "totp_invalid"),
                TotpVerificationOutcome::Replay => ("replay", "totp_replay"),
            };
            append_in_tx(
                &tx,
                &attempt(tenant_id, user_id, false, outcome_name, reason),
            )?;
            tx.commit().map_err(map_error)?;
            Ok(outcome)
        }))
    }
    fn backup_code_candidates(
        &self,
        tenant_id: TenantId,
        user_id: UserId,
    ) -> RepositoryFuture<'_, Vec<BackupCodeCandidate>> {
        Box::pin(self.run(move |db| {
            let snapshot = db.db.snapshot();
            let prefix = owned_key(BACKUP, tenant_id, user_id, &[]);
            let mut rows = Vec::new();
            for result in snapshot
                .iterator(IteratorMode::From(&prefix, Direction::Forward))
                .take(MFA_BACKUP_CODE_COUNT + 1)
            {
                let (k, v) = result.map_err(map_error)?;
                if !k.starts_with(&prefix) {
                    break;
                }
                let id = Uuid::from_slice(&k[prefix.len()..])
                    .map_err(|_| corrupt("invalid backup-code id"))?;
                let hash = EncodedSecretHash::new(decode::<String>(&v)?)
                    .map_err(|_| corrupt("invalid backup-code verifier"))?;
                rows.push(BackupCodeCandidate { id, hash });
            }
            if rows.len() > MFA_BACKUP_CODE_COUNT {
                return Err(corrupt("backup-code count exceeds bound"));
            }
            Ok(rows)
        }))
    }
    fn consume_backup_code_candidate(
        &self,
        tenant_id: TenantId,
        user_id: UserId,
        candidate_id: Uuid,
    ) -> RepositoryFuture<'_, Option<Uuid>> {
        Box::pin(self.run(move |db| {
            let tx = db.transaction();
            active(&tx, tenant_id, user_id)?;
            let row =
                read_tx::<Totp>(&tx, &totp_key(tenant_id, user_id), false)?.filter(|r| r.confirmed);
            let k = owned_key(BACKUP, tenant_id, user_id, candidate_id.as_bytes());
            let generation = if let Some(row) = row {
                if read_tx::<String>(&tx, &k, true)?.is_some() {
                    tx.delete(&k).map_err(map_error)?;
                    Some(row.id)
                } else {
                    None
                }
            } else {
                None
            };
            append_in_tx(
                &tx,
                &attempt(
                    tenant_id,
                    user_id,
                    true,
                    if generation.is_some() {
                        "success"
                    } else {
                        "replay"
                    },
                    if generation.is_some() {
                        "backup_code_accepted"
                    } else {
                        "backup_code_replay"
                    },
                ),
            )?;
            tx.commit().map_err(map_error)?;
            Ok(generation)
        }))
    }
    fn record_invalid_backup_code_attempt(
        &self,
        tenant_id: TenantId,
        user_id: UserId,
    ) -> RepositoryFuture<'_, ()> {
        Box::pin(self.invalid_mfa(tenant_id, user_id, true))
    }
    fn replace_backup_code_hashes<'a>(
        &'a self,
        tenant_id: TenantId,
        user_id: UserId,
        credential_id: Uuid,
        hashes: Vec<EncodedSecretHash>,
    ) -> RepositoryFuture<'a, bool> {
        Box::pin(self.replace_codes(tenant_id, user_id, credential_id, hashes, None))
    }
    fn replace_backup_code_hashes_with_required_audit<'a>(
        &'a self,
        tenant_id: TenantId,
        user_id: UserId,
        credential_id: Uuid,
        hashes: Vec<EncodedSecretHash>,
        source_ip_hash: String,
    ) -> RepositoryFuture<'a, bool> {
        Box::pin(self.replace_codes(
            tenant_id,
            user_id,
            credential_id,
            hashes,
            Some(source_ip_hash),
        ))
    }
    fn clear_mfa_state_if_current<'a>(
        &'a self,
        tenant_id: TenantId,
        user_id: UserId,
        credential_id: Uuid,
    ) -> RepositoryFuture<'a, bool> {
        Box::pin(self.clear_mfa(tenant_id, user_id, credential_id, None))
    }
    fn clear_mfa_state_if_current_with_required_audit<'a>(
        &'a self,
        tenant_id: TenantId,
        user_id: UserId,
        credential_id: Uuid,
        source_ip_hash: String,
    ) -> RepositoryFuture<'a, bool> {
        Box::pin(self.clear_mfa(tenant_id, user_id, credential_id, Some(source_ip_hash)))
    }
    fn remember_device(
        &self,
        tenant_id: TenantId,
        user_id: UserId,
        credential_id: Uuid,
        token_hash: String,
        user_agent_hash: Option<String>,
        expires_at: Timestamp,
    ) -> RepositoryFuture<'_, bool> {
        Box::pin(self.run(move |db| {
            let tx = db.transaction();
            active(&tx, tenant_id, user_id)?;
            if !read_tx::<Totp>(&tx, &totp_key(tenant_id, user_id), false)?
                .is_some_and(|r| r.confirmed && r.id == credential_id)
            {
                return Ok(false);
            }
            let k = owned_key(REMEMBERED, tenant_id, user_id, token_hash.as_bytes());
            if read_tx::<Remembered>(&tx, &k, true)?.is_some() {
                return Err(RepositoryError::Conflict);
            }
            put_expiring(
                &tx,
                &k,
                &Remembered {
                    generation: credential_id,
                    user_agent: user_agent_hash,
                    expires: expires_at,
                },
                expires_at,
            )?;
            tx.commit().map_err(map_error)?;
            Ok(true)
        }))
    }
}
impl RememberedMfaDevicePort for RocksDb {
    fn is_valid<'a>(
        &'a self,
        tenant_id: TenantId,
        user_id: UserId,
        token_hash: &'a str,
        user_agent_hash: Option<&'a str>,
        now: Timestamp,
    ) -> RepositoryFuture<'a, bool> {
        let token = token_hash.to_owned();
        let agent = user_agent_hash.map(str::to_owned);
        Box::pin(self.run(move |db| {
            let snapshot = db.db.snapshot();
            let Some(row) = read_snapshot::<Remembered>(
                &snapshot,
                &owned_key(REMEMBERED, tenant_id, user_id, token.as_bytes()),
            )?
            .filter(|r| r.expires > now && r.user_agent == agent) else {
                return Ok(false);
            };
            Ok(
                read_snapshot::<Totp>(&snapshot, &totp_key(tenant_id, user_id))?
                    .is_some_and(|r| r.confirmed && r.id == row.generation),
            )
        }))
    }
}
