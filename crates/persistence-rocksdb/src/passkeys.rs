//! Durable WebAuthn credential generations; ceremonies stay in the state adapter.
use crate::{
    RocksDb,
    audit::append_in_tx,
    db::{decode, key, map_error, put, read_snapshot, read_tx},
    users::{corrupt, read_principal_tx},
};
use jiff::Timestamp;
use nazo_identity::{
    TenantId, UserId,
    ports::{
        ObservedPasskey, PasskeyAuthenticationUpdate, PasskeyCredential, PasskeyCredentialSummary,
        PasskeyRepositoryPort, RepositoryError, RepositoryFuture,
    },
};
use nazo_passkey::{CredentialId, PasskeyCredential as WebauthnCredential};
use nazo_persistence::SecurityAuditEvent;
use rocksdb::{Direction, IteratorMode};
use serde::{Deserialize, Serialize};
use serde_json::json;
use uuid::Uuid;

const PASSKEY: u8 = 0x41;
const CREDENTIAL_INDEX: u8 = 0x42;
#[derive(Serialize, Deserialize)]
struct StoredPasskey {
    id: Uuid,
    user_id: UserId,
    credential: WebauthnCredential,
    label: String,
    last_used_at: Option<Timestamp>,
    created_at: Timestamp,
    updated_at: Timestamp,
    revision: Uuid,
}
impl StoredPasskey {
    fn domain(self, tenant_id: TenantId) -> PasskeyCredential {
        PasskeyCredential {
            id: self.id,
            tenant_id,
            user_id: self.user_id,
            credential: self.credential,
            label: self.label,
            last_used_at: self.last_used_at,
            created_at: self.created_at,
            updated_at: self.updated_at,
        }
    }
}
#[derive(Serialize, Deserialize)]
struct CredentialOwner {
    user: UserId,
    id: Uuid,
}
// These readers skip the public key and attestation payload for display-only paths.
#[derive(Deserialize)]
struct CredentialSummary {
    id: CredentialId,
    counter: u32,
}
#[derive(Deserialize)]
struct Summary {
    id: Uuid,
    user_id: UserId,
    credential: CredentialSummary,
    label: String,
    last_used_at: Option<Timestamp>,
    created_at: Timestamp,
    updated_at: Timestamp,
}
#[derive(Deserialize)]
struct CredentialOnly {
    credential: CredentialIdOnly,
}
#[derive(Deserialize)]
struct CredentialIdOnly {
    id: CredentialId,
}
fn passkey_key(tenant: Uuid, user: UserId, id: Uuid) -> Vec<u8> {
    let mut k = key(PASSKEY, tenant, user.as_uuid().as_bytes());
    k.extend_from_slice(id.as_bytes());
    k
}
fn event(tenant: TenantId, user: UserId, id: Uuid, kind: &str) -> SecurityAuditEvent {
    SecurityAuditEvent {
        event_id: Uuid::new_v4(),
        event_type: kind.into(),
        event_category: "authentication".into(),
        occurred_at: Timestamp::now(),
        payload: json!({"schema_version":nazo_persistence::SECURITY_AUDIT_SCHEMA_VERSION,"event_category":"authentication","tenant_id":tenant,"user_id":user,"credential_id":id}),
    }
}
impl PasskeyRepositoryPort for RocksDb {
    fn list(
        &self,
        tenant_id: TenantId,
        user_id: UserId,
    ) -> RepositoryFuture<'_, Vec<PasskeyCredential>> {
        Box::pin(self.run(move |db| {
            let snapshot = db.db.snapshot();
            let prefix = key(PASSKEY, tenant_id.as_uuid(), user_id.as_uuid().as_bytes());
            let mut rows = Vec::new();
            for result in snapshot.iterator(IteratorMode::From(&prefix, Direction::Forward)) {
                let (k, v) = result.map_err(map_error)?;
                if !k.starts_with(&prefix) {
                    break;
                }
                rows.push(decode::<StoredPasskey>(&v)?.domain(tenant_id));
            }
            Ok(rows)
        }))
    }
    fn list_summaries(
        &self,
        tenant_id: TenantId,
        user_id: UserId,
    ) -> RepositoryFuture<'_, Vec<PasskeyCredentialSummary>> {
        Box::pin(self.run(move |db| {
            let snapshot = db.db.snapshot();
            let prefix = key(PASSKEY, tenant_id.as_uuid(), user_id.as_uuid().as_bytes());
            let mut rows = Vec::new();
            for result in snapshot.iterator(IteratorMode::From(&prefix, Direction::Forward)) {
                let (k, v) = result.map_err(map_error)?;
                if !k.starts_with(&prefix) {
                    break;
                }
                let row: Summary = decode(&v)?;
                rows.push(PasskeyCredentialSummary {
                    id: row.id,
                    tenant_id,
                    user_id: row.user_id,
                    credential_id: row.credential.id.to_b64url(),
                    label: row.label,
                    sign_count: i64::from(row.credential.counter),
                    last_used_at: row.last_used_at,
                    created_at: row.created_at,
                    updated_at: row.updated_at,
                });
            }
            Ok(rows)
        }))
    }
    fn credential_ids(
        &self,
        tenant_id: TenantId,
        user_id: UserId,
    ) -> RepositoryFuture<'_, Vec<CredentialId>> {
        Box::pin(self.run(move |db| {
            let snapshot = db.db.snapshot();
            let prefix = key(PASSKEY, tenant_id.as_uuid(), user_id.as_uuid().as_bytes());
            let mut ids = Vec::new();
            for result in snapshot.iterator(IteratorMode::From(&prefix, Direction::Forward)) {
                let (k, v) = result.map_err(map_error)?;
                if !k.starts_with(&prefix) {
                    break;
                }
                ids.push(decode::<CredentialOnly>(&v)?.credential.id);
            }
            Ok(ids)
        }))
    }
    fn by_credential_id<'a>(
        &'a self,
        tenant_id: TenantId,
        user_id: UserId,
        credential_id: &'a str,
    ) -> RepositoryFuture<'a, Option<ObservedPasskey>> {
        let credential = credential_id.to_owned();
        Box::pin(self.run(move |db| {
            let snapshot = db.db.snapshot();
            let Some(owner) = read_snapshot::<CredentialOwner>(
                &snapshot,
                &key(CREDENTIAL_INDEX, tenant_id.as_uuid(), credential.as_bytes()),
            )?
            .filter(|o| o.user == user_id) else {
                return Ok(None);
            };
            let row: StoredPasskey = read_snapshot(
                &snapshot,
                &passkey_key(tenant_id.as_uuid(), user_id, owner.id),
            )?
            .ok_or_else(|| corrupt("passkey index references missing credential"))?;
            if row.credential.id.to_b64url() != credential {
                return Err(corrupt("passkey credential index mismatch"));
            }
            Ok(Some(ObservedPasskey {
                revision: Some(row.revision),
                row: row.domain(tenant_id),
            }))
        }))
    }
    fn insert(
        &self,
        tenant_id: TenantId,
        user_id: UserId,
        credential: WebauthnCredential,
        label: String,
    ) -> RepositoryFuture<'_, PasskeyCredential> {
        Box::pin(self.run(move |db| {
            let tx = db.transaction();
            read_principal_tx(&tx, tenant_id.as_uuid(), user_id.as_uuid(), false)?
                .filter(|p| p.active)
                .ok_or(RepositoryError::Conflict)?;
            let index = key(
                CREDENTIAL_INDEX,
                tenant_id.as_uuid(),
                credential.id.to_b64url().as_bytes(),
            );
            if read_tx::<CredentialOwner>(&tx, &index, true)?.is_some() {
                return Err(RepositoryError::Conflict);
            }
            let now = Timestamp::now();
            let id = Uuid::now_v7();
            let row = StoredPasskey {
                id,
                user_id,
                credential,
                label,
                last_used_at: None,
                created_at: now,
                updated_at: now,
                revision: Uuid::new_v4(),
            };
            put(&tx, &passkey_key(tenant_id.as_uuid(), user_id, id), &row)?;
            put(&tx, &index, &CredentialOwner { user: user_id, id })?;
            append_in_tx(&tx, &event(tenant_id, user_id, id, "passkey_registered"))?;
            tx.commit().map_err(map_error)?;
            Ok(row.domain(tenant_id))
        }))
    }
    fn update_authentication<'a>(
        &'a self,
        observed: &'a ObservedPasskey,
        update: PasskeyAuthenticationUpdate,
    ) -> RepositoryFuture<'a, ()> {
        let tenant = observed.row.tenant_id;
        let user = observed.row.user_id;
        let id = observed.row.id;
        let revision = observed.revision;
        Box::pin(self.run(move |db| {
            let tx = db.transaction();
            read_principal_tx(&tx, tenant.as_uuid(), user.as_uuid(), false)?
                .filter(|p| p.active)
                .ok_or(RepositoryError::Conflict)?;
            let k = passkey_key(tenant.as_uuid(), user, id);
            let mut row: StoredPasskey =
                read_tx(&tx, &k, true)?.ok_or(RepositoryError::Conflict)?;
            if revision != Some(row.revision) {
                return Err(RepositoryError::Conflict);
            }
            let c = &mut row.credential;
            let facts = update.credential;
            if c.counter != facts.expected_counter
                || c.backup_eligible != facts.expected_backup_eligible
                || c.backup_state != facts.expected_backup_state
                || c.backup_eligible
                    .is_some_and(|v| v != facts.backup_eligible)
            {
                return Err(RepositoryError::Conflict);
            }
            c.counter = facts.new_counter;
            c.backup_eligible = Some(facts.backup_eligible);
            c.backup_state = Some(facts.backup_state);
            if update.initialize_user_verification {
                c.uv_initialized = Some(true);
            }
            row.revision = Uuid::new_v4();
            row.updated_at = Timestamp::now();
            row.last_used_at = Some(row.updated_at);
            put(&tx, &k, &row)?;
            tx.commit().map_err(map_error)
        }))
    }
    fn delete(&self, tenant_id: TenantId, user_id: UserId, id: Uuid) -> RepositoryFuture<'_, bool> {
        Box::pin(self.run(move |db| {
            let tx = db.transaction();
            let k = passkey_key(tenant_id.as_uuid(), user_id, id);
            let Some(row) = read_tx::<StoredPasskey>(&tx, &k, true)? else {
                return Ok(false);
            };
            tx.delete(&k).map_err(map_error)?;
            tx.delete(key(
                CREDENTIAL_INDEX,
                tenant_id.as_uuid(),
                row.credential.id.to_b64url().as_bytes(),
            ))
            .map_err(map_error)?;
            append_in_tx(&tx, &event(tenant_id, user_id, id, "passkey_deleted"))?;
            tx.commit().map_err(map_error)?;
            Ok(true)
        }))
    }
}
