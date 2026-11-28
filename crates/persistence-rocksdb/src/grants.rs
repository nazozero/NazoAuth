//! Grant authority, owner indexes and ordered administrative pagination.

use crate::{
    RocksDb,
    audit::append_in_tx,
    clients,
    db::{decode, key, map_error, put, read_snapshot, read_tx},
    users,
};
use jiff::Timestamp;
use nazo_auth::{
    AdminGrantFuture, AdminGrantPage, AdminGrantRepositoryPort, AdminGrantRevocation,
    AdminGrantRevokeError, AdminGrantRevokeFuture, AdminGrantView, AuthorizationPortError,
    StoredAuthorizationGrant,
};
use nazo_identity::{
    TenantId,
    ports::{
        AuthorizedApplication, AuthorizedApplicationRepositoryPort, GrantSummaryRepositoryPort,
        RepositoryError, RepositoryFuture,
    },
};
use nazo_persistence::SecurityAuditEvent;
use rocksdb::{Direction, IteratorMode, SnapshotWithThreadMode, Transaction, TransactionDB};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use uuid::Uuid;

pub(crate) const GRANT: u8 = 0x30;
const GRANT_BY_CLIENT: u8 = 0x31;
const GRANT_BY_TIME: u8 = 0x32;
#[derive(Deserialize)]
pub(crate) struct GrantRecord {
    pub user_id: Uuid,
    pub client_id: Uuid,
    pub scopes: Vec<String>,
    pub resource_indicators: Vec<String>,
    pub authorization_details: Value,
    pub last_authorized_at: Timestamp,
    pub authorization_count: i32,
}
#[derive(Deserialize)]
struct GrantRevision {
    last_authorized_at: Timestamp,
    authorization_count: i32,
}
#[derive(Serialize)]
struct GrantWrite<'a> {
    user_id: Uuid,
    client_id: Uuid,
    scopes: &'a [String],
    resource_indicators: &'a [String],
    authorization_details: &'a Value,
    last_authorized_at: Timestamp,
    authorization_count: i32,
}
impl GrantRecord {
    pub(crate) fn authorization(self) -> StoredAuthorizationGrant {
        StoredAuthorizationGrant {
            scopes: Value::Array(self.scopes.into_iter().map(Value::String).collect()),
            resource_indicators: Value::Array(
                self.resource_indicators
                    .into_iter()
                    .map(Value::String)
                    .collect(),
            ),
            authorization_details: self.authorization_details,
        }
    }
}
pub(crate) fn grant_key(tenant: Uuid, user: Uuid, client: Uuid) -> Vec<u8> {
    let mut k = key(GRANT, tenant, user.as_bytes());
    k.extend_from_slice(client.as_bytes());
    k
}
fn client_key(tenant: Uuid, client: Uuid, user: Uuid) -> Vec<u8> {
    let mut k = key(GRANT_BY_CLIENT, tenant, client.as_bytes());
    k.extend_from_slice(user.as_bytes());
    k
}
fn time_key(tenant: Uuid, time: Timestamp, user: Uuid, client: Uuid) -> Vec<u8> {
    let mut k = key(
        GRANT_BY_TIME,
        tenant,
        &((time.as_microsecond() as u64) ^ (1 << 63)).to_be_bytes(),
    );
    k.extend_from_slice(user.as_bytes());
    k.extend_from_slice(client.as_bytes());
    k
}
pub(crate) fn read_grant_tx(
    tx: &Transaction<'_, TransactionDB>,
    tenant: Uuid,
    user: Uuid,
    client: Uuid,
    exclusive: bool,
) -> Result<Option<GrantRecord>, RepositoryError> {
    read_tx(tx, &grant_key(tenant, user, client), exclusive)
}
#[allow(clippy::too_many_arguments)]
pub(crate) fn write_grant_tx(
    tx: &Transaction<'_, TransactionDB>,
    tenant: Uuid,
    user: Uuid,
    client: Uuid,
    scopes: &[String],
    resources: &[String],
    details: &Value,
    new_authorization: bool,
    authorized_at: Timestamp,
) -> Result<(), RepositoryError> {
    let key = grant_key(tenant, user, client);
    let previous = read_tx::<GrantRevision>(tx, &key, true)?;
    let count = match previous {
        Some(ref g) => g
            .authorization_count
            .checked_add(i32::from(new_authorization))
            .ok_or_else(|| users::corrupt("grant authorization count exhausted"))?,
        None => 1,
    };
    put(
        tx,
        &key,
        &GrantWrite {
            user_id: user,
            client_id: client,
            scopes,
            resource_indicators: resources,
            authorization_details: details,
            last_authorized_at: authorized_at,
            authorization_count: count,
        },
    )?;
    if previous.is_none() {
        put(tx, &client_key(tenant, client, user), &())?;
    }
    if let Some(previous) = previous {
        tx.delete(time_key(tenant, previous.last_authorized_at, user, client))
            .map_err(map_error)?;
    }
    put(tx, &time_key(tenant, authorized_at, user, client), &())?;
    Ok(())
}
pub(crate) fn delete_scope_tx(
    tx: &Transaction<'_, TransactionDB>,
    tenant: Uuid,
    user: Uuid,
    client: Uuid,
) -> Result<usize, RepositoryError> {
    let key = grant_key(tenant, user, client);
    let Some(grant) = read_tx::<GrantRevision>(tx, &key, true)? else {
        return Ok(0);
    };
    tx.delete(&key).map_err(map_error)?;
    tx.delete(client_key(tenant, client, user))
        .map_err(map_error)?;
    tx.delete(time_key(tenant, grant.last_authorized_at, user, client))
        .map_err(map_error)?;
    Ok(1)
}
pub(crate) fn delete_for_user_tx(
    tx: &Transaction<'_, TransactionDB>,
    tenant: Uuid,
    user: Uuid,
) -> Result<usize, RepositoryError> {
    let prefix = key(GRANT, tenant, user.as_bytes());
    let mut count = 0;
    for result in tx.iterator(IteratorMode::From(&prefix, Direction::Forward)) {
        let (k, _) = result.map_err(map_error)?;
        if !k.starts_with(&prefix) {
            break;
        }
        let client = Uuid::from_slice(&k[prefix.len()..])
            .map_err(|_| users::corrupt("invalid grant owner index"))?;
        count += delete_scope_tx(tx, tenant, user, client)?;
    }
    Ok(count)
}
pub(crate) fn delete_for_client_tx(
    tx: &Transaction<'_, TransactionDB>,
    tenant: Uuid,
    client: Uuid,
) -> Result<usize, RepositoryError> {
    let prefix = key(GRANT_BY_CLIENT, tenant, client.as_bytes());
    let mut count = 0;
    for result in tx.iterator(IteratorMode::From(&prefix, Direction::Forward)) {
        let (k, _) = result.map_err(map_error)?;
        if !k.starts_with(&prefix) {
            break;
        }
        let user = Uuid::from_slice(&k[prefix.len()..])
            .map_err(|_| users::corrupt("invalid grant client index"))?;
        count += delete_scope_tx(tx, tenant, user, client)?;
    }
    Ok(count)
}
fn view(
    snapshot: &SnapshotWithThreadMode<'_, TransactionDB>,
    tenant: Uuid,
    grant: GrantRecord,
) -> Result<AdminGrantView, RepositoryError> {
    #[derive(Deserialize)]
    struct Email {
        email: String,
    }
    let account: Email = read_snapshot(
        snapshot,
        &key(users::USER_CLAIMS, tenant, grant.user_id.as_bytes()),
    )?
    .ok_or_else(|| users::corrupt("grant account missing"))?;
    let (client_id, client_name) = clients::client_display(snapshot, tenant, grant.client_id)?;
    Ok(AdminGrantView {
        user_id: grant.user_id,
        email: account.email,
        client_id,
        client_name,
        last_authorized_at: Some(grant.last_authorized_at),
        authorization_count: Some(grant.authorization_count),
        last_scopes: grant.scopes,
        last_authorization_details: grant.authorization_details,
    })
}
pub(crate) fn authorization_error(error: RepositoryError) -> AuthorizationPortError {
    match error {
        RepositoryError::Unavailable => AuthorizationPortError::Unavailable,
        RepositoryError::Conflict => AuthorizationPortError::Conflict,
        RepositoryError::Consistency(_) => AuthorizationPortError::CorruptData,
        _ => AuthorizationPortError::Unexpected,
    }
}
impl GrantSummaryRepositoryPort for RocksDb {
    fn authorized_client_count(
        &self,
        tenant_id: TenantId,
        user_id: Uuid,
    ) -> RepositoryFuture<'_, i64> {
        Box::pin(self.run(move |db| {
            let prefix = key(GRANT, tenant_id.as_uuid(), user_id.as_bytes());
            let snapshot = db.db.snapshot();
            let mut count = 0;
            let mut rows = snapshot.raw_iterator();
            rows.seek(&prefix);
            while let Some(k) = rows.key() {
                if !k.starts_with(&prefix) {
                    break;
                }
                count += 1;
                rows.next();
            }
            rows.status().map_err(map_error)?;
            Ok(count)
        }))
    }
}
impl AuthorizedApplicationRepositoryPort for RocksDb {
    fn applications_for_user(
        &self,
        tenant_id: TenantId,
        user_id: Uuid,
    ) -> RepositoryFuture<'_, Vec<AuthorizedApplication>> {
        Box::pin(self.run(move |db| {
            let tenant = tenant_id.as_uuid();
            let prefix = key(GRANT, tenant, user_id.as_bytes());
            let snapshot = db.db.snapshot();
            let mut apps = Vec::new();
            for result in snapshot.iterator(IteratorMode::From(&prefix, Direction::Forward)) {
                let (k, v) = result.map_err(map_error)?;
                if !k.starts_with(&prefix) {
                    break;
                }
                let grant: GrantRecord = decode(&v)?;
                let (client_id, client_name) =
                    clients::client_display(&snapshot, tenant, grant.client_id)?;
                apps.push(AuthorizedApplication {
                    client_id,
                    client_name,
                    last_scopes: Value::Array(
                        grant.scopes.into_iter().map(Value::String).collect(),
                    ),
                    last_authorized_at: Some(grant.last_authorized_at),
                    authorization_count: Some(grant.authorization_count),
                });
            }
            apps.sort_by(|a, b| {
                b.last_authorized_at
                    .cmp(&a.last_authorized_at)
                    .then_with(|| a.client_id.cmp(&b.client_id))
            });
            Ok(apps)
        }))
    }
}
impl AdminGrantRepositoryPort for RocksDb {
    fn page(
        &self,
        tenant_id: Uuid,
        limit: i64,
        offset: i64,
    ) -> AdminGrantFuture<'_, AdminGrantPage> {
        Box::pin(async move {
            self.run(move |db| {
                if limit < 0 || offset < 0 {
                    return Err(users::corrupt("negative grant page bounds"));
                }
                let snapshot = db.db.snapshot();
                let prefix = key(GRANT_BY_TIME, tenant_id, &[]);
                let mut upper = prefix.clone();
                upper.extend_from_slice(&[u8::MAX; 40]);
                let mut grants = Vec::new();
                let mut total = 0_i64;
                let mut rows = snapshot.raw_iterator();
                rows.seek_for_prev(&upper);
                while let Some(k) = rows.key() {
                    if !k.starts_with(&prefix) {
                        break;
                    }
                    if total >= offset && grants.len() < limit as usize {
                        let grant: GrantRecord = read_snapshot(
                            &snapshot,
                            &key(GRANT, tenant_id, &k[prefix.len() + 8..]),
                        )?
                        .ok_or_else(|| {
                            users::corrupt("grant time index references missing grant")
                        })?;
                        grants.push(view(&snapshot, tenant_id, grant)?);
                    }
                    total += 1;
                    rows.prev();
                }
                rows.status().map_err(map_error)?;
                Ok(AdminGrantPage { total, grants })
            })
            .await
            .map_err(authorization_error)
        })
    }
    fn revoke_by_client_id<'a>(
        &'a self,
        tenant_id: Uuid,
        user_id: Uuid,
        client_id: &'a str,
        admin_user_id: Uuid,
    ) -> AdminGrantRevokeFuture<'a> {
        let public_id = client_id.to_owned();
        Box::pin(async move {
            self.run(move |db| {
                let tx = db.transaction();
                let Some(client) = read_tx::<Uuid>(
                    &tx,
                    &key(clients::CLIENT_PUBLIC_ID, tenant_id, public_id.as_bytes()),
                    false,
                )?
                else {
                    return Err(RepositoryError::NotFound);
                };
                // Exclude new family/decision insertion while this scope is revoked.
                if read_tx::<clients::ClientPrincipal>(
                    &tx,
                    &key(clients::CLIENT_PRINCIPAL, tenant_id, client.as_bytes()),
                    true,
                )?
                .is_none()
                {
                    return Err(RepositoryError::NotFound);
                }
                let actor_tenant = read_tx::<Uuid>(
                    &tx,
                    &key(users::USER_TENANT, Uuid::nil(), admin_user_id.as_bytes()),
                    false,
                )?
                .ok_or(RepositoryError::Unavailable)?;
                users::read_principal_tx(&tx, actor_tenant, admin_user_id, false)?
                    .filter(|p| p.active && p.admin_level().is_some_and(|level| level > 0))
                    .ok_or(RepositoryError::Unavailable)?;
                let revoked =
                    crate::tokens::revoke_families(&tx, tenant_id, Some(client), Some(user_id))?;
                let removed = delete_scope_tx(&tx, tenant_id, user_id, client)?;
                crate::digital_credentials::issuance::revoke_for_scope(
                    &tx, tenant_id, user_id, &public_id,
                )?;
                append_in_tx(
                    &tx,
                    &SecurityAuditEvent {
                        event_id: Uuid::new_v4(),
                        event_type: "admin_grant_revoked".into(),
                        event_category: "administration".into(),
                        occurred_at: Timestamp::now(),
                        payload: json!({
                            "schema_version": nazo_persistence::SECURITY_AUDIT_SCHEMA_VERSION,
                            "event_category": "administration",
                            "tenant_id": tenant_id,
                            "admin_user_id": admin_user_id,
                            "actor_tenant_id": actor_tenant,
                            "user_id": user_id,
                            "outcome": "success",
                            "client_id": public_id,
                            "revoked_refresh_tokens": revoked,
                            "removed_grants": removed,
                        }),
                    },
                )?;
                tx.commit().map_err(map_error)?;
                Ok(AdminGrantRevocation {
                    revoked_refresh_tokens: revoked,
                    removed_grants: removed,
                })
            })
            .await
            .map_err(|error| {
                if error == RepositoryError::NotFound {
                    AdminGrantRevokeError::ClientNotFound
                } else {
                    AdminGrantRevokeError::Revoke(authorization_error(error))
                }
            })
        })
    }
}
