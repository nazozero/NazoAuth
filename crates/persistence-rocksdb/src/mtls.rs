//! Tenant-scoped trust lifecycle. Only active and pending query paths have
//! indexes; each mutation includes its source event and required audit.

use jiff::Timestamp;
use nazo_identity::{
    MtlsTrustAnchorRequest, MtlsTrustAnchorRequestPage, MtlsTrustAnchorStatus,
    NewMtlsTrustAnchorRequest, TenantId, UserId,
    ports::{MtlsTrustAnchorStore, RepositoryError, RepositoryFuture},
};
use nazo_persistence::tenant_resources::PreparedMtlsTrustAnchor;
use rocksdb::{Direction, IteratorMode, SnapshotWithThreadMode, Transaction, TransactionDB};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use uuid::Uuid;

use crate::{
    RocksDb,
    db::{decode, key, map_error, put, put_expiring, read_snapshot, read_tx},
};

const REQUEST: u8 = 0xc1;
const LOCK: u8 = 0xc2;
const ACTIVE: u8 = 0xc3;
const USER: u8 = 0xc4;
const EVENT: u8 = 0xc5;
const PENDING_CLIENT: u8 = 0xcb;
const PENDING_USER: u8 = 0xcc;
const CERTIFICATE: u8 = 0xcd;

#[derive(Serialize, Deserialize)]
struct Request {
    id: Uuid,
    requester: Option<Uuid>,
    client: Uuid,
    certificate_pem: String,
    certificate_sha256: String,
    subject_dn: String,
    not_before: Timestamp,
    not_after: Timestamp,
    status: i16,
    admin_note: Option<String>,
    created_at: Timestamp,
    resolved_at: Option<Timestamp>,
    revoked_at: Option<Timestamp>,
}

fn index_key(table: u8, tenant: Uuid, owner: Uuid, request: Uuid) -> Vec<u8> {
    let mut index = key(table, tenant, owner.as_bytes());
    index.extend_from_slice(request.as_bytes());
    index
}

fn lock(tx: &Transaction<'_, TransactionDB>, tenant: Uuid) -> Result<(), RepositoryError> {
    read_tx::<bool>(tx, &key(LOCK, tenant, &[]), true).map(|_| ())
}

fn eligible(client: &nazo_auth::OAuthClient) -> bool {
    client.is_active
        && ((client.token_endpoint_auth_method == "tls_client_auth"
            && client.tls_client_auth_cert_sha256.is_some())
            || client.require_mtls_bound_tokens)
}

fn count_prefix(
    tx: &Transaction<'_, TransactionDB>,
    prefix: &[u8],
) -> Result<usize, RepositoryError> {
    let mut count = 0;
    for row in tx.iterator(IteratorMode::From(prefix, Direction::Forward)) {
        let (storage_key, _) = row.map_err(map_error)?;
        if !storage_key.starts_with(prefix) {
            break;
        }
        count += 1;
    }
    Ok(count)
}

fn active_limits(
    tx: &Transaction<'_, TransactionDB>,
    tenant: Uuid,
    client: Uuid,
    certificate: &str,
    now: Timestamp,
) -> Result<(), RepositoryError> {
    let prefix = key(ACTIVE, tenant, &[]);
    let mut certificates = BTreeSet::new();
    let mut client_count = 0;
    for row in tx.iterator(IteratorMode::From(&prefix, Direction::Forward)) {
        let (storage_key, _) = row.map_err(map_error)?;
        if !storage_key.starts_with(&prefix) {
            break;
        }
        let id = Uuid::from_slice(&storage_key[33..])
            .map_err(|_| RepositoryError::Consistency("invalid trust anchor index".into()))?;
        let anchor: Request = read_tx(tx, &key(REQUEST, tenant, id.as_bytes()), false)?
            .ok_or_else(|| RepositoryError::Consistency("missing indexed trust anchor".into()))?;
        if anchor.status != 1 || anchor.not_before > now || anchor.not_after <= now {
            continue;
        }
        if anchor.client == client {
            client_count += 1;
        }
        if crate::clients::read_client_tx(tx, tenant, anchor.client, false)?
            .is_some_and(|client| client.is_active)
        {
            certificates.insert(anchor.certificate_sha256);
        }
    }
    if client_count >= 8 || (!certificates.contains(certificate) && certificates.len() >= 128) {
        return Err(RepositoryError::Conflict);
    }
    Ok(())
}

fn source_event(
    tx: &Transaction<'_, TransactionDB>,
    tenant: Uuid,
    request: Uuid,
    actor: Option<Uuid>,
    action: i16,
    note: Option<&str>,
) -> Result<(), RepositoryError> {
    put(
        tx,
        &key(EVENT, tenant, Uuid::now_v7().as_bytes()),
        &serde_json::json!({
            "request_id": request,
            "actor_user_id": actor,
            "action": action,
            "note": note,
            "occurred_at": Timestamp::now()
        }),
    )
}

fn admin_event(
    tx: &Transaction<'_, TransactionDB>,
    tenant: Uuid,
    id: Uuid,
    actor: Uuid,
    status: i16,
) -> Result<(), RepositoryError> {
    crate::audit::append_in_tx(
        tx,
        &nazo_persistence::SecurityAuditEvent {
            event_id: Uuid::now_v7(),
            event_type: match status {
                1 => "mtls_trust_anchor_approved",
                2 => "mtls_trust_anchor_rejected",
                _ => "mtls_trust_anchor_revoked",
            }
            .into(),
            event_category: "trust_lifecycle".into(),
            occurred_at: Timestamp::now(),
            payload: serde_json::json!({
                "schema_version": nazo_persistence::SECURITY_AUDIT_SCHEMA_VERSION,
                "event_category": "trust_lifecycle",
                "tenant_id": tenant,
                "request_id": id,
                "admin_user_id": actor,
                "outcome": "success"
            }),
        },
    )
}

fn view(row: Request, tenant: Uuid, email: String, client_id: String) -> MtlsTrustAnchorRequest {
    MtlsTrustAnchorRequest {
        id: row.id,
        tenant_id: tenant,
        user_id: row.requester.expect("session trust request"),
        requester_email: Some(email),
        client_id,
        certificate_pem: row.certificate_pem,
        certificate_sha256: row.certificate_sha256,
        subject_dn: row.subject_dn,
        not_before: row.not_before,
        not_after: row.not_after,
        status: row.status,
        admin_note: row.admin_note,
        created_at: row.created_at,
        resolved_at: row.resolved_at,
        revoked_at: row.revoked_at,
    }
}

fn view_snapshot(
    snapshot: &SnapshotWithThreadMode<'_, TransactionDB>,
    tenant: Uuid,
    row: Request,
) -> Result<Option<MtlsTrustAnchorRequest>, RepositoryError> {
    let Some(user) = row.requester else {
        return Ok(None);
    };
    let Some(account) = crate::users::public_account_snapshot(snapshot, tenant, user)? else {
        return Ok(None);
    };
    let Some(client) = crate::clients::read_client_snapshot(snapshot, tenant, row.client)? else {
        return Ok(None);
    };
    Ok(Some(view(
        row,
        tenant,
        account.account.email,
        client.client_id.clone(),
    )))
}

pub(crate) fn insert_managed_tx(
    tx: &Transaction<'_, TransactionDB>,
    tenant: Uuid,
    client_id: Uuid,
    material: PreparedMtlsTrustAnchor,
) -> Result<Uuid, RepositoryError> {
    lock(tx, tenant)?;
    let client = crate::clients::read_client_tx(tx, tenant, client_id, false)?
        .filter(eligible)
        .ok_or(RepositoryError::Conflict)?;
    let now = Timestamp::now();
    if material.not_before > now || material.not_after <= now {
        return Err(RepositoryError::Conflict);
    }
    active_limits(tx, tenant, client.id, &material.certificate_sha256, now)?;
    let mut certificate_key = key(CERTIFICATE, tenant, client.id.as_bytes());
    certificate_key.extend_from_slice(material.certificate_sha256.as_bytes());
    if read_tx::<Uuid>(tx, &certificate_key, true)?.is_some() {
        return Err(RepositoryError::Conflict);
    }
    let id = Uuid::now_v7();
    let request = Request {
        id,
        requester: None,
        client: client.id,
        certificate_pem: material.certificate_pem,
        certificate_sha256: material.certificate_sha256,
        subject_dn: material.subject_dn,
        not_before: material.not_before,
        not_after: material.not_after,
        status: 1,
        admin_note: Some("operator-managed".into()),
        created_at: now,
        resolved_at: Some(now),
        revoked_at: None,
    };
    put(tx, &key(REQUEST, tenant, id.as_bytes()), &request)?;
    put(tx, &certificate_key, &id)?;
    put_expiring(
        tx,
        &index_key(ACTIVE, tenant, client.id, id),
        &(),
        request.not_after,
    )?;
    source_event(tx, tenant, id, None, 0, Some("operator-managed"))?;
    source_event(tx, tenant, id, None, 1, Some("operator-managed"))?;
    Ok(id)
}

pub(crate) fn revoke_managed_tx(
    tx: &Transaction<'_, TransactionDB>,
    tenant: Uuid,
    id: Uuid,
) -> Result<bool, RepositoryError> {
    lock(tx, tenant)?;
    let storage_key = key(REQUEST, tenant, id.as_bytes());
    let Some(mut row) = read_tx::<Request>(tx, &storage_key, true)? else {
        return Ok(false);
    };
    if row.requester.is_some() || row.status != 1 {
        return Ok(false);
    }
    row.status = 3;
    row.revoked_at = Some(Timestamp::now());
    put(tx, &storage_key, &row)?;
    crate::db::delete_expiring(
        tx,
        &index_key(ACTIVE, tenant, row.client, id),
        row.not_after,
    )?;
    source_event(tx, tenant, id, None, 3, Some("operator-managed"))?;
    Ok(true)
}

impl RocksDb {
    fn resolve_trust(
        &self,
        tenant: TenantId,
        id: Uuid,
        actor: UserId,
        status: i16,
        note: Option<String>,
    ) -> RepositoryFuture<'_, MtlsTrustAnchorRequest> {
        Box::pin(self.run(move |db| {
            let tx = db.transaction();
            let tenant = tenant.as_uuid();
            lock(&tx, tenant)?;
            let principal = crate::users::read_principal_tx(&tx, tenant, actor.as_uuid(), false)?
                .filter(|principal| {
                    principal.active && principal.admin_level().is_some_and(|level| level > 0)
                })
                .ok_or(RepositoryError::Conflict)?;
            let storage_key = key(REQUEST, tenant, id.as_bytes());
            let mut row: Request =
                read_tx(&tx, &storage_key, true)?.ok_or(RepositoryError::Conflict)?;
            let user = row.requester.ok_or(RepositoryError::Conflict)?;
            if (status == 3 && row.status != 1)
                || (status != 3 && (row.status != 0 || user == actor.as_uuid()))
            {
                return Err(RepositoryError::Conflict);
            }
            let client = crate::clients::read_client_tx(&tx, tenant, row.client, false)?
                .ok_or(RepositoryError::Conflict)?;
            let now = Timestamp::now();
            if status == 1 {
                if !client.is_active || row.not_before > now || row.not_after <= now {
                    return Err(RepositoryError::Conflict);
                }
                active_limits(&tx, tenant, row.client, &row.certificate_sha256, now)?;
                put_expiring(
                    &tx,
                    &index_key(ACTIVE, tenant, row.client, id),
                    &(),
                    row.not_after,
                )?;
            }
            if row.status == 0 {
                tx.delete(index_key(PENDING_CLIENT, tenant, row.client, id))
                    .map_err(map_error)?;
                tx.delete(index_key(PENDING_USER, tenant, user, id))
                    .map_err(map_error)?;
            }
            if status == 3 {
                row.revoked_at = Some(now);
                crate::db::delete_expiring(
                    &tx,
                    &index_key(ACTIVE, tenant, row.client, id),
                    row.not_after,
                )?;
            } else {
                row.resolved_at = Some(now);
            }
            row.status = status;
            row.admin_note = note;
            put(&tx, &storage_key, &row)?;
            source_event(
                &tx,
                tenant,
                id,
                Some(principal.user_id.as_uuid()),
                status,
                row.admin_note.as_deref(),
            )?;
            admin_event(&tx, tenant, id, actor.as_uuid(), status)?;
            let requester = crate::users::read_principal_tx(&tx, tenant, user, false)?
                .ok_or(RepositoryError::Conflict)?;
            let account = crate::users::public_account_tx(&tx, requester)?;
            let result = view(row, tenant, account.account.email, client.client_id.clone());
            tx.commit().map_err(map_error)?;
            Ok(result)
        }))
    }
}

impl MtlsTrustAnchorStore for RocksDb {
    fn create_for_owned_client(
        &self,
        request: NewMtlsTrustAnchorRequest,
    ) -> RepositoryFuture<'_, MtlsTrustAnchorRequest> {
        Box::pin(self.run(move |db| {
            let tx = db.transaction();
            let tenant = request.tenant_id.as_uuid();
            let user = request.user_id.as_uuid();
            lock(&tx, tenant)?;
            let client_id = crate::access_requests::owned_client_tx(
                &tx,
                request.tenant_id,
                request.user_id,
                &request.client_id,
            )?
            .ok_or(RepositoryError::NotFound)?;
            let client = crate::clients::read_client_tx(&tx, tenant, client_id, false)?
                .filter(eligible)
                .ok_or(RepositoryError::NotFound)?;
            let requester = crate::users::read_principal_tx(&tx, tenant, user, false)?
                .filter(|p| p.active)
                .ok_or(RepositoryError::NotFound)?;
            let account = crate::users::public_account_tx(&tx, requester)?;
            let now = Timestamp::now();
            if request.not_before > now || request.not_after <= now {
                return Err(RepositoryError::NotFound);
            }
            if count_prefix(&tx, &key(PENDING_CLIENT, tenant, client.id.as_bytes()))? >= 4
                || count_prefix(&tx, &key(PENDING_USER, tenant, user.as_bytes()))? >= 16
            {
                return Err(RepositoryError::Conflict);
            }
            let mut certificate_key = key(CERTIFICATE, tenant, client.id.as_bytes());
            certificate_key.extend_from_slice(request.certificate_sha256.as_bytes());
            if read_tx::<Uuid>(&tx, &certificate_key, true)?.is_some() {
                return Err(RepositoryError::Conflict);
            }
            let id = Uuid::now_v7();
            let row = Request {
                id,
                requester: Some(user),
                client: client.id,
                certificate_pem: request.certificate_pem,
                certificate_sha256: request.certificate_sha256,
                subject_dn: request.subject_dn,
                not_before: request.not_before,
                not_after: request.not_after,
                status: 0,
                admin_note: None,
                created_at: now,
                resolved_at: None,
                revoked_at: None,
            };
            put(&tx, &key(REQUEST, tenant, id.as_bytes()), &row)?;
            put(&tx, &certificate_key, &id)?;
            for (table, owner) in [
                (USER, user),
                (PENDING_CLIENT, client.id),
                (PENDING_USER, user),
            ] {
                put(&tx, &index_key(table, tenant, owner, id), &())?;
            }
            source_event(&tx, tenant, id, Some(user), 0, None)?;
            crate::audit::append_in_tx(
                &tx,
                &nazo_persistence::SecurityAuditEvent {
                    event_id: Uuid::now_v7(),
                    event_type: "mtls_trust_anchor_requested".into(),
                    event_category: "trust_lifecycle".into(),
                    occurred_at: now,
                    payload: serde_json::json!({
                        "schema_version": nazo_persistence::SECURITY_AUDIT_SCHEMA_VERSION,
                        "event_category": "trust_lifecycle",
                        "tenant_id": tenant,
                        "request_id": id,
                        "requester_user_id": user,
                        "client_id": client.client_id,
                        "certificate_sha256": row.certificate_sha256
                    }),
                },
            )?;
            let result = view(row, tenant, account.account.email, client.client_id.clone());
            tx.commit().map_err(map_error)?;
            Ok(result)
        }))
    }

    fn list_for_user(
        &self,
        tenant_id: TenantId,
        user_id: UserId,
    ) -> RepositoryFuture<'_, Vec<MtlsTrustAnchorRequest>> {
        Box::pin(self.run(move |db| {
            let snapshot = db.db.snapshot();
            let tenant = tenant_id.as_uuid();
            let prefix = key(USER, tenant, user_id.as_uuid().as_bytes());
            let mut result = Vec::new();
            for row in snapshot.iterator(IteratorMode::From(&prefix, Direction::Forward)) {
                let (storage_key, _) = row.map_err(map_error)?;
                if !storage_key.starts_with(&prefix) {
                    break;
                }
                let id = Uuid::from_slice(&storage_key[33..])
                    .map_err(|_| RepositoryError::Consistency("invalid trust user index".into()))?;
                let row: Request = read_snapshot(&snapshot, &key(REQUEST, tenant, id.as_bytes()))?
                    .ok_or_else(|| RepositoryError::Consistency("missing trust request".into()))?;
                if let Some(view) = view_snapshot(&snapshot, tenant, row)? {
                    result.push(view);
                }
            }
            result.sort_by_key(|row| std::cmp::Reverse((row.created_at, row.id)));
            Ok(result)
        }))
    }

    fn page(
        &self,
        tenant_id: TenantId,
        status: Option<MtlsTrustAnchorStatus>,
        limit: i64,
        offset: i64,
    ) -> RepositoryFuture<'_, MtlsTrustAnchorRequestPage> {
        Box::pin(self.run(move |db| {
            if limit < 0 || offset < 0 {
                return Err(RepositoryError::Conflict);
            }
            let snapshot = db.db.snapshot();
            let tenant = tenant_id.as_uuid();
            let prefix = key(REQUEST, tenant, &[]);
            let mut rows = Vec::new();
            for row in snapshot.iterator(IteratorMode::From(&prefix, Direction::Forward)) {
                let (storage_key, value) = row.map_err(map_error)?;
                if !storage_key.starts_with(&prefix) {
                    break;
                }
                let row: Request = decode(&value)?;
                if row.requester.is_some()
                    && status.is_none_or(|status| status.code() == row.status)
                {
                    rows.push(row);
                }
            }
            rows.sort_by_key(|row| std::cmp::Reverse((row.created_at, row.id)));
            let total = rows.len() as i64;
            let items = rows
                .into_iter()
                .skip(offset as usize)
                .take(limit as usize)
                .map(|row| view_snapshot(&snapshot, tenant, row))
                .collect::<Result<Vec<_>, _>>()?
                .into_iter()
                .flatten()
                .collect();
            Ok(MtlsTrustAnchorRequestPage { total, items })
        }))
    }

    fn by_id(
        &self,
        tenant_id: TenantId,
        id: Uuid,
    ) -> RepositoryFuture<'_, Option<MtlsTrustAnchorRequest>> {
        Box::pin(self.run(move |db| {
            let snapshot = db.db.snapshot();
            let tenant = tenant_id.as_uuid();
            match read_snapshot(&snapshot, &key(REQUEST, tenant, id.as_bytes()))? {
                Some(row) => view_snapshot(&snapshot, tenant, row),
                None => Ok(None),
            }
        }))
    }
    fn approve(
        &self,
        tenant: TenantId,
        id: Uuid,
        actor: UserId,
        note: Option<String>,
    ) -> RepositoryFuture<'_, MtlsTrustAnchorRequest> {
        self.resolve_trust(tenant, id, actor, 1, note)
    }
    fn reject(
        &self,
        tenant: TenantId,
        id: Uuid,
        actor: UserId,
        note: Option<String>,
    ) -> RepositoryFuture<'_, MtlsTrustAnchorRequest> {
        self.resolve_trust(tenant, id, actor, 2, note)
    }
    fn revoke(
        &self,
        tenant: TenantId,
        id: Uuid,
        actor: UserId,
        note: String,
    ) -> RepositoryFuture<'_, MtlsTrustAnchorRequest> {
        self.resolve_trust(tenant, id, actor, 3, Some(note))
    }

    fn active_bundle(
        &self,
        tenant_id: TenantId,
        client_id: Option<Uuid>,
    ) -> RepositoryFuture<'_, String> {
        Box::pin(self.run(move |db| {
            let snapshot = db.db.snapshot();
            let tenant = tenant_id.as_uuid();
            let prefix = key(
                ACTIVE,
                tenant,
                client_id
                    .as_ref()
                    .map_or(&[][..], |id| id.as_bytes().as_slice()),
            );
            let now = Timestamp::now();
            let mut certificates = BTreeSet::new();
            for row in snapshot.iterator(IteratorMode::From(&prefix, Direction::Forward)) {
                let (storage_key, _) = row.map_err(map_error)?;
                if !storage_key.starts_with(&prefix) {
                    break;
                }
                let id = Uuid::from_slice(&storage_key[33..]).map_err(|_| {
                    RepositoryError::Consistency("invalid active trust index".into())
                })?;
                let request: Request =
                    read_snapshot(&snapshot, &key(REQUEST, tenant, id.as_bytes()))?.ok_or_else(
                        || RepositoryError::Consistency("missing active trust request".into()),
                    )?;
                if request.status != 1 || request.not_before > now || request.not_after <= now {
                    continue;
                }
                if crate::clients::read_client_snapshot(&snapshot, tenant, request.client)?
                    .is_some_and(|client| {
                        client.is_active
                            && (client.token_endpoint_auth_method == "tls_client_auth"
                                || client.require_mtls_bound_tokens)
                    })
                {
                    certificates.insert(request.certificate_pem);
                    if certificates.len() > 128 {
                        return Err(RepositoryError::Conflict);
                    }
                }
            }
            Ok(certificates.into_iter().collect())
        }))
    }
}

#[cfg(test)]
#[path = "../tests/unit/mtls.rs"]
mod tests;
