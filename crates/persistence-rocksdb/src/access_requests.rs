//! Access approval, client creation and its Required evidence have one owner.
use futures_util::future::BoxFuture;
use nazo_auth::{ApprovedClient, PreparedClientRegistration};
use nazo_identity::{
    AccessRequest, AccessRequestPage, AccessRequestStatus, NewAccessRequest, TenantContext,
    TenantId, UserId,
    ports::{AccessRequestRepositoryPort, RepositoryError, RepositoryFuture},
};
use nazo_persistence::{AdminAccessRequestApproval, AdminAccessRequestStore, SecurityAuditEvent};
use rocksdb::{SnapshotWithThreadMode, Transaction, TransactionDB};
use serde::{Deserialize, Serialize};
use serde_json::json;
use uuid::Uuid;

use crate::{
    RocksDb,
    audit::append_in_tx,
    clients,
    db::{decode, key, map_error, put, read_snapshot, read_tx},
    users,
};

const REQUEST: u8 = 0x93;
const BY_USER: u8 = 0x94;
const PENDING: u8 = 0x95;
const OWNER: u8 = 0x96;
const ORDER: u8 = 0x97;

#[derive(Serialize, Deserialize)]
struct Request {
    id: Uuid,
    tenant_id: TenantId,
    user_id: UserId,
    site_name: String,
    site_url: String,
    request_description: String,
    status: i16,
    admin_note: Option<String>,
    approved_client_id: Option<Uuid>,
    required_approval_event_id: Option<Uuid>,
    created_at: jiff::Timestamp,
    resolved_at: Option<jiff::Timestamp>,
}
impl Request {
    fn view(self, requester_email: Option<String>) -> Result<AccessRequest, RepositoryError> {
        Ok(AccessRequest {
            id: self.id,
            tenant_id: self.tenant_id,
            user_id: self.user_id,
            requester_email,
            site_name: self.site_name,
            site_url: self.site_url,
            request_description: self.request_description,
            status: AccessRequestStatus::from_code(self.status)
                .ok_or_else(|| users::corrupt("invalid access request state"))?,
            admin_note: self.admin_note,
            approved_client_id: self.approved_client_id,
            created_at: self.created_at,
            resolved_at: self.resolved_at,
        })
    }
}
fn ordered_key(table: u8, row: &Request) -> Vec<u8> {
    let mut suffix = Vec::with_capacity(40);
    if table == BY_USER {
        suffix.extend_from_slice(row.user_id.as_uuid().as_bytes());
    }
    suffix.extend_from_slice(&((row.created_at.as_microsecond() as u64) ^ (1 << 63)).to_be_bytes());
    suffix.extend_from_slice(row.id.as_bytes());
    key(table, row.tenant_id.as_uuid(), &suffix)
}
fn email(
    snapshot: &SnapshotWithThreadMode<'_, TransactionDB>,
    tenant: TenantId,
    user: UserId,
) -> Result<Option<String>, RepositoryError> {
    Ok(read_snapshot::<nazo_identity::SubjectClaims>(
        snapshot,
        &key(
            users::USER_CLAIMS,
            tenant.as_uuid(),
            user.as_uuid().as_bytes(),
        ),
    )?
    .map(|claims| claims.email))
}
pub(crate) fn owned_client_tx(
    tx: &Transaction<'_, TransactionDB>,
    tenant: TenantId,
    user: UserId,
    public_id: &str,
) -> Result<Option<Uuid>, RepositoryError> {
    let Some(client) = read_tx::<Uuid>(
        tx,
        &key(
            clients::CLIENT_PUBLIC_ID,
            tenant.as_uuid(),
            public_id.as_bytes(),
        ),
        false,
    )?
    else {
        return Ok(None);
    };
    if !read_tx::<clients::ClientPrincipal>(
        tx,
        &key(
            clients::CLIENT_PRINCIPAL,
            tenant.as_uuid(),
            client.as_bytes(),
        ),
        false,
    )?
    .is_some_and(|row| row.active)
    {
        return Ok(None);
    }
    let Some((owner, request)) =
        read_tx::<(UserId, Uuid)>(tx, &key(OWNER, tenant.as_uuid(), client.as_bytes()), false)?
    else {
        return Ok(None);
    };
    if owner != user {
        return Ok(None);
    }
    Ok(read_tx::<Request>(
        tx,
        &key(REQUEST, tenant.as_uuid(), request.as_bytes()),
        false,
    )?
    .filter(|row| {
        row.status == 1
            && row.user_id == user
            && row.approved_client_id == Some(client)
            && row.required_approval_event_id.is_some()
    })
    .map(|_| client))
}
impl RocksDb {
    async fn access_delivery_matches(
        &self,
        tenant: TenantId,
        user: UserId,
        request: Uuid,
        approved: Uuid,
        public_id: String,
        secret: Option<String>,
    ) -> Result<bool, RepositoryError> {
        self.run(move |store| {
            let snapshot = store.db.snapshot();
            let Some(row) = read_snapshot::<Request>(
                &snapshot,
                &key(REQUEST, tenant.as_uuid(), request.as_bytes()),
            )?
            else {
                return Ok(false);
            };
            if row.user_id != user
                || row.status != 1
                || row.approved_client_id != Some(approved)
                || row.required_approval_event_id.is_none()
            {
                return Ok(false);
            }
            let Some(client) = read_snapshot::<clients::ClientPrincipal>(
                &snapshot,
                &key(
                    clients::CLIENT_PRINCIPAL,
                    tenant.as_uuid(),
                    approved.as_bytes(),
                ),
            )?
            else {
                return Ok(false);
            };
            Ok(client.active
                && client.public_id == public_id
                && read_snapshot::<String>(
                    &snapshot,
                    &key(
                        clients::CLIENT_SECRET,
                        tenant.as_uuid(),
                        approved.as_bytes(),
                    ),
                )? == secret)
        })
        .await
    }
}
impl AccessRequestRepositoryPort for RocksDb {
    fn list_for_user(
        &self,
        tenant: TenantId,
        user: UserId,
    ) -> RepositoryFuture<'_, Vec<AccessRequest>> {
        Box::pin(self.run(move |store| {
            let snapshot = store.db.snapshot();
            let prefix = key(BY_USER, tenant.as_uuid(), user.as_uuid().as_bytes());
            let mut end = prefix.clone();
            end.extend_from_slice(&[0xff; 24]);
            let mut iter = snapshot.raw_iterator();
            iter.seek_for_prev(end);
            let mut items = Vec::new();
            while iter.valid() && iter.key().is_some_and(|key| key.starts_with(&prefix)) {
                let id: Uuid = decode(iter.value().expect("valid iterator"))?;
                let row = read_snapshot::<Request>(
                    &snapshot,
                    &key(REQUEST, tenant.as_uuid(), id.as_bytes()),
                )?
                .ok_or_else(|| users::corrupt("access request index references missing row"))?;
                items.push(row.view(None)?);
                iter.prev();
            }
            iter.status().map_err(map_error)?;
            Ok(items)
        }))
    }
    fn create(&self, request: NewAccessRequest) -> RepositoryFuture<'_, AccessRequest> {
        Box::pin(self.run(move |store| {
            let tx = store.transaction();
            let tenant = request.tenant_id.as_uuid();
            let user = request.user_id.as_uuid();
            users::read_principal_tx(&tx, tenant, user, false)?.ok_or(RepositoryError::NotFound)?;
            let pending = key(PENDING, tenant, user.as_bytes());
            if read_tx::<Uuid>(&tx, &pending, true)?.is_some() {
                return Err(RepositoryError::Conflict);
            }
            let row = Request {
                id: Uuid::now_v7(),
                tenant_id: request.tenant_id,
                user_id: request.user_id,
                site_name: request.site_name,
                site_url: request.site_url,
                request_description: request.request_description,
                status: 0,
                admin_note: None,
                approved_client_id: None,
                required_approval_event_id: None,
                created_at: jiff::Timestamp::now(),
                resolved_at: None,
            };
            put(&tx, &key(REQUEST, tenant, row.id.as_bytes()), &row)?;
            put(&tx, &ordered_key(BY_USER, &row), &row.id)?;
            put(&tx, &ordered_key(ORDER, &row), &row.id)?;
            put(&tx, &pending, &row.id)?;
            tx.commit().map_err(map_error)?;
            row.view(None)
        }))
    }
    fn approved_delivery_with_required_audit_matches<'a>(
        &'a self,
        tenant: TenantId,
        user: UserId,
        request: Uuid,
        approved: Uuid,
        public_id: &'a str,
        secret: Option<&'a str>,
    ) -> RepositoryFuture<'a, bool> {
        Box::pin(self.access_delivery_matches(
            tenant,
            user,
            request,
            approved,
            public_id.to_owned(),
            secret.map(str::to_owned),
        ))
    }
}
impl AdminAccessRequestStore for RocksDb {
    fn approved_delivery_with_required_audit_matches<'a>(
        &'a self,
        tenant: TenantId,
        user: UserId,
        request: Uuid,
        approved: Uuid,
        public_id: &'a str,
        secret: Option<&'a str>,
    ) -> BoxFuture<'a, Result<bool, RepositoryError>> {
        Box::pin(self.access_delivery_matches(
            tenant,
            user,
            request,
            approved,
            public_id.to_owned(),
            secret.map(str::to_owned),
        ))
    }
    fn approve_with_required_audit<'a>(
        &'a self,
        tenant: TenantContext,
        id: Uuid,
        actor: UserId,
        prepared: &'a PreparedClientRegistration,
        source: String,
    ) -> BoxFuture<'a, Result<AdminAccessRequestApproval, RepositoryError>> {
        let prepared = prepared.clone();
        Box::pin(self.run(move|store|{
            if prepared.tenant!=tenant{return Err(users::corrupt("prepared client tenant does not match approval"));}
            let tx=store.transaction();
            if crate::tenancy::active_context_tx(&tx,tenant.tenant_id)?!=Some(tenant){return Err(RepositoryError::NotFound);}
            users::admin_principal_tx(&tx,tenant,actor.as_uuid())?;
            let record_key=key(REQUEST,tenant.tenant_id.as_uuid(),id.as_bytes());
            let mut row=read_tx::<Request>(&tx,&record_key,true)?.filter(|row|row.status==0).ok_or(RepositoryError::AlreadyProcessed)?;
            let requester=users::read_principal_tx(&tx,tenant.tenant_id.as_uuid(),row.user_id.as_uuid(),false)?.filter(|principal|principal.active&&principal.tenant==tenant).ok_or_else(||users::corrupt("request owner outside accepting authority"))?;
            let requester_email=Some(users::public_account_tx(&tx,requester)?.account.email);
            let write=prepared.into_write();
            clients::insert_client_tx(&tx,&write.client,write.client_secret_hash.as_deref(),write.registration_access_token_blake3.as_deref(),0)?;
            let event=SecurityAuditEvent{event_id:Uuid::now_v7(),event_type:"client_created".into(),event_category:"client_lifecycle".into(),occurred_at:jiff::Timestamp::now(),payload:json!({"schema_version":nazo_persistence::SECURITY_AUDIT_SCHEMA_VERSION,"event_category":"client_lifecycle","tenant_id":tenant.tenant_id,"request_id":id,"request_user_id":row.user_id,"admin_user_id":actor,"approved_client_id":write.client.id,"client_id":write.client.client_id,"outcome":"success","source_ip_hash":source})};
            append_in_tx(&tx,&event)?;row.status=1;row.approved_client_id=Some(write.client.id);row.required_approval_event_id=Some(event.event_id);row.resolved_at=Some(event.occurred_at);
            put(&tx,&record_key,&row)?;tx.delete(key(PENDING,tenant.tenant_id.as_uuid(),row.user_id.as_uuid().as_bytes())).map_err(map_error)?;
            put(&tx,&key(OWNER,tenant.tenant_id.as_uuid(),write.client.id.as_bytes()),&(row.user_id,row.id))?;
            tx.commit().map_err(map_error)?;
            Ok(AdminAccessRequestApproval{client:ApprovedClient{id:write.client.id,client_id:write.client.registration.client_id},request:row.view(requester_email)?})
        }))
    }
    fn reject_with_required_audit(
        &self,
        tenant: TenantContext,
        id: Uuid,
        actor: UserId,
        note: String,
    ) -> BoxFuture<'_, Result<AccessRequest, RepositoryError>> {
        Box::pin(self.run(move|store|{
            let tx=store.transaction();
            if crate::tenancy::active_context_tx(&tx,tenant.tenant_id)?!=Some(tenant){return Err(RepositoryError::NotFound);}
            users::admin_principal_tx(&tx,tenant,actor.as_uuid())?;
            let record_key=key(REQUEST,tenant.tenant_id.as_uuid(),id.as_bytes());
            let mut row=read_tx::<Request>(&tx,&record_key,true)?.filter(|row|row.status==0).ok_or(RepositoryError::Conflict)?;
            let requester=users::read_principal_tx(&tx,tenant.tenant_id.as_uuid(),row.user_id.as_uuid(),false)?.filter(|principal|principal.tenant==tenant).ok_or_else(||users::corrupt("request owner outside accepting authority"))?;
            let requester_email=Some(users::public_account_tx(&tx,requester)?.account.email);
            let now=jiff::Timestamp::now();
            append_in_tx(&tx,&SecurityAuditEvent{event_id:Uuid::now_v7(),event_type:"admin_access_request_rejected".into(),event_category:"administration".into(),occurred_at:now,payload:json!({"schema_version":nazo_persistence::SECURITY_AUDIT_SCHEMA_VERSION,"event_category":"administration","tenant_id":tenant.tenant_id,"request_id":id,"request_user_id":row.user_id,"admin_user_id":actor,"outcome":"success"})})?;
            row.status=2;row.admin_note=Some(note);row.resolved_at=Some(now);put(&tx,&record_key,&row)?;
            tx.delete(key(PENDING,tenant.tenant_id.as_uuid(),row.user_id.as_uuid().as_bytes())).map_err(map_error)?;
            tx.commit().map_err(map_error)?;row.view(requester_email)
        }))
    }
    fn page<'a>(
        &'a self,
        tenant: TenantId,
        limit: i64,
        offset: i64,
        search: Option<&'a str>,
        status: Option<AccessRequestStatus>,
    ) -> BoxFuture<'a, Result<AccessRequestPage, RepositoryError>> {
        let search = search.map(str::to_lowercase);
        Box::pin(self.run(move |store| {
            if offset < 0 || limit < 0 {
                return Err(users::corrupt("negative access request page bounds"));
            }
            let snapshot = store.db.snapshot();
            let prefix = key(ORDER, tenant.as_uuid(), &[]);
            let mut end = prefix.clone();
            end.extend_from_slice(&[0xff; 24]);
            let mut iter = snapshot.raw_iterator();
            iter.seek_for_prev(end);
            let mut items = Vec::new();
            let mut total = 0i64;
            while iter.valid() && iter.key().is_some_and(|key| key.starts_with(&prefix)) {
                let id: Uuid = decode(iter.value().expect("valid iterator"))?;
                let row = read_snapshot::<Request>(
                    &snapshot,
                    &key(REQUEST, tenant.as_uuid(), id.as_bytes()),
                )?
                .ok_or_else(|| users::corrupt("access request index references missing row"))?;
                let requester_email = email(&snapshot, tenant, row.user_id)?;
                let matches = status.is_none_or(|status| row.status == status.code())
                    && search.as_ref().is_none_or(|search| {
                        row.site_name.to_lowercase().contains(search)
                            || row.site_url.to_lowercase().contains(search)
                            || requester_email
                                .as_ref()
                                .is_some_and(|email| email.to_lowercase().contains(search))
                    });
                if matches {
                    if total >= offset && items.len() < limit as usize {
                        items.push(row.view(requester_email)?);
                    }
                    total += 1;
                }
                iter.prev();
            }
            iter.status().map_err(map_error)?;
            Ok(AccessRequestPage { total, items })
        }))
    }
    fn by_id(
        &self,
        tenant: TenantId,
        id: Uuid,
    ) -> BoxFuture<'_, Result<Option<AccessRequest>, RepositoryError>> {
        Box::pin(self.run(move |store| {
            let snapshot = store.db.snapshot();
            read_snapshot::<Request>(&snapshot, &key(REQUEST, tenant.as_uuid(), id.as_bytes()))?
                .map(|row| {
                    let email = email(&snapshot, tenant, row.user_id)?;
                    row.view(email)
                })
                .transpose()
        }))
    }
}
