//! External identity ownership is unique within a tenant/provider/subject tuple.
use nazo_identity::{PublicAccount, SubjectClaims, TenantId, UserId, UserRole, ports::*};
use nazo_persistence::SecurityAuditEvent;
use rocksdb::{Transaction, TransactionDB};
use serde::{Deserialize, Serialize};
use serde_json::json;
use uuid::Uuid;

use crate::{
    RocksDb,
    audit::append_in_tx,
    db::{decode, key, map_error, put, read, read_tx},
    users,
};

const LINK: u8 = 0x90;
const SUBJECT: u8 = 0x91;
const USER: u8 = 0x92;

#[derive(Serialize, Deserialize)]
struct Link {
    id: Uuid,
    tenant_id: TenantId,
    user_id: UserId,
    provider_type: String,
    provider_id: String,
    subject: String,
    email: String,
    claims: serde_json::Value,
    created_at: jiff::Timestamp,
    updated_at: jiff::Timestamp,
    last_login_at: Option<jiff::Timestamp>,
}
impl Link {
    fn summary(self) -> FederationLinkSummary {
        FederationLinkSummary {
            id: self.id,
            tenant_id: self.tenant_id,
            user_id: self.user_id,
            provider_type: self.provider_type,
            provider_id: self.provider_id,
            subject: self.subject,
            email: self.email,
            created_at: self.created_at,
            updated_at: self.updated_at,
            last_login_at: self.last_login_at,
        }
    }
}

fn subject_key(tenant: TenantId, kind: &str, provider: &str, subject: &str) -> Vec<u8> {
    let mut hash = blake3::Hasher::new();
    for part in [kind, provider, subject] {
        hash.update(&(part.len() as u64).to_be_bytes());
        hash.update(part.as_bytes());
    }
    key(SUBJECT, tenant.as_uuid(), hash.finalize().as_bytes())
}
fn user_key(tenant: TenantId, user: UserId, id: Uuid) -> Vec<u8> {
    let mut bytes = [0; 32];
    bytes[..16].copy_from_slice(user.as_uuid().as_bytes());
    bytes[16..].copy_from_slice(id.as_bytes());
    key(USER, tenant.as_uuid(), &bytes)
}
fn audit(
    tx: &Transaction<'_, TransactionDB>,
    row: &Link,
    event: &str,
) -> Result<(), RepositoryError> {
    append_in_tx(
        tx,
        &SecurityAuditEvent {
            event_id: Uuid::now_v7(),
            event_type: event.into(),
            event_category: "identity_lifecycle".into(),
            payload: json!({"schema_version":nazo_persistence::SECURITY_AUDIT_SCHEMA_VERSION,"event_category":"identity_lifecycle","tenant_id":row.tenant_id,"user_id":row.user_id,"link_id":row.id,"provider_type":row.provider_type,"provider_id":row.provider_id}),
            occurred_at: jiff::Timestamp::now(),
        },
    )
}
fn insert_link(
    tx: &Transaction<'_, TransactionDB>,
    link: NewFederationLink,
    first_login: bool,
) -> Result<(), RepositoryError> {
    let lookup = subject_key(
        link.tenant_id,
        &link.provider_type,
        &link.provider_id,
        &link.subject,
    );
    if let Some(existing) = read_tx::<Uuid>(tx, &lookup, true)? {
        let row: Link = read_tx(
            tx,
            &key(LINK, link.tenant_id.as_uuid(), existing.as_bytes()),
            false,
        )?
        .ok_or(RepositoryError::NotFound)?;
        return if row.user_id == link.user_id {
            Ok(())
        } else {
            Err(RepositoryError::Conflict)
        };
    }
    users::read_principal_tx(tx, link.tenant_id.as_uuid(), link.user_id.as_uuid(), false)?
        .filter(|principal| principal.active)
        .ok_or(RepositoryError::NotFound)?;
    let now = jiff::Timestamp::now();
    let row = Link {
        id: Uuid::now_v7(),
        tenant_id: link.tenant_id,
        user_id: link.user_id,
        provider_type: link.provider_type,
        provider_id: link.provider_id,
        subject: link.subject,
        email: link.email,
        claims: link.claims,
        created_at: now,
        updated_at: now,
        last_login_at: first_login.then_some(now),
    };
    put(tx, &lookup, &row.id)?;
    put(tx, &user_key(row.tenant_id, row.user_id, row.id), &row.id)?;
    put(
        tx,
        &key(LINK, row.tenant_id.as_uuid(), row.id.as_bytes()),
        &row,
    )?;
    audit(tx, &row, "external_identity_linked")
}

impl FederationLinkRepositoryPort for RocksDb {
    fn list_summaries(
        &self,
        tenant: TenantId,
        user: UserId,
    ) -> RepositoryFuture<'_, Vec<FederationLinkSummary>> {
        Box::pin(self.run(move |store| {
            let snapshot = store.db.snapshot();
            let prefix = key(USER, tenant.as_uuid(), user.as_uuid().as_bytes());
            let mut iter = snapshot.raw_iterator();
            iter.seek(&prefix);
            let mut rows = Vec::new();
            while iter.valid() && iter.key().is_some_and(|key| key.starts_with(&prefix)) {
                let id: Uuid = decode(iter.value().expect("valid iterator"))?;
                let row = crate::db::read_snapshot::<Link>(
                    &snapshot,
                    &key(LINK, tenant.as_uuid(), id.as_bytes()),
                )?
                .ok_or(RepositoryError::NotFound)?;
                rows.push(row.summary());
                iter.next();
            }
            iter.status().map_err(map_error)?;
            Ok(rows)
        }))
    }
    fn delete(
        &self,
        tenant: TenantId,
        user: UserId,
        id: Uuid,
    ) -> RepositoryFuture<'_, Option<FederationLinkSummary>> {
        Box::pin(self.run(move |store| {
            let record_key = key(LINK, tenant.as_uuid(), id.as_bytes());
            let Some(observed) =
                read::<Link>(&store.db, &record_key)?.filter(|row| row.user_id == user)
            else {
                return Ok(None);
            };
            let tx = store.transaction();
            let lookup = subject_key(
                tenant,
                &observed.provider_type,
                &observed.provider_id,
                &observed.subject,
            );
            tx.get_pinned_for_update(&lookup, true).map_err(map_error)?;
            let Some(row) =
                read_tx::<Link>(&tx, &record_key, true)?.filter(|row| row.user_id == user)
            else {
                return Ok(None);
            };
            audit(&tx, &row, "external_identity_unlinked")?;
            tx.delete(lookup).map_err(map_error)?;
            tx.delete(record_key).map_err(map_error)?;
            tx.delete(user_key(tenant, user, id)).map_err(map_error)?;
            tx.commit().map_err(map_error)?;
            Ok(Some(row.summary()))
        }))
    }
}
impl FederationLoginRepositoryPort for RocksDb {
    fn resolve_existing<'a>(
        &'a self,
        login: &'a FederationLogin,
    ) -> RepositoryFuture<'a, Option<PublicAccount>> {
        let login = login.clone();
        Box::pin(self.run(move |store| {
            let tx = store.transaction();
            let tenant = login.tenant.tenant_id;
            let lookup = subject_key(
                tenant,
                &login.provider_type,
                &login.provider_id,
                &login.subject,
            );
            let Some(id) = read_tx::<Uuid>(&tx, &lookup, false)? else {
                return Ok(None);
            };
            let record_key = key(LINK, tenant.as_uuid(), id.as_bytes());
            let mut row: Link =
                read_tx(&tx, &record_key, true)?.ok_or(RepositoryError::NotFound)?;
            let principal =
                users::read_principal_tx(&tx, tenant.as_uuid(), row.user_id.as_uuid(), false)?
                    .filter(|principal| principal.tenant == login.tenant)
                    .ok_or(RepositoryError::NotFound)?;
            let account = users::public_account_tx(&tx, principal)?;
            if let Some(email) = login.email {
                row.email = email;
            }
            row.claims = login.claims;
            row.updated_at = jiff::Timestamp::now();
            row.last_login_at = Some(row.updated_at);
            put(&tx, &record_key, &row)?;
            tx.commit().map_err(map_error)?;
            Ok(Some(account))
        }))
    }
    fn email_exists<'a>(&'a self, tenant: TenantId, email: &'a str) -> RepositoryFuture<'a, bool> {
        RegistrationAccountRepositoryPort::email_exists(self, tenant, email)
    }
    fn create_federated(
        &self,
        identity: NewFederatedIdentity,
    ) -> RepositoryFuture<'_, PublicAccount> {
        Box::pin(self.run(move |store| {
            let tx = store.transaction();
            let NewFederatedIdentity {
                login,
                email,
                display_name,
                password_hash,
            } = identity;
            let tenant = login.tenant.tenant_id;
            let lookup = subject_key(
                tenant,
                &login.provider_type,
                &login.provider_id,
                &login.subject,
            );
            if let Some(id) = read_tx::<Uuid>(&tx, &lookup, true)? {
                let row: Link = read_tx(&tx, &key(LINK, tenant.as_uuid(), id.as_bytes()), false)?
                    .ok_or(RepositoryError::NotFound)?;
                let principal =
                    users::read_principal_tx(&tx, tenant.as_uuid(), row.user_id.as_uuid(), false)?
                        .filter(|principal| principal.tenant == login.tenant)
                        .ok_or(RepositoryError::NotFound)?;
                return users::public_account_tx(&tx, principal);
            }
            if crate::tenancy::active_context_tx(&tx, tenant)? != Some(login.tenant) {
                return Err(RepositoryError::NotFound);
            }
            let mut account = users::create_user_tx(
                &tx,
                NewUser {
                    tenant: login.tenant,
                    username: email.clone(),
                    email: email.clone(),
                    password_hash,
                    email_verified: true,
                },
                UserRole::User,
            )?;
            let claims_key = key(
                users::USER_CLAIMS,
                tenant.as_uuid(),
                account.principal.user_id.as_uuid().as_bytes(),
            );
            let mut claims: SubjectClaims =
                read_tx(&tx, &claims_key, true)?.ok_or(RepositoryError::NotFound)?;
            claims.name = display_name;
            put(&tx, &claims_key, &claims)?;
            account = users::public_account_tx(&tx, account.principal)?;
            insert_link(
                &tx,
                NewFederationLink {
                    tenant_id: tenant,
                    user_id: account.principal.user_id,
                    provider_type: login.provider_type,
                    provider_id: login.provider_id,
                    subject: login.subject,
                    email,
                    claims: login.claims,
                },
                true,
            )?;
            tx.commit().map_err(map_error)?;
            Ok(account)
        }))
    }
    fn link_authenticated(&self, link: NewFederationLink) -> RepositoryFuture<'_, ()> {
        Box::pin(self.run(move |store| {
            let tx = store.transaction();
            insert_link(&tx, link, false)?;
            tx.commit().map_err(map_error)
        }))
    }
}
