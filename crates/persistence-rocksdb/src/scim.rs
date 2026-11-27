//! SCIM updates share account authority, uniqueness and revocation transactions.
use nazo_identity::{
    PublicAccount, SubjectClaims, TenantContext, UserId, UserRole,
    ports::{
        NewScimUser, NewUser, RepositoryError, RepositoryFuture, ScimCredentialPort, ScimListQuery,
        ScimRepositoryPort, UserPage,
    },
    scim::{NormalizedScimUser, ScimPatch, ScimTokenCredential},
};
use nazo_persistence::SecurityAuditEvent;
use nazo_scim_events::{
    EventFuture, EventPage, EventReceiver, EventStoreError, EventStorePort, MutationContext,
    StoredEvent, ValidatedPollRequest,
};
use rocksdb::{Transaction, TransactionDB};
use serde::{Deserialize, Serialize};
use serde_json::json;
use uuid::Uuid;

use crate::{
    RocksDb,
    audit::append_in_tx,
    db::{decode, key, map_error, put, put_expiring, read_snapshot, read_tx},
    users,
};

const TOKEN: u8 = 0xb0;
const TOKEN_HASH: u8 = 0xb1;
const EVENT: u8 = 0xb2;
const EVENT_ORDER: u8 = 0xb3;
const DISPOSITION: u8 = 0xb4;

pub(crate) struct ScimRepository {
    pub(crate) store: RocksDb,
    pub(crate) retention_seconds: u64,
}
enum Change {
    Replace(NormalizedScimUser),
    Patch(ScimPatch),
    Delete,
}

fn event_order(event: &StoredEvent) -> Vec<u8> {
    let mut suffix = ((event.occurred_at.as_microsecond() as u64) ^ (1 << 63))
        .to_be_bytes()
        .to_vec();
    suffix.extend_from_slice(event.id.as_bytes());
    key(EVENT_ORDER, event.tenant_id, &suffix)
}
fn disposition_key(tenant: Uuid, token: Uuid, event: Uuid) -> Vec<u8> {
    let mut key = key(DISPOSITION, tenant, token.as_bytes());
    key.extend_from_slice(event.as_bytes());
    key
}
fn append_mutation(
    tx: &Transaction<'_, TransactionDB>,
    principal: &nazo_identity::Principal,
    kind: &str,
    mutation: MutationContext,
    transition: Option<bool>,
    attributes: &[String],
    retention: u64,
) -> Result<(), RepositoryError> {
    let tenant = principal.tenant.tenant_id;
    let user = principal.user_id;
    let now = jiff::Timestamp::now();
    append_in_tx(
        tx,
        &SecurityAuditEvent {
            event_id: Uuid::now_v7(),
            event_type: format!("scim_user_{kind}"),
            event_category: "identity_lifecycle".into(),
            occurred_at: now,
            payload: json!({"schema_version":nazo_persistence::SECURITY_AUDIT_SCHEMA_VERSION,"event_category":"identity_lifecycle","tenant_id":tenant,"user_id":user,"transaction_id":mutation.transaction_id()}),
        },
    )?;
    if let Some(transaction) = mutation.transaction_id() {
        let event = match kind {
            "created" => {
                StoredEvent::create_notice(tenant.as_uuid(), user.as_uuid(), transaction, now)
            }
            "replaced" => StoredEvent::put_notice(
                tenant.as_uuid(),
                user.as_uuid(),
                transaction,
                now,
                transition,
            ),
            "patched" => StoredEvent::patch_notice(
                tenant.as_uuid(),
                user.as_uuid(),
                transaction,
                now,
                attributes,
                transition,
            ),
            "deleted" => StoredEvent::delete(tenant.as_uuid(), user.as_uuid(), transaction, now),
            _ => return Err(users::corrupt("invalid SCIM mutation")),
        };
        let expires = now
            .checked_add(std::time::Duration::from_secs(retention))
            .map_err(|_| users::corrupt("SCIM retention is out of range"))?;
        put_expiring(
            tx,
            &key(EVENT, tenant.as_uuid(), event.id.as_bytes()),
            &event,
            expires,
        )?;
        put_expiring(tx, &event_order(&event), &event.id, expires)?;
    }
    Ok(())
}
impl ScimRepository {
    async fn change(
        &self,
        tenant: TenantContext,
        user: UserId,
        change: Change,
        mutation: MutationContext,
    ) -> Result<PublicAccount, RepositoryError> {
        let retention = self.retention_seconds;
        self.store
            .run(move |store| {
                let tx = store.transaction();
                let tid = tenant.tenant_id.as_uuid();
                let uid = user.as_uuid();
                if crate::tenancy::active_context_tx(&tx, tenant.tenant_id)? != Some(tenant) {
                    return Err(RepositoryError::NotFound);
                }
                let managed = crate::tenant_resources::managed_user_tx(&tx, tid, uid)?;
                let mut principal = users::read_principal_tx(&tx, tid, uid, true)?
                    .filter(|p| p.tenant == tenant)
                    .ok_or(RepositoryError::NotFound)?;
                if tx
                    .get_pinned_for_update(key(users::DELETED_USER, tid, uid.as_bytes()), false)
                    .map_err(map_error)?
                    .is_some()
                {
                    return Err(RepositoryError::NotFound);
                }
                let claims_key = key(users::USER_CLAIMS, tid, uid.as_bytes());
                let metadata_key = key(users::USER_METADATA, tid, uid.as_bytes());
                let mut claims: SubjectClaims = read_tx(&tx, &claims_key, true)?
                    .ok_or_else(|| users::corrupt("SCIM account claims missing"))?;
                let mut metadata: users::AccountMetadata = read_tx(&tx, &metadata_key, true)?
                    .ok_or_else(|| users::corrupt("SCIM account metadata missing"))?;
                let old_claims = managed.then(|| claims.clone());
                let old_email = claims.email.clone();
                let old_name = claims.preferred_username.clone();
                let old_active = principal.active;
                let (kind, attributes) = match change {
                    Change::Replace(input) => {
                        principal.active = input.active;
                        claims.preferred_username = input.user_name;
                        claims.email = input.email;
                        claims.email_verified = true;
                        claims.name = input.display_name;
                        claims.given_name = input.given_name;
                        claims.family_name = input.family_name;
                        ("replaced", Vec::new())
                    }
                    Change::Patch(patch) => {
                        let attributes = patch.event_attributes();
                        if let Some(v) = patch.active {
                            principal.active = v;
                        }
                        if let Some(v) = patch.user_name {
                            claims.preferred_username = v;
                        }
                        if let Some(v) = patch.email {
                            claims.email = v;
                        }
                        claims.email_verified = true;
                        if let Some(v) = patch.display_name {
                            claims.name = Some(v);
                        }
                        if let Some(v) = patch.given_name {
                            claims.given_name = Some(v);
                        }
                        if let Some(v) = patch.family_name {
                            claims.family_name = Some(v);
                        }
                        ("patched", attributes)
                    }
                    Change::Delete => {
                        if managed {
                            return Err(RepositoryError::Conflict);
                        }
                        principal.active = false;
                        put(&tx, &key(users::DELETED_USER, tid, uid.as_bytes()), &true)?;
                        ("deleted", Vec::new())
                    }
                };
                if managed
                    && (old_active != principal.active
                        || old_claims.as_ref().is_some_and(|old| old != &claims))
                {
                    return Err(RepositoryError::Conflict);
                }
                for (table, old, new) in [
                    (
                        users::USER_EMAIL,
                        old_email.to_lowercase(),
                        claims.email.to_lowercase(),
                    ),
                    (
                        users::USER_NAME,
                        old_name,
                        claims.preferred_username.clone(),
                    ),
                ] {
                    if old != new {
                        let new_key = key(table, tid, new.as_bytes());
                        if read_tx::<Uuid>(&tx, &new_key, true)?.is_some_and(|owner| owner != uid) {
                            return Err(RepositoryError::Conflict);
                        }
                        tx.delete(key(table, tid, old.as_bytes()))
                            .map_err(map_error)?;
                        put(&tx, &new_key, &uid)?;
                    }
                }
                if old_active && !principal.active {
                    principal.authorization_epoch = principal
                        .authorization_epoch
                        .checked_add(1)
                        .ok_or_else(|| users::corrupt("SCIM account epoch exhausted"))?;
                }
                if !principal.active {
                    crate::tokens::revoke_families(&tx, tid, None, Some(uid))?;
                    crate::grants::delete_for_user_tx(&tx, tid, uid)?;
                    crate::digital_credentials::issuance::revoke_for_subject(&tx, tid, uid)?;
                }
                metadata.updated_at = jiff::Timestamp::now();
                claims.updated_at = metadata.updated_at.as_second();
                put(
                    &tx,
                    &key(users::USER_PRINCIPAL, tid, uid.as_bytes()),
                    &principal,
                )?;
                put(&tx, &claims_key, &claims)?;
                put(&tx, &metadata_key, &metadata)?;
                append_mutation(
                    &tx,
                    &principal,
                    kind,
                    mutation,
                    (old_active != principal.active).then_some(principal.active),
                    &attributes,
                    retention,
                )?;
                tx.commit().map_err(map_error)?;
                users::public_account(principal, claims, metadata)
            })
            .await
    }
}
impl ScimRepositoryPort for ScimRepository {
    fn list<'a>(&'a self, query: ScimListQuery) -> RepositoryFuture<'a, UserPage> {
        Box::pin(self.store.run(move |store| {
            let snapshot = store.db.snapshot();
            let tid = query.tenant_id.as_uuid();
            let prefix = key(users::USER_CREATED, tid, &[]);
            let after = query
                .after
                .map(|(created, user)| users::user_created_key(tid, created, user));
            let mut iter = snapshot.raw_iterator();
            iter.seek(&prefix);
            let mut page = Vec::new();
            let mut total = 0;
            let mut skipped = 0;
            while iter.valid() && iter.key().is_some_and(|key| key.starts_with(&prefix)) {
                let index = iter.key().expect("valid iterator");
                let uid = Uuid::from_slice(
                    index
                        .get(25..)
                        .ok_or_else(|| users::corrupt("invalid account creation index"))?,
                )
                .map_err(|_| users::corrupt("invalid account creation index"))?;
                if snapshot
                    .get_pinned(key(users::DELETED_USER, tid, uid.as_bytes()))
                    .map_err(map_error)?
                    .is_none()
                {
                    let matches = if let Some(email) = &query.email {
                        read_snapshot::<SubjectClaims>(
                            &snapshot,
                            &key(users::USER_CLAIMS, tid, uid.as_bytes()),
                        )?
                        .is_some_and(|claims| claims.email == *email)
                    } else {
                        true
                    };
                    if matches {
                        total += 1;
                        if after.as_ref().is_none_or(|after| index > after.as_slice()) {
                            if skipped < query.offset.max(0) {
                                skipped += 1;
                            } else if page.len() < (query.limit.max(0) as usize) {
                                page.push(
                                    users::public_account_snapshot(&snapshot, tid, uid)?
                                        .ok_or_else(|| users::corrupt("SCIM account missing"))?,
                                );
                            }
                        }
                    }
                }
                iter.next();
            }
            iter.status().map_err(map_error)?;
            Ok(UserPage { total, users: page })
        }))
    }
    fn get<'a>(
        &'a self,
        tenant: TenantContext,
        user: UserId,
    ) -> RepositoryFuture<'a, Option<PublicAccount>> {
        Box::pin(self.store.run(move |store| {
            let snapshot = store.db.snapshot();
            if snapshot
                .get_pinned(key(
                    users::DELETED_USER,
                    tenant.tenant_id.as_uuid(),
                    user.as_uuid().as_bytes(),
                ))
                .map_err(map_error)?
                .is_some()
            {
                return Ok(None);
            }
            Ok(users::public_account_snapshot(
                &snapshot,
                tenant.tenant_id.as_uuid(),
                user.as_uuid(),
            )?
            .filter(|account| account.principal.tenant == tenant))
        }))
    }
    fn create<'a>(&'a self, new_user: NewScimUser) -> RepositoryFuture<'a, PublicAccount> {
        let retention = self.retention_seconds;
        Box::pin(self.store.run(move |store| {
            let NewScimUser {
                tenant,
                input,
                password_hash,
                mutation,
            } = new_user;
            let tx = store.transaction();
            if crate::tenancy::active_context_tx(&tx, tenant.tenant_id)? != Some(tenant) {
                return Err(RepositoryError::NotFound);
            }
            let account = users::create_user_tx(
                &tx,
                NewUser {
                    tenant,
                    username: input.user_name,
                    email: input.email,
                    password_hash,
                    email_verified: true,
                },
                UserRole::User,
            )?;
            let tid = tenant.tenant_id.as_uuid();
            let uid = account.principal.user_id.as_uuid();
            let mut principal = account.principal;
            principal.active = input.active;
            let claims_key = key(users::USER_CLAIMS, tid, uid.as_bytes());
            let mut claims: SubjectClaims = read_tx(&tx, &claims_key, true)?
                .ok_or_else(|| users::corrupt("SCIM account claims missing"))?;
            claims.name = input.display_name;
            claims.given_name = input.given_name;
            claims.family_name = input.family_name;
            put(
                &tx,
                &key(users::USER_PRINCIPAL, tid, uid.as_bytes()),
                &principal,
            )?;
            put(&tx, &claims_key, &claims)?;
            append_mutation(&tx, &principal, "created", mutation, None, &[], retention)?;
            let account = users::public_account_tx(&tx, principal)?;
            tx.commit().map_err(map_error)?;
            Ok(account)
        }))
    }
    fn replace<'a>(
        &'a self,
        tenant: TenantContext,
        user: UserId,
        input: NormalizedScimUser,
        mutation: MutationContext,
    ) -> RepositoryFuture<'a, PublicAccount> {
        Box::pin(self.change(tenant, user, Change::Replace(input), mutation))
    }
    fn patch<'a>(
        &'a self,
        tenant: TenantContext,
        user: UserId,
        patch: ScimPatch,
        mutation: MutationContext,
    ) -> RepositoryFuture<'a, PublicAccount> {
        Box::pin(self.change(tenant, user, Change::Patch(patch), mutation))
    }
    fn delete<'a>(
        &'a self,
        tenant: TenantContext,
        user: UserId,
        mutation: MutationContext,
    ) -> RepositoryFuture<'a, bool> {
        Box::pin(async move {
            match self.change(tenant, user, Change::Delete, mutation).await {
                Ok(_) => Ok(true),
                Err(RepositoryError::NotFound) => Ok(false),
                Err(error) => Err(error),
            }
        })
    }
}

#[derive(Serialize, Deserialize)]
struct Credential {
    id: Uuid,
    tenant_id: Uuid,
    scopes: Vec<String>,
    event_audience: Option<String>,
    created_at: jiff::Timestamp,
    expires_at: Option<jiff::Timestamp>,
    revoked: bool,
}
impl Credential {
    fn active(&self) -> bool {
        !self.revoked
            && self
                .expires_at
                .is_none_or(|expiry| expiry > jiff::Timestamp::now())
    }
}
impl RocksDb {
    /// Provision bearer authority while the server is stopped; only its digest is persisted.
    pub async fn provision_scim_credential(
        &self,
        credential: &ScimTokenCredential,
        token_hash: &str,
        expires_at: Option<jiff::Timestamp>,
    ) -> Result<(), RepositoryError> {
        let credential = credential.clone();
        let token_hash = token_hash.to_owned();
        self.run(move |store| {
            if credential.id.is_nil()
                || credential.tenant_id.is_nil()
                || token_hash.len() != 64
                || !token_hash.bytes().all(|byte| byte.is_ascii_hexdigit())
                || credential.scopes.is_empty()
                || credential.scopes.iter().any(|scope| {
                    !matches!(
                        scope.as_str(),
                        "scim:read" | "scim:write" | "scim:events" | "scim:*"
                    )
                })
            {
                return Err(users::corrupt("invalid SCIM credential"));
            }
            let tx = store.transaction();
            let hash_key = key(TOKEN_HASH, Uuid::nil(), token_hash.as_bytes());
            let token_key = key(TOKEN, credential.tenant_id, credential.id.as_bytes());
            if read_tx::<(Uuid, Uuid)>(&tx, &hash_key, true)?.is_some()
                || read_tx::<Credential>(&tx, &token_key, true)?.is_some()
            {
                return Err(RepositoryError::Conflict);
            }
            let row = Credential {
                id: credential.id,
                tenant_id: credential.tenant_id,
                scopes: credential.scopes,
                event_audience: credential.event_audience,
                created_at: jiff::Timestamp::now(),
                expires_at,
                revoked: false,
            };
            put(&tx, &token_key, &row)?;
            put(&tx, &hash_key, &(row.tenant_id, row.id))?;
            tx.commit().map_err(map_error)
        })
        .await
    }
}
impl ScimCredentialPort for RocksDb {
    fn active_credential<'a>(
        &'a self,
        token_hash: &'a str,
    ) -> RepositoryFuture<'a, Option<ScimTokenCredential>> {
        let token_hash = token_hash.to_owned();
        Box::pin(self.run(move |store| {
            let snapshot = store.db.snapshot();
            let Some((tenant, id)) = read_snapshot::<(Uuid, Uuid)>(
                &snapshot,
                &key(TOKEN_HASH, Uuid::nil(), token_hash.as_bytes()),
            )?
            else {
                return Ok(None);
            };
            Ok(
                read_snapshot::<Credential>(&snapshot, &key(TOKEN, tenant, id.as_bytes()))?
                    .filter(Credential::active)
                    .map(|row| ScimTokenCredential {
                        id: row.id,
                        tenant_id: row.tenant_id,
                        scopes: row.scopes,
                        event_audience: row.event_audience,
                    }),
            )
        }))
    }
}
impl EventStorePort for RocksDb {
    fn apply_dispositions_and_poll<'a>(
        &'a self,
        receiver: &'a EventReceiver,
        request: &'a ValidatedPollRequest,
    ) -> EventFuture<'a, Result<EventPage, EventStoreError>> {
        let receiver = receiver.clone();
        let request = request.clone();
        Box::pin(async move {
            self.run(move |store| {
                let tx = store.transaction();
                let Some(credential) = read_tx::<Credential>(
                    &tx,
                    &key(TOKEN, receiver.tenant_id, receiver.token_id.as_bytes()),
                    false,
                )?
                .filter(|row| {
                    row.active() && row.event_audience.as_deref() == Some(&receiver.audience)
                }) else {
                    return Ok(EventPage {
                        events: Vec::new(),
                        more_available: false,
                    });
                };
                let now = jiff::Timestamp::now();
                for (id, error) in request.ack.iter().map(|id| (*id, None)).chain(
                    request
                        .set_errors
                        .iter()
                        .map(|(id, error)| (*id, Some(error))),
                ) {
                    let event_key = key(EVENT, receiver.tenant_id, id.as_bytes());
                    if let Some(raw) = tx.get_pinned(&event_key).map_err(map_error)? {
                        let event: StoredEvent = decode(&raw)?;
                        let expiry = crate::db::expiration(&raw)?;
                        if event.occurred_at >= credential.created_at
                            && expiry > now.as_microsecond()
                        {
                            let receipt =
                                disposition_key(receiver.tenant_id, receiver.token_id, id);
                            if tx
                                .get_pinned_for_update(&receipt, true)
                                .map_err(map_error)?
                                .is_none()
                            {
                                put_expiring(
                                    &tx,
                                    &receipt,
                                    &error,
                                    jiff::Timestamp::from_microsecond(expiry)
                                        .map_err(|_| users::corrupt("invalid SCIM event expiry"))?,
                                )?;
                            }
                        }
                    }
                }
                let prefix = key(EVENT_ORDER, receiver.tenant_id, &[]);
                let mut start = prefix.clone();
                start.extend_from_slice(
                    &((credential.created_at.as_microsecond() as u64) ^ (1 << 63)).to_be_bytes(),
                );
                let mut iter = tx.raw_iterator();
                iter.seek(start);
                let mut events = Vec::with_capacity(request.max_events as usize + 1);
                while iter.valid()
                    && iter.key().is_some_and(|key| key.starts_with(&prefix))
                    && events.len() <= request.max_events as usize
                {
                    let raw = iter.value().expect("valid iterator");
                    if crate::db::expiration(raw)? > now.as_microsecond() {
                        let id: Uuid = decode(raw)?;
                        if tx
                            .get_pinned(disposition_key(receiver.tenant_id, receiver.token_id, id))
                            .map_err(map_error)?
                            .is_none()
                            && let Some(event) = tx
                                .get_pinned(key(EVENT, receiver.tenant_id, id.as_bytes()))
                                .map_err(map_error)?
                            && crate::db::expiration(&event)? > now.as_microsecond()
                        {
                            events.push(decode::<StoredEvent>(&event)?);
                        }
                    }
                    iter.next();
                }
                iter.status().map_err(map_error)?;
                drop(iter);
                let more_available = events.len() > request.max_events as usize;
                events.truncate(request.max_events as usize);
                tx.commit().map_err(map_error)?;
                Ok(EventPage {
                    events,
                    more_available,
                })
            })
            .await
            .map_err(|_| EventStoreError::Unavailable)
        })
    }
}

#[cfg(test)]
#[path = "../tests/unit/scim.rs"]
mod tests;
