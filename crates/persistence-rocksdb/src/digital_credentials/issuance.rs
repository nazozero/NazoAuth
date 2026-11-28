//! Credential offers, access and issuance leases share one durable owner.
//! Offers and owner indexes are tenant-scoped. The port's opaque access, nonce,
//! response and intent identities are global; their access grant carries the
//! tenant and the core continuation predicate enforces it.
use super::EncryptedStore;
use crate::{
    RocksDb,
    clients::{CLIENT_PRINCIPAL, CLIENT_PUBLIC_ID, ClientPrincipal},
    db::{decode, key, map_error, put_expiring, read_snapshot, read_tx},
    users::USER_PRINCIPAL,
};
use jiff::{SignedDuration, Timestamp};
use nazo_identity::{Principal, ports::RepositoryError};
use nazo_openid4vci::*;
use nazo_persistence::Openid4vciStore;
use rocksdb::{Direction, IteratorMode, SnapshotWithThreadMode, Transaction, TransactionDB};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;

pub(crate) const OFFER: u8 = 0xd0;
pub(crate) const ISSUER_STATE: u8 = 0xd1;
pub(crate) const CODE: u8 = 0xd2;
pub(crate) const ACCESS: u8 = 0xd3;
pub(crate) const TOKEN_HASH: u8 = 0xd4;
pub(crate) const NONCE: u8 = 0xd5;
pub(crate) const DEFERRED: u8 = 0xd6;
pub(crate) const RESPONSE: u8 = 0xd7;
pub(crate) const NOTIFICATION: u8 = 0xd8;
pub(crate) const BY_SUBJECT: u8 = 0xd9;
pub(crate) const BY_CLIENT: u8 = 0xda;

type Tx<'a> = Transaction<'a, TransactionDB>;
type Snapshot<'a> = SnapshotWithThreadMode<'a, TransactionDB>;
type StoreResult<T> = Result<T, StoreError>;

enum StoreError {
    Invalid,
    ClientInactive,
    Storage(RepositoryError),
}
impl From<RepositoryError> for StoreError {
    fn from(error: RepositoryError) -> Self {
        Self::Storage(error)
    }
}
impl From<rocksdb::Error> for StoreError {
    fn from(error: rocksdb::Error) -> Self {
        Self::Storage(map_error(error))
    }
}
impl From<serde_json::Error> for StoreError {
    fn from(_: serde_json::Error) -> Self {
        Self::Invalid
    }
}
impl From<StoreError> for CredentialStoreError {
    fn from(error: StoreError) -> Self {
        match error {
            StoreError::Invalid => Self::InvalidTransition,
            StoreError::ClientInactive => Self::ClientInactive,
            StoreError::Storage(RepositoryError::Unavailable | RepositoryError::Unexpected(_)) => {
                Self::Unavailable
            }
            StoreError::Storage(_) => Self::InvalidTransition,
        }
    }
}

#[derive(Clone)]
pub(crate) struct IssuerStore {
    store: EncryptedStore,
    verifier: Arc<dyn nazo_identity::ports::SecretVerifyPort>,
}

// Serde's remote projection borrows the existing domain value while encoding;
// storage-specific derives and representations stay outside the core.
#[derive(Serialize, Deserialize)]
#[serde(remote = "CredentialAccess")]
struct AccessWire {
    authorization_id: Option<Uuid>,
    mtls_x5t_s256: Option<String>,
    proof_origin: CredentialProofOrigin,
    token_id: Uuid,
    tenant_id: Uuid,
    subject_id: Uuid,
    client_id: String,
    configuration_ids: Vec<String>,
    credential_identifiers: Vec<CredentialIdentifier>,
    dpop_jkt: Option<String>,
    expires_at: Timestamp,
}

#[derive(Serialize, Deserialize)]
struct AccessRecord {
    #[serde(with = "AccessWire")]
    access: CredentialAccess,
    token_hash: String,
    revoked_at: Option<Timestamp>,
    retain_until: Timestamp,
}

#[derive(Clone, PartialEq, Serialize, Deserialize)]
struct OfferSnapshot {
    id: Uuid,
    tenant_id: Uuid,
    subject_id: Option<Uuid>,
    configurations: Vec<String>,
    issuer_state: Option<String>,
    code_hash: Option<String>,
    tx_code_hash: Option<String>,
    expires_at: Timestamp,
}
#[derive(Serialize, Deserialize)]
struct OfferRecord {
    snapshot: OfferSnapshot,
    grants: String,
    consumed: bool,
}

#[derive(Serialize, Deserialize)]
struct Lease {
    claim_id: String,
    expires_at: Timestamp,
    token_id: Option<Uuid>,
}

#[derive(Serialize, Deserialize)]
struct Nonce {
    expires_at: Timestamp,
    consumed: bool,
    lease: Option<Lease>,
}

#[derive(Serialize, Deserialize)]
struct DeferredRecord {
    id: Uuid,
    token_id: Uuid,
    authorization_id: Option<Uuid>,
    selection: Option<CredentialSelection>,
    configuration_id: String,
    format: nazo_digital_credentials::CredentialFormat,
    holder_bindings: Vec<Option<nazo_digital_credentials::HolderBinding>>,
    payload: String,
    ready_at: Timestamp,
    expires_at: Timestamp,
    consumed: bool,
    lease: Option<Lease>,
}

#[derive(Serialize, Deserialize)]
struct ResponseRecord {
    token_id: Uuid,
    request_digest: String,
    selection: Option<CredentialSelection>,
    body: String,
    encoding: String,
    status: u16,
    dpop_nonce: Option<String>,
    expires_at: Timestamp,
}

#[derive(Serialize, Deserialize)]
struct NotificationRecord {
    token_id: Uuid,
    selection: Option<CredentialSelection>,
    expires_at: Timestamp,
    event: Option<NotificationEvent>,
    description: Option<String>,
    occurred_at: Option<Timestamp>,
}

enum Completion {
    Immediate,
    Nonce(String, String),
    Deferred(String, Uuid, String),
}

fn subject_index(tenant: Uuid, user: Uuid, token: Uuid) -> Vec<u8> {
    let mut result = key(BY_SUBJECT, tenant, user.as_bytes());
    result.extend_from_slice(token.as_bytes());
    result
}
fn client_index(tenant: Uuid, client: &str, token: Uuid) -> Vec<u8> {
    let mut result = key(
        BY_CLIENT,
        tenant,
        blake3::hash(client.as_bytes()).as_bytes(),
    );
    result.extend_from_slice(token.as_bytes());
    result
}

fn access_expiry(access: &CredentialAccess) -> StoreResult<Timestamp> {
    access
        .expires_at
        .checked_add(SignedDuration::from_secs(
            nazo_resource_server::MAX_ACCESS_TOKEN_CLOCK_SKEW_SECONDS,
        ))
        .map_err(|_| StoreError::Invalid)
}

fn persist_access(tx: &Tx<'_>, record: &AccessRecord) -> StoreResult<()> {
    let access = &record.access;
    put_expiring(
        tx,
        &key(ACCESS, Uuid::nil(), access.token_id.as_bytes()),
        record,
        record.retain_until,
    )?;
    put_expiring(
        tx,
        &key(TOKEN_HASH, Uuid::nil(), record.token_hash.as_bytes()),
        &access.token_id,
        record.retain_until,
    )?;
    put_expiring(
        tx,
        &subject_index(access.tenant_id, access.subject_id, access.token_id),
        &(),
        record.retain_until,
    )?;
    put_expiring(
        tx,
        &client_index(access.tenant_id, &access.client_id, access.token_id),
        &(),
        record.retain_until,
    )?;
    Ok(())
}

fn live_access_tx(tx: &Tx<'_>, token: Uuid, now: Timestamp) -> StoreResult<Option<AccessRecord>> {
    Ok(
        read_tx::<AccessRecord>(tx, &key(ACCESS, Uuid::nil(), token.as_bytes()), true)?
            .filter(|a| a.revoked_at.is_none() && a.access.expires_at > now),
    )
}

fn continuation_tx(
    tx: &Tx<'_>,
    original: Uuid,
    current: Uuid,
    selection: Option<&CredentialSelection>,
    now: Timestamp,
) -> StoreResult<Option<(AccessRecord, AccessRecord)>> {
    let mut ids = [original, current];
    ids.sort_unstable();
    for id in ids {
        let _ = tx.get_pinned_for_update(key(ACCESS, Uuid::nil(), id.as_bytes()), true)?;
    }
    let Some(original) =
        read_tx::<AccessRecord>(tx, &key(ACCESS, Uuid::nil(), original.as_bytes()), true)?
    else {
        return Ok(None);
    };
    let Some(current) = live_access_tx(tx, current, now)? else {
        return Ok(None);
    };
    if !current
        .access
        .continues_access(&original.access, selection, now)
    {
        return Ok(None);
    }
    Ok(Some((original, current)))
}

fn continuation_snapshot(
    snapshot: &Snapshot<'_>,
    original: Uuid,
    current: Uuid,
    selection: Option<&CredentialSelection>,
    now: Timestamp,
) -> StoreResult<bool> {
    let Some(original) =
        read_snapshot::<AccessRecord>(snapshot, &key(ACCESS, Uuid::nil(), original.as_bytes()))?
    else {
        return Ok(false);
    };
    let Some(current) =
        read_snapshot::<AccessRecord>(snapshot, &key(ACCESS, Uuid::nil(), current.as_bytes()))?
    else {
        return Ok(false);
    };
    Ok(current.revoked_at.is_none()
        && current
            .access
            .continues_access(&original.access, selection, now))
}

impl IssuerStore {
    pub(crate) fn new(
        provider: RocksDb,
        key: [u8; 32],
        verifier: Arc<dyn nazo_identity::ports::SecretVerifyPort>,
    ) -> Self {
        Self {
            store: EncryptedStore::new(provider, key),
            verifier,
        }
    }

    fn require_tenant(&self, tenant: Uuid) -> StoreResult<()> {
        if tenant.is_nil() {
            return Err(StoreError::Invalid);
        }
        Ok(())
    }

    async fn run<T: Send + 'static, F: FnOnce(&Self) -> StoreResult<T> + Send + 'static>(
        &self,
        operation: F,
    ) -> Result<T, CredentialStoreError> {
        let store = self.clone();
        self.store
            .provider
            .run(move |_| Ok(operation(&store)))
            .await
            .map_err(|e| CredentialStoreError::from(StoreError::Storage(e)))?
            .map_err(Into::into)
    }

    fn validate_access(&self, access: &CredentialAccess) -> StoreResult<()> {
        self.require_tenant(access.tenant_id)?;
        if access.token_id.is_nil()
            || access.subject_id.is_nil()
            || access.client_id.is_empty()
            || access.configuration_ids.is_empty()
            || (access.dpop_jkt.is_some() && access.mtls_x5t_s256.is_some())
        {
            return Err(StoreError::Invalid);
        }
        Ok(())
    }

    fn lock_access_principals(&self, tx: &Tx<'_>, access: &CredentialAccess) -> StoreResult<()> {
        if access.proof_origin != CredentialProofOrigin::AnonymousPreAuthorized {
            let client: Option<Uuid> = tx
                .get_pinned(key(
                    CLIENT_PUBLIC_ID,
                    access.tenant_id,
                    access.client_id.as_bytes(),
                ))?
                .map(|raw| decode(&raw))
                .transpose()?;
            let Some(client) = client else {
                return Err(StoreError::ClientInactive);
            };
            if !read_tx::<ClientPrincipal>(
                tx,
                &key(CLIENT_PRINCIPAL, access.tenant_id, client.as_bytes()),
                false,
            )?
            .is_some_and(|c| c.active)
            {
                return Err(StoreError::ClientInactive);
            }
        }
        if !read_tx::<Principal>(
            tx,
            &key(
                USER_PRINCIPAL,
                access.tenant_id,
                access.subject_id.as_bytes(),
            ),
            false,
        )?
        .is_some_and(|u| u.active)
        {
            return Err(StoreError::Invalid);
        }
        Ok(())
    }

    fn upsert_access_tx(
        &self,
        tx: &Tx<'_>,
        hash: String,
        access: CredentialAccess,
    ) -> StoreResult<()> {
        self.validate_access(&access)?;
        if access.expires_at <= Timestamp::now() {
            return Err(StoreError::Invalid);
        }
        let previous: Option<AccessRecord> = read_tx(
            tx,
            &key(ACCESS, Uuid::nil(), access.token_id.as_bytes()),
            true,
        )?;
        if read_tx::<Uuid>(tx, &key(TOKEN_HASH, Uuid::nil(), hash.as_bytes()), true)?
            .is_some_and(|id| id != access.token_id)
        {
            return Err(StoreError::Invalid);
        }
        let mut retain_until = access_expiry(&access)?;
        let revoked_at = if let Some(previous) = previous {
            let original = &previous.access;
            if previous.token_hash != hash
                || original.tenant_id != access.tenant_id
                || original.subject_id != access.subject_id
                || original.client_id != access.client_id
                || original.authorization_id != access.authorization_id
                || original.proof_origin != access.proof_origin
                || (original.authorization_id.is_some() && original.dpop_jkt != access.dpop_jkt)
                || (original.mtls_x5t_s256 != access.mtls_x5t_s256
                    && !(original.authorization_id.is_none() && original.mtls_x5t_s256.is_none()))
            {
                return Err(StoreError::Invalid);
            }
            retain_until = retain_until.max(previous.retain_until);
            if original == &access {
                return Ok(());
            }
            previous.revoked_at
        } else {
            None
        };
        persist_access(
            tx,
            &AccessRecord {
                access,
                token_hash: hash,
                revoked_at,
                retain_until,
            },
        )
    }

    fn response_record(&self, response: &StoredCredentialResponse) -> StoreResult<ResponseRecord> {
        if !matches!(response.status, 200 | 202) {
            return Err(StoreError::Invalid);
        }
        Ok(ResponseRecord {
            token_id: response.token_id,
            request_digest: response.request_digest.clone(),
            selection: response.selection.clone(),
            body: self.store.seal(
                &key(RESPONSE, Uuid::nil(), response.issuance_id.as_bytes()),
                &response.body,
            )?,
            encoding: match response.encoding {
                CredentialResponseEncoding::Json => "json",
                CredentialResponseEncoding::Jwt => "jwt",
            }
            .into(),
            status: response.status,
            dpop_nonce: response.dpop_nonce.clone(),
            expires_at: response.expires_at,
        })
    }

    fn put_response(&self, tx: &Tx<'_>, id: Uuid, response: &ResponseRecord) -> StoreResult<()> {
        let response_key = key(RESPONSE, Uuid::nil(), id.as_bytes());
        if tx.get_pinned_for_update(&response_key, true)?.is_some() {
            return Err(StoreError::Invalid);
        }
        put_expiring(tx, &response_key, response, response.expires_at)?;
        Ok(())
    }

    fn put_notification(&self, tx: &Tx<'_>, handle: &NotificationHandle) -> StoreResult<()> {
        let notification_key = key(NOTIFICATION, Uuid::nil(), handle.notification_id.as_bytes());
        if tx.get_pinned_for_update(&notification_key, true)?.is_some() {
            return Err(StoreError::Invalid);
        }
        put_expiring(
            tx,
            &notification_key,
            &NotificationRecord {
                token_id: handle.token_id,
                selection: handle.selection.clone(),
                expires_at: handle.expires_at,
                event: None,
                description: None,
                occurred_at: None,
            },
            handle.expires_at,
        )?;
        Ok(())
    }

    fn extend_access(
        tx: &Tx<'_>,
        access: &mut AccessRecord,
        deadline: Timestamp,
    ) -> StoreResult<()> {
        if deadline > access.retain_until {
            access.retain_until = deadline;
            persist_access(tx, access)?;
        }
        Ok(())
    }

    fn complete(
        &self,
        completion: Completion,
        handle: NotificationHandle,
        response: StoredCredentialResponse,
        now: Timestamp,
    ) -> StoreResult<bool> {
        if handle.token_id != response.token_id || handle.selection != response.selection {
            return Err(StoreError::Invalid);
        }
        let response_record = self.response_record(&response)?;
        let tx = self.store.provider.transaction();
        let now = now.max(Timestamp::now());
        let Some(mut access) = live_access_tx(&tx, response.token_id, now)? else {
            return Ok(false);
        };
        let mut deadline = access
            .access
            .expires_at
            .min(response.expires_at)
            .min(handle.expires_at);
        if response.expires_at <= now || handle.expires_at <= now {
            return Ok(false);
        }
        if response
            .selection
            .as_ref()
            .is_some_and(|s| !access.access.authorizes_selection(s))
        {
            return Ok(false);
        }
        match completion {
            Completion::Immediate => {}
            Completion::Nonce(hash, claim) => {
                let nonce_key = key(NONCE, Uuid::nil(), hash.as_bytes());
                let Some(mut nonce) = read_tx::<Nonce>(&tx, &nonce_key, true)? else {
                    return Ok(false);
                };
                if nonce.consumed
                    || nonce.expires_at <= now
                    || !nonce.lease.as_ref().is_some_and(|l| l.claim_id == claim)
                {
                    return Ok(false);
                }
                deadline = deadline.min(nonce.expires_at);
                nonce.consumed = true;
                nonce.lease = None;
                put_expiring(&tx, &nonce_key, &nonce, nonce.expires_at)?;
            }
            Completion::Deferred(hash, token, claim) => {
                if token != response.token_id {
                    return Err(StoreError::Invalid);
                }
                let deferred_key = key(DEFERRED, Uuid::nil(), hash.as_bytes());
                let Some(mut deferred) = read_tx::<DeferredRecord>(&tx, &deferred_key, true)?
                else {
                    return Ok(false);
                };
                if deferred.consumed
                    || deferred.expires_at <= now
                    || deferred.selection != response.selection
                    || !deferred
                        .lease
                        .as_ref()
                        .is_some_and(|l| l.claim_id == claim && l.token_id == Some(token))
                {
                    return Ok(false);
                }
                deadline = deadline.min(deferred.expires_at);
                deferred.consumed = true;
                deferred.lease = None;
                put_expiring(&tx, &deferred_key, &deferred, deferred.expires_at)?;
            }
        }
        self.put_response(&tx, response.issuance_id, &response_record)?;
        self.put_notification(&tx, &handle)?;
        Self::extend_access(&tx, &mut access, response.expires_at.max(handle.expires_at))?;
        if deadline <= Timestamp::now() {
            return Ok(false);
        }
        tx.commit()?;
        Ok(true)
    }

    fn defer(
        &self,
        credential: DeferredCredential,
        nonce: Option<(String, String)>,
        response: StoredCredentialResponse,
        now: Timestamp,
    ) -> StoreResult<()> {
        self.validate_access(&credential.access)?;
        if credential.access.token_id != response.token_id
            || credential.selection != response.selection
            || credential
                .selection
                .as_ref()
                .is_some_and(|s| s.configuration_id != credential.configuration_id)
            || credential.holder_bindings.is_empty()
            || credential
                .selection
                .as_ref()
                .is_some_and(|selection| !credential.access.authorizes_selection(selection))
        {
            return Err(StoreError::Invalid);
        }
        let deferred_key = key(
            DEFERRED,
            Uuid::nil(),
            credential.transaction_hash.as_bytes(),
        );
        let record = DeferredRecord {
            id: credential.id,
            token_id: credential.access.token_id,
            authorization_id: credential.access.authorization_id,
            selection: credential.selection,
            configuration_id: credential.configuration_id,
            format: credential.format,
            holder_bindings: credential.holder_bindings,
            payload: self.store.seal_value(&deferred_key, &credential.payload)?,
            ready_at: credential.ready_at,
            expires_at: credential.expires_at,
            consumed: false,
            lease: None,
        };
        let response_record = self.response_record(&response)?;
        let tx = self.store.provider.transaction();
        let now = now.max(Timestamp::now());
        let Some(mut access) = live_access_tx(&tx, response.token_id, now)? else {
            return Err(StoreError::Invalid);
        };
        let mut deadline = access
            .access
            .expires_at
            .min(response.expires_at)
            .min(record.expires_at);
        if access.access != credential.access
            || response.expires_at <= now
            || record.expires_at <= now
        {
            return Err(StoreError::Invalid);
        }
        if let Some((hash, claim)) = nonce {
            let nonce_key = key(NONCE, Uuid::nil(), hash.as_bytes());
            let Some(mut nonce) = read_tx::<Nonce>(&tx, &nonce_key, true)? else {
                return Err(StoreError::Invalid);
            };
            if nonce.consumed
                || nonce.expires_at <= now
                || !nonce.lease.as_ref().is_some_and(|l| l.claim_id == claim)
            {
                return Err(StoreError::Invalid);
            }
            deadline = deadline.min(nonce.expires_at);
            nonce.consumed = true;
            nonce.lease = None;
            put_expiring(&tx, &nonce_key, &nonce, nonce.expires_at)?;
        }
        self.put_response(&tx, response.issuance_id, &response_record)?;
        if tx.get_pinned_for_update(&deferred_key, true)?.is_some() {
            return Err(StoreError::Invalid);
        }
        put_expiring(&tx, &deferred_key, &record, record.expires_at)?;
        Self::extend_access(&tx, &mut access, response.expires_at.max(record.expires_at))?;
        if deadline <= Timestamp::now() {
            return Err(StoreError::Invalid);
        }
        tx.commit()?;
        Ok(())
    }
}

impl Openid4vciStore for IssuerStore {
    fn insert_offer<'a>(
        &'a self,
        offer: &'a StoredCredentialOffer,
        issuer_state_hash: Option<&'a str>,
        pre_authorized_code_hash: Option<&'a str>,
        tx_code_hash: Option<&'a str>,
    ) -> CredentialStoreFuture<'a, Result<(), CredentialStoreError>> {
        let offer = offer.clone();
        let issuer_state = issuer_state_hash.map(str::to_owned);
        let code_hash = pre_authorized_code_hash.map(str::to_owned);
        let tx_code_hash = tx_code_hash.map(str::to_owned);
        Box::pin(self.run(move |store| {
            store.require_tenant(offer.tenant_id)?;
            let offer_key = key(OFFER, offer.tenant_id, offer.id.as_bytes());
            let record = OfferRecord {
                snapshot: OfferSnapshot {
                    id: offer.id,
                    tenant_id: offer.tenant_id,
                    subject_id: offer.subject_id,
                    configurations: offer.credential_configuration_ids,
                    issuer_state,
                    code_hash,
                    tx_code_hash,
                    expires_at: offer.expires_at,
                },
                grants: store.store.seal_value(&offer_key, &offer.grants)?,
                consumed: false,
            };
            let tx = store.store.provider.transaction();
            if tx.get_pinned_for_update(&offer_key, true)?.is_some() {
                return Err(StoreError::Invalid);
            }
            for (table, hash) in [
                (ISSUER_STATE, record.snapshot.issuer_state.as_deref()),
                (CODE, record.snapshot.code_hash.as_deref()),
            ] {
                if let Some(hash) = hash {
                    let index = key(table, offer.tenant_id, hash.as_bytes());
                    if tx.get_pinned_for_update(&index, true)?.is_some() {
                        return Err(StoreError::Invalid);
                    }
                    put_expiring(&tx, &index, &offer.id, offer.expires_at)?;
                }
            }
            put_expiring(&tx, &offer_key, &record, offer.expires_at)?;
            tx.commit()?;
            Ok(())
        }))
    }
}

impl AuthorizationOfferPort for IssuerStore {
    fn resolve_authorization_offer<'a>(
        &'a self,
        tenant_id: Uuid,
        issuer_state_hash: &'a str,
        subject_id: Uuid,
        client_id: &'a str,
        now: Timestamp,
    ) -> CredentialStoreFuture<'a, Result<Option<CredentialAuthorization>, CredentialStoreError>>
    {
        let hash = issuer_state_hash.to_owned();
        let client_id = client_id.to_owned();
        Box::pin(self.run(move |store| {
            store.require_tenant(tenant_id)?;
            let snapshot = store.store.provider.db.snapshot();
            let Some(id) =
                read_snapshot::<Uuid>(&snapshot, &key(ISSUER_STATE, tenant_id, hash.as_bytes()))?
            else {
                return Ok(None);
            };
            let Some(offer) =
                read_snapshot::<OfferRecord>(&snapshot, &key(OFFER, tenant_id, id.as_bytes()))?
            else {
                return Ok(None);
            };
            let offer = offer.snapshot;
            if offer.subject_id != Some(subject_id) || offer.expires_at <= now {
                return Ok(None);
            }
            Ok(Some(CredentialAuthorization {
                tenant_id,
                subject_id,
                client_id,
                configuration_ids: offer.configurations,
                credential_identifiers: Vec::new(),
                expires_at: (now + SignedDuration::from_mins(10)).min(offer.expires_at),
            }))
        }))
    }
}

impl CredentialStorePort for IssuerStore {
    fn upsert_access<'a>(
        &'a self,
        token_hash: &'a str,
        access: &'a CredentialAccess,
    ) -> CredentialStoreFuture<'a, Result<(), CredentialStoreError>> {
        let hash = token_hash.to_owned();
        let access = access.clone();
        Box::pin(self.run(move |store| {
            let tx = store.store.provider.transaction();
            store.lock_access_principals(&tx, &access)?;
            let deadline = access.expires_at;
            store.upsert_access_tx(&tx, hash, access)?;
            if deadline <= Timestamp::now() {
                return Err(StoreError::Invalid);
            }
            tx.commit()?;
            Ok(())
        }))
    }

    fn persist_pre_authorized_access<'a>(
        &'a self,
        prepared: &'a [u8],
        token_hash: &'a str,
        access: &'a CredentialAccess,
        registered_client_id: Option<&'a str>,
    ) -> CredentialStoreFuture<'a, Result<(), CredentialStoreError>> {
        Box::pin(async move {
            let prepared: OfferSnapshot = serde_json::from_slice(prepared)
                .map_err(|_| CredentialStoreError::InvalidTransition)?;
            let expected_origin = if registered_client_id.is_some() {
                CredentialProofOrigin::RegisteredClient
            } else {
                CredentialProofOrigin::AnonymousPreAuthorized
            };
            if prepared.tenant_id != access.tenant_id
                || prepared.subject_id != Some(access.subject_id)
                || prepared.configurations != access.configuration_ids
                || !access.credential_identifiers.is_empty()
                || access.expires_at > prepared.expires_at
                || registered_client_id.is_some_and(|id| id != access.client_id)
                || access.proof_origin != expected_origin
                || prepared.code_hash.is_none()
            {
                return Err(CredentialStoreError::InvalidTransition);
            }
            let hash = token_hash.to_owned();
            let access = access.clone();
            self.run(move |store| {
                let tx = store.store.provider.transaction();
                store.lock_access_principals(&tx, &access)?;
                let deadline = access.expires_at;
                store.upsert_access_tx(&tx, hash, access)?;
                let offer_key = key(OFFER, prepared.tenant_id, prepared.id.as_bytes());
                let Some(mut current) = read_tx::<OfferRecord>(&tx, &offer_key, true)? else {
                    return Err(StoreError::Invalid);
                };
                if current.consumed
                    || current.snapshot != prepared
                    || current.snapshot.expires_at <= Timestamp::now()
                {
                    return Err(StoreError::Invalid);
                }
                current.consumed = true;
                current.grants.clear();
                current.snapshot.tx_code_hash = None;
                put_expiring(&tx, &offer_key, &current, current.snapshot.expires_at)?;
                if deadline.min(current.snapshot.expires_at) <= Timestamp::now() {
                    return Err(StoreError::Invalid);
                }
                tx.commit()?;
                Ok(())
            })
            .await
        })
    }

    fn offer<'a>(
        &'a self,
        tenant_id: Uuid,
        id: Uuid,
        now: Timestamp,
    ) -> CredentialStoreFuture<'a, Result<Option<StoredCredentialOffer>, CredentialStoreError>>
    {
        Box::pin(self.run(move |store| {
            store.require_tenant(tenant_id)?;
            let offer_key = key(OFFER, tenant_id, id.as_bytes());
            let Some(record) =
                crate::db::read::<OfferRecord>(&store.store.provider.db, &offer_key)?
            else {
                return Ok(None);
            };
            if record.consumed || record.snapshot.expires_at <= now {
                return Ok(None);
            }
            let grants = store.store.open(&offer_key, &record.grants)?;
            Ok(Some(StoredCredentialOffer {
                id,
                tenant_id,
                subject_id: record.snapshot.subject_id,
                credential_configuration_ids: record.snapshot.configurations,
                grants,
                expires_at: record.snapshot.expires_at,
            }))
        }))
    }

    fn prepare_pre_authorized_offer<'a>(
        &'a self,
        tenant_id: Uuid,
        code_hash: &'a str,
        tx_code: Option<&'a str>,
        client_id: &'a str,
        now: Timestamp,
    ) -> CredentialStoreFuture<'a, Result<Option<PreparedPreAuthorizedOffer>, CredentialStoreError>>
    {
        let hash = code_hash.to_owned();
        Box::pin(async move {
            // No database lock survives the CPU-bound secret verifier.
            let offer = self
                .run(move |store| {
                    store.require_tenant(tenant_id)?;
                    let snapshot = store.store.provider.db.snapshot();
                    let Some(id) =
                        read_snapshot::<Uuid>(&snapshot, &key(CODE, tenant_id, hash.as_bytes()))?
                    else {
                        return Ok(None);
                    };
                    Ok(read_snapshot::<OfferRecord>(
                        &snapshot,
                        &key(OFFER, tenant_id, id.as_bytes()),
                    )?
                    .filter(|o| !o.consumed && o.snapshot.expires_at > now)
                    .map(|o| o.snapshot))
                })
                .await?;
            let Some(offer) = offer else { return Ok(None) };
            let Some(subject_id) = offer.subject_id else {
                return Ok(None);
            };
            let verified = match (offer.tx_code_hash.as_deref(), tx_code) {
                (None, None) => true,
                (Some(hash), Some(presented)) => {
                    let hash = nazo_identity::PasswordHash::new(hash)
                        .map_err(|_| CredentialStoreError::InvalidTransition)?;
                    self.verifier
                        .verify_secret(presented.to_owned(), hash)
                        .await
                        .map_err(|_| CredentialStoreError::Unavailable)?
                }
                _ => false,
            };
            if !verified {
                return Ok(None);
            }
            Ok(Some(PreparedPreAuthorizedOffer {
                commit_token: serde_json::to_vec(&offer)
                    .map_err(|_| CredentialStoreError::InvalidTransition)?,
                authorization: CredentialAuthorization {
                    tenant_id,
                    subject_id,
                    client_id: client_id.to_owned(),
                    configuration_ids: offer.configurations,
                    credential_identifiers: Vec::new(),
                    expires_at: (now + SignedDuration::from_mins(10)).min(offer.expires_at),
                },
            }))
        })
    }

    fn issue_nonce<'a>(
        &'a self,
        nonce: &'a NonceRecord,
    ) -> CredentialStoreFuture<'a, Result<(), CredentialStoreError>> {
        let nonce = nonce.clone();
        Box::pin(self.run(move |store| {
            let tx = store.store.provider.transaction();
            let nonce_key = key(NONCE, Uuid::nil(), nonce.nonce_hash.as_bytes());
            if tx.get_pinned_for_update(&nonce_key, true)?.is_none() {
                put_expiring(
                    &tx,
                    &nonce_key,
                    &Nonce {
                        expires_at: nonce.expires_at,
                        consumed: false,
                        lease: None,
                    },
                    nonce.expires_at,
                )?;
            }
            tx.commit()?;
            Ok(())
        }))
    }

    fn claim_nonce<'a>(
        &'a self,
        nonce_hash: &'a str,
        claim_id: &'a str,
        now: Timestamp,
    ) -> CredentialStoreFuture<'a, Result<bool, CredentialStoreError>> {
        let hash = nonce_hash.to_owned();
        let claim = claim_id.to_owned();
        Box::pin(self.run(move |store| {
            let tx = store.store.provider.transaction();
            let nonce_key = key(NONCE, Uuid::nil(), hash.as_bytes());
            let Some(mut nonce) = read_tx::<Nonce>(&tx, &nonce_key, true)? else {
                return Ok(false);
            };
            let now = now.max(Timestamp::now());
            if nonce.consumed
                || nonce.expires_at <= now
                || nonce.lease.as_ref().is_some_and(|l| l.expires_at > now)
            {
                return Ok(false);
            }
            nonce.lease = Some(Lease {
                claim_id: claim,
                expires_at: now + SignedDuration::from_mins(5),
                token_id: None,
            });
            put_expiring(&tx, &nonce_key, &nonce, nonce.expires_at)?;
            tx.commit()?;
            Ok(true)
        }))
    }

    fn release_nonce<'a>(
        &'a self,
        nonce_hash: &'a str,
        claim_id: &'a str,
        _now: Timestamp,
    ) -> CredentialStoreFuture<'a, Result<bool, CredentialStoreError>> {
        let hash = nonce_hash.to_owned();
        let claim = claim_id.to_owned();
        Box::pin(self.run(move |store| {
            let tx = store.store.provider.transaction();
            let nonce_key = key(NONCE, Uuid::nil(), hash.as_bytes());
            let Some(mut nonce) = read_tx::<Nonce>(&tx, &nonce_key, true)? else {
                return Ok(false);
            };
            if nonce.consumed || !nonce.lease.as_ref().is_some_and(|l| l.claim_id == claim) {
                return Ok(false);
            }
            nonce.lease = None;
            put_expiring(&tx, &nonce_key, &nonce, nonce.expires_at)?;
            tx.commit()?;
            Ok(true)
        }))
    }

    fn resolve_access<'a>(
        &'a self,
        token_hash: &'a str,
        now: Timestamp,
    ) -> CredentialStoreFuture<'a, Result<Option<CredentialAccess>, CredentialStoreError>> {
        let hash = token_hash.to_owned();
        Box::pin(self.run(move |store| {
            let snapshot = store.store.provider.db.snapshot();
            let Some(token) =
                read_snapshot::<Uuid>(&snapshot, &key(TOKEN_HASH, Uuid::nil(), hash.as_bytes()))?
            else {
                return Ok(None);
            };
            Ok(read_snapshot::<AccessRecord>(
                &snapshot,
                &key(ACCESS, Uuid::nil(), token.as_bytes()),
            )?
            .filter(|a| a.revoked_at.is_none() && a.access.expires_at > now)
            .map(|a| a.access))
        }))
    }

    fn find_response<'a>(
        &'a self,
        issuance_id: Uuid,
        token_id: Uuid,
        request_digest: &'a str,
        now: Timestamp,
    ) -> CredentialStoreFuture<'a, Result<Option<StoredCredentialResponse>, CredentialStoreError>>
    {
        let digest = request_digest.to_owned();
        Box::pin(self.run(move |store| {
            let snapshot = store.store.provider.db.snapshot();
            let response_key = key(RESPONSE, Uuid::nil(), issuance_id.as_bytes());
            let Some(response) = read_snapshot::<ResponseRecord>(&snapshot, &response_key)? else {
                return Ok(None);
            };
            if response.expires_at <= now
                || response.request_digest != digest
                || !continuation_snapshot(
                    &snapshot,
                    response.token_id,
                    token_id,
                    response.selection.as_ref(),
                    now,
                )?
            {
                return Ok(None);
            }
            let encoding = match response.encoding.as_str() {
                "json" => CredentialResponseEncoding::Json,
                "jwt" => CredentialResponseEncoding::Jwt,
                _ => return Err(StoreError::Invalid),
            };
            if !matches!(response.status, 200 | 202) {
                return Err(StoreError::Invalid);
            }
            Ok(Some(StoredCredentialResponse {
                issuance_id,
                token_id: response.token_id,
                request_digest: response.request_digest,
                selection: response.selection,
                body: store.store.open_bytes(&response_key, &response.body)?,
                encoding,
                status: response.status,
                dpop_nonce: response.dpop_nonce,
                expires_at: response.expires_at,
            }))
        }))
    }

    fn finalize_nonce_with_notification_and_response<'a>(
        &'a self,
        nonce_hash: &'a str,
        claim_id: &'a str,
        handle: &'a NotificationHandle,
        response: &'a StoredCredentialResponse,
        now: Timestamp,
    ) -> CredentialStoreFuture<'a, Result<bool, CredentialStoreError>> {
        let completion = Completion::Nonce(nonce_hash.to_owned(), claim_id.to_owned());
        let handle = handle.clone();
        let response = response.clone();
        Box::pin(self.run(move |store| store.complete(completion, handle, response, now)))
    }

    fn store_response_with_notification<'a>(
        &'a self,
        handle: &'a NotificationHandle,
        response: &'a StoredCredentialResponse,
        now: Timestamp,
    ) -> CredentialStoreFuture<'a, Result<(), CredentialStoreError>> {
        let handle = handle.clone();
        let response = response.clone();
        Box::pin(self.run(move |store| {
            if store.complete(Completion::Immediate, handle, response, now)? {
                Ok(())
            } else {
                Err(StoreError::Invalid)
            }
        }))
    }

    fn store_deferred_and_finalize_nonce_with_response<'a>(
        &'a self,
        credential: &'a DeferredCredential,
        nonce_hash: &'a str,
        claim_id: &'a str,
        response: &'a StoredCredentialResponse,
        now: Timestamp,
    ) -> CredentialStoreFuture<'a, Result<(), CredentialStoreError>> {
        let credential = credential.clone();
        let response = response.clone();
        let nonce = Some((nonce_hash.to_owned(), claim_id.to_owned()));
        Box::pin(self.run(move |store| store.defer(credential, nonce, response, now)))
    }

    fn store_deferred_with_response<'a>(
        &'a self,
        credential: &'a DeferredCredential,
        response: &'a StoredCredentialResponse,
        now: Timestamp,
    ) -> CredentialStoreFuture<'a, Result<(), CredentialStoreError>> {
        let credential = credential.clone();
        let response = response.clone();
        Box::pin(self.run(move |store| store.defer(credential, None, response, now)))
    }

    fn claim_ready_deferred<'a>(
        &'a self,
        transaction_hash: &'a str,
        token_id: Uuid,
        claim_id: &'a str,
        _now: Timestamp,
    ) -> CredentialStoreFuture<'a, Result<DeferredClaimOutcome, CredentialStoreError>> {
        let hash = transaction_hash.to_owned();
        let claim = claim_id.to_owned();
        Box::pin(self.run(move |store| {
            let deferred_key = key(DEFERRED, Uuid::nil(), hash.as_bytes());
            let Some(hint) =
                crate::db::read::<DeferredRecord>(&store.store.provider.db, &deferred_key)?
            else {
                return Ok(DeferredClaimOutcome::Invalid);
            };
            let tx = store.store.provider.transaction();
            let now = Timestamp::now();
            let Some((original, current)) =
                continuation_tx(&tx, hint.token_id, token_id, hint.selection.as_ref(), now)?
            else {
                return Ok(DeferredClaimOutcome::Invalid);
            };
            let Some(mut deferred) = read_tx::<DeferredRecord>(&tx, &deferred_key, true)? else {
                return Ok(DeferredClaimOutcome::Invalid);
            };
            let now = Timestamp::now();
            if deferred.consumed
                || deferred.expires_at <= now
                || current.access.expires_at <= now
                || deferred.token_id != original.access.token_id
                || deferred.authorization_id != original.access.authorization_id
                || deferred.selection != hint.selection
            {
                return Ok(DeferredClaimOutcome::Invalid);
            }
            if deferred.ready_at > now {
                return Ok(DeferredClaimOutcome::Pending {
                    retry_at: deferred.ready_at,
                });
            }
            if let Some(lease) = &deferred.lease
                && lease.expires_at > now
            {
                return Ok(DeferredClaimOutcome::Busy {
                    retry_at: lease.expires_at,
                });
            }
            let payload = store.store.open(&deferred_key, &deferred.payload)?;
            deferred.lease = Some(Lease {
                claim_id: claim,
                expires_at: now + SignedDuration::from_mins(5),
                token_id: Some(token_id),
            });
            put_expiring(&tx, &deferred_key, &deferred, deferred.expires_at)?;
            tx.commit()?;
            Ok(DeferredClaimOutcome::Claimed(Box::new(
                DeferredCredential {
                    id: deferred.id,
                    transaction_hash: hash,
                    access: original.access,
                    selection: deferred.selection,
                    configuration_id: deferred.configuration_id,
                    format: deferred.format,
                    holder_bindings: deferred.holder_bindings,
                    payload,
                    ready_at: deferred.ready_at,
                    expires_at: deferred.expires_at,
                },
            )))
        }))
    }

    fn release_deferred<'a>(
        &'a self,
        transaction_hash: &'a str,
        token_id: Uuid,
        claim_id: &'a str,
        _now: Timestamp,
    ) -> CredentialStoreFuture<'a, Result<bool, CredentialStoreError>> {
        let hash = transaction_hash.to_owned();
        let claim = claim_id.to_owned();
        Box::pin(self.run(move |store| {
            let tx = store.store.provider.transaction();
            let deferred_key = key(DEFERRED, Uuid::nil(), hash.as_bytes());
            let Some(mut deferred) = read_tx::<DeferredRecord>(&tx, &deferred_key, true)? else {
                return Ok(false);
            };
            if deferred.consumed
                || !deferred
                    .lease
                    .as_ref()
                    .is_some_and(|l| l.claim_id == claim && l.token_id == Some(token_id))
            {
                return Ok(false);
            }
            deferred.lease = None;
            put_expiring(&tx, &deferred_key, &deferred, deferred.expires_at)?;
            tx.commit()?;
            Ok(true)
        }))
    }

    fn finalize_deferred_with_notification_and_response<'a>(
        &'a self,
        transaction_hash: &'a str,
        token_id: Uuid,
        claim_id: &'a str,
        handle: &'a NotificationHandle,
        response: &'a StoredCredentialResponse,
        now: Timestamp,
    ) -> CredentialStoreFuture<'a, Result<bool, CredentialStoreError>> {
        let completion =
            Completion::Deferred(transaction_hash.to_owned(), token_id, claim_id.to_owned());
        let handle = handle.clone();
        let response = response.clone();
        Box::pin(self.run(move |store| store.complete(completion, handle, response, now)))
    }

    fn record_notification<'a>(
        &'a self,
        notification: &'a IssuanceNotification,
    ) -> CredentialStoreFuture<'a, Result<bool, CredentialStoreError>> {
        let notification = notification.clone();
        Box::pin(self.run(move |store| {
            let notification_key = key(
                NOTIFICATION,
                Uuid::nil(),
                notification.notification_id.as_bytes(),
            );
            let Some(hint) =
                crate::db::read::<NotificationRecord>(&store.store.provider.db, &notification_key)?
            else {
                return Ok(false);
            };
            let tx = store.store.provider.transaction();
            let now = notification.occurred_at.max(Timestamp::now());
            let Some((_, current)) = continuation_tx(
                &tx,
                hint.token_id,
                notification.token_id,
                hint.selection.as_ref(),
                now,
            )?
            else {
                return Ok(false);
            };
            let Some(mut handle) = read_tx::<NotificationRecord>(&tx, &notification_key, true)?
            else {
                return Ok(false);
            };
            let now = now.max(Timestamp::now());
            if handle.expires_at <= now
                || current.access.expires_at <= now
                || handle.token_id != hint.token_id
                || handle.selection != hint.selection
            {
                return Ok(false);
            }
            if handle.event.is_some() {
                return Ok(handle.event == Some(notification.event)
                    && handle.description == notification.description);
            }
            handle.event = Some(notification.event);
            handle.description = notification.description;
            handle.occurred_at = Some(notification.occurred_at);
            put_expiring(&tx, &notification_key, &handle, handle.expires_at)?;
            tx.commit()?;
            Ok(true)
        }))
    }
}

// The caller holds the owner's principal exclusively, excluding any new access
// insertion while its existing grants are revoked. Each issuer mutation locks
// the access record before its nonce, deferred record or notification.
fn revoke_index(
    tx: &Tx<'_>,
    tenant: Uuid,
    prefix: &[u8],
    client: Option<&str>,
) -> Result<usize, RepositoryError> {
    let now = Timestamp::now();
    let mut affected = 0;
    for item in tx.iterator(IteratorMode::From(prefix, Direction::Forward)) {
        let (index, _) = item.map_err(map_error)?;
        if !index.starts_with(prefix) {
            break;
        }
        let token = Uuid::from_slice(&index[prefix.len()..])
            .map_err(|_| crate::users::corrupt("invalid credential access index"))?;
        let access_key = key(ACCESS, Uuid::nil(), token.as_bytes());
        if let Some(mut access) = read_tx::<AccessRecord>(tx, &access_key, true)?
            && access.revoked_at.is_none()
            && client.is_none_or(|id| access.access.client_id == id)
        {
            if access.access.tenant_id != tenant {
                return Err(crate::users::corrupt(
                    "credential access owner index mismatch",
                ));
            }
            access.revoked_at = Some(now);
            put_expiring(tx, &access_key, &access, access.retain_until)?;
            if access.access.expires_at
                > now
                    - SignedDuration::from_secs(
                        nazo_resource_server::MAX_ACCESS_TOKEN_CLOCK_SKEW_SECONDS,
                    )
                && let Some(client_id) = tx
                    .get_pinned(key(
                        CLIENT_PUBLIC_ID,
                        tenant,
                        access.access.client_id.as_bytes(),
                    ))
                    .map_err(map_error)?
                    .map(|raw| decode::<Uuid>(&raw))
                    .transpose()?
            {
                crate::tokens::revoke_jti(
                    tx,
                    tenant,
                    client_id,
                    blake3::hash(access.access.token_id.to_string().as_bytes()).as_bytes(),
                    access.access.expires_at,
                )?;
            }
            affected += 1;
        }
    }
    Ok(affected)
}

pub(crate) fn revoke_for_subject(
    tx: &Tx<'_>,
    tenant: Uuid,
    subject: Uuid,
) -> Result<usize, RepositoryError> {
    revoke_index(
        tx,
        tenant,
        &key(BY_SUBJECT, tenant, subject.as_bytes()),
        None,
    )
}

pub(crate) fn revoke_for_client(
    tx: &Tx<'_>,
    tenant: Uuid,
    client: &str,
) -> Result<usize, RepositoryError> {
    revoke_index(
        tx,
        tenant,
        &key(
            BY_CLIENT,
            tenant,
            blake3::hash(client.as_bytes()).as_bytes(),
        ),
        Some(client),
    )
}

pub(crate) fn revoke_for_scope(
    tx: &Tx<'_>,
    tenant: Uuid,
    subject: Uuid,
    client: &str,
) -> Result<usize, RepositoryError> {
    revoke_index(
        tx,
        tenant,
        &key(BY_SUBJECT, tenant, subject.as_bytes()),
        Some(client),
    )
}

#[cfg(test)]
#[path = "../../tests/unit/issuance.rs"]
mod tests;
