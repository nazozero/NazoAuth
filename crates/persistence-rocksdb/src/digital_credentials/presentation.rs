use jiff::Timestamp;
use nazo_identity::ports::RepositoryError;
use nazo_openid4vp::{
    AuthorizationRequest, ClientIdPrefix, PresentationCreateIdempotency, PresentationCreateOutcome,
    PresentationResult, PresentationStoreError as Error, PresentationStoreFuture,
    PresentationStorePort, PresentationTransaction, RequestMethod,
};
use rocksdb::{SnapshotWithThreadMode, Transaction, TransactionDB};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::EncryptedStore;
use crate::{
    RocksDb,
    db::{key, map_error, put_expiring, read_snapshot, read_tx},
    tenant_resources::{trust_binding_current_snapshot, trust_binding_current_tx},
    users::corrupt,
};

const TRANSACTION: u8 = 0xde;
const REQUEST: u8 = 0xdf;

pub(crate) struct PresentationStore(EncryptedStore);

#[derive(Serialize, Deserialize)]
struct RequestRecord {
    client_id_prefix: ClientIdPrefix,
    request_method: RequestMethod,
    wallet_authorization_endpoint: String,
    request: AuthorizationRequest,
    request_object: Option<String>,
    request_uri: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct Record {
    id: Uuid,
    request_sha256: String,
    canonical_request: String,
    request: RequestRecord,
    state_hash: String,
    trust_id: Option<Uuid>,
    trust_resource: Option<String>,
    trust_digest: Option<String>,
    private_key: Option<String>,
    result: Option<String>,
    completed_at: Option<Timestamp>,
    created_at: Timestamp,
    expires_at: Timestamp,
}

fn error(error: RepositoryError) -> Error {
    match error {
        RepositoryError::Conflict => Error::IdempotencyConflict,
        RepositoryError::Unavailable => Error::Unavailable,
        _ => Error::InvalidTransition,
    }
}
fn aad(tenant: Uuid, id: Uuid, purpose: u8) -> Vec<u8> {
    let mut key = key(TRANSACTION, tenant, id.as_bytes());
    key.push(purpose);
    key
}
fn request_key(tenant: Uuid, jti: &str) -> Vec<u8> {
    key(REQUEST, tenant, jti.as_bytes())
}
fn trusted_tx(
    tx: &Transaction<'_, TransactionDB>,
    tenant: Uuid,
    row: &Record,
) -> Result<bool, RepositoryError> {
    trust_binding_current_tx(
        tx,
        tenant,
        row.trust_id,
        row.trust_resource.as_deref(),
        row.trust_digest.as_deref(),
    )
}
fn trusted_snapshot(
    snapshot: &SnapshotWithThreadMode<'_, TransactionDB>,
    tenant: Uuid,
    row: &Record,
) -> Result<bool, RepositoryError> {
    trust_binding_current_snapshot(
        snapshot,
        tenant,
        row.trust_id,
        row.trust_resource.as_deref(),
        row.trust_digest.as_deref(),
    )
}
fn idempotent(row: &Record, digest: &str, canonical: &str) -> Result<(), RepositoryError> {
    if row.request_sha256 == digest && row.canonical_request == canonical {
        Ok(())
    } else {
        Err(RepositoryError::Conflict)
    }
}

impl PresentationStore {
    pub(crate) fn new(provider: RocksDb, key: [u8; 32]) -> Self {
        Self(EncryptedStore::new(provider, key))
    }

    fn view(
        encrypted: &EncryptedStore,
        row: Record,
        include_key: bool,
    ) -> Result<PresentationTransaction, RepositoryError> {
        let private_key = if include_key {
            row.private_key
                .map(|cipher| {
                    let bytes = encrypted
                        .open_bytes(&aad(encrypted.provider.tenant_id, row.id, 0), &cipher)?;
                    bytes
                        .as_ref()
                        .try_into()
                        .map_err(|_| corrupt("invalid presentation private key"))
                })
                .transpose()?
        } else {
            None
        };
        Ok(PresentationTransaction {
            id: row.id,
            client_id_prefix: row.request.client_id_prefix,
            request_method: row.request.request_method,
            wallet_authorization_endpoint: row.request.wallet_authorization_endpoint,
            request: row.request.request,
            request_object: row.request.request_object,
            request_uri: row.request.request_uri,
            openid4vc_trust_policy_binding_id: row.trust_id,
            openid4vc_trust_policy_resource_id: row.trust_resource,
            openid4vc_trust_policy_digest: row.trust_digest,
            response_encryption_private_key: private_key,
            created_at: row.created_at,
            expires_at: row.expires_at,
        })
    }
}

impl PresentationStorePort for PresentationStore {
    fn create<'a>(
        &'a self,
        transaction: &'a PresentationTransaction,
        binding: PresentationCreateIdempotency<'a>,
    ) -> PresentationStoreFuture<'a, Result<PresentationCreateOutcome, Error>> {
        let transaction = transaction.clone();
        let jti = binding.request_jti.to_owned();
        let digest = binding.request_sha256.to_owned();
        let canonical = binding.canonical_request.to_owned();
        let encrypted = self.0.clone();
        Box::pin(async move {
            self.0
                .provider
                .run(move |store| {
                    let tx = store.transaction();
                    let tenant = store.tenant_id;
                    let index = request_key(tenant, &jti);
                    if let Some(id) = read_tx::<Uuid>(&tx, &index, true)?
                        && let Some(row) =
                            read_tx::<Record>(&tx, &key(TRANSACTION, tenant, id.as_bytes()), false)?
                                .filter(|row| row.expires_at > Timestamp::now())
                    {
                        idempotent(&row, &digest, &canonical)?;
                        return Ok(PresentationCreateOutcome::Existing(Box::new(Self::view(
                            &encrypted, row, false,
                        )?)));
                    }
                    let record_key = key(TRANSACTION, tenant, transaction.id.as_bytes());
                    if read_tx::<Record>(&tx, &record_key, true)?.is_some() {
                        return Err(corrupt("presentation identifier already exists"));
                    }
                    let row = Record {
                        id: transaction.id,
                        request_sha256: digest,
                        canonical_request: canonical,
                        state_hash: blake3::hash(transaction.request.state.as_bytes())
                            .to_hex()
                            .to_string(),
                        private_key: transaction
                            .response_encryption_private_key
                            .as_ref()
                            .map(|private| encrypted.seal(&aad(tenant, transaction.id, 0), private))
                            .transpose()?,
                        request: RequestRecord {
                            client_id_prefix: transaction.client_id_prefix,
                            request_method: transaction.request_method,
                            wallet_authorization_endpoint: transaction
                                .wallet_authorization_endpoint,
                            request: transaction.request,
                            request_object: transaction.request_object,
                            request_uri: transaction.request_uri,
                        },
                        trust_id: transaction.openid4vc_trust_policy_binding_id,
                        trust_resource: transaction.openid4vc_trust_policy_resource_id,
                        trust_digest: transaction.openid4vc_trust_policy_digest,
                        result: None,
                        completed_at: None,
                        created_at: transaction.created_at,
                        expires_at: transaction.expires_at,
                    };
                    if !trusted_tx(&tx, tenant, &row)? || row.expires_at <= Timestamp::now() {
                        return Err(corrupt("presentation is no longer valid"));
                    }
                    put_expiring(&tx, &record_key, &row, row.expires_at)?;
                    put_expiring(&tx, &index, &row.id, row.expires_at)?;
                    tx.commit().map_err(map_error)?;
                    Ok(PresentationCreateOutcome::Created)
                })
                .await
                .map_err(error)
        })
    }

    fn find_by_create_request<'a>(
        &'a self,
        binding: PresentationCreateIdempotency<'a>,
    ) -> PresentationStoreFuture<'a, Result<Option<PresentationTransaction>, Error>> {
        let index = request_key(self.0.provider.tenant_id, binding.request_jti);
        let digest = binding.request_sha256.to_owned();
        let canonical = binding.canonical_request.to_owned();
        let encrypted = self.0.clone();
        Box::pin(async move {
            self.0
                .provider
                .run(move |store| {
                    let snapshot = store.db.snapshot();
                    let Some(id) = read_snapshot::<Uuid>(&snapshot, &index)? else {
                        return Ok(None);
                    };
                    let Some(row) = read_snapshot::<Record>(
                        &snapshot,
                        &key(TRANSACTION, store.tenant_id, id.as_bytes()),
                    )?
                    .filter(|row| row.expires_at > Timestamp::now()) else {
                        return Ok(None);
                    };
                    idempotent(&row, &digest, &canonical)?;
                    Self::view(&encrypted, row, false).map(Some)
                })
                .await
                .map_err(error)
        })
    }

    fn request<'a>(
        &'a self,
        id: Uuid,
        now: Timestamp,
    ) -> PresentationStoreFuture<'a, Result<Option<PresentationTransaction>, Error>> {
        let encrypted = self.0.clone();
        Box::pin(async move {
            self.0
                .provider
                .run(move |store| {
                    let snapshot = store.db.snapshot();
                    let Some(row) = read_snapshot::<Record>(
                        &snapshot,
                        &key(TRANSACTION, store.tenant_id, id.as_bytes()),
                    )?
                    .filter(|row| row.expires_at > now && row.completed_at.is_none()) else {
                        return Ok(None);
                    };
                    if !trusted_snapshot(&snapshot, store.tenant_id, &row)? {
                        return Ok(None);
                    }
                    Self::view(&encrypted, row, true).map(Some)
                })
                .await
                .map_err(error)
        })
    }

    fn bind_wallet_nonce<'a>(
        &'a self,
        id: Uuid,
        nonce: &'a str,
        now: Timestamp,
    ) -> PresentationStoreFuture<'a, Result<bool, Error>> {
        let nonce = nonce.to_owned();
        Box::pin(async move {
            self.0
                .provider
                .run(move |store| {
                    let tx = store.transaction();
                    let key = key(TRANSACTION, store.tenant_id, id.as_bytes());
                    let Some(mut row) = read_tx::<Record>(&tx, &key, true)?
                        .filter(|row| row.expires_at > now && row.completed_at.is_none())
                    else {
                        return Ok(false);
                    };
                    if !trusted_tx(&tx, store.tenant_id, &row)?
                        || row.expires_at <= Timestamp::now()
                    {
                        return Ok(false);
                    }
                    row.request.request.wallet_nonce = Some(nonce);
                    put_expiring(&tx, &key, &row, row.expires_at)?;
                    tx.commit().map_err(map_error)?;
                    Ok(true)
                })
                .await
                .map_err(error)
        })
    }

    fn complete<'a>(
        &'a self,
        id: Uuid,
        state_hash: &'a str,
        result: &'a PresentationResult,
        now: Timestamp,
    ) -> PresentationStoreFuture<'a, Result<bool, Error>> {
        let state_hash = state_hash.to_owned();
        let result = result.clone();
        let encrypted = self.0.clone();
        Box::pin(async move {
            if result.transaction_id != id || result.completed_at != now {
                return Err(Error::InvalidTransition);
            }
            self.0
                .provider
                .run(move |store| {
                    let ciphertext = encrypted.seal_value(&aad(store.tenant_id, id, 1), &result)?;
                    let tx = store.transaction();
                    let key = key(TRANSACTION, store.tenant_id, id.as_bytes());
                    let Some(mut row) = read_tx::<Record>(&tx, &key, true)?.filter(|row| {
                        row.expires_at > now
                            && row.completed_at.is_none()
                            && row.state_hash == state_hash
                    }) else {
                        return Ok(false);
                    };
                    if !trusted_tx(&tx, store.tenant_id, &row)?
                        || row.expires_at <= Timestamp::now()
                    {
                        return Ok(false);
                    }
                    row.result = Some(ciphertext);
                    row.completed_at = Some(now);
                    row.private_key = None;
                    put_expiring(&tx, &key, &row, row.expires_at)?;
                    tx.commit().map_err(map_error)?;
                    Ok(true)
                })
                .await
                .map_err(error)
        })
    }

    fn result<'a>(
        &'a self,
        id: Uuid,
        now: Timestamp,
    ) -> PresentationStoreFuture<'a, Result<Option<PresentationResult>, Error>> {
        let encrypted = self.0.clone();
        Box::pin(async move {
            self.0
                .provider
                .run(move |store| {
                    let snapshot = store.db.snapshot();
                    let Some(row) = read_snapshot::<Record>(
                        &snapshot,
                        &key(TRANSACTION, store.tenant_id, id.as_bytes()),
                    )?
                    .filter(|row| row.expires_at > now) else {
                        return Ok(None);
                    };
                    if !trusted_snapshot(&snapshot, store.tenant_id, &row)? {
                        return Ok(None);
                    }
                    let Some(ciphertext) = row.result else {
                        return if row.completed_at.is_none() {
                            Ok(None)
                        } else {
                            Err(corrupt("presentation result missing"))
                        };
                    };
                    let result: PresentationResult =
                        encrypted.open(&aad(store.tenant_id, id, 1), &ciphertext)?;
                    if result.transaction_id != id || Some(result.completed_at) != row.completed_at
                    {
                        return Err(corrupt("presentation result binding mismatch"));
                    }
                    Ok(Some(result))
                })
                .await
                .map_err(error)
        })
    }
}
