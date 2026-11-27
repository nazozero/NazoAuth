use futures_util::future::BoxFuture;
use jiff::Timestamp;
use nazo_identity::{TenantContext, ports::RepositoryError};
use nazo_openid4vci::CredentialStoreError;
use nazo_persistence::{
    ManagedCredentialDataset, ManagedCredentialDatasetWrite, Openid4vciDatasetStore,
    SecurityAuditEvent,
};
use rocksdb::{Transaction, TransactionDB};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use uuid::Uuid;
use zeroize::Zeroizing;

use super::EncryptedStore;
use crate::{
    RocksDb,
    audit::append_in_tx,
    db::{key, map_error, put, read_snapshot, read_tx},
    users::{corrupt, read_principal_tx},
};

const DATASET: u8 = 0xdc;
const EVENT: u8 = 0xdd;
const ADMIN_SOURCE: &str = "admin-session";

pub(crate) struct DatasetStore(EncryptedStore);

#[derive(Serialize, Deserialize)]
struct Dataset {
    ciphertext: String,
    source: String,
    revision: Uuid,
    valid_from: Option<Timestamp>,
    valid_until: Option<Timestamp>,
    updated_at: Timestamp,
}

// Availability checks skip the encrypted claims without allocating their string.
#[derive(Deserialize)]
struct Validity {
    valid_from: Option<Timestamp>,
    valid_until: Option<Timestamp>,
}

impl Dataset {
    fn current(&self, now: Timestamp) -> bool {
        self.valid_from.is_none_or(|from| from <= now)
            && self.valid_until.is_none_or(|until| until > now)
    }
}

fn dataset_key(tenant: Uuid, subject: Uuid, configuration: &str) -> Vec<u8> {
    let mut result = key(DATASET, tenant, subject.as_bytes());
    result.extend_from_slice(configuration.as_bytes());
    result
}

fn error(error: RepositoryError) -> CredentialStoreError {
    match error {
        RepositoryError::Unavailable => CredentialStoreError::Unavailable,
        _ => CredentialStoreError::InvalidTransition,
    }
}

#[allow(clippy::too_many_arguments)]
fn source_event(
    tx: &Transaction<'_, TransactionDB>,
    tenant: Uuid,
    subject: Uuid,
    configuration: &str,
    source: &str,
    revision: Uuid,
    actor: Option<Uuid>,
    deleted: bool,
    now: Timestamp,
) -> Result<(), RepositoryError> {
    put(
        tx,
        &key(EVENT, tenant, revision.as_bytes()),
        &json!({
            "subject_id":subject,"configuration_id":configuration,"source":source,
            "actor_user_id":actor,"deleted":deleted,"occurred_at":now
        }),
    )
}

fn audit(
    tx: &Transaction<'_, TransactionDB>,
    write: &ManagedCredentialDatasetWrite,
    revision: Uuid,
    now: Timestamp,
    deleted: bool,
) -> Result<(), RepositoryError> {
    append_in_tx(
        tx,
        &SecurityAuditEvent {
            event_id: revision,
            event_type: if deleted {
                "openid4vci_credential_dataset_deleted"
            } else {
                "openid4vci_credential_dataset_updated"
            }
            .into(),
            event_category: "credential_lifecycle".into(),
            occurred_at: now,
            payload: json!({"schema_version":nazo_persistence::SECURITY_AUDIT_SCHEMA_VERSION,
            "event_category":"credential_lifecycle","tenant_id":write.tenant_id,
            "admin_user_id":write.actor_user_id,"subject_id":write.subject_id,
            "credential_configuration_id":write.credential_configuration_id,"outcome":"success"}),
        },
    )
}

fn actor_authorized(
    tx: &Transaction<'_, TransactionDB>,
    tenant: Uuid,
    actor: Uuid,
) -> Result<bool, RepositoryError> {
    Ok(read_principal_tx(tx, tenant, actor, false)?
        .is_some_and(|p| p.active && p.admin_level().is_some_and(|level| level > 0)))
}

impl DatasetStore {
    pub(crate) fn new(provider: RocksDb, key: [u8; 32]) -> Self {
        Self(EncryptedStore::new(provider, key))
    }

    fn view(
        encrypted: &EncryptedStore,
        key: &[u8],
        row: Dataset,
    ) -> Result<ManagedCredentialDataset, RepositoryError> {
        Ok(ManagedCredentialDataset {
            claims: encrypted.open(key, &row.ciphertext)?,
            valid_from: row.valid_from,
            valid_until: row.valid_until,
            updated_at: row.updated_at,
        })
    }
}

impl Openid4vciDatasetStore for DatasetStore {
    fn datasets_available<'a>(
        &'a self,
        tenant: Uuid,
        subject: Uuid,
        configurations: &'a [String],
    ) -> BoxFuture<'a, Result<bool, CredentialStoreError>> {
        let configurations = configurations.to_vec();
        Box::pin(async move {
            self.0
                .provider
                .run(move |store| {
                    let snapshot = store.db.snapshot();
                    let now = Timestamp::now();
                    for configuration in configurations {
                        if !read_snapshot::<Validity>(
                            &snapshot,
                            &dataset_key(tenant, subject, &configuration),
                        )?
                        .is_some_and(|row| {
                            row.valid_from.is_none_or(|from| from <= now)
                                && row.valid_until.is_none_or(|until| until > now)
                        }) {
                            return Ok(false);
                        }
                    }
                    Ok(true)
                })
                .await
                .map_err(error)
        })
    }

    fn dataset<'a>(
        &'a self,
        tenant: Uuid,
        subject: Uuid,
        configuration: &'a str,
    ) -> BoxFuture<'a, Result<Option<Value>, CredentialStoreError>> {
        let key = dataset_key(tenant, subject, configuration);
        let encrypted = self.0.clone();
        Box::pin(async move {
            self.0
                .provider
                .run(move |store| {
                    read_snapshot::<Dataset>(&store.db.snapshot(), &key)?
                        .filter(|row| row.current(Timestamp::now()))
                        .map(|row| encrypted.open(&key, &row.ciphertext))
                        .transpose()
                })
                .await
                .map_err(error)
        })
    }

    fn managed_dataset<'a>(
        &'a self,
        tenant: Uuid,
        subject: Uuid,
        configuration: &'a str,
    ) -> BoxFuture<'a, Result<Option<ManagedCredentialDataset>, CredentialStoreError>> {
        let key = dataset_key(tenant, subject, configuration);
        let encrypted = self.0.clone();
        Box::pin(async move {
            self.0
                .provider
                .run(move |store| {
                    read_snapshot::<Dataset>(&store.db.snapshot(), &key)?
                        .map(|row| Self::view(&encrypted, &key, row))
                        .transpose()
                })
                .await
                .map_err(error)
        })
    }

    fn upsert_managed_dataset(
        &self,
        write: ManagedCredentialDatasetWrite,
    ) -> BoxFuture<'_, Result<Option<ManagedCredentialDataset>, CredentialStoreError>> {
        let encrypted = self.0.clone();
        Box::pin(async move {
            self.0
                .provider
                .run(move |store| {
                    let tx = store.transaction();
                    if !actor_authorized(&tx, write.tenant_id, write.actor_user_id)?
                        || !read_principal_tx(&tx, write.tenant_id, write.subject_id, false)?
                            .is_some_and(|p| p.active)
                    {
                        return Ok(None);
                    }
                    let key = dataset_key(
                        write.tenant_id,
                        write.subject_id,
                        &write.credential_configuration_id,
                    );
                    if read_tx::<Dataset>(&tx, &key, true)?
                        .is_some_and(|row| row.source != ADMIN_SOURCE)
                    {
                        return Ok(None);
                    }
                    let now = Timestamp::now();
                    let revision = Uuid::now_v7();
                    let row = Dataset {
                        ciphertext: encrypted.seal_value(&key, &write.claims)?,
                        source: ADMIN_SOURCE.into(),
                        revision,
                        valid_from: write.valid_from,
                        valid_until: write.valid_until,
                        updated_at: now,
                    };
                    put(&tx, &key, &row)?;
                    source_event(
                        &tx,
                        write.tenant_id,
                        write.subject_id,
                        &write.credential_configuration_id,
                        ADMIN_SOURCE,
                        revision,
                        Some(write.actor_user_id),
                        false,
                        now,
                    )?;
                    audit(&tx, &write, revision, now, false)?;
                    let view = Self::view(&encrypted, &key, row)?;
                    tx.commit().map_err(map_error)?;
                    Ok(Some(view))
                })
                .await
                .map_err(error)
        })
    }

    fn delete_managed_dataset<'a>(
        &'a self,
        tenant: Uuid,
        actor: Uuid,
        subject: Uuid,
        configuration: &'a str,
    ) -> BoxFuture<'a, Result<bool, CredentialStoreError>> {
        let configuration = configuration.to_owned();
        Box::pin(async move {
            self.0
                .provider
                .run(move |store| {
                    let tx = store.transaction();
                    if !actor_authorized(&tx, tenant, actor)? {
                        return Ok(false);
                    }
                    let key = dataset_key(tenant, subject, &configuration);
                    if !read_tx::<Dataset>(&tx, &key, true)?
                        .is_some_and(|row| row.source == ADMIN_SOURCE)
                    {
                        return Ok(false);
                    }
                    let revision = Uuid::now_v7();
                    let now = Timestamp::now();
                    tx.delete(key).map_err(map_error)?;
                    source_event(
                        &tx,
                        tenant,
                        subject,
                        &configuration,
                        ADMIN_SOURCE,
                        revision,
                        Some(actor),
                        true,
                        now,
                    )?;
                    audit(
                        &tx,
                        &ManagedCredentialDatasetWrite {
                            tenant_id: tenant,
                            actor_user_id: actor,
                            subject_id: subject,
                            credential_configuration_id: configuration,
                            claims: Value::Null,
                            valid_from: None,
                            valid_until: None,
                        },
                        revision,
                        now,
                        true,
                    )?;
                    tx.commit().map_err(map_error)?;
                    Ok(true)
                })
                .await
                .map_err(error)
        })
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn write_managed_dataset_tx(
    tx: &Transaction<'_, TransactionDB>,
    data_key: &[u8; 32],
    tenant: TenantContext,
    subject: Uuid,
    configuration: &str,
    claims: &Value,
    valid_from: Timestamp,
    valid_until: Option<Timestamp>,
    source: &str,
) -> Result<Uuid, RepositoryError> {
    if !read_principal_tx(tx, tenant.tenant_id.as_uuid(), subject, false)?
        .is_some_and(|p| p.active && p.tenant == tenant)
    {
        return Err(RepositoryError::NotFound);
    }
    let tenant = tenant.tenant_id.as_uuid();
    let key = dataset_key(tenant, subject, configuration);
    if read_tx::<Dataset>(tx, &key, true)?.is_some_and(|row| row.source != source) {
        return Err(RepositoryError::Conflict);
    }
    let plaintext =
        Zeroizing::new(serde_json::to_vec(claims).map_err(|_| corrupt("invalid dataset claims"))?);
    let revision = Uuid::now_v7();
    let now = Timestamp::now();
    put(
        tx,
        &key,
        &Dataset {
            ciphertext: super::seal(data_key, &key, &plaintext)?,
            source: source.into(),
            revision,
            valid_from: Some(valid_from),
            valid_until,
            updated_at: now,
        },
    )?;
    source_event(
        tx,
        tenant,
        subject,
        configuration,
        source,
        revision,
        None,
        false,
        now,
    )?;
    Ok(revision)
}

pub(crate) fn remove_managed_dataset_tx(
    tx: &Transaction<'_, TransactionDB>,
    tenant: Uuid,
    subject: Uuid,
    configuration: &str,
    source: &str,
) -> Result<bool, RepositoryError> {
    let key = dataset_key(tenant, subject, configuration);
    if !read_tx::<Dataset>(tx, &key, true)?.is_some_and(|row| row.source == source) {
        return Ok(false);
    }
    tx.delete(key).map_err(map_error)?;
    source_event(
        tx,
        tenant,
        subject,
        configuration,
        source,
        Uuid::now_v7(),
        None,
        true,
        Timestamp::now(),
    )?;
    Ok(true)
}
