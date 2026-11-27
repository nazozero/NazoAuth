#![forbid(unsafe_code)]

//! Single-process native persistence backed by synchronous RocksDB transactions.

#[cfg(test)]
#[path = "../tests/support/mod.rs"]
mod support;

mod access_requests;
mod audit;
mod authorization;
mod clients;
mod control;
mod db;
mod digital_credentials;
mod federation;
mod grants;
mod keys;
mod logout;
mod maintenance;
mod mfa;
mod mfa_keys;
mod mtls;
mod passkeys;
mod provider;
mod runtime;
mod scim;
mod tenancy;
mod tenant_resources;
mod tokens;
mod users;

pub use mfa_keys::{MfaTotpKey, MfaTotpKeyError, MfaTotpKeyRing};
pub use tenant_resources::RocksDbTenantResourceExecutor;

use std::{path::Path, sync::Arc};

use nazo_identity::ports::RepositoryError;
use rocksdb::{
    Options, Transaction, TransactionDB, TransactionDBOptions, TransactionOptions, WriteOptions,
};
use uuid::Uuid;

/// One database directory and its tenant-bound application capability views.
/// Clones share the database; opening the same directory in another process fails.
#[derive(Clone)]
pub struct RocksDb {
    pub(crate) db: Arc<TransactionDB>,
    pub(crate) tenant_id: Uuid,
    pub(crate) totp_keys: Option<MfaTotpKeyRing>,
}

impl RocksDb {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, RepositoryError> {
        let mut options = Options::default();
        options.create_if_missing(true);
        options.set_compression_type(rocksdb::DBCompressionType::Lz4);
        // Bound the mutable working set without tuning away WAL durability.
        options.set_write_buffer_size(32 * 1024 * 1024);
        options.set_max_write_buffer_number(2);
        let db = TransactionDB::open(&options, &TransactionDBOptions::default(), path)
            .map_err(db::map_error)?;
        let store = Self {
            db: Arc::new(db),
            tenant_id: nazo_identity::TenantContext::default_system()
                .tenant_id
                .as_uuid(),
            totp_keys: None,
        };
        let tx = store.transaction();
        match db::read_tx::<u32>(&tx, db::SCHEMA_KEY, true)? {
            None => db::put(&tx, db::SCHEMA_KEY, &1_u32)?,
            Some(1) => {}
            Some(_) => {
                return Err(RepositoryError::Consistency(
                    "unsupported RocksDB schema version".into(),
                ));
            }
        }
        tx.commit().map_err(db::map_error)?;
        Ok(store)
    }

    #[must_use]
    pub fn for_tenant(&self, tenant_id: Uuid) -> Self {
        Self {
            tenant_id,
            ..self.clone()
        }
    }

    /// Create a consistent native checkpoint in a new directory. Copy that
    /// directory to independent durable storage before treating it as a backup.
    pub fn checkpoint(&self, destination: impl AsRef<Path>) -> Result<(), RepositoryError> {
        rocksdb::checkpoint::TransactionDBCheckpoint::new(&self.db)
            .and_then(|checkpoint| checkpoint.create_checkpoint(destination))
            .map_err(db::map_error)
    }

    pub(crate) fn transaction(&self) -> Transaction<'_, TransactionDB> {
        let mut writes = WriteOptions::default();
        writes.set_sync(true);
        let mut transaction = TransactionOptions::default();
        transaction.set_deadlock_detect(true);
        self.db.transaction_opt(&writes, &transaction)
    }

    pub(crate) async fn run<T, F>(&self, operation: F) -> Result<T, RepositoryError>
    where
        T: Send + 'static,
        F: FnOnce(&Self) -> Result<T, RepositoryError> + Send + 'static,
    {
        let store = self.clone();
        tokio::task::spawn_blocking(move || operation(&store))
            .await
            .map_err(|_| RepositoryError::Unavailable)?
    }
}

impl nazo_persistence::DatabaseHealthPort for RocksDb {
    fn check(
        &self,
    ) -> futures_util::future::BoxFuture<'_, Result<(), nazo_persistence::DatabaseHealthError>>
    {
        Box::pin(async move {
            self.run(|store| match db::read::<u32>(&store.db, db::SCHEMA_KEY)? {
                Some(1) => Ok(()),
                _ => Err(RepositoryError::Unavailable),
            })
            .await
            .map_err(|_| nazo_persistence::DatabaseHealthError)
        })
    }
}
