//! Tenant-bound signing key generations are one atomic CAS record.

use crate::{
    RocksDb,
    db::{key, map_error, put, read, read_tx},
    users::corrupt,
};
use nazo_identity::ports::RepositoryError;
use nazo_key_management::{
    PersistedSigningKeyset, SigningKeyRepository, SigningKeyRepositoryFuture,
    SigningKeyRepositoryUnavailable, SigningKeysetCompareAndSwapResult, SigningKeysetCreateResult,
};
use serde::{Deserialize, Serialize};

const KEYSET: u8 = 0x40;
#[derive(Deserialize)]
struct Keyset {
    revision: i64,
    public_metadata: serde_json::Value,
    encrypted_private_material: Vec<u8>,
    wrapping_key_id: String,
}
#[derive(Serialize)]
struct KeysetWrite<'a> {
    revision: i64,
    public_metadata: &'a serde_json::Value,
    encrypted_private_material: &'a [u8],
    wrapping_key_id: &'a str,
}
impl From<Keyset> for PersistedSigningKeyset {
    fn from(k: Keyset) -> Self {
        Self {
            revision: k.revision,
            public_metadata: k.public_metadata,
            encrypted_private_material: k.encrypted_private_material,
            wrapping_key_id: k.wrapping_key_id,
        }
    }
}
impl<'a> From<&'a PersistedSigningKeyset> for KeysetWrite<'a> {
    fn from(k: &'a PersistedSigningKeyset) -> Self {
        Self {
            revision: k.revision,
            public_metadata: &k.public_metadata,
            encrypted_private_material: &k.encrypted_private_material,
            wrapping_key_id: &k.wrapping_key_id,
        }
    }
}
fn error(e: RepositoryError) -> anyhow::Error {
    match e {
        RepositoryError::Unavailable => SigningKeyRepositoryUnavailable(e.into()).into(),
        _ => e.into(),
    }
}
impl SigningKeyRepository for RocksDb {
    fn load(&self) -> SigningKeyRepositoryFuture<'_, Option<PersistedSigningKeyset>> {
        Box::pin(async move {
            self.run(|db| {
                Ok(read::<Keyset>(&db.db, &key(KEYSET, db.tenant_id, &[]))?.map(Into::into))
            })
            .await
            .map_err(error)
        })
    }
    fn create_if_absent(
        &self,
        candidate: PersistedSigningKeyset,
    ) -> SigningKeyRepositoryFuture<'_, SigningKeysetCreateResult> {
        Box::pin(async move {
            anyhow::ensure!(
                candidate.revision == 1,
                "initial signing-key revision must be 1"
            );
            self.run(move |db| {
                let tx = db.transaction();
                let k = key(KEYSET, db.tenant_id, &[]);
                if let Some(existing) = read_tx::<Keyset>(&tx, &k, true)? {
                    return Ok(SigningKeysetCreateResult::Existing(existing.into()));
                }
                put(&tx, &k, &KeysetWrite::from(&candidate))?;
                tx.commit().map_err(map_error)?;
                Ok(SigningKeysetCreateResult::Created(candidate))
            })
            .await
            .map_err(error)
        })
    }
    fn compare_and_swap(
        &self,
        expected_revision: i64,
        candidate: PersistedSigningKeyset,
    ) -> SigningKeyRepositoryFuture<'_, SigningKeysetCompareAndSwapResult> {
        Box::pin(async move {
            anyhow::ensure!(
                expected_revision > 0
                    && expected_revision.checked_add(1) == Some(candidate.revision),
                "signing-key update must advance exactly one revision"
            );
            self.run(move |db| {
                let tx = db.transaction();
                let k = key(KEYSET, db.tenant_id, &[]);
                let old: Keyset = read_tx(&tx, &k, true)?
                    .ok_or_else(|| corrupt("tenant signing keyset no longer exists"))?;
                if old.revision != expected_revision {
                    return Ok(SigningKeysetCompareAndSwapResult::Conflict(old.into()));
                }
                put(&tx, &k, &KeysetWrite::from(&candidate))?;
                tx.commit().map_err(map_error)?;
                Ok(SigningKeysetCompareAndSwapResult::Applied(candidate))
            })
            .await
            .map_err(error)
        })
    }
}
