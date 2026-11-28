//! Private key/record encoding shared by this adapter's repositories.

use nazo_identity::ports::RepositoryError;
use rocksdb::{SnapshotWithThreadMode, Transaction, TransactionDB};
use serde::{Serialize, de::DeserializeOwned};
use uuid::Uuid;

pub(crate) const SCHEMA_KEY: &[u8] = b"\0schema";
pub(crate) const EXPIRY: u8 = 1;
pub(crate) const HISTORY_EXPIRY: u8 = 2;
const NO_EXPIRY: i64 = i64::MAX;

pub(crate) fn map_error(error: rocksdb::Error) -> RepositoryError {
    match error.kind() {
        rocksdb::ErrorKind::Corruption | rocksdb::ErrorKind::InvalidArgument => {
            RepositoryError::Consistency("RocksDB persistence invariant failed".into())
        }
        _ => RepositoryError::Unavailable,
    }
}

pub(crate) fn key(table: u8, tenant: Uuid, id: &[u8]) -> Vec<u8> {
    let mut key = Vec::with_capacity(17 + id.len());
    key.push(table);
    key.extend_from_slice(tenant.as_bytes());
    key.extend_from_slice(id);
    key
}

pub(crate) fn encode<T: Serialize + ?Sized>(value: &T) -> Result<Vec<u8>, RepositoryError> {
    encode_with_expiry(value, NO_EXPIRY)
}

fn encode_with_expiry<T: Serialize + ?Sized>(
    value: &T,
    expires: i64,
) -> Result<Vec<u8>, RepositoryError> {
    let mut bytes = Vec::with_capacity(128);
    bytes.extend_from_slice(&expires.to_be_bytes());
    serde_json::to_writer(&mut bytes, value)
        .map_err(|_| RepositoryError::Consistency("RocksDB record cannot be encoded".into()))?;
    Ok(bytes)
}

pub(crate) fn decode<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, RepositoryError> {
    let payload = bytes
        .get(8..)
        .ok_or_else(|| RepositoryError::Consistency("truncated RocksDB record".into()))?;
    serde_json::from_slice(payload)
        .map_err(|_| RepositoryError::Consistency("invalid RocksDB record".into()))
}

pub(crate) fn expiration(bytes: &[u8]) -> Result<i64, RepositoryError> {
    let bytes: [u8; 8] = bytes
        .get(..8)
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| RepositoryError::Consistency("truncated RocksDB record".into()))?;
    Ok(i64::from_be_bytes(bytes))
}

pub(crate) fn read<T: DeserializeOwned>(
    db: &TransactionDB,
    key: &[u8],
) -> Result<Option<T>, RepositoryError> {
    db.get_pinned(key)
        .map_err(map_error)?
        .map(|value| decode(&value))
        .transpose()
}

pub(crate) fn read_snapshot<T: DeserializeOwned>(
    snapshot: &SnapshotWithThreadMode<'_, TransactionDB>,
    key: &[u8],
) -> Result<Option<T>, RepositoryError> {
    snapshot
        .get_pinned(key)
        .map_err(map_error)?
        .map(|value| decode(&value))
        .transpose()
}

pub(crate) fn read_tx<T: DeserializeOwned>(
    tx: &Transaction<'_, TransactionDB>,
    key: &[u8],
    exclusive: bool,
) -> Result<Option<T>, RepositoryError> {
    tx.get_pinned_for_update(key, exclusive)
        .map_err(map_error)?
        .map(|value| decode(&value))
        .transpose()
}

pub(crate) fn put<T: Serialize + ?Sized>(
    tx: &Transaction<'_, TransactionDB>,
    key: &[u8],
    value: &T,
) -> Result<(), RepositoryError> {
    tx.put(key, encode(value)?).map_err(map_error)
}

pub(crate) fn expiry_key(key: &[u8], expires: i64) -> Vec<u8> {
    let mut index = Vec::with_capacity(9 + key.len());
    index.push(
        if matches!(
            key.first(),
            Some(&crate::mfa::REMEMBERED)
                | Some(&crate::authorization::REQUEST)
                | Some(&crate::authorization::PAR)
        ) {
            HISTORY_EXPIRY
        } else {
            EXPIRY
        },
    );
    index.extend_from_slice(&((expires as u64) ^ (1 << 63)).to_be_bytes());
    index.extend_from_slice(key);
    index
}

pub(crate) fn put_expiring<T: Serialize + ?Sized>(
    tx: &Transaction<'_, TransactionDB>,
    key: &[u8],
    value: &T,
    expires: jiff::Timestamp,
) -> Result<(), RepositoryError> {
    let expires = expires.as_microsecond();
    let previous = tx
        .get_pinned_for_update(key, true)
        .map_err(map_error)?
        .map(|value| expiration(&value))
        .transpose()?;
    if let Some(previous) =
        previous.filter(|previous| *previous != NO_EXPIRY && *previous != expires)
    {
        tx.delete(expiry_key(key, previous)).map_err(map_error)?;
    }
    tx.put(key, encode_with_expiry(value, expires)?)
        .map_err(map_error)?;
    if previous != Some(expires) {
        tx.put(expiry_key(key, expires), []).map_err(map_error)?;
    }
    Ok(())
}

pub(crate) fn delete_expiring(
    tx: &Transaction<'_, TransactionDB>,
    key: &[u8],
    expires: jiff::Timestamp,
) -> Result<(), RepositoryError> {
    tx.delete(key).map_err(map_error)?;
    tx.delete(expiry_key(key, expires.as_microsecond()))
        .map_err(map_error)
}
