//! Durable logout delivery with an ordered due index and attempt fencing.
use futures_util::future::BoxFuture;
use nazo_auth::{
    BackchannelLogoutDelivery, BackchannelLogoutOutboxPort, IdempotentBackchannelLogoutDelivery,
    LogoutFuture,
};
use nazo_identity::ports::RepositoryError;
use nazo_persistence::BackchannelLogoutDeliveryStore;
use rocksdb::{Transaction, TransactionDB};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    RocksDb,
    db::{decode, key, map_error, put, put_expiring, read_tx},
};

const DELIVERY: u8 = 0xa0;
const DUE: u8 = 0xa1;
const IDEMPOTENT: u8 = 0xa2;

#[derive(Serialize, Deserialize)]
struct Delivery {
    id: Uuid,
    tenant: Uuid,
    client: Uuid,
    operation: String,
    uri: String,
    token: String,
    attempts: i32,
    expires: jiff::Timestamp,
    due: Option<jiff::Timestamp>,
    lease: Option<jiff::Timestamp>,
    pending: bool,
    last_error: Option<String>,
}
fn idempotent_key(tenant: Uuid, operation: &str, client: Uuid) -> Vec<u8> {
    let mut bytes = [0; 48];
    bytes[..32].copy_from_slice(blake3::hash(operation.as_bytes()).as_bytes());
    bytes[32..].copy_from_slice(client.as_bytes());
    key(IDEMPOTENT, tenant, &bytes)
}
fn delivery_key(id: Uuid) -> Vec<u8> {
    key(DELIVERY, Uuid::nil(), id.as_bytes())
}
fn due_key(due: jiff::Timestamp, id: Uuid) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(25);
    bytes.push(DUE);
    bytes.extend_from_slice(&((due.as_microsecond() as u64) ^ (1 << 63)).to_be_bytes());
    bytes.extend_from_slice(id.as_bytes());
    bytes
}
fn store_delivery(
    tx: &Transaction<'_, TransactionDB>,
    row: &Delivery,
    old_due: Option<jiff::Timestamp>,
) -> Result<(), RepositoryError> {
    if let Some(due) = old_due {
        tx.delete(due_key(due, row.id)).map_err(map_error)?;
    }
    if let Some(due) = row.due {
        put(tx, &due_key(due, row.id), &row.id)?;
    }
    put_expiring(tx, &delivery_key(row.id), row, row.expires)
}
pub(crate) fn cleanup(
    tx: &Transaction<'_, TransactionDB>,
    raw: &[u8],
) -> Result<(), RepositoryError> {
    let row: Delivery = decode(raw)?;
    if let Some(due) = row.due {
        tx.delete(due_key(due, row.id)).map_err(map_error)?;
    }
    tx.delete(idempotent_key(row.tenant, &row.operation, row.client))
        .map_err(map_error)
}

impl BackchannelLogoutOutboxPort for RocksDb {
    fn enqueue_idempotent_batch<'a>(
        &'a self,
        deliveries: &'a [IdempotentBackchannelLogoutDelivery],
    ) -> LogoutFuture<'a, ()> {
        let deliveries = deliveries.to_vec();
        Box::pin(async move {
            if deliveries.is_empty() {
                return Ok(());
            }
            self.run(move |store| {
                let tx = store.transaction();
                // A deterministic lock order lets independent logout batches overlap.
                let mut items: Vec<_> = deliveries
                    .into_iter()
                    .map(|delivery| {
                        (
                            idempotent_key(
                                delivery.tenant_id,
                                &delivery.operation_key,
                                delivery.client_id,
                            ),
                            delivery,
                        )
                    })
                    .collect();
                items.sort_unstable_by(|left, right| left.0.cmp(&right.0));
                for (lookup, delivery) in items {
                    if read_tx::<Uuid>(&tx, &lookup, true)?.is_some() {
                        continue;
                    }
                    let row = Delivery {
                        id: Uuid::now_v7(),
                        tenant: delivery.tenant_id,
                        client: delivery.client_id,
                        operation: delivery.operation_key,
                        uri: delivery.logout_uri,
                        token: delivery.logout_token,
                        attempts: 0,
                        expires: delivery.expires_at,
                        due: Some(jiff::Timestamp::now()),
                        lease: None,
                        pending: true,
                        last_error: None,
                    };
                    put(&tx, &lookup, &row.id)?;
                    store_delivery(&tx, &row, None)?;
                }
                tx.commit().map_err(map_error)
            })
            .await
            .map_err(|_| nazo_auth::LogoutDependencyError::Unavailable)
        })
    }
}
impl BackchannelLogoutDeliveryStore for RocksDb {
    fn claim_due(
        &self,
        limit: i64,
        lock_timeout_seconds: i32,
    ) -> BoxFuture<'_, Result<Vec<BackchannelLogoutDelivery>, RepositoryError>> {
        Box::pin(self.run(move |store| {
            if !(1..=100).contains(&limit) || !(1..=600).contains(&lock_timeout_seconds) {
                return Err(RepositoryError::Unexpected(
                    "invalid logout claim bounds".into(),
                ));
            }
            let now = jiff::Timestamp::now();
            let end = due_key(now, Uuid::max());
            let mut iterator = store.db.raw_iterator();
            iterator.seek([DUE]);
            let mut candidates = Vec::with_capacity(limit as usize);
            while iterator.valid()
                && iterator
                    .key()
                    .is_some_and(|key| key.first() == Some(&DUE) && key <= end.as_slice())
                && candidates.len() < limit as usize
            {
                candidates.push(decode::<Uuid>(iterator.value().expect("valid iterator"))?);
                iterator.next();
            }
            iterator.status().map_err(map_error)?;
            drop(iterator);
            if candidates.is_empty() {
                return Ok(Vec::new());
            }
            let tx = store.transaction();
            let mut claimed = Vec::with_capacity(candidates.len());
            for id in candidates {
                let Some(mut row) = read_tx::<Delivery>(&tx, &delivery_key(id), true)? else {
                    continue;
                };
                if !row.pending || row.due.is_none_or(|due| due > now) {
                    continue;
                }
                let old_due = row.due;
                if row.expires <= now {
                    row.pending = false;
                    row.token.clear();
                    row.due = None;
                } else {
                    row.attempts = row.attempts.checked_add(1).ok_or_else(|| {
                        RepositoryError::Consistency("logout attempts exhausted".into())
                    })?;
                    let lease = now
                        .checked_add(std::time::Duration::from_secs(lock_timeout_seconds as u64))
                        .map_err(|_| RepositoryError::Unavailable)?;
                    row.lease = Some(lease);
                    row.due = Some(lease);
                    claimed.push(BackchannelLogoutDelivery {
                        id,
                        logout_uri: row.uri.clone(),
                        logout_token: row.token.clone(),
                        attempts: row.attempts,
                        expires_at: row.expires,
                    });
                }
                store_delivery(&tx, &row, old_due)?;
            }
            tx.commit().map_err(map_error)?;
            Ok(claimed)
        }))
    }
    fn complete(
        &self,
        id: Uuid,
        expected_attempts: i32,
    ) -> BoxFuture<'_, Result<(), RepositoryError>> {
        Box::pin(self.run(move |store| {
            let tx = store.transaction();
            let Some(mut row) = read_tx::<Delivery>(&tx, &delivery_key(id), true)?.filter(|row| {
                row.pending
                    && row.attempts == expected_attempts
                    && row
                        .lease
                        .is_some_and(|lease| lease > jiff::Timestamp::now())
            }) else {
                return Ok(());
            };
            let old_due = row.due;
            row.pending = false;
            row.due = None;
            row.lease = None;
            row.token.clear();
            store_delivery(&tx, &row, old_due)?;
            tx.commit().map_err(map_error)
        }))
    }
    fn fail<'a>(
        &'a self,
        id: Uuid,
        expected_attempts: i32,
        next_attempt_at: Option<jiff::Timestamp>,
        last_error: &'a str,
    ) -> BoxFuture<'a, Result<(), RepositoryError>> {
        let message: String = last_error.chars().take(512).collect();
        Box::pin(self.run(move |store| {
            let tx = store.transaction();
            let Some(mut row) = read_tx::<Delivery>(&tx, &delivery_key(id), true)?.filter(|row| {
                row.pending
                    && row.attempts == expected_attempts
                    && row
                        .lease
                        .is_some_and(|lease| lease > jiff::Timestamp::now())
            }) else {
                return Ok(());
            };
            let old_due = row.due;
            row.pending = next_attempt_at.is_some();
            row.due = next_attempt_at;
            row.lease = None;
            row.last_error = Some(message);
            if !row.pending {
                row.token.clear();
            }
            store_delivery(&tx, &row, old_due)?;
            tx.commit().map_err(map_error)
        }))
    }
}

#[cfg(test)]
#[path = "../tests/unit/logout.rs"]
mod tests;
