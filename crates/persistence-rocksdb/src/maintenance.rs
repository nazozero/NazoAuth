//! Expiry-ordered scans bound work by candidates, including stale index entries.

use nazo_persistence::{
    CleanupBatchResult, CleanupScope, SecurityStateMaintenanceFuture, SecurityStateMaintenancePort,
};

use crate::{
    RocksDb,
    db::{EXPIRY, HISTORY_EXPIRY, expiration, map_error},
    users::corrupt,
};

const BATCH: usize = 512;

fn count(result: &mut CleanupBatchResult, table: u8) {
    match table {
        0x47 => result.remembered_mfa_devices += 1,
        0x50 => {
            result.refresh_tokens += 1;
            result.refresh_contracts += 1;
        }
        0x53 => result.spent_refresh_proofs += 1,
        0x57 => result.issuances += 1,
        0x59 => result.revocations += 1,
        0x69 | 0x6b => result.identity_approvals += 1,
        0x85 => result.authorization_decisions += 1,
        0x87 => result.device_authorization_decisions += 1,
        0xa0 => result.logout_deliveries += 1,
        0xb2 => result.scim_security_events += 1,
        0xd0 => result.credential_offers += 1,
        0xd3 => result.credential_access_grants += 1,
        0xd5 => result.credential_nonces += 1,
        0xd6 => result.deferred_credentials += 1,
        0xd7 => result.credential_responses += 1,
        0xd8 => result.credential_notifications += 1,
        0xde => result.presentations += 1,
        _ => {} // Secondary entries have independent, equally bounded expiry.
    }
}

impl SecurityStateMaintenancePort for RocksDb {
    fn cleanup_batch(
        &self,
        scope: CleanupScope,
    ) -> SecurityStateMaintenanceFuture<'_, CleanupBatchResult> {
        Box::pin(async move {
            let mut result = self
                .run(move |store| {
                    let now = jiff::Timestamp::now().as_microsecond();
                    let mut result = CleanupBatchResult::default();
                    let indexes: &[u8] = if scope == CleanupScope::IncludingHistory {
                        &[EXPIRY, HISTORY_EXPIRY]
                    } else {
                        &[EXPIRY]
                    };
                    for &index in indexes {
                        let mut iterator = store.db.raw_iterator();
                        iterator.seek([index]);
                        let mut candidates = Vec::with_capacity(BATCH);
                        while iterator.valid()
                            && iterator
                                .key()
                                .is_some_and(|key| key.first() == Some(&index))
                        {
                            let key = iterator.key().expect("valid iterator");
                            let encoded: [u8; 8] = key
                                .get(1..9)
                                .and_then(|bytes| bytes.try_into().ok())
                                .ok_or_else(|| corrupt("invalid expiry index"))?;
                            let expires = (u64::from_be_bytes(encoded) ^ (1 << 63)) as i64;
                            // Index precision is microseconds; leave the current
                            // bucket until every nanosecond deadline has elapsed.
                            if expires >= now {
                                break;
                            }
                            if candidates.len() == BATCH {
                                result.saturated = true;
                                break;
                            }
                            candidates.push((key.to_vec(), expires));
                            iterator.next();
                        }
                        iterator.status().map_err(map_error)?;
                        drop(iterator);
                        if candidates.is_empty() {
                            continue;
                        }
                        let tx = store.transaction();
                        for (index_key, expires) in candidates {
                            let record_key = index_key
                                .get(9..)
                                .filter(|key| !key.is_empty())
                                .ok_or_else(|| corrupt("invalid expiry record key"))?;
                            if let Some(raw) = tx
                                .get_pinned_for_update(record_key, true)
                                .map_err(map_error)?
                            {
                                // A concurrent renewal may have replaced this candidate.
                                if expiration(&raw)? == expires {
                                    match record_key[0] {
                                        crate::tokens::FAMILY => {
                                            crate::tokens::cleanup_family(&tx, record_key, &raw)?
                                        }
                                        0xa0 => crate::logout::cleanup(&tx, &raw)?,
                                        _ => {}
                                    }
                                    tx.delete(record_key).map_err(map_error)?;
                                    count(&mut result, record_key[0]);
                                }
                            }
                            tx.delete(index_key).map_err(map_error)?;
                        }
                        tx.commit().map_err(map_error)?;
                    }
                    Ok(result)
                })
                .await?;
            if scope == CleanupScope::IncludingHistory {
                result.totp_rewrapped = self.rewrap_totp_batch().await?;
                result.saturated |= result.totp_rewrapped == 256;
            }
            Ok(result)
        })
    }
}

#[cfg(test)]
#[path = "../tests/unit/maintenance.rs"]
mod tests;
