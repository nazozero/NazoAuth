use jiff::Timestamp;
use kevy_store::Store;
use nazo_auth::{
    CibaAtomicResult, CibaPingClaimBatch, CibaPingDelivery, CibaPingFinishOutcome,
    CibaPingFinishResult, CibaPingNotificationStatus, CibaRequestState, CibaStateFuture,
    CibaStatePortError, CibaStateStorePort, CibaStateVersion, CibaStoredRequest,
};
use nazo_oauth_server::ports::transient_state::{
    CibaPingDeliveryPort, TransientStateError, TransientStateFuture,
};
use std::borrow::Cow;

use crate::{
    Error, TenantState,
    storage::{decode, encode, set_until},
};

fn port_error(error: Error) -> CibaStatePortError {
    match error {
        Error::Unavailable => CibaStatePortError::Unavailable,
        Error::CorruptData => CibaStatePortError::CorruptData,
        Error::Unexpected => CibaStatePortError::Unexpected,
    }
}

fn delivery_error(error: Error) -> TransientStateError {
    match error {
        Error::Unavailable => TransientStateError::Unavailable,
        Error::CorruptData => TransientStateError::CorruptData,
        Error::Unexpected => TransientStateError::Unexpected,
    }
}

fn deadline_ms(deadline: i64) -> Result<u64, Error> {
    u64::try_from(deadline)
        .ok()
        .and_then(|value| value.checked_mul(1_000))
        .ok_or(Error::CorruptData)
}

fn schedule(
    store: &mut Store,
    queue: &[u8],
    hash: &[u8],
    state: &CibaRequestState,
) -> Result<(), Error> {
    let next = state
        .ping_notification
        .as_ref()
        .filter(|notification| notification.status == CibaPingNotificationStatus::Pending)
        .and_then(|notification| notification.next_attempt_at);
    match next {
        Some(at) => {
            store.zadd(queue, &[(at as f64, hash)])?;
        }
        None => {
            store.zrem(queue, &[hash])?;
        }
    }
    Ok(())
}

impl TenantState {
    fn ciba_key(&self, hash: &[u8]) -> Vec<u8> {
        self.key("ciba", &[hash])
    }

    fn ciba_replace(
        &self,
        auth_req_id: &str,
        version: &CibaStateVersion,
        replacement: Option<&CibaRequestState>,
        authorization_deadline: Option<i64>,
    ) -> Result<CibaAtomicResult, Error> {
        if replacement
            .is_some_and(|state| state.retention_expires_at != version.retention_expires_at())
        {
            return Err(Error::CorruptData);
        }
        let raw = replacement.map(encode).transpose()?;
        let retention = deadline_ms(version.retention_expires_at())?;
        let hash = blake3::hash(auth_req_id.as_bytes()).to_hex();
        let key = self.ciba_key(hash.as_bytes());
        let queue = self.key("ciba_ping", &[]);
        self.volatile.with_key(&key, |store| {
            let now = Timestamp::now().as_second();
            if authorization_deadline.is_some_and(|deadline| now >= deadline) {
                return Ok(CibaAtomicResult::DeadlineElapsed);
            }
            let matches =
                store.get(&key)?.as_deref() == Some(version.comparison_token().as_bytes());
            if now >= version.retention_expires_at() {
                if matches {
                    store.zrem(&queue, &[hash.as_bytes()])?;
                    store.del(&[&key]);
                }
                return Ok(CibaAtomicResult::DeadlineElapsed);
            }
            if !matches {
                return Ok(CibaAtomicResult::Conflict);
            }
            match (replacement, raw) {
                (Some(state), Some(raw)) => {
                    schedule(store, &queue, hash.as_bytes(), state)?;
                    set_until(store, &key, raw, retention);
                }
                _ => {
                    store.zrem(&queue, &[hash.as_bytes()])?;
                    store.del(&[&key]);
                }
            }
            Ok(CibaAtomicResult::Applied)
        })
    }

    fn claim_ciba_ping(
        &self,
        now: i64,
        lock_until: i64,
        limit: usize,
    ) -> Result<CibaPingClaimBatch, Error> {
        let queue = self.key("ciba_ping", &[]);
        self.volatile.with_key(&queue, |store| {
            let mut batch = CibaPingClaimBatch {
                scanned: 0,
                deliveries: Vec::new(),
            };
            if limit == 0 {
                return Ok(batch);
            }
            // Rank-bounded lookup avoids materializing the whole due set.
            let members = store.zrange(&queue, 0, i64::try_from(limit - 1).unwrap_or(i64::MAX))?;
            for (hash, _) in members
                .into_iter()
                .take_while(|(_, due)| *due <= now as f64)
            {
                batch.scanned += 1;
                let key = self.ciba_key(&hash);
                let Some(raw) = store.get(&key)? else {
                    store.zrem(&queue, &[&hash])?;
                    continue;
                };
                let mut state: CibaRequestState = decode(&raw)?;
                let expires_at = state.expires_at;
                let retention = deadline_ms(state.retention_expires_at)?;
                let Some(notification) = state.ping_notification.as_mut() else {
                    store.zrem(&queue, &[&hash])?;
                    continue;
                };
                if expires_at <= now {
                    notification.status = CibaPingNotificationStatus::Failed;
                    notification.next_attempt_at = None;
                    notification.client_notification_token = None;
                    let raw = encode(&state)?;
                    store.zrem(&queue, &[&hash])?;
                    set_until(store, &key, raw, retention);
                    continue;
                }
                if notification.status != CibaPingNotificationStatus::Pending {
                    store.zrem(&queue, &[&hash])?;
                    continue;
                }
                if let Some(next) = notification.next_attempt_at
                    && next > now
                {
                    store.zadd(&queue, &[(next as f64, &hash)])?;
                    continue;
                }
                let (Some(auth_req_id), Some(token)) = (
                    &notification.auth_req_id,
                    &notification.client_notification_token,
                ) else {
                    return Err(Error::CorruptData);
                };
                notification.attempts = notification
                    .attempts
                    .checked_add(1)
                    .ok_or(Error::CorruptData)?;
                notification.next_attempt_at = Some(lock_until);
                let delivery = CibaPingDelivery {
                    auth_req_id_hash: String::from_utf8(hash).map_err(|_| Error::CorruptData)?,
                    auth_req_id: auth_req_id.clone(),
                    endpoint: notification.endpoint.clone(),
                    client_notification_token: token.clone(),
                    attempts: notification.attempts,
                    expires_at,
                };
                let raw = encode(&state)?;
                store.zadd(
                    &queue,
                    &[(lock_until as f64, delivery.auth_req_id_hash.as_bytes())],
                )?;
                set_until(store, &key, raw, retention);
                batch.deliveries.push(delivery);
            }
            Ok(batch)
        })
    }

    fn finish_ciba_ping(
        &self,
        delivery: &CibaPingDelivery,
        outcome: CibaPingFinishOutcome,
    ) -> Result<CibaPingFinishResult, Error> {
        let hash = delivery.auth_req_id_hash.as_bytes();
        let key = self.ciba_key(hash);
        let queue = self.key("ciba_ping", &[]);
        self.volatile.with_key(&key, |store| {
            let Some(raw) = store.get(&key)? else {
                store.zrem(&queue, &[hash])?;
                return Ok(CibaPingFinishResult::Missing);
            };
            let mut state: CibaRequestState = decode(&raw)?;
            let retention = deadline_ms(state.retention_expires_at)?;
            let notification = state.ping_notification.as_mut().ok_or(Error::CorruptData)?;
            if notification.status != CibaPingNotificationStatus::Pending
                || notification.attempts != delivery.attempts
            {
                return Ok(CibaPingFinishResult::Conflict);
            }
            match outcome {
                CibaPingFinishOutcome::RetryAt(at) => notification.next_attempt_at = Some(at),
                CibaPingFinishOutcome::Delivered | CibaPingFinishOutcome::Failed => {
                    notification.status = if outcome == CibaPingFinishOutcome::Delivered {
                        CibaPingNotificationStatus::Delivered
                    } else {
                        CibaPingNotificationStatus::Failed
                    };
                    notification.next_attempt_at = None;
                    notification.client_notification_token = None;
                }
            }
            let raw = encode(&state)?;
            schedule(store, &queue, hash, &state)?;
            set_until(store, &key, raw, retention);
            Ok(CibaPingFinishResult::Applied)
        })
    }
}

impl CibaStateStorePort for TenantState {
    type Version = CibaStateVersion;

    fn load<'a>(
        &'a self,
        auth_req_id: &'a str,
    ) -> CibaStateFuture<'a, Option<CibaStoredRequest<Self::Version>>> {
        Box::pin(async move {
            let hash = blake3::hash(auth_req_id.as_bytes()).to_hex();
            let key = self.ciba_key(hash.as_bytes());
            self.volatile
                .with_key(&key, |store| {
                    let Some(raw) = store.get(&key)? else {
                        return Ok(None);
                    };
                    let state: CibaRequestState = decode(&raw)?;
                    if Timestamp::now().as_second() >= state.retention_expires_at {
                        return Ok(None);
                    }
                    let token = std::str::from_utf8(&raw)
                        .map_err(|_| Error::CorruptData)?
                        .to_owned();
                    let version = CibaStateVersion::new(token, state.retention_expires_at);
                    Ok(Some(CibaStoredRequest::new(state, version)))
                })
                .map_err(port_error)
        })
    }

    fn create<'a>(
        &'a self,
        auth_req_id: &'a str,
        state: &'a CibaRequestState,
    ) -> CibaStateFuture<'a, CibaAtomicResult> {
        self.create_with_authorization_deadline(auth_req_id, state, None)
    }

    fn create_with_authorization_deadline<'a>(
        &'a self,
        auth_req_id: &'a str,
        state: &'a CibaRequestState,
        authorization_deadline: Option<i64>,
    ) -> CibaStateFuture<'a, CibaAtomicResult> {
        Box::pin(async move {
            let mut state = Cow::Borrowed(state);
            if state.ping_notification.is_some() {
                state
                    .to_mut()
                    .ping_notification
                    .as_mut()
                    .unwrap()
                    .auth_req_id = Some(auth_req_id.to_owned());
            }
            let raw = encode(&state).map_err(port_error)?;
            let retention = deadline_ms(state.retention_expires_at).map_err(port_error)?;
            let hash = blake3::hash(auth_req_id.as_bytes()).to_hex();
            let key = self.ciba_key(hash.as_bytes());
            let queue = self.key("ciba_ping", &[]);
            self.volatile
                .with_key(&key, |store| {
                    let now = Timestamp::now().as_second();
                    if now >= state.retention_expires_at
                        || authorization_deadline.is_some_and(|deadline| now >= deadline)
                    {
                        return Ok(CibaAtomicResult::DeadlineElapsed);
                    }
                    if store.exists(&[&key]) != 0 {
                        return Ok(CibaAtomicResult::Conflict);
                    }
                    schedule(store, &queue, hash.as_bytes(), &state)?;
                    set_until(store, &key, raw, retention);
                    Ok(CibaAtomicResult::Applied)
                })
                .map_err(port_error)
        })
    }

    fn replace<'a>(
        &'a self,
        auth_req_id: &'a str,
        version: &'a Self::Version,
        state: &'a CibaRequestState,
    ) -> CibaStateFuture<'a, CibaAtomicResult> {
        self.replace_with_authorization_deadline(auth_req_id, version, state, None)
    }

    fn replace_with_authorization_deadline<'a>(
        &'a self,
        auth_req_id: &'a str,
        version: &'a Self::Version,
        state: &'a CibaRequestState,
        authorization_deadline: Option<i64>,
    ) -> CibaStateFuture<'a, CibaAtomicResult> {
        Box::pin(async move {
            self.ciba_replace(auth_req_id, version, Some(state), authorization_deadline)
                .map_err(port_error)
        })
    }

    fn delete<'a>(
        &'a self,
        auth_req_id: &'a str,
        version: &'a Self::Version,
    ) -> CibaStateFuture<'a, CibaAtomicResult> {
        self.delete_with_authorization_deadline(auth_req_id, version, None)
    }

    fn delete_with_authorization_deadline<'a>(
        &'a self,
        auth_req_id: &'a str,
        version: &'a Self::Version,
        authorization_deadline: Option<i64>,
    ) -> CibaStateFuture<'a, CibaAtomicResult> {
        Box::pin(async move {
            self.ciba_replace(auth_req_id, version, None, authorization_deadline)
                .map_err(port_error)
        })
    }
}

impl CibaPingDeliveryPort for TenantState {
    fn claim_due<'a>(
        &'a self,
        now: i64,
        lock_until: i64,
        limit: usize,
    ) -> TransientStateFuture<'a, CibaPingClaimBatch> {
        Box::pin(async move {
            self.claim_ciba_ping(now, lock_until, limit)
                .map_err(delivery_error)
        })
    }

    fn finish<'a>(
        &'a self,
        delivery: &'a CibaPingDelivery,
        outcome: CibaPingFinishOutcome,
    ) -> TransientStateFuture<'a, CibaPingFinishResult> {
        Box::pin(async move {
            self.finish_ciba_ping(delivery, outcome)
                .map_err(delivery_error)
        })
    }
}

#[cfg(test)]
#[path = "../tests/unit/ciba.rs"]
mod tests;
