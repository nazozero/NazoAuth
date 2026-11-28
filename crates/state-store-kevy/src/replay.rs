use std::{sync::Arc, thread::JoinHandle};

use nazo_auth::{DpopStateFuture, DpopStateStoreError, DpopStateStorePort};
use nazo_oauth_server::ports::fapi_replay::{
    FapiHttpSignatureReplayConsumption, FapiHttpSignatureReplayStore,
    FapiHttpSignatureReplayStoreError,
};
use nazo_resource_server::{
    DpopNonceStorage, DpopNonceValidationResult, DpopReplayConsumption,
    DpopReplayConsumptionResult, DpopReplayKey, ProtectedResourceDependencyError,
    ResourceServerPortFuture,
};
use tokio::sync::{Mutex, mpsc, oneshot};

use crate::{
    Error, TenantState,
    storage::{REPLAY_BINDING, REWRITE_MIN_BYTES, ReplayState, now_ms},
    ttl,
};

const REPLAY_BATCH_LIMIT: usize = 256;

enum Deadline {
    Relative(u64),
    Absolute(i64),
}

struct ReplayRequest {
    key: Vec<u8>,
    deadline: Deadline,
    not_before: Option<i64>,
    reply: oneshot::Sender<Result<bool, Error>>,
}

pub(crate) struct ReplayWorker {
    pub(crate) state: Arc<Mutex<ReplayState>>,
    sender: Option<mpsc::Sender<ReplayRequest>>,
    thread: Option<JoinHandle<()>>,
}

impl ReplayWorker {
    pub(crate) fn start(state: ReplayState) -> Result<Self, Error> {
        let state = Arc::new(Mutex::new(state));
        let (sender, mut receiver) = mpsc::channel::<ReplayRequest>(REPLAY_BATCH_LIMIT);
        let worker_state = state.clone();
        let thread = std::thread::Builder::new()
            .name("nazo-kevy-replay".into())
            .spawn(move || {
                let mut batch = Vec::with_capacity(REPLAY_BATCH_LIMIT);
                let mut results = Vec::with_capacity(REPLAY_BATCH_LIMIT);
                while let Some(first) = receiver.blocking_recv() {
                    batch.push(first);
                    let mut state = worker_state.blocking_lock();
                    // Coalesce only work already waiting; no batching delay.
                    while batch.len() < REPLAY_BATCH_LIMIT {
                        match receiver.try_recv() {
                            Ok(request) => batch.push(request),
                            Err(_) => break,
                        }
                    }
                    let committed = state.commit_batch(&batch, &mut results);
                    drop(state);
                    for (index, request) in batch.drain(..).enumerate() {
                        let result = match committed {
                            Ok(()) => results[index],
                            Err(error) => Err(error),
                        };
                        let _ = request.reply.send(result);
                    }
                    results.clear();
                }
            })
            .map_err(|_| Error::Unavailable)?;
        Ok(Self {
            state,
            sender: Some(sender),
            thread: Some(thread),
        })
    }
}

impl Drop for ReplayWorker {
    fn drop(&mut self) {
        drop(self.sender.take());
        if let Some(thread) = self.thread.take() {
            // Release the directory only after the last queued write ends.
            let _ = thread.join();
        }
    }
}

impl ReplayState {
    fn reserve_marker(&self, request: &ReplayRequest) -> Result<bool, Error> {
        let now = now_ms();
        if request
            .not_before
            .is_some_and(|start| i128::from(start) * 1_000 > i128::from(now))
        {
            return Ok(false);
        }
        let expires_at = match request.deadline {
            Deadline::Relative(seconds) => now
                .checked_add(seconds.checked_mul(1_000).ok_or(Error::Unexpected)?)
                .ok_or(Error::Unexpected)?,
            Deadline::Absolute(seconds) => match u64::try_from(seconds)
                .ok()
                .and_then(|seconds| seconds.checked_mul(1_000))
            {
                Some(deadline) if deadline > now => deadline,
                _ => return Ok(false),
            },
        };
        let existing = self
            .store
            .get_with(&request.key, |value| {
                value
                    .map(|raw| {
                        let raw: [u8; 8] = raw.try_into().map_err(|_| Error::CorruptData)?;
                        Ok::<_, Error>(u64::from_be_bytes(raw) > now)
                    })
                    .transpose()
            })
            .map_err(|_| Error::Unavailable)??;
        if existing == Some(true) {
            return Ok(false);
        }
        self.store
            .set(&request.key, &expires_at.to_be_bytes())
            .map_err(|_| Error::Unavailable)?;
        Ok(true)
    }

    fn commit_batch(
        &mut self,
        requests: &[ReplayRequest],
        results: &mut Vec<Result<bool, Error>>,
    ) -> Result<(), Error> {
        if self.failed {
            return Err(Error::Unavailable);
        }
        // Leave the latch set on an unknown write outcome or an unwind. The
        // next request sees earlier reservations, but none is accepted yet.
        self.failed = true;
        let mut wrote = false;
        for request in requests {
            let result = self.reserve_marker(request);
            match result {
                Ok(true) => wrote = true,
                Err(error @ (Error::CorruptData | Error::Unavailable)) => return Err(error),
                _ => {}
            }
            results.push(result);
        }
        if wrote {
            // One native durability boundary covers all independent markers.
            // A failed append or sync can have changed memory; accept none.
            self.store.fsync_aof().map_err(|_| Error::Unavailable)?;
            self.compact_if_needed()?;
        }
        self.failed = false;
        Ok(())
    }

    fn compact_if_needed(&mut self) -> Result<(), Error> {
        if self.aof.metadata().map_err(|_| Error::Unavailable)?.len() < self.next_rewrite_bytes {
            return Ok(());
        }
        // The stored absolute deadline is the only expiry authority:
        // native TTL conversion can shorten it during AOF recovery.
        // Borrow values and copy only keys due for this compaction.
        let now = now_ms();
        self.store.with(|store| {
            let mut expired = Vec::new();
            let mut corrupt = false;
            store.snapshot_each(|key, _, _| {
                if key == REPLAY_BINDING {
                    return;
                }
                let deadline = store.get_shared_with(key, |raw| {
                    raw.and_then(|raw| raw.try_into().ok())
                        .map(u64::from_be_bytes)
                });
                match deadline {
                    Ok(Some(deadline)) if deadline <= now => expired.push(key.to_vec()),
                    Ok(Some(_)) => {}
                    _ => corrupt = true,
                }
            });
            if corrupt {
                return Err(Error::CorruptData);
            }
            store.del(&expired.iter().map(Vec::as_slice).collect::<Vec<_>>());
            Ok(())
        })?;
        // Own native rewrite so cutover errors cannot be discarded by the
        // upstream background worker. Every failure leaves admission latched.
        let stats = self
            .store
            .rewrite_aof()
            .map_err(|_| Error::Unavailable)?
            .ok_or(Error::Unavailable)?;
        self.next_rewrite_bytes = REWRITE_MIN_BYTES.max(stats.bytes.saturating_mul(2));
        // Rewrite replaces the inode. Keep the constant-time probe on the
        // live log without Store::info's full keyspace scan.
        self.aof = std::fs::File::open(
            self.store
                .config()
                .data_dir
                .as_ref()
                .ok_or(Error::Unavailable)?
                .join("aof-0.aof"),
        )
        .map_err(|_| Error::Unavailable)?;
        self.directory.sync_all().map_err(|_| Error::Unavailable)
    }
}

impl TenantState {
    pub(crate) async fn consume_replay(
        &self,
        purpose: &str,
        parts: &[&[u8]],
        ttl_seconds: u64,
    ) -> Result<bool, Error> {
        ttl(ttl_seconds)?;
        self.consume_marker(
            self.key(purpose, parts),
            Deadline::Relative(ttl_seconds),
            None,
        )
        .await
    }

    pub(crate) async fn consume_replay_until(
        &self,
        purpose: &str,
        parts: &[&[u8]],
        expires_at: i64,
        not_before: Option<i64>,
    ) -> Result<bool, Error> {
        self.consume_marker(
            self.key(purpose, parts),
            Deadline::Absolute(expires_at),
            not_before,
        )
        .await
    }

    async fn consume_marker(
        &self,
        key: Vec<u8>,
        deadline: Deadline,
        not_before: Option<i64>,
    ) -> Result<bool, Error> {
        let (reply, result) = oneshot::channel();
        self.replay
            .sender
            .as_ref()
            .ok_or(Error::Unavailable)?
            .send(ReplayRequest {
                key,
                deadline,
                not_before,
                reply,
            })
            .await
            .map_err(|_| Error::Unavailable)?;
        result.await.map_err(|_| Error::Unavailable)?
    }

    pub(crate) async fn replay_check(&self) -> Result<(), Error> {
        if self.replay.state.lock().await.failed
            || self
                .replay
                .sender
                .as_ref()
                .is_none_or(mpsc::Sender::is_closed)
        {
            Err(Error::Unavailable)
        } else {
            Ok(())
        }
    }

    pub(crate) fn issue_nonce(&self, nonce: &str, ttl_seconds: u64) -> Result<(), Error> {
        let duration = ttl(ttl_seconds)?;
        let key = self.key("dpop-nonce", &[nonce.as_bytes()]);
        self.volatile.with(|store| {
            store.set_slice(&key, b"1", Some(duration), kevy_store::SetCondition::Always);
        });
        Ok(())
    }

    pub(crate) fn nonce_valid(&self, nonce: &str) -> Result<bool, Error> {
        let key = self.key("dpop-nonce", &[nonce.as_bytes()]);
        self.volatile
            .get_with(&key, |raw| raw.is_some())
            .map_err(|_| Error::Unavailable)
    }
}

impl DpopStateStorePort for TenantState {
    fn consume_replay<'a>(
        &'a self,
        jkt: &'a str,
        jti: &'a str,
        ttl_seconds: u64,
    ) -> DpopStateFuture<'a, bool> {
        Box::pin(async move {
            self.consume_replay("dpop", &[jkt.as_bytes(), jti.as_bytes()], ttl_seconds)
                .await
                .map_err(|_| DpopStateStoreError)
        })
    }

    fn issue_nonce<'a>(&'a self, nonce: &'a str, ttl_seconds: u64) -> DpopStateFuture<'a, ()> {
        Box::pin(async move {
            self.issue_nonce(nonce, ttl_seconds)
                .map_err(|_| DpopStateStoreError)
        })
    }

    fn validate_nonce<'a>(&'a self, nonce: &'a str) -> DpopStateFuture<'a, bool> {
        Box::pin(async move { self.nonce_valid(nonce).map_err(|_| DpopStateStoreError) })
    }
}

impl DpopReplayConsumption for TenantState {
    fn consume<'a>(
        &'a self,
        key: DpopReplayKey<'a>,
    ) -> ResourceServerPortFuture<
        'a,
        Result<DpopReplayConsumptionResult, ProtectedResourceDependencyError>,
    > {
        Box::pin(async move {
            self.consume_replay_until(
                "dpop",
                &[key.jkt.as_bytes(), key.jti.as_bytes()],
                key.expires_at,
                None,
            )
            .await
            .map(|accepted| {
                if accepted {
                    DpopReplayConsumptionResult::Accepted
                } else {
                    DpopReplayConsumptionResult::Replay
                }
            })
            .map_err(|_| ProtectedResourceDependencyError::DpopReplayStoreUnavailable)
        })
    }
}

impl DpopNonceStorage for TenantState {
    fn issue_nonce<'a>(
        &'a self,
        nonce: &'a str,
        expires_at: i64,
    ) -> ResourceServerPortFuture<'a, Result<(), ProtectedResourceDependencyError>> {
        Box::pin(async move {
            let ttl_seconds = expires_at
                .saturating_sub(jiff::Timestamp::now().as_second())
                .max(1) as u64;
            self.issue_nonce(nonce, ttl_seconds)
                .map_err(|_| ProtectedResourceDependencyError::DpopNonceStoreUnavailable)
        })
    }

    fn validate_nonce<'a>(
        &'a self,
        nonce: &'a str,
    ) -> ResourceServerPortFuture<
        'a,
        Result<DpopNonceValidationResult, ProtectedResourceDependencyError>,
    > {
        Box::pin(async move {
            self.nonce_valid(nonce)
                .map(|valid| {
                    if valid {
                        DpopNonceValidationResult::Accepted
                    } else {
                        DpopNonceValidationResult::Unknown
                    }
                })
                .map_err(|_| ProtectedResourceDependencyError::DpopNonceStoreUnavailable)
        })
    }
}

impl FapiHttpSignatureReplayStore for TenantState {
    fn consume<'a>(
        &'a self,
        tenant_id: nazo_identity::TenantId,
        fingerprint: &'a [u8],
        ttl_seconds: i64,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<
                    Output = Result<
                        FapiHttpSignatureReplayConsumption,
                        FapiHttpSignatureReplayStoreError,
                    >,
                > + Send
                + 'a,
        >,
    > {
        Box::pin(async move {
            if tenant_id != self.tenant_id || fingerprint.len() != 32 {
                return Err(FapiHttpSignatureReplayStoreError);
            }
            let ttl_seconds = ttl_seconds
                .checked_add(5)
                .and_then(|value| u64::try_from(value).ok())
                .ok_or(FapiHttpSignatureReplayStoreError)?;
            self.consume_replay("http-signature", &[fingerprint], ttl_seconds)
                .await
                .map(|accepted| {
                    if accepted {
                        FapiHttpSignatureReplayConsumption::Accepted
                    } else {
                        FapiHttpSignatureReplayConsumption::Replay
                    }
                })
                .map_err(|_| FapiHttpSignatureReplayStoreError)
        })
    }
}

#[cfg(test)]
#[path = "../tests/unit/replay.rs"]
mod tests;
