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

use crate::{
    Error, TenantState,
    storage::{REPLAY_BINDING, REWRITE_MIN_BYTES, now_ms},
    ttl,
};

enum Deadline {
    Relative(u64),
    Absolute(i64),
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
        let mut replay = self.replay.clone().lock_owned().await;
        tokio::task::spawn_blocking(move || {
            if replay.failed {
                return Err(Error::Unavailable);
            }
            let now = now_ms();
            if not_before.is_some_and(|start| i128::from(start) * 1_000 > i128::from(now)) {
                return Ok(false);
            }
            let expires_at = match deadline {
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
            let existing = replay.store.get_with(&key, |value| {
                value
                    .map(|raw| {
                        let raw: [u8; 8] = raw.try_into().map_err(|_| Error::CorruptData)?;
                        Ok::<_, Error>(u64::from_be_bytes(raw) > now)
                    })
                    .transpose()
            });
            match existing {
                Ok(Ok(Some(true))) => return Ok(false),
                Ok(Ok(_)) => {}
                Ok(Err(error)) => {
                    replay.failed = true;
                    return Err(error);
                }
                Err(_) => {
                    replay.failed = true;
                    return Err(Error::Unavailable);
                }
            }
            // Only a confirmed synchronous write grants consumption. The
            // mutex excludes later consumers until its outcome is known.
            // Leave the latch set on an I/O error or an unwinding write.
            replay.failed = true;
            if replay.store.set(&key, &expires_at.to_be_bytes()).is_err() {
                // A failed append can still have changed Kevy's memory.
                // No subsequent operation may interpret that state as known.
                return Err(Error::Unavailable);
            }
            // The background rewrite in Kevy 7 logs and discards cutover
            // errors. Own the native rewrite here so any error stays latched.
            if replay.aof.metadata().map_err(|_| Error::Unavailable)?.len()
                >= replay.next_rewrite_bytes
            {
                // The stored absolute deadline is the only expiry authority:
                // native TTL conversion can shorten it during AOF recovery.
                // Borrow values and copy only keys due for this compaction.
                replay.store.with(|store| {
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
                let stats = replay
                    .store
                    .rewrite_aof()
                    .map_err(|_| Error::Unavailable)?
                    .ok_or(Error::Unavailable)?;
                replay.next_rewrite_bytes = REWRITE_MIN_BYTES.max(stats.bytes.saturating_mul(2));
                // Rewrite replaces the inode. Keep the size probe on the
                // live log without Store::info's full keyspace scan.
                replay.aof = std::fs::File::open(
                    replay
                        .store
                        .config()
                        .data_dir
                        .as_ref()
                        .ok_or(Error::Unavailable)?
                        .join("aof-0.aof"),
                )
                .map_err(|_| Error::Unavailable)?;
                replay
                    .directory
                    .sync_all()
                    .map_err(|_| Error::Unavailable)?;
            }
            replay.failed = false;
            Ok(true)
        })
        .await
        .map_err(|_| Error::Unavailable)?
    }

    pub(crate) async fn replay_check(&self) -> Result<(), Error> {
        if self.replay.lock().await.failed {
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
