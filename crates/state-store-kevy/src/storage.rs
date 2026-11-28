use std::{
    fs::File,
    path::Path,
    sync::{Arc, Mutex},
    time::Duration,
};

use kevy_embedded::{AppendFsync, Config, Store};
use kevy_store::SetCondition;
use nazo_identity::{TenantDirectorySnapshot, TenantId};
use serde::{Serialize, de::DeserializeOwned};

use crate::{Error, replay::ReplayWorker};

/// One process owns the volatile workflows and the durable replay directory.
#[derive(Clone)]
pub struct KevyBackend {
    volatile: Store,
    replay: Arc<ReplayWorker>,
    pub(crate) directory: Arc<Mutex<Option<Arc<TenantDirectorySnapshot>>>>,
}

pub(crate) struct ReplayState {
    pub(crate) store: Store,
    pub(crate) failed: bool,
    pub(crate) directory: File,
    pub(crate) aof: File,
    pub(crate) next_rewrite_bytes: u64,
}

pub(crate) const REWRITE_MIN_BYTES: u64 = 64 * 1024 * 1024;
pub(crate) const REPLAY_BINDING: &[u8] = b"nazo-kevy:deployment:v1";

/// Tenant-bound semantic ports. The key prefix is applied by the adapter.
#[derive(Clone)]
pub struct TenantState {
    pub(crate) volatile: Store,
    pub(crate) replay: Arc<ReplayWorker>,
    pub(crate) tenant_id: TenantId,
}

impl KevyBackend {
    /// Opens a single-process deployment, retaining proof-consumption markers.
    /// Pending workflows start empty. Call this before admitting requests.
    pub fn open(
        replay_directory: impl AsRef<Path>,
        deployment_identity: &str,
    ) -> Result<Self, Error> {
        let path = std::path::absolute(replay_directory).map_err(|_| Error::Unavailable)?;
        let existing_ancestor = path
            .ancestors()
            .skip(1)
            .find(|ancestor| ancestor.exists())
            .unwrap_or(&path);
        if deployment_identity.is_empty() {
            return Err(Error::Unexpected);
        }
        std::fs::create_dir_all(&path).map_err(|_| Error::Unavailable)?;
        let directory = File::open(&path).map_err(|_| Error::Unavailable)?;
        // Own the directory before inspecting it. Kevy's own lock is acquired
        // inside open, after this adapter must have ruled out lossy repair.
        directory.try_lock().map_err(|_| Error::Unavailable)?;
        // Kevy repairs a damaged tail while opening it. Its quarantine must
        // continue to block admission on subsequent opens, after the repair.
        // This owner disables staging. Reject another mode's ring before
        // Kevy can silently discard and remove it while settling that ring.
        if std::fs::read_dir(&path)
            .map_err(|_| Error::Unavailable)?
            .any(|entry| {
                entry.map_or(true, |entry| {
                    let name = entry.file_name();
                    name == "aof-0.aof.stage"
                        || name.to_string_lossy().contains(".corrupt-quarantine.")
                })
            })
        {
            return Err(Error::CorruptData);
        }
        // This native streaming validation does not modify the AOF. Reject
        // damage before open can truncate it and lose its quarantine on crash.
        let checked = kevy_persist::replay_aof_in_place(
            &path.join("aof-0.aof"),
            kevy_persist::ReplayMode::Strict,
            kevy_persist::ReplaySummary::Quiet,
            |_| {},
        )
        .map_err(|_| Error::Unavailable)?;
        if checked.corrupt || checked.dropped_bytes != 0 || checked.zero_tail != 0 {
            return Err(Error::CorruptData);
        }
        let replay = Store::open(
            Config::default()
                .with_persist(&path)
                .with_appendfsync(AppendFsync::No)
                .with_stage_ring(0)
                .with_mapped_aof(false)
                .with_auto_aof_rewrite_disabled()
                .with_ttl_reaper_manual(),
        )
        .map_err(|_| Error::Unavailable)?;
        let report = replay.open_report();
        if report.corrupt
            || report.dropped_bytes != 0
            || report.resynced_bytes != 0
            || report.stage_discarded != 0
            || !report.quarantine_paths.is_empty()
        {
            directory.sync_all().map_err(|_| Error::Unavailable)?;
            return Err(Error::CorruptData);
        }
        let existing = replay
            .get_with(REPLAY_BINDING, |value| {
                value.map(|value| value == deployment_identity.as_bytes())
            })
            .map_err(|_| Error::Unavailable)?;
        match existing {
            Some(true) => {}
            Some(false) => return Err(Error::Unexpected),
            None => {
                replay
                    .set(REPLAY_BINDING, deployment_identity.as_bytes())
                    .map_err(|_| Error::Unavailable)?;
            }
        }
        replay.fsync_aof().map_err(|_| Error::Unavailable)?;
        // Persist the AOF's name and every newly created ancestor's entry.
        directory.sync_all().map_err(|_| Error::Unavailable)?;
        for ancestor in path.ancestors().skip(1) {
            File::open(ancestor)
                .and_then(|directory| directory.sync_all())
                .map_err(|_| Error::Unavailable)?;
            if ancestor == existing_ancestor {
                break;
            }
        }
        let aof = File::open(path.join("aof-0.aof")).map_err(|_| Error::Unavailable)?;
        Ok(Self {
            volatile: Store::open(Config::default()).map_err(|_| Error::Unavailable)?,
            replay: Arc::new(ReplayWorker::start(ReplayState {
                store: replay,
                failed: false,
                directory,
                aof,
                next_rewrite_bytes: REWRITE_MIN_BYTES,
            })?),
            directory: Arc::new(Mutex::new(None)),
        })
    }

    #[must_use]
    pub fn for_tenant(&self, tenant_id: TenantId) -> TenantState {
        TenantState {
            volatile: self.volatile.clone(),
            replay: self.replay.clone(),
            tenant_id,
        }
    }
}

impl TenantState {
    pub(crate) fn key(&self, namespace: &str, parts: &[&[u8]]) -> Vec<u8> {
        let capacity = 16 + namespace.len() + 1 + parts.iter().map(|p| 8 + p.len()).sum::<usize>();
        let mut key = Vec::with_capacity(capacity);
        key.extend_from_slice(self.tenant_id.as_uuid().as_bytes());
        key.extend_from_slice(namespace.as_bytes());
        key.push(0);
        for part in parts {
            key.extend_from_slice(&(part.len() as u64).to_be_bytes());
            key.extend_from_slice(part);
        }
        key
    }

    pub(crate) fn read_json<T: DeserializeOwned>(&self, key: &[u8]) -> Result<Option<T>, Error> {
        self.volatile
            .get_with(key, |raw| raw.map(decode).transpose())
            .map_err(|_| Error::Unavailable)?
    }

    pub(crate) fn put_json<T: Serialize + ?Sized>(
        &self,
        key: &[u8],
        value: &T,
        ttl_seconds: u64,
    ) -> Result<(), Error> {
        let raw = encode(value)?;
        let duration = ttl(ttl_seconds)?;
        self.volatile.with(|store| {
            store.set(key, raw, Some(duration), SetCondition::Always);
        });
        Ok(())
    }

    pub(crate) fn take_json<T: DeserializeOwned>(&self, key: &[u8]) -> Result<Option<T>, Error> {
        self.volatile.with(|store| {
            let value = store.get(key)?.as_deref().map(decode).transpose();
            store.del(&[key]);
            value
        })
    }

    pub(crate) fn compare_delete(&self, key: &[u8], expected: &[u8]) -> Result<bool, Error> {
        self.volatile.with(|store| {
            if store.get(key)?.as_deref() != Some(expected) {
                return Ok(false);
            }
            Ok(store.del(&[key]) == 1)
        })
    }

    pub(crate) fn delete(&self, key: &[u8]) {
        self.volatile.with(|store| {
            store.del(&[key]);
        });
    }
}

pub(crate) fn encode<T: Serialize + ?Sized>(value: &T) -> Result<Vec<u8>, Error> {
    serde_json::to_vec(value).map_err(|_| Error::Unexpected)
}

pub(crate) fn decode<T: DeserializeOwned>(value: &[u8]) -> Result<T, Error> {
    serde_json::from_slice(value).map_err(|_| Error::CorruptData)
}

pub(crate) fn ttl(seconds: u64) -> Result<Duration, Error> {
    if seconds == 0 {
        return Err(Error::Unexpected);
    }
    Ok(Duration::from_secs(seconds))
}

pub(crate) fn now_ms() -> u64 {
    jiff::Timestamp::now().as_millisecond() as u64
}

pub(crate) fn deadline(ttl_seconds: u64) -> Result<u64, Error> {
    ttl(ttl_seconds)?;
    now_ms()
        .checked_add(ttl_seconds.checked_mul(1_000).ok_or(Error::Unexpected)?)
        .ok_or(Error::Unexpected)
}

pub(crate) fn set_until(
    store: &mut kevy_store::Store,
    key: &[u8],
    raw: Vec<u8>,
    expires_at_ms: u64,
) {
    store.set(
        key,
        raw,
        Some(Duration::from_millis(
            expires_at_ms.saturating_sub(now_ms()),
        )),
        SetCondition::Always,
    );
}

#[cfg(test)]
#[path = "../tests/unit/storage.rs"]
mod tests;
