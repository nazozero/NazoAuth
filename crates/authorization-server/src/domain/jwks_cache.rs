//! Bounded JWKS storage and per-URI request ownership, independent of the executor.
use std::{
    collections::{HashMap, hash_map::RandomState},
    hash::BuildHasher,
    num::NonZeroUsize,
    sync::{Arc, RwLock, RwLockWriteGuard},
    time::Duration,
};

use futures_channel::oneshot;
use futures_util::{
    FutureExt,
    future::{BoxFuture, Shared},
};
use lru::LruCache;
use serde_json::Value;

type FetchResult = Result<Arc<Value>, String>;
pub(super) type Pending = Shared<BoxFuture<'static, FetchResult>>;

struct Entry {
    document: Arc<Value>,
    expires_at: Duration,
    refreshed: bool,
}

struct State {
    entries: LruCache<String, Entry>,
    pending: HashMap<String, Pending>,
}

pub(super) struct JwksCache {
    states: Box<[RwLock<State>]>,
    hasher: RandomState,
    ttl: Duration,
}

pub(super) enum Lookup<'a> {
    Ready(Arc<Value>),
    Wait(Pending),
    Fetch(FetchGuard<'a>),
}

impl JwksCache {
    pub(super) fn new(capacity: NonZeroUsize, ttl: Duration) -> Self {
        // Bound total storage, with LRU ordering within each shard. Small caches
        // keep one shard; the production capacity of 256 uses eight of 32.
        let count = (capacity.get() / 32).clamp(1, 8);
        Self {
            states: (0..count)
                .map(|index| {
                    let slots =
                        capacity.get() / count + usize::from(index < capacity.get() % count);
                    RwLock::new(State {
                        entries: LruCache::new(
                            NonZeroUsize::new(slots).expect("nonzero shard capacity"),
                        ),
                        pending: HashMap::new(),
                    })
                })
                .collect(),
            hasher: RandomState::new(),
            ttl,
        }
    }

    fn shard(&self, key: &str) -> &RwLock<State> {
        &self.states[self.hasher.hash_one(key) as usize % self.states.len()]
    }

    fn lock(&self, key: &str) -> RwLockWriteGuard<'_, State> {
        self.shard(key).write().expect("JWKS cache lock poisoned")
    }

    pub(super) fn get(&self, key: &str, now: Duration) -> Option<Arc<Value>> {
        let shard = self.shard(key);
        {
            let state = shard.read().expect("JWKS cache lock poisoned");
            // Reading the MRU entry cannot change LRU order. Concurrent callers
            // for the same hot URI therefore need only a shared lock.
            if let Some((latest, entry)) = state.entries.peek_mru()
                && latest == key
                && now < entry.expires_at
            {
                return Some(Arc::clone(&entry.document));
            }
        }
        // Recheck after reacquiring: another writer may have replaced or evicted
        // the entry since the shared lock was released.
        let mut state = shard.write().expect("JWKS cache lock poisoned");
        match state.entries.get(key) {
            Some(entry) if now < entry.expires_at => return Some(Arc::clone(&entry.document)),
            None => return None,
            Some(_) => {}
        }
        let expired = state.entries.pop(key);
        drop(state);
        drop(expired);
        None
    }

    // Recheck after the caller inspected the kid outside the lock. Registering a
    // fetch and checking for an existing one are one atomic state transition.
    pub(super) fn begin(
        &self,
        key: String,
        previous: Option<&Arc<Value>>,
        now: Duration,
    ) -> Lookup<'_> {
        let mut state = self.lock(&key);
        if let Some(pending) = state.pending.get(&key) {
            return Lookup::Wait(pending.clone());
        }
        let current = state
            .entries
            .get_mut(&key)
            .filter(|entry| now < entry.expires_at);
        let refreshed = if let Some(entry) = current {
            if previous.is_none_or(|previous| !Arc::ptr_eq(previous, &entry.document))
                || entry.refreshed
            {
                return Lookup::Ready(Arc::clone(&entry.document));
            }
            entry.refreshed = true;
            true
        } else {
            false
        };
        let (sender, receiver) = oneshot::channel();
        let pending = async move {
            receiver
                .await
                .unwrap_or_else(|_| Err("remote JWKS request cancelled".to_owned()))
        }
        .boxed()
        .shared();
        state.pending.insert(key.clone(), pending);
        Lookup::Fetch(FetchGuard {
            cache: self,
            key,
            sender: Some(sender),
            refreshed,
        })
    }
}

// Ownership is scoped to the fetching future: dropping it wakes all existing
// waiters with cancellation and permits a subsequent request to retry.
pub(super) struct FetchGuard<'a> {
    cache: &'a JwksCache,
    key: String,
    sender: Option<oneshot::Sender<FetchResult>>,
    refreshed: bool,
}

impl FetchGuard<'_> {
    pub(super) fn finish(mut self, result: Result<Value, String>, now: Duration) -> FetchResult {
        let result = result.map(Arc::new);
        let mut state = self.cache.lock(&self.key);
        let evicted = match &result {
            Ok(document) => state.entries.push(
                self.key.clone(),
                Entry {
                    document: Arc::clone(document),
                    expires_at: now.saturating_add(self.cache.ttl),
                    refreshed: self.refreshed,
                },
            ),
            Err(_) => None,
        };
        state.pending.remove(&self.key);
        drop(state);
        drop(evicted);
        if let Some(sender) = self.sender.take() {
            let _ = sender.send(result.clone());
        }
        result
    }
}

impl Drop for FetchGuard<'_> {
    fn drop(&mut self) {
        if self.sender.is_some() {
            self.cache.lock(&self.key).pending.remove(&self.key);
        }
    }
}

#[cfg(test)]
#[path = "../../tests/unit/domain/jwks_cache.rs"]
mod tests;
