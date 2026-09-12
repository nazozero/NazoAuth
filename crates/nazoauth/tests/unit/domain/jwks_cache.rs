use super::*;
use serde_json::json;

fn cache(capacity: usize) -> JwksCache {
    JwksCache::new(
        NonZeroUsize::new(capacity).unwrap(),
        Duration::from_secs(30),
    )
}

fn fetch<'a>(
    cache: &'a JwksCache,
    key: &str,
    previous: Option<&Arc<Value>>,
    now: u64,
) -> FetchGuard<'a> {
    match cache.begin(key.to_owned(), previous, Duration::from_secs(now)) {
        Lookup::Fetch(guard) => guard,
        _ => panic!("expected fetch ownership"),
    }
}

fn wait(cache: &JwksCache, key: &str) -> Pending {
    match cache.begin(key.to_owned(), None, Duration::ZERO) {
        Lookup::Wait(pending) => pending,
        _ => panic!("expected shared pending request"),
    }
}

#[test]
fn ttl_starts_at_completion_and_reads_do_not_extend_it() {
    let cache = cache(2);
    fetch(&cache, "a", None, 0)
        .finish(Ok(json!({"keys": []})), Duration::from_secs(10))
        .unwrap();
    assert!(cache.get("a", Duration::from_secs(39)).is_some());
    assert!(cache.get("a", Duration::from_secs(40)).is_none());
    assert!(cache.lock("a").entries.is_empty());
}

#[test]
fn capacity_evicts_lru_and_keeps_recently_read_entry() {
    let cache = cache(2);
    for key in ["a", "b"] {
        fetch(&cache, key, None, 0)
            .finish(Ok(json!(key)), Duration::ZERO)
            .unwrap();
    }
    assert!(cache.get("a", Duration::ZERO).is_some());
    fetch(&cache, "c", None, 0)
        .finish(Ok(json!("c")), Duration::ZERO)
        .unwrap();
    assert!(cache.get("b", Duration::ZERO).is_none());
    assert!(cache.get("a", Duration::ZERO).is_some());
    assert_eq!(cache.lock("a").entries.len(), 2);
}

#[test]
fn shard_capacity_is_bounded_and_collisions_follow_lru_order() {
    let cache = cache(259);
    assert_eq!(cache.states.len(), 8);
    let total: usize = cache
        .states
        .iter()
        .map(|state| state.read().unwrap().entries.cap().get())
        .sum();
    assert_eq!(total, 259);
    let slots = cache.lock("a").entries.cap().get();
    let keys: Vec<_> = (0..)
        .map(|index| format!("key-{index}"))
        .filter(|key| std::ptr::eq(cache.shard(key), cache.shard("a")))
        .take(slots + 1)
        .collect();
    for key in &keys[..slots] {
        fetch(&cache, key, None, 0)
            .finish(Ok(json!(key)), Duration::ZERO)
            .unwrap();
    }
    // A real promotion followed by the read-only MRU path must both keep key 0.
    assert!(cache.get(&keys[0], Duration::ZERO).is_some());
    assert!(cache.get(&keys[0], Duration::ZERO).is_some());
    fetch(&cache, &keys[slots], None, 0)
        .finish(Ok(json!("new")), Duration::ZERO)
        .unwrap();
    assert!(cache.get(&keys[1], Duration::ZERO).is_none());
    assert!(cache.get(&keys[0], Duration::ZERO).is_some());
    assert_eq!(cache.lock("a").entries.len(), slots);
    assert!(cache.get(&keys[0], Duration::from_secs(30)).is_none());
}

#[test]
fn one_shard_writer_does_not_block_another_uri_shard() {
    let cache = cache(256);
    let other = (0..)
        .map(|index| format!("key-{index}"))
        .find(|key| !std::ptr::eq(cache.shard(key), cache.shard("a")))
        .unwrap();
    let held = cache.lock("a");
    assert!(cache.shard(&other).try_write().is_ok());
    fetch(&cache, &other, None, 0)
        .finish(Ok(json!(42)), Duration::ZERO)
        .unwrap();
    assert_eq!(*cache.get(&other, Duration::ZERO).unwrap(), json!(42));
    drop(held);
}

#[test]
fn failures_are_shared_and_a_later_request_can_retry() {
    let cache = cache(2);
    let guard = fetch(&cache, "a", None, 0);
    let first = wait(&cache, "a");
    let second = wait(&cache, "a");
    assert!(first.clone().now_or_never().is_none());
    assert!(
        guard
            .finish(Err("fetch failed".into()), Duration::ZERO)
            .is_err()
    );
    for pending in [first, second] {
        assert_eq!(pending.now_or_never().unwrap().unwrap_err(), "fetch failed");
    }
    assert!(cache.lock("a").pending.is_empty());
    drop(fetch(&cache, "a", None, 0));
}

#[test]
fn cancelled_owner_wakes_waiters_and_dropped_waiter_does_not_cancel_owner() {
    let cache = cache(2);
    let guard = fetch(&cache, "a", None, 0);
    drop(wait(&cache, "a"));
    let pending = wait(&cache, "a");
    drop(guard);
    assert!(
        pending
            .now_or_never()
            .unwrap()
            .unwrap_err()
            .contains("cancelled")
    );
    assert!(cache.lock("a").pending.is_empty());
    fetch(&cache, "a", None, 0)
        .finish(Ok(json!(1)), Duration::ZERO)
        .unwrap();
}

#[test]
fn refresh_budget_survives_failure_and_resets_after_expiry() {
    let cache = cache(2);
    let old = fetch(&cache, "a", None, 0)
        .finish(Ok(json!(1)), Duration::ZERO)
        .unwrap();
    let guard = fetch(&cache, "a", Some(&old), 1);
    let pending = wait(&cache, "a");
    assert!(
        guard
            .finish(Err("failed".into()), Duration::from_secs(2))
            .is_err()
    );
    assert!(pending.now_or_never().unwrap().is_err());
    assert!(matches!(
        cache.begin("a".into(), Some(&old), Duration::from_secs(3)),
        Lookup::Ready(_)
    ));
    let fresh = fetch(&cache, "a", Some(&old), 30)
        .finish(Ok(json!(2)), Duration::from_secs(30))
        .unwrap();
    drop(fetch(&cache, "a", Some(&fresh), 31));
}

#[test]
fn stale_observer_reuses_new_result_without_spending_refresh_budget() {
    let cache = cache(2);
    let document = fetch(&cache, "a", None, 0)
        .finish(Ok(json!(1)), Duration::ZERO)
        .unwrap();
    assert!(matches!(
        cache.begin("a".into(), None, Duration::ZERO),
        Lookup::Ready(_)
    ));
    drop(fetch(&cache, "a", Some(&document), 1));
}

#[test]
fn unrelated_uri_and_eviction_do_not_break_inflight_ownership() {
    let cache = cache(1);
    let old = fetch(&cache, "a", None, 0)
        .finish(Ok(json!(1)), Duration::ZERO)
        .unwrap();
    let guard = fetch(&cache, "a", Some(&old), 1);
    fetch(&cache, "b", None, 1)
        .finish(Ok(json!(2)), Duration::from_secs(1))
        .unwrap();
    let pending = wait(&cache, "a");
    guard.finish(Ok(json!(3)), Duration::from_secs(2)).unwrap();
    assert_eq!(*pending.now_or_never().unwrap().unwrap(), json!(3));
}

#[test]
fn concurrent_cold_misses_elect_exactly_one_owner() {
    use std::sync::{
        Barrier,
        atomic::{AtomicUsize, Ordering},
    };
    let cache = cache(256);
    let barrier = Barrier::new(32);
    let owners = AtomicUsize::new(0);
    std::thread::scope(|scope| {
        for _ in 0..32 {
            scope.spawn(|| {
                barrier.wait();
                let lookup = cache.begin("a".into(), None, Duration::ZERO);
                if matches!(&lookup, Lookup::Fetch(_)) {
                    owners.fetch_add(1, Ordering::SeqCst);
                }
                barrier.wait();
                match lookup {
                    Lookup::Fetch(guard) => {
                        guard.finish(Ok(json!(42)), Duration::ZERO).unwrap();
                    }
                    Lookup::Wait(pending) => {
                        // Poll without assuming an async runtime. Completion must wake
                        // a normal executor too; the receiver supplies that mechanism.
                        while pending.clone().now_or_never().is_none() {
                            std::thread::yield_now();
                        }
                        assert_eq!(*pending.now_or_never().unwrap().unwrap(), json!(42));
                    }
                    Lookup::Ready(_) => {
                        panic!("owner must remain pending until all callers arrive")
                    }
                }
            });
        }
    });
    assert_eq!(owners.load(Ordering::SeqCst), 1);
    assert!(cache.lock("a").pending.is_empty());
}
