use std::collections::BTreeSet;

use super::*;

#[test]
fn closed_generation_rejects_a_delayed_stale_snapshot() {
    let tracker = RequestLeaseTracker::default();
    let snapshot = Arc::new(ActiveModuleSnapshot {
        revision: ModuleRevision::new(7),
        accepting: BTreeSet::from([ModuleId::Ciba]),
        draining: BTreeSet::new(),
    });

    tracker.close_generation(ModuleId::Ciba, snapshot.revision);

    assert!(tracker.acquire(snapshot, ModuleId::Ciba).is_none());
}

#[test]
fn closing_an_old_generation_does_not_reject_a_new_generation() {
    let tracker = RequestLeaseTracker::default();
    tracker.close_generation(ModuleId::Ciba, ModuleRevision::new(7));
    let snapshot = Arc::new(ActiveModuleSnapshot {
        revision: ModuleRevision::new(8),
        accepting: BTreeSet::from([ModuleId::Ciba]),
        draining: BTreeSet::new(),
    });

    assert!(tracker.acquire(snapshot, ModuleId::Ciba).is_some());
}

#[test]
fn drain_waits_for_all_retained_generations_and_rejects_delayed_acquisition() {
    use std::future::Future;
    use std::task::{Context, Poll, Waker};
    let tracker = RequestLeaseTracker::default();
    let snapshot = |revision| Arc::new(ActiveModuleSnapshot {
        revision: ModuleRevision::new(revision), accepting: BTreeSet::from([ModuleId::Ciba]), draining: BTreeSet::new(),
    });
    let old = tracker.acquire(snapshot(7), ModuleId::Ciba).unwrap();
    let newer = tracker.acquire(snapshot(8), ModuleId::Ciba).unwrap();
    tracker.close_generation(ModuleId::Ciba, ModuleRevision::new(8));
    assert!(tracker.acquire(snapshot(7), ModuleId::Ciba).is_none());
    assert!(tracker.acquire(snapshot(8), ModuleId::Ciba).is_none());
    let mut drain = std::pin::pin!(tracker.wait_until_zero(ModuleId::Ciba, ModuleRevision::new(8)));
    let mut context = Context::from_waker(Waker::noop());
    assert!(matches!(drain.as_mut().poll(&mut context), Poll::Pending));
    drop(newer);
    assert!(matches!(drain.as_mut().poll(&mut context), Poll::Pending));
    drop(old);
    assert!(matches!(drain.as_mut().poll(&mut context), Poll::Ready(())));
}
