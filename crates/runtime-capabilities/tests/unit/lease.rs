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
    let snapshot = |revision| {
        Arc::new(ActiveModuleSnapshot {
            revision: ModuleRevision::new(revision),
            accepting: BTreeSet::from([ModuleId::Ciba]),
            draining: BTreeSet::new(),
        })
    };
    let old = tracker.acquire(snapshot(7), ModuleId::Ciba).unwrap();
    let newer = tracker.acquire(snapshot(8), ModuleId::Ciba).unwrap();
    tracker.close_generation(ModuleId::Ciba, ModuleRevision::new(8));
    assert!(tracker.acquire(snapshot(7), ModuleId::Ciba).is_none());
    assert!(tracker.acquire(snapshot(8), ModuleId::Ciba).is_none());
    let mut drain = std::pin::pin!(tracker.wait_until_zero(ModuleId::Ciba));
    let mut context = Context::from_waker(Waker::noop());
    assert!(matches!(drain.as_mut().poll(&mut context), Poll::Pending));
    drop(newer);
    assert!(matches!(drain.as_mut().poll(&mut context), Poll::Pending));
    drop(old);
    assert!(matches!(drain.as_mut().poll(&mut context), Poll::Ready(())));
}

#[test]
fn request_view_counts_only_used_modules_and_keeps_admitted_work_alive() {
    use crate::SnapshotStore;
    let store = SnapshotStore::new(ActiveModuleSnapshot {
        revision: ModuleRevision::new(1),
        accepting: [ModuleId::Ciba, ModuleId::TokenExchange].into(),
        draining: Default::default(),
    });
    let request = store.request();
    let delayed = store.request();
    assert_eq!(
        store.leases.active(ModuleId::Ciba, ModuleRevision::new(1)),
        0
    );
    assert!(request.permits(ModuleId::Ciba, CapabilityAdmission::NewRequest));
    assert!(request.permits(ModuleId::Ciba, CapabilityAdmission::NewRequest));
    assert_eq!(
        store.leases.active(ModuleId::Ciba, ModuleRevision::new(1)),
        1
    );
    assert_eq!(
        store
            .leases
            .active(ModuleId::TokenExchange, ModuleRevision::new(1)),
        0
    );
    store
        .compare_and_publish(
            ModuleRevision::new(1),
            ActiveModuleSnapshot {
                revision: ModuleRevision::new(2),
                accepting: Default::default(),
                draining: Default::default(),
            },
        )
        .unwrap();
    assert!(request.permits(ModuleId::Ciba, CapabilityAdmission::NewRequest));
    assert!(!delayed.permits(ModuleId::Ciba, CapabilityAdmission::NewRequest));
    assert!(
        store
            .lease(ModuleId::Ciba, CapabilityAdmission::NewRequest)
            .is_none()
    );
    drop(request);
    assert_eq!(
        store.leases.active(ModuleId::Ciba, ModuleRevision::new(1)),
        0
    );
}

#[test]
fn stored_transaction_admission_is_fenced_before_the_final_drain() {
    use crate::SnapshotStore;
    use std::{
        future::Future,
        task::{Context, Poll, Waker},
    };
    let store = SnapshotStore::new(ActiveModuleSnapshot {
        revision: ModuleRevision::new(2),
        accepting: Default::default(),
        draining: [ModuleId::Ciba].into(),
    });
    let request = store.request();
    let delayed = store.request();
    assert!(!request.permits(ModuleId::Ciba, CapabilityAdmission::NewRequest));
    assert!(request.permits(ModuleId::Ciba, CapabilityAdmission::ExistingTransaction));
    store
        .compare_and_publish(
            ModuleRevision::new(2),
            ActiveModuleSnapshot {
                revision: ModuleRevision::new(3),
                accepting: Default::default(),
                draining: Default::default(),
            },
        )
        .unwrap();
    assert!(!delayed.permits(ModuleId::Ciba, CapabilityAdmission::ExistingTransaction));
    assert!(
        store
            .lease(ModuleId::Ciba, CapabilityAdmission::ExistingTransaction)
            .is_none()
    );
    let mut drain = std::pin::pin!(store.leases.wait_until_zero(ModuleId::Ciba));
    let mut context = Context::from_waker(Waker::noop());
    assert!(matches!(drain.as_mut().poll(&mut context), Poll::Pending));
    drop(request);
    assert!(matches!(drain.as_mut().poll(&mut context), Poll::Ready(())));
}
