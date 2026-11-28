use super::*;

#[tokio::test]
async fn reconciler_is_one_abortable_tenant_owned_task() {
    let worker = tokio::spawn(run_reconciler(
        || Box::pin(std::future::pending()),
        |_| Box::pin(async { Ok(ReconcileOutcome::NoChange) }),
    ));
    tokio::time::sleep(Duration::from_millis(10)).await;
    worker.abort();
    let error = worker.await.expect_err("aborted reconciler should stop");
    assert!(error.is_cancelled());
}

mod scheduler {
    use super::*;
    use std::collections::BTreeMap;
    use std::mem::DropGuard;
    use std::sync::{
        Mutex,
        atomic::{AtomicUsize, Ordering},
    };
    use tokio::sync::Semaphore;

    #[derive(Default)]
    struct Counts {
        reads: AtomicUsize,
        planners_live: AtomicUsize,
        live: AtomicUsize,
        max_live: AtomicUsize,
        starts: Mutex<BTreeMap<ModuleId, usize>>,
        writes: AtomicUsize,
    }
    fn start_loop(
        counts: Arc<Counts>,
        ids: Vec<ModuleId>,
        first_plan: Arc<Semaphore>,
        holds: Arc<BTreeMap<ModuleId, Arc<Semaphore>>>,
    ) -> tokio::task::JoinHandle<()> {
        let planning_counts = counts.clone();
        tokio::spawn(run_reconciler(
            move || {
                let counts = planning_counts.clone();
                let ids = ids.clone();
                let first_plan = first_plan.clone();
                Box::pin(async move {
                    let read = counts.reads.fetch_add(1, Ordering::SeqCst);
                    counts.planners_live.fetch_add(1, Ordering::SeqCst);
                    let _guard = DropGuard::new(&counts.planners_live, |live| {
                        live.fetch_sub(1, Ordering::SeqCst);
                    });
                    if read == 0 {
                        first_plan.acquire().await.unwrap().forget();
                    }
                    Ok(ids)
                })
            },
            move |id| {
                let counts = counts.clone();
                let hold = holds.get(&id).cloned();
                Box::pin(async move {
                    *counts.starts.lock().unwrap().entry(id).or_default() += 1;
                    let live = counts.live.fetch_add(1, Ordering::SeqCst) + 1;
                    counts.max_live.fetch_max(live, Ordering::SeqCst);
                    let _guard = DropGuard::new(&counts.live, |live| {
                        live.fetch_sub(1, Ordering::SeqCst);
                    });
                    if let Some(hold) = hold {
                        hold.acquire().await.unwrap().forget();
                    }
                    counts.writes.fetch_add(1, Ordering::SeqCst);
                    Ok(ReconcileOutcome::NoChange)
                })
            },
        ))
    }
    async fn settle() {
        for _ in 0..64 {
            tokio::task::yield_now().await;
        }
    }
    async fn stop(owner: tokio::task::JoinHandle<()>) {
        owner.abort();
        assert!(owner.await.unwrap_err().is_cancelled());
    }

    #[tokio::test(start_paused = true)]
    async fn held_planner_survives_ticks_and_long_drain_does_not_block_another_module() {
        let counts = Arc::new(Counts::default());
        let planner = Arc::new(Semaphore::new(0));
        let drain = Arc::new(Semaphore::new(0));
        let a = ModuleId::Openid4vpVerifier;
        let b = ModuleId::DeviceAuthorization;
        let owner = start_loop(
            counts.clone(),
            vec![a, b],
            planner.clone(),
            Arc::new(BTreeMap::from([(a, drain)])),
        );
        settle().await;
        assert_eq!(counts.reads.load(Ordering::SeqCst), 1);
        for _ in 0..5 {
            tokio::time::advance(Duration::from_secs(1)).await;
            settle().await;
        }
        assert_eq!(counts.reads.load(Ordering::SeqCst), 1);
        assert_eq!(counts.planners_live.load(Ordering::SeqCst), 1);
        planner.add_permits(1);
        settle().await;
        assert_eq!(counts.starts.lock().unwrap().get(&a), Some(&1));
        assert_eq!(counts.writes.load(Ordering::SeqCst), 1);
        for _ in 0..3 {
            tokio::time::advance(Duration::from_secs(1)).await;
            settle().await;
        }
        assert_eq!(counts.starts.lock().unwrap().get(&a), Some(&1));
        assert!(counts.starts.lock().unwrap()[&b] >= 2);
        assert_eq!(counts.live.load(Ordering::SeqCst), 1);
        stop(owner).await;
        assert_eq!(counts.live.load(Ordering::SeqCst), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn repeated_all_module_plans_keep_one_transition_per_module_and_bounded_total() {
        let counts = Arc::new(Counts::default());
        let ids = ModuleId::ALL.to_vec();
        let holds: Arc<BTreeMap<_, _>> = Arc::new(
            ids.iter()
                .map(|id| (*id, Arc::new(Semaphore::new(0))))
                .collect(),
        );
        let owner = start_loop(
            counts.clone(),
            ids.clone(),
            Arc::new(Semaphore::new(1)),
            holds.clone(),
        );
        settle().await;
        for _ in 0..5 {
            tokio::time::advance(Duration::from_secs(1)).await;
            settle().await;
        }
        assert_eq!(counts.live.load(Ordering::SeqCst), ids.len());
        assert_eq!(counts.max_live.load(Ordering::SeqCst), ids.len());
        assert!(
            counts
                .starts
                .lock()
                .unwrap()
                .values()
                .all(|starts| *starts == 1)
        );
        let released = ids[0];
        holds[&released].add_permits(1);
        settle().await;
        tokio::time::advance(Duration::from_secs(1)).await;
        settle().await;
        {
            let starts = counts.starts.lock().unwrap();
            assert_eq!(starts[&released], 2);
            assert!(
                ids.iter()
                    .filter(|id| **id != released)
                    .all(|id| starts[id] == 1)
            );
        }

        assert!(counts.max_live.load(Ordering::SeqCst) <= ids.len());
        stop(owner).await;
        assert_eq!(counts.live.load(Ordering::SeqCst), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn aborting_owner_drops_held_planner_and_every_transition_without_later_write() {
        let counts = Arc::new(Counts::default());
        let planner_hold = Arc::new(Semaphore::new(0));
        let transition_hold = Arc::new(Semaphore::new(0));
        let planning_counts = counts.clone();
        let held_plan = planner_hold.clone();
        let transition_counts = counts.clone();
        let held_transition = transition_hold.clone();
        let owner = tokio::spawn(run_reconciler(
            move || {
                let counts = planning_counts.clone();
                let hold = held_plan.clone();
                Box::pin(async move {
                    let read = counts.reads.fetch_add(1, Ordering::SeqCst);
                    counts.planners_live.fetch_add(1, Ordering::SeqCst);
                    let _guard = DropGuard::new(&counts.planners_live, |live| {
                        live.fetch_sub(1, Ordering::SeqCst);
                    });
                    if read != 0 {
                        hold.acquire().await.unwrap().forget();
                    }
                    Ok(vec![
                        ModuleId::DeviceAuthorization,
                        ModuleId::Openid4vpVerifier,
                    ])
                })
            },
            move |id| {
                let counts = transition_counts.clone();
                let hold = held_transition.clone();
                Box::pin(async move {
                    *counts.starts.lock().unwrap().entry(id).or_default() += 1;
                    counts.live.fetch_add(1, Ordering::SeqCst);
                    let _guard = DropGuard::new(&counts.live, |live| {
                        live.fetch_sub(1, Ordering::SeqCst);
                    });
                    hold.acquire().await.unwrap().forget();
                    counts.writes.fetch_add(1, Ordering::SeqCst);
                    Ok(ReconcileOutcome::NoChange)
                })
            },
        ));
        settle().await;
        tokio::time::advance(Duration::from_secs(1)).await;
        settle().await;
        assert_eq!(counts.live.load(Ordering::SeqCst), 2);
        assert_eq!(counts.planners_live.load(Ordering::SeqCst), 1);
        stop(owner).await;
        assert_eq!(counts.live.load(Ordering::SeqCst), 0);
        assert_eq!(counts.planners_live.load(Ordering::SeqCst), 0);
        let reads = counts.reads.load(Ordering::SeqCst);
        let starts = counts.starts.lock().unwrap().clone();
        planner_hold.add_permits(1);
        transition_hold.add_permits(2);
        tokio::time::advance(Duration::from_secs(30)).await;
        settle().await;
        assert_eq!(counts.reads.load(Ordering::SeqCst), reads);
        assert_eq!(*counts.starts.lock().unwrap(), starts);
        assert_eq!(counts.writes.load(Ordering::SeqCst), 0);
    }
}
