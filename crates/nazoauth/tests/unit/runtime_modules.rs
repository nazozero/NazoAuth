use super::*;
use crate::config::ConfigSource;

#[test]
fn catalog_keeps_static_module_dependencies() {
    let settings =
        Settings::from_config(&ConfigSource::default()).expect("default settings should load");
    let catalog = module_catalog(&settings).expect("module catalog should be valid");

    assert_eq!(
        catalog
            .spec(ModuleId::ScimSecurityEvents)
            .unwrap()
            .dependencies,
        BTreeSet::from([ModuleId::Scim])
    );
    assert_eq!(
        catalog.spec(ModuleId::NativeSso).unwrap().dependencies,
        BTreeSet::from([ModuleId::TokenExchange])
    );
}

#[tokio::test]
async fn reconciler_is_one_abortable_tenant_owned_task() {
    let settings =
        Settings::from_config(&ConfigSource::default()).expect("default settings should load");
    let catalog = module_catalog(&settings).expect("module catalog should be valid");
    let pool =
        nazo_postgres::create_pool("not a postgres url", 1).expect("a lazy test pool should build");
    let registry = test_support::runtime_module_registry_with_modules_for_test(
        pool.clone(),
        &settings,
        BTreeSet::new(),
    )
    .expect("test registry should build");
    let repository = Arc::new(PersistenceRuntimeModuleRepository::new(Arc::new(
        nazo_postgres::RuntimeModuleRepository::new(pool),
    )));
    let modules = web::Data::new(RuntimeModules {
        repository,
        registry,
        catalog,
        instance_id: "tenant-runtime-test".to_owned(),
    });

    let worker = RuntimeModules::spawn_reconciler(modules);
    tokio::time::sleep(Duration::from_millis(10)).await;
    worker.abort();
    let error = worker.await.expect_err("aborted reconciler should stop");
    assert!(error.is_cancelled());
}

#[test]
fn vp_drain_horizon_uses_the_constructed_transaction_ttl_instead_of_session_ttl() {
    let mut settings = Settings::from_config(&ConfigSource::default()).unwrap();
    settings.session.session_ttl_seconds = 60;
    settings.openid4vc.transaction_ttl_seconds = 300;
    settings.modules.enable_openid4vp_verifier = true;
    let catalog = module_catalog(&settings).unwrap();
    assert_eq!(
        catalog.effective_disable_policy(ModuleId::Openid4vpVerifier),
        Some(
            nazo_runtime_modules::DisablePolicy::DrainStoredTransactions {
                max_duration: Duration::from_secs(300)
            }
        )
    );
    settings.openid4vc.transaction_ttl_seconds = 1;
    let catalog = module_catalog(&settings).unwrap();
    assert_eq!(
        catalog.effective_disable_policy(ModuleId::Openid4vpVerifier),
        Some(
            nazo_runtime_modules::DisablePolicy::DrainStoredTransactions {
                max_duration: Duration::from_secs(30)
            }
        )
    );
}


mod scheduler {
    use super::*;
    use std::collections::BTreeMap;
    use std::sync::{Mutex, atomic::{AtomicUsize, Ordering}};
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
    struct LiveGuard(Arc<Counts>, bool);
    impl Drop for LiveGuard {
        fn drop(&mut self) {
            if self.1 { self.0.planners_live.fetch_sub(1, Ordering::SeqCst); }
            else { self.0.live.fetch_sub(1, Ordering::SeqCst); }
        }
    }
    fn start_loop(counts: Arc<Counts>, ids: Vec<ModuleId>, first_plan: Arc<Semaphore>, holds: Arc<BTreeMap<ModuleId, Arc<Semaphore>>>) -> tokio::task::JoinHandle<()> {
        let planning_counts = counts.clone();
        tokio::spawn(run_reconciler(
            move || {
                let counts = planning_counts.clone(); let ids = ids.clone(); let first_plan = first_plan.clone();
                Box::pin(async move {
                    let read = counts.reads.fetch_add(1, Ordering::SeqCst);
                    counts.planners_live.fetch_add(1, Ordering::SeqCst);
                    let _guard = LiveGuard(counts, true);
                    if read == 0 { first_plan.acquire().await.unwrap().forget(); }
                    Ok(ids)
                })
            },
            move |id| {
                let counts = counts.clone(); let hold = holds.get(&id).cloned();
                Box::pin(async move {
                    *counts.starts.lock().unwrap().entry(id).or_default() += 1;
                    let live = counts.live.fetch_add(1, Ordering::SeqCst) + 1;
                    counts.max_live.fetch_max(live, Ordering::SeqCst);
                    let _guard = LiveGuard(counts.clone(), false);
                    if let Some(hold) = hold { hold.acquire().await.unwrap().forget(); }
                    counts.writes.fetch_add(1, Ordering::SeqCst);
                    Ok(ReconcileOutcome::NoChange)
                })
            },
        ))
    }
    async fn settle() { for _ in 0..64 { tokio::task::yield_now().await; } }
    async fn stop(owner: tokio::task::JoinHandle<()>) { owner.abort(); assert!(owner.await.unwrap_err().is_cancelled()); }

    #[tokio::test(start_paused = true)]
    async fn held_planner_survives_ticks_and_long_drain_does_not_block_another_module() {
        let counts = Arc::new(Counts::default());
        let planner = Arc::new(Semaphore::new(0));
        let drain = Arc::new(Semaphore::new(0));
        let a = ModuleId::Openid4vpVerifier; let b = ModuleId::DeviceAuthorization;
        let owner = start_loop(counts.clone(), vec![a, b], planner.clone(), Arc::new(BTreeMap::from([(a, drain)])));
        settle().await;
        assert_eq!(counts.reads.load(Ordering::SeqCst), 1);
        for _ in 0..5 { tokio::time::advance(Duration::from_secs(1)).await; settle().await; }
        assert_eq!(counts.reads.load(Ordering::SeqCst), 1);
        assert_eq!(counts.planners_live.load(Ordering::SeqCst), 1);
        planner.add_permits(1); settle().await;
        assert_eq!(counts.starts.lock().unwrap().get(&a), Some(&1));
        assert_eq!(counts.writes.load(Ordering::SeqCst), 1);
        for _ in 0..3 { tokio::time::advance(Duration::from_secs(1)).await; settle().await; }
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
        let holds: Arc<BTreeMap<_, _>> = Arc::new(ids.iter().map(|id| (*id, Arc::new(Semaphore::new(0)))).collect());
        let owner = start_loop(counts.clone(), ids.clone(), Arc::new(Semaphore::new(1)), holds.clone());
        settle().await;
        for _ in 0..5 { tokio::time::advance(Duration::from_secs(1)).await; settle().await; }
        assert_eq!(counts.live.load(Ordering::SeqCst), ids.len());
        assert_eq!(counts.max_live.load(Ordering::SeqCst), ids.len());
        assert!(counts.starts.lock().unwrap().values().all(|starts| *starts == 1));
        let released = ids[0]; holds[&released].add_permits(1); settle().await;
        tokio::time::advance(Duration::from_secs(1)).await; settle().await;
        let starts = counts.starts.lock().unwrap();
        assert_eq!(starts[&released], 2);
        assert!(ids.iter().filter(|id| **id != released).all(|id| starts[id] == 1));
        drop(starts);
        assert!(counts.max_live.load(Ordering::SeqCst) <= ids.len());
        stop(owner).await;
        assert_eq!(counts.live.load(Ordering::SeqCst), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn aborting_owner_drops_held_planner_and_every_transition_without_later_write() {
        let counts = Arc::new(Counts::default());
        let planner_hold = Arc::new(Semaphore::new(0));
        let transition_hold = Arc::new(Semaphore::new(0));
        let planning_counts = counts.clone(); let held_plan = planner_hold.clone();
        let transition_counts = counts.clone(); let held_transition = transition_hold.clone();
        let owner = tokio::spawn(run_reconciler(
            move || {
                let counts = planning_counts.clone(); let hold = held_plan.clone();
                Box::pin(async move {
                    let read = counts.reads.fetch_add(1, Ordering::SeqCst);
                    counts.planners_live.fetch_add(1, Ordering::SeqCst);
                    let _guard = LiveGuard(counts, true);
                    if read != 0 { hold.acquire().await.unwrap().forget(); }
                    Ok(vec![ModuleId::DeviceAuthorization, ModuleId::Openid4vpVerifier])
                })
            },
            move |id| {
                let counts = transition_counts.clone(); let hold = held_transition.clone();
                Box::pin(async move {
                    *counts.starts.lock().unwrap().entry(id).or_default() += 1;
                    counts.live.fetch_add(1, Ordering::SeqCst);
                    let _guard = LiveGuard(counts.clone(), false);
                    hold.acquire().await.unwrap().forget();
                    counts.writes.fetch_add(1, Ordering::SeqCst);
                    Ok(ReconcileOutcome::NoChange)
                })
            },
        ));
        settle().await;
        tokio::time::advance(Duration::from_secs(1)).await; settle().await;
        assert_eq!(counts.live.load(Ordering::SeqCst), 2);
        assert_eq!(counts.planners_live.load(Ordering::SeqCst), 1);
        stop(owner).await;
        assert_eq!(counts.live.load(Ordering::SeqCst), 0);
        assert_eq!(counts.planners_live.load(Ordering::SeqCst), 0);
        let reads = counts.reads.load(Ordering::SeqCst);
        let starts = counts.starts.lock().unwrap().clone();
        planner_hold.add_permits(1); transition_hold.add_permits(2);
        tokio::time::advance(Duration::from_secs(30)).await; settle().await;
        assert_eq!(counts.reads.load(Ordering::SeqCst), reads);
        assert_eq!(*counts.starts.lock().unwrap(), starts);
        assert_eq!(counts.writes.load(Ordering::SeqCst), 0);
    }
}
