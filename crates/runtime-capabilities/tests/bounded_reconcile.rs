use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Barrier, Mutex};
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use nazo_runtime_modules::*;
use web_time::SystemTime;

fn block_on<F: Future>(future: F) -> F::Output {
    let mut future = std::pin::pin!(future);
    let mut context = Context::from_waker(Waker::noop());
    loop {
        if let Poll::Ready(value) = future.as_mut().poll(&mut context) {
            return value;
        }
        std::thread::yield_now();
    }
}

#[derive(Default)]
struct State {
    desired: BTreeMap<ModuleId, DesiredStateRecord>,
    instances: BTreeMap<(String, ModuleId), InstanceStateRecord>,
    events: Vec<ModuleEventRecord>,
}

struct Pause {
    entered: Barrier,
    release: Barrier,
}

impl Pause {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            entered: Barrier::new(2),
            release: Barrier::new(2),
        })
    }

    fn wait(&self) {
        self.entered.wait();
        self.release.wait();
    }
}

#[derive(Default)]
struct Repository {
    state: Mutex<State>,
    joined_reads: AtomicUsize,
    failed_reads: AtomicBool,
    pause_read: Mutex<Option<Arc<Pause>>>,
    pause_desired: Mutex<Option<Arc<Pause>>>,
    unknown_drain_start: AtomicBool,
}

impl Repository {
    fn new(enabled: &[ModuleId]) -> Arc<Self> {
        let repository = Arc::new(Self::default());
        for module in ModuleId::ALL {
            repository.force_desired(
                module,
                1,
                if enabled.contains(&module) {
                    DesiredMode::Enabled
                } else {
                    DesiredMode::Disabled
                },
                SystemTime::UNIX_EPOCH,
            );
        }
        repository
    }

    fn force_desired(&self, module: ModuleId, revision: u64, mode: DesiredMode, at: SystemTime) {
        self.state.lock().unwrap().desired.insert(
            module,
            DesiredStateRecord {
                module_id: module,
                mode,
                revision: ModuleRevision::new(revision),
                actor_id: None,
                reason: Some("bounded lifecycle fixture".into()),
                updated_at: at,
            },
        );
    }

    fn desired(&self, module: ModuleId) -> DesiredStateRecord {
        self.state.lock().unwrap().desired[&module].clone()
    }

    fn instance(&self, id: &str, module: ModuleId) -> Option<InstanceStateRecord> {
        self.state
            .lock()
            .unwrap()
            .instances
            .get(&(id.to_owned(), module))
            .cloned()
    }

    fn events(&self) -> Vec<ModuleEventType> {
        self.state
            .lock()
            .unwrap()
            .events
            .iter()
            .map(|event| event.event_type)
            .collect()
    }
}

impl ModuleStateRepository for Repository {
    type Error = &'static str;

    async fn read_desired(&self, id: ModuleId) -> Result<Option<DesiredStateRecord>, Self::Error> {
        let desired = self.state.lock().unwrap().desired.get(&id).cloned();
        let pause = self.pause_desired.lock().unwrap().take();
        if let Some(pause) = pause {
            pause.wait();
        }
        Ok(desired)
    }

    async fn read_all_desired(&self) -> Result<Vec<DesiredStateRecord>, Self::Error> {
        Ok(self
            .state
            .lock()
            .unwrap()
            .desired
            .values()
            .cloned()
            .collect())
    }

    async fn read_reconcile_state(
        &self,
        instance: &str,
    ) -> Result<Vec<ModuleReconcileState>, Self::Error> {
        self.joined_reads.fetch_add(1, Ordering::SeqCst);
        if self.failed_reads.load(Ordering::SeqCst) {
            return Err("authority unavailable");
        }
        let states = {
            let state = self.state.lock().unwrap();
            state
                .desired
                .values()
                .map(|desired| ModuleReconcileState {
                    desired: desired.clone(),
                    instance: state
                        .instances
                        .get(&(instance.to_owned(), desired.module_id))
                        .cloned(),
                })
                .collect()
        };
        let pause = self.pause_read.lock().unwrap().take();
        if let Some(pause) = pause {
            pause.wait();
        }
        Ok(states)
    }

    async fn compare_and_set_desired(
        &self,
        change: DesiredStateChange,
    ) -> Result<CasOutcome<DesiredStateRecord>, Self::Error> {
        self.compare_and_set_desired_guarded(change, Vec::new())
            .await
    }

    async fn compare_and_set_desired_guarded(
        &self,
        change: DesiredStateChange,
        guards: Vec<DesiredRevisionGuard>,
    ) -> Result<CasOutcome<DesiredStateRecord>, Self::Error> {
        let mut state = self.state.lock().unwrap();
        let current = state.desired.get(&change.next.module_id).cloned();
        if current.as_ref().map(|record| record.revision) != change.expected_revision
            || guards.iter().any(|guard| {
                state
                    .desired
                    .get(&guard.module_id)
                    .map(|record| record.revision)
                    != guard.expected_revision
            })
        {
            return Ok(CasOutcome::Stale { current });
        }
        let noop = current
            .as_ref()
            .is_some_and(|record| record.mode == change.next.mode);
        let applied = if noop {
            current.clone().unwrap()
        } else {
            change.next.clone()
        };
        if !noop {
            state.desired.insert(applied.module_id, applied.clone());
        }
        state.events.push(ModuleEventRecord {
            event_id: uuid::Uuid::now_v7().to_string(),
            module_id: applied.module_id,
            event_type: ModuleEventType::DesiredStateChanged,
            revision: applied.revision,
            instance_id: None,
            actor_id: change.next.actor_id,
            reason: change.next.reason,
            before: current.map(|record| ModuleEventState::Desired(record.mode.into())),
            after: Some(ModuleEventState::Desired(applied.mode.into())),
            outcome_code: noop.then(|| "noop".into()),
            occurred_at: change.next.updated_at,
        });
        Ok(CasOutcome::Applied(applied))
    }

    async fn read_instance(
        &self,
        instance: &str,
        module: ModuleId,
    ) -> Result<Option<InstanceStateRecord>, Self::Error> {
        Ok(self.instance(instance, module))
    }

    async fn read_all_instances(
        &self,
        instance: &str,
    ) -> Result<Vec<InstanceStateRecord>, Self::Error> {
        Ok(self
            .state
            .lock()
            .unwrap()
            .instances
            .values()
            .filter(|record| record.instance_id == instance)
            .cloned()
            .collect())
    }

    async fn page_events(&self, offset: i64, limit: i64) -> Result<ModuleEventPage, Self::Error> {
        let state = self.state.lock().unwrap();
        Ok(ModuleEventPage {
            total: state.events.len().try_into().unwrap(),
            events: state
                .events
                .iter()
                .skip(offset.try_into().unwrap())
                .take(limit.try_into().unwrap())
                .cloned()
                .collect(),
        })
    }

    async fn compare_and_set_instance(
        &self,
        mut mutation: InstanceStateMutation,
    ) -> Result<CasOutcome<InstanceStateRecord>, Self::Error> {
        let mut state = self.state.lock().unwrap();
        let key = (
            mutation.change.next.instance_id.clone(),
            mutation.change.next.module_id,
        );
        let current = state.instances.get(&key).cloned();
        if current.as_ref().map(|record| record.transition_revision)
            != mutation.change.expected_revision
            || state.desired[&key.1].revision != mutation.change.next.transition_revision
        {
            mutation.event.event_type = ModuleEventType::StaleTransitionDiscarded;
            state.events.push(mutation.event);
            return Ok(CasOutcome::Stale { current });
        }
        let unknown = mutation.event.event_type == ModuleEventType::DrainStarted
            && self.unknown_drain_start.swap(false, Ordering::SeqCst);
        state.instances.insert(key, mutation.change.next.clone());
        state.events.push(mutation.event);
        if unknown {
            return Err("drain start commit unknown");
        }
        Ok(CasOutcome::Applied(mutation.change.next))
    }

    async fn record_instance_observation(
        &self,
        observation: InstanceStateObservation,
    ) -> Result<(), Self::Error> {
        self.state.lock().unwrap().events.push(observation.event);
        Ok(())
    }

    async fn validate_revision(
        &self,
        id: ModuleId,
        expected: ModuleRevision,
    ) -> Result<bool, Self::Error> {
        Ok(self
            .state
            .lock()
            .unwrap()
            .desired
            .get(&id)
            .is_some_and(|record| record.revision == expected))
    }
}

#[derive(Default)]
struct Lifecycle {
    remaining: Mutex<Vec<Duration>>,
    // 0 = deadline only, 1 = pending even at deadline, 2 = complete, 3 = failure.
    progress: AtomicUsize,
    pause_poll: Mutex<Option<Arc<Pause>>>,
    reenable: Mutex<Option<Arc<Repository>>>,
}

impl ModuleLifecycle for Lifecycle {
    fn drain_stored_transactions(
        &self,
        _module: ModuleId,
        _revision: ModuleRevision,
        _remaining: Duration,
    ) -> LifecycleFuture<'_, Result<bool, LifecycleFailure>> {
        Box::pin(async { panic!("bounded synchronization called the waiting lifecycle") })
    }

    fn poll_stored_transactions(
        &self,
        module: ModuleId,
        revision: ModuleRevision,
        remaining: Duration,
    ) -> LifecycleFuture<'_, Result<DrainProgress, LifecycleFailure>> {
        Box::pin(async move {
            self.remaining.lock().unwrap().push(remaining);
            let pause = self.pause_poll.lock().unwrap().take();
            if let Some(pause) = pause {
                pause.wait();
            }
            if let Some(repository) = self.reenable.lock().unwrap().take() {
                repository.force_desired(
                    module,
                    revision.get() + 1,
                    DesiredMode::Enabled,
                    SystemTime::now(),
                );
            }
            if self.progress.load(Ordering::SeqCst) == 3 {
                return Err(LifecycleFailure {
                    code: "observation_failed",
                });
            }
            Ok(match self.progress.load(Ordering::SeqCst) {
                0 if remaining.is_zero() => DrainProgress::Complete,
                2 => DrainProgress::Complete,
                _ => DrainProgress::Pending,
            })
        })
    }
}

fn catalog() -> ModuleCatalog {
    ModuleCatalog::fixed(CatalogDurations {
        device_authorization: Duration::from_secs(60),
        ciba: Duration::from_secs(60),
        authorization_code: Duration::from_secs(60),
        refresh_token: Duration::from_secs(60),
        session: Duration::from_secs(60),
        presentation_transaction: Duration::from_secs(60),
        scim_security_events: Duration::from_secs(60),
    })
}

fn registry(
    repository: &Arc<Repository>,
    lifecycle: &Arc<Lifecycle>,
    id: &str,
    enabled: &[ModuleId],
) -> Arc<RuntimeModuleRegistry<Repository, Lifecycle>> {
    Arc::new(RuntimeModuleRegistry::new(
        repository.clone(),
        lifecycle.clone(),
        catalog(),
        id.into(),
        ActiveModuleSnapshot {
            revision: ModuleRevision::new(0),
            accepting: enabled.iter().copied().collect(),
            draining: BTreeSet::new(),
        },
    ))
}

#[test]
fn concurrent_cold_and_stable_reads_do_not_write_or_wait_on_another_request() {
    let repository = Repository::new(&ModuleId::ALL);
    let lifecycle = Arc::new(Lifecycle::default());
    let registry = registry(&repository, &lifecycle, "cold", &ModuleId::ALL);
    for _ in 0..2 {
        let start = Arc::new(Barrier::new(17));
        let workers = (0..16)
            .map(|_| {
                let (registry, start) = (registry.clone(), start.clone());
                std::thread::spawn(move || {
                    start.wait();
                    block_on(registry.synchronize_step())
                })
            })
            .collect::<Vec<_>>();
        start.wait();
        for worker in workers {
            assert_eq!(worker.join().unwrap().unwrap(), Vec::new());
        }
    }
    assert_eq!(repository.joined_reads.load(Ordering::SeqCst), 32);
    assert!(repository.events().is_empty());
    assert!(repository.state.lock().unwrap().instances.is_empty());
    assert_eq!(registry.snapshot().accepting.len(), 16);
}

#[cfg_attr(
    all(target_arch = "wasm32", target_os = "unknown"),
    wasm_bindgen_test::wasm_bindgen_test
)]
#[cfg_attr(not(all(target_arch = "wasm32", target_os = "unknown")), test)]
fn cold_expired_disabled_projection_has_no_invented_instance_or_history() {
    let repository = Repository::new(&[]);
    let lifecycle = Arc::new(Lifecycle::default());
    let registry = registry(&repository, &lifecycle, "cold", &[]);
    assert!(block_on(registry.synchronize_step()).unwrap().is_empty());
    assert!(repository.events().is_empty());
    assert!(repository.state.lock().unwrap().instances.is_empty());
    assert!(registry.snapshot().draining.is_empty());
}

#[cfg_attr(
    all(target_arch = "wasm32", target_os = "unknown"),
    wasm_bindgen_test::wasm_bindgen_test
)]
#[cfg_attr(not(all(target_arch = "wasm32", target_os = "unknown")), test)]
fn hot_cold_drains_share_the_authoritative_deadline_and_audited_noop_cannot_extend_it() {
    let module = ModuleId::DeviceAuthorization;
    let repository = Repository::new(&[module]);
    let lifecycle = Arc::new(Lifecycle::default());
    let hot = registry(&repository, &lifecycle, "hot", &[module]);
    block_on(hot.synchronize_step()).unwrap();
    let at = SystemTime::now();
    repository.force_desired(module, 2, DesiredMode::Disabled, at);
    assert_eq!(
        block_on(hot.synchronize_step()).unwrap(),
        vec![(module, ReconcileOutcome::Pending)]
    );
    let cold = registry(&repository, &lifecycle, "cold", &[]);
    assert_eq!(
        block_on(cold.synchronize_step()).unwrap(),
        vec![(module, ReconcileOutcome::Pending)]
    );
    let deadline = at.checked_add(Duration::from_secs(60)).unwrap();
    for id in ["hot", "cold"] {
        assert_eq!(
            repository.instance(id, module).unwrap().drain_deadline,
            Some(deadline)
        );
    }
    let original = repository.desired(module);
    let outcome = block_on(hot.set_desired_mode(
        module,
        DesiredMode::Disabled,
        Some(original.revision),
        None,
        Some("repeat disable".into()),
        at + Duration::from_secs(30),
    ))
    .unwrap();
    assert_eq!(outcome, CasOutcome::Applied(original.clone()));
    assert_eq!(repository.desired(module), original);
    assert_eq!(
        repository
            .state
            .lock()
            .unwrap()
            .events
            .last()
            .unwrap()
            .outcome_code
            .as_deref(),
        Some("noop")
    );
    let events = repository.events().len();
    assert_eq!(
        block_on(hot.synchronize_step()).unwrap(),
        vec![(module, ReconcileOutcome::Pending)]
    );
    assert_eq!(
        repository.events().len(),
        events,
        "pending poll does not append repeated transition starts"
    );
    assert!(
        hot.snapshot()
            .permits(module, CapabilityAdmission::ExistingTransaction)
    );
    assert!(
        !hot.snapshot()
            .permits(module, CapabilityAdmission::NewRequest)
    );
}

#[cfg_attr(
    all(target_arch = "wasm32", target_os = "unknown"),
    wasm_bindgen_test::wasm_bindgen_test
)]
#[cfg_attr(not(all(target_arch = "wasm32", target_os = "unknown")), test)]
fn pending_at_expiry_never_reopens_stored_admission_or_acknowledges_completion() {
    let module = ModuleId::DeviceAuthorization;
    let repository = Repository::new(&[module]);
    let lifecycle = Arc::new(Lifecycle::default());
    lifecycle.progress.store(1, Ordering::SeqCst);
    let registry = registry(&repository, &lifecycle, "hot", &[module]);
    block_on(registry.synchronize_step()).unwrap();
    repository.force_desired(module, 2, DesiredMode::Disabled, SystemTime::UNIX_EPOCH);
    // Keep a previously running instance so even an expired lifecycle must
    // inspect unfinished work instead of assuming a cold baseline is complete.
    repository.state.lock().unwrap().instances.insert(
        ("hot".into(), module),
        InstanceStateRecord {
            instance_id: "hot".into(),
            module_id: module,
            state: ModuleState::Enabled,
            transition_revision: ModuleRevision::new(1),
            applied_revision: Some(ModuleRevision::new(1)),
            drain_deadline: None,
            error_code: None,
            updated_at: SystemTime::UNIX_EPOCH,
        },
    );
    assert_eq!(
        block_on(registry.synchronize_step()).unwrap(),
        vec![(module, ReconcileOutcome::Pending)]
    );
    assert!(
        !registry
            .snapshot()
            .permits(module, CapabilityAdmission::ExistingTransaction)
    );
    assert_eq!(*lifecycle.remaining.lock().unwrap(), vec![Duration::ZERO]);
    assert!(
        !repository
            .events()
            .contains(&ModuleEventType::DrainCompleted)
    );
    assert!(
        !repository
            .events()
            .contains(&ModuleEventType::TransitionCompleted)
    );
}

#[cfg_attr(
    all(target_arch = "wasm32", target_os = "unknown"),
    wasm_bindgen_test::wasm_bindgen_test
)]
#[cfg_attr(not(all(target_arch = "wasm32", target_os = "unknown")), test)]
fn local_lease_holds_pending_after_stored_work_completes_without_reopening_or_repolling() {
    let module = ModuleId::DeviceAuthorization;
    let repository = Repository::new(&[module]);
    let lifecycle = Arc::new(Lifecycle::default());
    lifecycle.progress.store(2, Ordering::SeqCst);
    let registry = registry(&repository, &lifecycle, "hot", &[module]);
    block_on(registry.synchronize_step()).unwrap();
    let lease = registry.lease(module).unwrap();
    repository.force_desired(module, 2, DesiredMode::Disabled, SystemTime::now());
    for _ in 0..2 {
        assert_eq!(
            block_on(registry.synchronize_step()).unwrap(),
            vec![(module, ReconcileOutcome::Pending)]
        );
        assert!(
            !registry
                .snapshot()
                .permits(module, CapabilityAdmission::ExistingTransaction)
        );
        assert!(
            !repository
                .events()
                .contains(&ModuleEventType::DrainCompleted)
        );
    }
    assert_eq!(lifecycle.remaining.lock().unwrap().len(), 1);
    drop(lease);
    assert_eq!(
        block_on(registry.synchronize_step()).unwrap(),
        vec![(module, ReconcileOutcome::Disabled)]
    );
    assert_eq!(
        repository.events(),
        vec![
            ModuleEventType::TransitionStarted,
            ModuleEventType::DrainStarted,
            ModuleEventType::DrainCompleted,
            ModuleEventType::TransitionCompleted
        ]
    );
}

#[cfg_attr(
    all(target_arch = "wasm32", target_os = "unknown"),
    wasm_bindgen_test::wasm_bindgen_test
)]
#[cfg_attr(not(all(target_arch = "wasm32", target_os = "unknown")), test)]
fn a_missing_instance_cannot_bypass_an_existing_local_request_lease() {
    let module = ModuleId::TokenExchange;
    let repository = Repository::new(&[module]);
    let lifecycle = Arc::new(Lifecycle::default());
    let registry = registry(&repository, &lifecycle, "hot", &[module]);
    block_on(registry.synchronize_step()).unwrap();
    let lease = registry.lease(module).unwrap();
    repository.force_desired(module, 2, DesiredMode::Disabled, SystemTime::UNIX_EPOCH);
    assert_eq!(
        block_on(registry.synchronize_step()).unwrap(),
        vec![(module, ReconcileOutcome::Pending)]
    );
    assert!(repository.instance("hot", module).is_none());
    assert!(repository.events().is_empty());
    assert!(registry.lease(module).is_none());
    drop(lease);
    assert_eq!(
        block_on(registry.synchronize_step()).unwrap(),
        vec![(module, ReconcileOutcome::Disabled)]
    );
}

#[test]
fn stable_pending_drain_does_not_block_unrelated_concurrent_requests() {
    let module = ModuleId::DeviceAuthorization;
    let repository = Repository::new(&ModuleId::ALL);
    let lifecycle = Arc::new(Lifecycle::default());
    let registry = registry(&repository, &lifecycle, "hot", &ModuleId::ALL);
    block_on(registry.synchronize_step()).unwrap();
    repository.force_desired(module, 2, DesiredMode::Disabled, SystemTime::now());
    block_on(registry.synchronize_step()).unwrap();
    let pause = Pause::new();
    *lifecycle.pause_poll.lock().unwrap() = Some(pause.clone());
    let worker = {
        let registry = registry.clone();
        std::thread::spawn(move || block_on(registry.synchronize_step()))
    };
    pause.entered.wait();
    for _ in 0..16 {
        assert_eq!(
            block_on(registry.synchronize_step()).unwrap(),
            vec![(module, ReconcileOutcome::Pending)]
        );
        assert!(registry.snapshot().admits(ModuleId::TokenExchange));
        assert!(!registry.snapshot().admits(module));
        assert!(registry.snapshot().draining.contains(&module));
    }
    pause.release.wait();
    assert_eq!(
        worker.join().unwrap().unwrap(),
        vec![(module, ReconcileOutcome::Pending)]
    );
    assert_eq!(
        repository.events(),
        vec![
            ModuleEventType::TransitionStarted,
            ModuleEventType::DrainStarted
        ]
    );
}

#[test]
fn old_coherent_read_cannot_overwrite_a_newer_published_revision() {
    let module = ModuleId::TokenExchange;
    let repository = Repository::new(&[module]);
    let lifecycle = Arc::new(Lifecycle::default());
    let registry = registry(&repository, &lifecycle, "hot", &[module]);
    block_on(registry.synchronize_step()).unwrap();
    let pause = Pause::new();
    *repository.pause_read.lock().unwrap() = Some(pause.clone());
    let worker = {
        let registry = registry.clone();
        std::thread::spawn(move || block_on(registry.synchronize_step()))
    };
    pause.entered.wait();
    repository.force_desired(module, 2, DesiredMode::Disabled, SystemTime::now());
    block_on(registry.synchronize_step()).unwrap();
    assert!(!registry.snapshot().admits(module));
    pause.release.wait();
    worker.join().unwrap().unwrap();
    assert!(!registry.snapshot().admits(module));
    assert_eq!(
        repository.instance("hot", module).unwrap().applied_revision,
        Some(ModuleRevision::new(2))
    );
}

#[cfg_attr(
    all(target_arch = "wasm32", target_os = "unknown"),
    wasm_bindgen_test::wasm_bindgen_test
)]
#[cfg_attr(not(all(target_arch = "wasm32", target_os = "unknown")), test)]
fn authority_failure_closes_admission_and_same_revision_recovers_without_fake_history() {
    let repository = Repository::new(&ModuleId::ALL);
    let lifecycle = Arc::new(Lifecycle::default());
    let registry = registry(&repository, &lifecycle, "hot", &ModuleId::ALL);
    block_on(registry.synchronize_step()).unwrap();
    repository.failed_reads.store(true, Ordering::SeqCst);
    assert!(matches!(
        block_on(registry.synchronize_step()),
        Err(RegistryError::Repository("authority unavailable"))
    ));
    assert!(registry.snapshot().accepting.is_empty());
    repository.failed_reads.store(false, Ordering::SeqCst);
    assert!(block_on(registry.synchronize_step()).unwrap().is_empty());
    assert_eq!(registry.snapshot().accepting.len(), 16);
    assert!(repository.events().is_empty());
}

#[test]
fn a_successful_read_captured_before_an_authority_failure_cannot_reopen_admission() {
    let repository = Repository::new(&ModuleId::ALL);
    let lifecycle = Arc::new(Lifecycle::default());
    let registry = registry(&repository, &lifecycle, "hot", &ModuleId::ALL);
    block_on(registry.synchronize_step()).unwrap();
    let pause = Pause::new();
    *repository.pause_read.lock().unwrap() = Some(pause.clone());
    let worker = {
        let registry = registry.clone();
        std::thread::spawn(move || block_on(registry.synchronize_step()))
    };
    pause.entered.wait();
    repository.failed_reads.store(true, Ordering::SeqCst);
    assert!(block_on(registry.synchronize_step()).is_err());
    assert!(registry.snapshot().accepting.is_empty());
    pause.release.wait();
    assert!(matches!(
        worker.join().unwrap(),
        Err(RegistryError::Repository("authority unavailable"))
    ));
    assert!(registry.snapshot().accepting.is_empty());
    repository.failed_reads.store(false, Ordering::SeqCst);
    block_on(registry.synchronize_step()).unwrap();
    assert_eq!(registry.snapshot().accepting.len(), 16);
}

#[cfg_attr(
    all(target_arch = "wasm32", target_os = "unknown"),
    wasm_bindgen_test::wasm_bindgen_test
)]
#[cfg_attr(not(all(target_arch = "wasm32", target_os = "unknown")), test)]
fn changing_intent_without_advancing_its_revision_fails_closed() {
    let module = ModuleId::DeviceAuthorization;
    let repository = Repository::new(&[module]);
    let lifecycle = Arc::new(Lifecycle::default());
    let registry = registry(&repository, &lifecycle, "hot", &[module]);
    block_on(registry.synchronize_step()).unwrap();
    repository.force_desired(module, 1, DesiredMode::Disabled, SystemTime::now());
    assert!(matches!(
        block_on(registry.synchronize_step()),
        Err(RegistryError::InconsistentDesiredState(
            ModuleId::DeviceAuthorization
        ))
    ));
    assert!(registry.snapshot().accepting.is_empty());
    assert!(repository.events().is_empty());
}

#[cfg_attr(
    all(target_arch = "wasm32", target_os = "unknown"),
    wasm_bindgen_test::wasm_bindgen_test
)]
#[cfg_attr(not(all(target_arch = "wasm32", target_os = "unknown")), test)]
fn reenabling_during_a_pending_step_uses_the_new_revision_without_completing_old_drain() {
    let module = ModuleId::DeviceAuthorization;
    let repository = Repository::new(&[module]);
    let lifecycle = Arc::new(Lifecycle::default());
    let registry = registry(&repository, &lifecycle, "hot", &[module]);
    block_on(registry.synchronize_step()).unwrap();
    repository.force_desired(module, 2, DesiredMode::Disabled, SystemTime::now());
    *lifecycle.reenable.lock().unwrap() = Some(repository.clone());
    assert_eq!(
        block_on(registry.synchronize_step()).unwrap(),
        vec![(module, ReconcileOutcome::Pending)]
    );
    assert!(
        !registry.snapshot().admits(module),
        "the stale attempt consumes this invocation's one-step budget"
    );
    block_on(registry.synchronize_step()).unwrap();
    assert!(registry.snapshot().admits(module));
    assert!(!registry.snapshot().draining.contains(&module));
    assert_eq!(
        repository.instance("hot", module).unwrap().applied_revision,
        Some(ModuleRevision::new(3))
    );
    assert!(
        !repository
            .events()
            .contains(&ModuleEventType::DrainCompleted)
    );
}

#[cfg_attr(
    all(target_arch = "wasm32", target_os = "unknown"),
    wasm_bindgen_test::wasm_bindgen_test
)]
#[cfg_attr(not(all(target_arch = "wasm32", target_os = "unknown")), test)]
fn one_step_budget_rotates_past_long_drains_without_acknowledging_unstarted_work() {
    let modules = [ModuleId::DeviceAuthorization, ModuleId::Ciba];
    let repository = Repository::new(&modules);
    let lifecycle = Arc::new(Lifecycle::default());
    let registry = registry(&repository, &lifecycle, "hot", &modules);
    block_on(registry.synchronize_step()).unwrap();
    let changed_at = SystemTime::now();
    for module in modules {
        repository.force_desired(module, 2, DesiredMode::Disabled, changed_at);
    }
    let expected = modules
        .into_iter()
        .map(|module| (module, ReconcileOutcome::Pending))
        .collect::<Vec<_>>();
    assert_eq!(block_on(registry.synchronize_step()).unwrap(), expected);
    assert!(
        repository
            .instance("hot", ModuleId::DeviceAuthorization)
            .is_some()
    );
    assert!(repository.instance("hot", ModuleId::Ciba).is_none());
    assert!(
        registry
            .snapshot()
            .permits(ModuleId::Ciba, CapabilityAdmission::ExistingTransaction)
    );
    assert_eq!(block_on(registry.synchronize_step()).unwrap(), expected);
    assert!(repository.instance("hot", ModuleId::Ciba).is_some());
    assert_eq!(lifecycle.remaining.lock().unwrap().len(), 2);
    assert!(
        !repository
            .events()
            .contains(&ModuleEventType::TransitionCompleted)
    );
}

#[cfg_attr(
    all(target_arch = "wasm32", target_os = "unknown"),
    wasm_bindgen_test::wasm_bindgen_test
)]
#[cfg_attr(not(all(target_arch = "wasm32", target_os = "unknown")), test)]
fn unknown_drain_start_is_recovered_with_start_evidence_before_completion() {
    let module = ModuleId::DeviceAuthorization;
    let repository = Repository::new(&[module]);
    let lifecycle = Arc::new(Lifecycle::default());
    let registry = registry(&repository, &lifecycle, "hot", &[module]);
    block_on(registry.synchronize_step()).unwrap();
    repository.force_desired(module, 2, DesiredMode::Disabled, SystemTime::now());
    repository.unknown_drain_start.store(true, Ordering::SeqCst);
    assert!(block_on(registry.synchronize_step()).is_err());
    assert!(registry.snapshot().draining.is_empty());
    lifecycle.progress.store(2, Ordering::SeqCst);
    block_on(registry.synchronize_step()).unwrap();
    let events = repository.events();
    assert_eq!(
        events
            .iter()
            .filter(|event| **event == ModuleEventType::DrainStarted)
            .count(),
        2
    );
    assert_eq!(
        &events[events.len() - 2..],
        &[
            ModuleEventType::DrainCompleted,
            ModuleEventType::TransitionCompleted
        ]
    );
}

#[cfg_attr(
    all(target_arch = "wasm32", target_os = "unknown"),
    wasm_bindgen_test::wasm_bindgen_test
)]
#[cfg_attr(not(all(target_arch = "wasm32", target_os = "unknown")), test)]
fn cold_management_projection_reports_only_a_verified_applied_generation() {
    let module = ModuleId::DeviceAuthorization;
    let repository = Repository::new(&[module]);
    let lifecycle = Arc::new(Lifecycle::default());
    let registry = registry(&repository, &lifecycle, "cold", &[module]);
    let management =
        RuntimeModuleManagement::new(repository.clone(), registry.clone(), catalog(), "cold");
    assert!(
        block_on(management.list())
            .unwrap()
            .iter()
            .all(|view| view.applied_revision.is_none())
    );
    block_on(registry.synchronize_step()).unwrap();
    let views = block_on(management.list()).unwrap();
    for view in views {
        assert_eq!(view.applied_revision, view.revision);
    }
    repository.failed_reads.store(true, Ordering::SeqCst);
    assert!(block_on(registry.synchronize_step()).is_err());
    repository.failed_reads.store(false, Ordering::SeqCst);
    assert!(
        block_on(management.list())
            .unwrap()
            .iter()
            .all(|view| view.applied_revision.is_none())
    );
    assert!(repository.state.lock().unwrap().instances.is_empty());
    assert!(repository.events().is_empty());
}

#[cfg_attr(
    all(target_arch = "wasm32", target_os = "unknown"),
    wasm_bindgen_test::wasm_bindgen_test
)]
#[cfg_attr(not(all(target_arch = "wasm32", target_os = "unknown")), test)]
fn constructed_availability_caps_cold_and_changed_desired_state() {
    let repository = Repository::new(&ModuleId::ALL);
    let lifecycle = Arc::new(Lifecycle::default());
    let registry = RuntimeModuleRegistry::new(
        repository.clone(),
        lifecycle,
        catalog().with_constructed_availability([(ModuleId::Ciba, false)]),
        "cold".into(),
        ActiveModuleSnapshot {
            revision: ModuleRevision::new(0),
            accepting: ModuleId::ALL.into_iter().collect(),
            draining: BTreeSet::new(),
        },
    );
    block_on(registry.synchronize_step()).unwrap();
    assert!(!registry.snapshot().admits(ModuleId::Ciba));
    assert!(matches!(
        block_on(registry.set_desired_mode(
            ModuleId::Ciba,
            DesiredMode::Enabled,
            Some(ModuleRevision::new(1)),
            None,
            None,
            SystemTime::now()
        )),
        Err(RegistryError::ServiceNotConstructed(ModuleId::Ciba))
    ));
    assert!(repository.events().is_empty());
}

#[cfg_attr(
    all(target_arch = "wasm32", target_os = "unknown"),
    wasm_bindgen_test::wasm_bindgen_test
)]
#[cfg_attr(not(all(target_arch = "wasm32", target_os = "unknown")), test)]
fn native_waiting_entry_still_waits_for_real_lifecycle_completion() {
    struct WaitingLifecycle {
        released: AtomicBool,
        remaining: Mutex<Option<Duration>>,
    }
    impl ModuleLifecycle for WaitingLifecycle {
        fn drain_stored_transactions(
            &self,
            _module: ModuleId,
            _revision: ModuleRevision,
            remaining: Duration,
        ) -> LifecycleFuture<'_, Result<bool, LifecycleFailure>> {
            *self.remaining.lock().unwrap() = Some(remaining);
            Box::pin(futures_util::future::poll_fn(|_| {
                if self.released.load(Ordering::SeqCst) {
                    Poll::Ready(Ok(true))
                } else {
                    Poll::Pending
                }
            }))
        }
    }
    let module = ModuleId::DeviceAuthorization;
    let repository = Repository::new(&[]);
    repository.force_desired(module, 2, DesiredMode::Disabled, SystemTime::now());
    let lifecycle = Arc::new(WaitingLifecycle {
        released: AtomicBool::new(false),
        remaining: Mutex::new(None),
    });
    let registry = RuntimeModuleRegistry::new(
        repository.clone(),
        lifecycle.clone(),
        catalog(),
        "native".into(),
        ActiveModuleSnapshot {
            revision: ModuleRevision::new(0),
            accepting: BTreeSet::from([module]),
            draining: BTreeSet::new(),
        },
    );
    let mut future = std::pin::pin!(registry.reconcile_once(module));
    let mut context = Context::from_waker(Waker::noop());
    assert!(future.as_mut().poll(&mut context).is_pending());
    let remaining = lifecycle.remaining.lock().unwrap().unwrap();
    assert!(remaining > Duration::ZERO && remaining <= Duration::from_secs(60));
    assert!(registry.snapshot().draining.contains(&module));
    assert!(
        !repository
            .events()
            .contains(&ModuleEventType::DrainCompleted)
    );
    lifecycle.released.store(true, Ordering::SeqCst);
    assert!(matches!(
        future.as_mut().poll(&mut context),
        Poll::Ready(Ok(ReconcileOutcome::Disabled))
    ));
    assert!(
        !registry
            .snapshot()
            .permits(module, CapabilityAdmission::ExistingTransaction)
    );
}

fn scim_registry(
    repository: &Arc<Repository>,
    lifecycle: &Arc<Lifecycle>,
) -> Arc<RuntimeModuleRegistry<Repository, Lifecycle>> {
    Arc::new(RuntimeModuleRegistry::new(
        repository.clone(),
        lifecycle.clone(),
        catalog()
            .with_dependencies(ModuleId::ScimSecurityEvents, [ModuleId::Scim])
            .unwrap(),
        "scim".into(),
        ActiveModuleSnapshot {
            revision: ModuleRevision::new(0),
            accepting: BTreeSet::from([ModuleId::Scim, ModuleId::ScimSecurityEvents]),
            draining: BTreeSet::new(),
        },
    ))
}

#[cfg_attr(
    all(target_arch = "wasm32", target_os = "unknown"),
    wasm_bindgen_test::wasm_bindgen_test
)]
#[cfg_attr(not(all(target_arch = "wasm32", target_os = "unknown")), test)]
fn a_disabled_parent_waits_for_its_unstarted_dependent_and_local_lease() {
    let modules = [ModuleId::Scim, ModuleId::ScimSecurityEvents];
    let repository = Repository::new(&modules);
    let lifecycle = Arc::new(Lifecycle::default());
    let registry = scim_registry(&repository, &lifecycle);
    block_on(registry.synchronize_step()).unwrap();
    let lease = registry.lease(ModuleId::ScimSecurityEvents).unwrap();
    for module in modules {
        repository.force_desired(module, 2, DesiredMode::Disabled, SystemTime::UNIX_EPOCH);
    }
    let pending = modules
        .map(|module| (module, ReconcileOutcome::Pending))
        .to_vec();
    assert_eq!(block_on(registry.synchronize_step()).unwrap(), pending);
    assert!(repository.instance("scim", ModuleId::Scim).is_none());
    assert!(
        repository.events().is_empty(),
        "closed child admission does not acknowledge its active lease"
    );
    drop(lease);
    block_on(registry.synchronize_step()).unwrap();
    assert!(
        repository.instance("scim", ModuleId::Scim).is_none(),
        "the one-step budget must complete the child first"
    );
    assert_eq!(
        repository
            .instance("scim", ModuleId::ScimSecurityEvents)
            .unwrap()
            .state,
        ModuleState::Disabled
    );
    block_on(registry.synchronize_step()).unwrap();
    assert_eq!(
        repository.instance("scim", ModuleId::Scim).unwrap().state,
        ModuleState::Disabled
    );
}

#[cfg_attr(
    all(target_arch = "wasm32", target_os = "unknown"),
    wasm_bindgen_test::wasm_bindgen_test
)]
#[cfg_attr(not(all(target_arch = "wasm32", target_os = "unknown")), test)]
fn cold_parent_disable_is_blocked_by_the_authoritative_child_window_without_an_instance() {
    let repository = Repository::new(&[ModuleId::Scim]);
    let at = SystemTime::now();
    for module in [ModuleId::DeviceAuthorization, ModuleId::ScimSecurityEvents] {
        repository.force_desired(module, 2, DesiredMode::Disabled, at);
    }
    let lifecycle = Arc::new(Lifecycle::default());
    let registry = RuntimeModuleRegistry::new(
        repository.clone(),
        lifecycle,
        catalog()
            .with_dependencies(ModuleId::ScimSecurityEvents, [ModuleId::Scim])
            .unwrap(),
        "cold".into(),
        ActiveModuleSnapshot {
            revision: ModuleRevision::new(0),
            accepting: BTreeSet::from([ModuleId::Scim]),
            draining: BTreeSet::new(),
        },
    );
    let disable_parent = || {
        registry.set_desired_mode(
            ModuleId::Scim,
            DesiredMode::Disabled,
            Some(ModuleRevision::new(1)),
            None,
            None,
            SystemTime::now(),
        )
    };
    assert!(matches!(
        block_on(disable_parent()),
        Err(RegistryError::ActiveDependent {
            dependent: ModuleId::ScimSecurityEvents,
            ..
        })
    ));
    block_on(registry.synchronize_step()).unwrap();
    assert!(
        repository
            .instance("cold", ModuleId::ScimSecurityEvents)
            .is_none()
    );
    assert!(registry.snapshot().permits(
        ModuleId::ScimSecurityEvents,
        CapabilityAdmission::ExistingTransaction
    ));
    assert!(matches!(
        block_on(disable_parent()),
        Err(RegistryError::ActiveDependent {
            dependent: ModuleId::ScimSecurityEvents,
            ..
        })
    ));
    assert_eq!(
        repository.desired(ModuleId::Scim).mode,
        DesiredMode::Enabled
    );
}

#[cfg_attr(
    all(target_arch = "wasm32", target_os = "unknown"),
    wasm_bindgen_test::wasm_bindgen_test
)]
#[cfg_attr(not(all(target_arch = "wasm32", target_os = "unknown")), test)]
fn cold_multiple_drains_preserve_all_live_transactions_with_one_transition_budget() {
    let modules = [ModuleId::DeviceAuthorization, ModuleId::Ciba];
    let repository = Repository::new(&[]);
    let at = SystemTime::now();
    for module in modules {
        repository.force_desired(module, 2, DesiredMode::Disabled, at);
    }
    let lifecycle = Arc::new(Lifecycle::default());
    let registry = registry(&repository, &lifecycle, "cold", &[]);
    assert_eq!(
        block_on(registry.synchronize_step()).unwrap(),
        modules
            .map(|module| (module, ReconcileOutcome::Pending))
            .to_vec()
    );
    for module in modules {
        assert!(
            registry
                .snapshot()
                .permits(module, CapabilityAdmission::ExistingTransaction)
        );
        assert!(
            !registry
                .snapshot()
                .permits(module, CapabilityAdmission::NewRequest)
        );
    }
    assert_eq!(repository.state.lock().unwrap().instances.len(), 1);
    assert_eq!(
        repository.events(),
        vec![
            ModuleEventType::TransitionStarted,
            ModuleEventType::DrainStarted
        ]
    );
}

#[test]
fn a_delayed_same_revision_draining_read_cannot_reopen_a_failed_instance() {
    let module = ModuleId::DeviceAuthorization;
    let repository = Repository::new(&[module]);
    let lifecycle = Arc::new(Lifecycle::default());
    let registry = registry(&repository, &lifecycle, "hot", &[module]);
    block_on(registry.synchronize_step()).unwrap();
    repository.force_desired(module, 2, DesiredMode::Disabled, SystemTime::now());
    block_on(registry.synchronize_step()).unwrap();
    let old_read = Pause::new();
    *repository.pause_read.lock().unwrap() = Some(old_read.clone());
    let worker = {
        let registry = registry.clone();
        std::thread::spawn(move || block_on(registry.synchronize_step()))
    };
    old_read.entered.wait();
    lifecycle.progress.store(3, Ordering::SeqCst);
    assert_eq!(
        block_on(registry.synchronize_step()).unwrap(),
        vec![(module, ReconcileOutcome::Failed)]
    );
    assert!(
        !registry
            .snapshot()
            .permits(module, CapabilityAdmission::ExistingTransaction)
    );
    let retry = Pause::new();
    *repository.pause_desired.lock().unwrap() = Some(retry.clone());
    old_read.release.wait();
    retry.entered.wait();
    assert!(
        !registry
            .snapshot()
            .permits(module, CapabilityAdmission::ExistingTransaction),
        "older Draining cannot reopen Failed before fresh retry initialization"
    );
    retry.release.wait();
    assert_eq!(
        worker.join().unwrap().unwrap(),
        vec![(module, ReconcileOutcome::Failed)]
    );
    assert!(
        !registry
            .snapshot()
            .permits(module, CapabilityAdmission::ExistingTransaction)
    );
}

#[test]
fn a_delayed_same_revision_read_observes_completion_without_restarting_it() {
    let module = ModuleId::DeviceAuthorization;
    let repository = Repository::new(&[module]);
    let lifecycle = Arc::new(Lifecycle::default());
    let registry = registry(&repository, &lifecycle, "hot", &[module]);
    block_on(registry.synchronize_step()).unwrap();
    repository.force_desired(module, 2, DesiredMode::Disabled, SystemTime::now());
    block_on(registry.synchronize_step()).unwrap();
    let old_read = Pause::new();
    *repository.pause_read.lock().unwrap() = Some(old_read.clone());
    let worker = {
        let registry = registry.clone();
        std::thread::spawn(move || block_on(registry.synchronize_step()))
    };
    old_read.entered.wait();
    lifecycle.progress.store(2, Ordering::SeqCst);
    assert_eq!(
        block_on(registry.synchronize_step()).unwrap(),
        vec![(module, ReconcileOutcome::Disabled)]
    );
    let events = repository.events();
    old_read.release.wait();
    assert!(worker.join().unwrap().unwrap().is_empty());
    assert_eq!(repository.events(), events);
    assert!(
        !registry
            .snapshot()
            .permits(module, CapabilityAdmission::ExistingTransaction)
    );
}

#[test]
fn finishing_an_unchanged_pending_poll_does_not_invalidate_a_concurrent_read() {
    let module = ModuleId::DeviceAuthorization;
    let repository = Repository::new(&[module]);
    let lifecycle = Arc::new(Lifecycle::default());
    let registry = registry(&repository, &lifecycle, "hot", &[module]);
    block_on(registry.synchronize_step()).unwrap();
    repository.force_desired(module, 2, DesiredMode::Disabled, SystemTime::now());
    block_on(registry.synchronize_step()).unwrap();
    let reads = repository.joined_reads.load(Ordering::SeqCst);
    let publication = registry.snapshot().revision;
    let old_read = Pause::new();
    *repository.pause_read.lock().unwrap() = Some(old_read.clone());
    let worker = {
        let registry = registry.clone();
        std::thread::spawn(move || block_on(registry.synchronize_step()))
    };
    old_read.entered.wait();
    assert_eq!(
        block_on(registry.synchronize_step()).unwrap(),
        vec![(module, ReconcileOutcome::Pending)]
    );
    old_read.release.wait();
    assert_eq!(
        worker.join().unwrap().unwrap(),
        vec![(module, ReconcileOutcome::Pending)]
    );
    assert_eq!(repository.joined_reads.load(Ordering::SeqCst) - reads, 4);
    assert_eq!(registry.snapshot().revision, publication);
}
