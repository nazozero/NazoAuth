#![cfg(feature = "local-sqlite")]

use std::{
    sync::{Arc, Barrier},
    time::Duration,
};

use futures_executor::block_on;
use nazo_identity::TenantId;
use nazo_persistence::RuntimeModuleStore;
use nazo_runtime_modules::{
    CasOutcome, DesiredMode, DesiredRevisionGuard, DesiredStateChange, DesiredStateRecord,
    HistoricalDesiredMode, InstanceStateChange, InstanceStateMutation, InstanceStateObservation,
    InstanceStateRecord, ModuleEventRecord, ModuleEventState, ModuleEventType, ModuleId,
    ModuleRevision, ModuleState,
};
use serde_json::{Value, json};
use uuid::Uuid;
use web_time::{SystemTime, UNIX_EPOCH};

use crate::{D1Provider, Database};

fn at(seconds: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(seconds)
}

async fn fixture() -> (Database, D1Provider) {
    let database = Database::in_memory().unwrap();
    database.execute_schema().unwrap();
    let provider = D1Provider::new(database.clone(), TenantId::new(Uuid::new_v4()).unwrap());
    provider.initialize_modules(&ModuleId::ALL).await.unwrap();
    (database, provider)
}

fn change(current: &DesiredStateRecord, mode: DesiredMode, time: SystemTime) -> DesiredStateChange {
    DesiredStateChange {
        expected_revision: Some(current.revision),
        next: DesiredStateRecord {
            module_id: current.module_id,
            mode,
            revision: ModuleRevision::new(current.revision.get() + 1),
            actor_id: Some(Uuid::new_v4().to_string()),
            reason: Some("operator requested transition".into()),
            updated_at: time,
        },
    }
}

fn mutation(
    instance: &str,
    desired: &DesiredStateRecord,
    before: Option<&InstanceStateRecord>,
    state: ModuleState,
    kind: ModuleEventType,
) -> InstanceStateMutation {
    let next = InstanceStateRecord {
        instance_id: instance.into(),
        module_id: desired.module_id,
        state,
        transition_revision: desired.revision,
        applied_revision: (state == ModuleState::Enabled || state == ModuleState::Disabled)
            .then_some(desired.revision),
        drain_deadline: (state == ModuleState::Draining)
            .then_some(desired.updated_at + Duration::from_secs(600)),
        error_code: (state == ModuleState::Failed).then(|| "lifecycle_failed".into()),
        updated_at: at(100),
    };
    let event = ModuleEventRecord {
        event_id: Uuid::new_v4().to_string(),
        module_id: next.module_id,
        event_type: kind,
        revision: next.transition_revision,
        instance_id: Some(next.instance_id.clone()),
        actor_id: desired.actor_id.clone(),
        reason: desired.reason.clone(),
        before: before.map(|value| ModuleEventState::Actual(value.state)),
        after: Some(ModuleEventState::Actual(next.state)),
        outcome_code: None,
        occurred_at: next.updated_at,
    };
    InstanceStateMutation {
        change: InstanceStateChange {
            expected_revision: before.map(|value| value.transition_revision),
            next,
        },
        event,
    }
}

async fn desired(provider: &D1Provider, module: ModuleId) -> DesiredStateRecord {
    provider.read_desired(module).await.unwrap().unwrap()
}

async fn rows(database: &Database, table: &str) -> Vec<Value> {
    database
        .query::<Value>(&format!("SELECT * FROM {table}"), vec![])
        .await
        .unwrap()
}

fn applied<T: std::fmt::Debug>(outcome: CasOutcome<T>) -> T {
    match outcome {
        CasOutcome::Applied(value) => value,
        CasOutcome::Stale { current } => panic!("unexpected stale outcome: {current:?}"),
    }
}

#[test]
fn deployment_profile_migrates_without_fabricated_events_and_is_never_reapplied() {
    block_on(async {
        let database = Database::in_memory().unwrap();
        database
            .execute_sql(include_str!("../../migrations/0001.sql"))
            .unwrap();
        let tenant = TenantId::new(Uuid::new_v4()).unwrap();
        let provider = D1Provider::new(database.clone(), tenant);
        provider
            .initialize_modules(&[ModuleId::DeviceAuthorization])
            .await
            .unwrap();
        database.execute_schema().unwrap();
        let initial = provider.read_all_desired().await.unwrap();
        assert_eq!(initial.len(), ModuleId::ALL.len());
        assert!(
            initial
                .iter()
                .all(|row| row.revision == ModuleRevision::new(1)
                    && row.updated_at == UNIX_EPOCH
                    && row.actor_id.is_none())
        );
        assert_eq!(
            initial
                .iter()
                .filter(|row| row.mode == DesiredMode::Enabled)
                .count(),
            1
        );
        assert_eq!(provider.page_events(0, 100).await.unwrap().total, 0);
        assert!(
            provider
                .read_all_instances("cold-isolate")
                .await
                .unwrap()
                .is_empty()
        );
        let old = desired(&provider, ModuleId::DeviceAuthorization).await;
        let updated = applied(
            provider
                .compare_and_set_desired(change(&old, DesiredMode::Disabled, at(10)))
                .await
                .unwrap(),
        );
        database.execute_schema().unwrap();
        // Replay the idempotent data migration as well as its local ledger.
        database
            .execute_sql(include_str!("../../migrations/0015_runtime_modules.sql"))
            .unwrap();
        assert_eq!(
            desired(&provider, ModuleId::DeviceAuthorization).await,
            updated
        );
        assert_eq!(provider.page_events(0, 100).await.unwrap().total, 1);
    });
}

#[test]
fn desired_cas_has_one_concurrent_winner_and_a_complete_canonical_event() {
    let (database, provider) = block_on(fixture());
    let current = block_on(desired(&provider, ModuleId::DeviceAuthorization));
    let request = change(&current, DesiredMode::Disabled, at(20));
    let provider = Arc::new(provider);
    let barrier = Arc::new(Barrier::new(16));
    let winners = std::thread::scope(|scope| {
        let tasks = (0..16)
            .map(|_| {
                let provider = provider.clone();
                let barrier = barrier.clone();
                let request = request.clone();
                scope.spawn(move || {
                    barrier.wait();
                    block_on(provider.compare_and_set_desired(request)).unwrap()
                })
            })
            .collect::<Vec<_>>();
        tasks
            .into_iter()
            .map(|task| task.join().unwrap())
            .filter(|outcome| matches!(outcome, CasOutcome::Applied(_)))
            .count()
    });
    assert_eq!(winners, 1);
    block_on(async {
        assert_eq!(desired(&provider, current.module_id).await, request.next);
        let page = provider.page_events(0, 100).await.unwrap();
        assert_eq!(page.total, 1);
        let event = &page.events[0];
        assert_eq!(event.module_id, current.module_id);
        assert_eq!(event.event_type, ModuleEventType::DesiredStateChanged);
        assert_eq!(event.revision, request.next.revision);
        assert_eq!(event.actor_id, request.next.actor_id);
        assert_eq!(event.reason, request.next.reason);
        assert_eq!(
            event.before,
            Some(ModuleEventState::Desired(HistoricalDesiredMode::Enabled))
        );
        assert_eq!(
            event.after,
            Some(ModuleEventState::Desired(HistoricalDesiredMode::Disabled))
        );
        assert_eq!(event.occurred_at, request.next.updated_at);
        assert_eq!(event.instance_id, None);
        assert_eq!(event.outcome_code, None);
        // ModuleEventRecord is the native audit contract; no second schema is invented.
        assert!(rows(&database, "nazo_audit").await.is_empty());
    });
}

#[test]
fn concurrent_dependency_guards_cannot_commit_an_incompatible_pair() {
    let (_, provider) = block_on(fixture());
    let scim = block_on(desired(&provider, ModuleId::Scim));
    let events = block_on(desired(&provider, ModuleId::ScimSecurityEvents));
    let events = applied(
        block_on(provider.compare_and_set_desired(change(&events, DesiredMode::Disabled, at(10))))
            .unwrap(),
    );
    let changes = [
        (
            change(&scim, DesiredMode::Disabled, at(20)),
            DesiredRevisionGuard {
                module_id: events.module_id,
                expected_revision: Some(events.revision),
            },
        ),
        (
            change(&events, DesiredMode::Enabled, at(20)),
            DesiredRevisionGuard {
                module_id: scim.module_id,
                expected_revision: Some(scim.revision),
            },
        ),
    ];
    let barrier = Arc::new(Barrier::new(2));
    let winners = std::thread::scope(|scope| {
        let tasks = changes
            .into_iter()
            .map(|(request, guard)| {
                let provider = &provider;
                let barrier = barrier.clone();
                scope.spawn(move || {
                    barrier.wait();
                    block_on(provider.compare_and_set_desired_guarded(request, vec![guard]))
                        .unwrap()
                })
            })
            .collect::<Vec<_>>();
        tasks
            .into_iter()
            .map(|task| task.join().unwrap())
            .filter(|outcome| matches!(outcome, CasOutcome::Applied(_)))
            .count()
    });
    assert_eq!(winners, 1);
    block_on(async {
        let scim = desired(&provider, scim.module_id).await;
        let events = desired(&provider, events.module_id).await;
        assert!(!(scim.mode == DesiredMode::Disabled && events.mode == DesiredMode::Enabled));
        assert_eq!(provider.page_events(0, 100).await.unwrap().total, 2);
        let stale = provider
            .compare_and_set_desired_guarded(
                change(&scim, DesiredMode::Disabled, at(30)),
                vec![DesiredRevisionGuard {
                    module_id: events.module_id,
                    expected_revision: None,
                }],
            )
            .await
            .unwrap();
        assert_eq!(
            stale,
            CasOutcome::Stale {
                current: Some(scim)
            }
        );
        assert_eq!(provider.page_events(0, 100).await.unwrap().total, 2);
    });
}

#[test]
fn repeated_disable_is_audited_without_extending_the_authoritative_drain_start() {
    block_on(async {
        let (_, provider) = fixture().await;
        let initial = desired(&provider, ModuleId::DeviceAuthorization).await;
        let disabled = applied(
            provider
                .compare_and_set_desired(change(&initial, DesiredMode::Disabled, at(10)))
                .await
                .unwrap(),
        );
        let noop = change(&disabled, DesiredMode::Disabled, at(900));
        assert_eq!(
            provider
                .compare_and_set_desired(noop.clone())
                .await
                .unwrap(),
            CasOutcome::Applied(disabled.clone())
        );
        assert_eq!(desired(&provider, initial.module_id).await, disabled);
        let event = provider.page_events(0, 1).await.unwrap().events.remove(0);
        assert_eq!(event.revision, disabled.revision);
        assert_eq!(event.outcome_code.as_deref(), Some("noop"));
        assert_eq!(event.actor_id, noop.next.actor_id);
        assert_eq!(event.reason, noop.next.reason);
        assert_eq!(event.occurred_at, at(900));
        assert_eq!(event.before, event.after);
        assert!(
            provider
                .validate_revision(initial.module_id, disabled.revision)
                .await
                .unwrap()
        );
        assert!(
            !provider
                .validate_revision(initial.module_id, initial.revision)
                .await
                .unwrap()
        );
    });
}

#[test]
fn coherent_snapshot_keeps_missing_instances_and_tenant_boundaries() {
    block_on(async {
        let (database, provider) = fixture().await;
        let before = provider.read_reconcile_state("one").await.unwrap();
        assert_eq!(before.len(), 16);
        assert!(before.iter().all(|row| row.instance.is_none()));
        let target = desired(&provider, ModuleId::DeviceAuthorization).await;
        let request = mutation(
            "one",
            &target,
            None,
            ModuleState::Starting,
            ModuleEventType::TransitionStarted,
        );
        applied(
            provider
                .compare_and_set_instance(request.clone())
                .await
                .unwrap(),
        );
        let one = provider.read_reconcile_state("one").await.unwrap();
        assert_eq!(one.iter().filter(|row| row.instance.is_some()).count(), 1);
        assert_eq!(
            one.iter()
                .find(|row| row.desired.module_id == target.module_id)
                .unwrap()
                .instance
                .as_ref(),
            Some(&request.change.next)
        );
        assert!(
            provider
                .read_reconcile_state("two")
                .await
                .unwrap()
                .iter()
                .all(|row| row.instance.is_none())
        );
        let other = D1Provider::new(database.clone(), TenantId::new(Uuid::new_v4()).unwrap());
        other.initialize_modules(&[]).await.unwrap();
        assert!(
            other
                .read_reconcile_state("one")
                .await
                .unwrap()
                .iter()
                .all(|row| row.instance.is_none() && row.desired.mode == DesiredMode::Disabled)
        );
        assert_eq!(other.page_events(0, 100).await.unwrap().total, 0);
        let empty = D1Provider::new(database.clone(), TenantId::new(Uuid::new_v4()).unwrap());
        assert!(empty.read_reconcile_state("one").await.is_err());
        // Snapshot reads do not insert all sixteen per-isolate observations.
        assert_eq!(rows(&database, "nazo_module_instances").await.len(), 1);
    });
}

#[test]
fn cold_disabled_instance_can_drain_and_stale_revisions_only_append_discard_evidence() {
    block_on(async {
        let (_, provider) = fixture().await;
        let enabled = desired(&provider, ModuleId::DeviceAuthorization).await;
        let disabled = applied(
            provider
                .compare_and_set_desired(change(&enabled, DesiredMode::Disabled, at(10)))
                .await
                .unwrap(),
        );
        let mut first = mutation(
            "cold",
            &disabled,
            None,
            ModuleState::Draining,
            ModuleEventType::DrainStarted,
        );
        // Zero is a valid native "not yet applied" observation revision.
        first.change.next.applied_revision = Some(ModuleRevision::new(0));
        let draining = applied(
            provider
                .compare_and_set_instance(first.clone())
                .await
                .unwrap(),
        );
        assert_eq!(draining.drain_deadline, Some(at(610)));
        assert_eq!(
            provider.page_events(0, 1).await.unwrap().events[0].before,
            None
        );
        let second = mutation(
            "cold",
            &disabled,
            Some(&draining),
            ModuleState::Disabled,
            ModuleEventType::DrainCompleted,
        );
        let reenabled = applied(
            provider
                .compare_and_set_desired(change(&disabled, DesiredMode::Enabled, at(120)))
                .await
                .unwrap(),
        );
        assert_eq!(
            provider
                .compare_and_set_instance(second.clone())
                .await
                .unwrap(),
            CasOutcome::Stale {
                current: Some(draining.clone())
            }
        );
        assert_eq!(
            provider
                .read_instance("cold", disabled.module_id)
                .await
                .unwrap(),
            Some(draining)
        );
        let page = provider.page_events(0, 100).await.unwrap();
        let stale = page
            .events
            .iter()
            .find(|event| event.event_id == second.event.event_id)
            .unwrap();
        assert_eq!(stale.event_type, ModuleEventType::StaleTransitionDiscarded);
        assert_eq!(stale.revision, disabled.revision);
        assert_eq!(desired(&provider, disabled.module_id).await, reenabled);
        let missing = mutation(
            "never-observed",
            &disabled,
            None,
            ModuleState::Draining,
            ModuleEventType::DrainStarted,
        );
        assert_eq!(
            provider.compare_and_set_instance(missing).await.unwrap(),
            CasOutcome::Stale { current: None }
        );
        let mut zero = mutation(
            "zero-revision",
            &disabled,
            None,
            ModuleState::Draining,
            ModuleEventType::DrainStarted,
        );
        zero.change.next.transition_revision = ModuleRevision::new(0);
        zero.event.revision = ModuleRevision::new(0);
        assert_eq!(
            provider.compare_and_set_instance(zero).await.unwrap(),
            CasOutcome::Stale { current: None }
        );
    });
}

#[test]
fn instance_cas_competition_has_one_winner_and_all_discard_events() {
    let (_, provider) = block_on(fixture());
    let target = block_on(desired(&provider, ModuleId::JwtBearerGrant));
    let provider = Arc::new(provider);
    let barrier = Arc::new(Barrier::new(8));
    let winners = std::thread::scope(|scope| {
        let tasks = (0..8)
            .map(|_| {
                let provider = provider.clone();
                let barrier = barrier.clone();
                let request = mutation(
                    "shared-id",
                    &target,
                    None,
                    ModuleState::Starting,
                    ModuleEventType::TransitionStarted,
                );
                scope.spawn(move || {
                    barrier.wait();
                    block_on(provider.compare_and_set_instance(request)).unwrap()
                })
            })
            .collect::<Vec<_>>();
        tasks
            .into_iter()
            .map(|task| task.join().unwrap())
            .filter(|outcome| matches!(outcome, CasOutcome::Applied(_)))
            .count()
    });
    assert_eq!(winners, 1);
    let page = block_on(provider.page_events(0, 100)).unwrap();
    assert_eq!(page.total, 8);
    assert_eq!(
        page.events
            .iter()
            .filter(|event| event.event_type == ModuleEventType::StaleTransitionDiscarded)
            .count(),
        7
    );
}

#[test]
fn ignored_or_aborted_desired_state_and_required_event_writes_fail_closed() {
    for behavior in ["IGNORE", "ABORT,'test write rejected'"] {
        for target in [
            "BEFORE INSERT ON nazo_module_events",
            "BEFORE UPDATE ON nazo_module_desired",
        ] {
            block_on(async {
                let (database, provider) = fixture().await;
                let initial = desired(&provider, ModuleId::DeviceAuthorization).await;
                database.execute_sql(&format!("CREATE TRIGGER reject_mutation {target} BEGIN SELECT RAISE({behavior}); END;")).unwrap();
                assert!(
                    provider
                        .compare_and_set_desired(change(&initial, DesiredMode::Disabled, at(30)))
                        .await
                        .is_err()
                );
                assert_eq!(desired(&provider, initial.module_id).await, initial);
                assert_eq!(provider.page_events(0, 100).await.unwrap().total, 0);
                database
                    .execute_sql("DROP TRIGGER reject_mutation")
                    .unwrap();
                applied(
                    provider
                        .compare_and_set_desired(change(&initial, DesiredMode::Disabled, at(30)))
                        .await
                        .unwrap(),
                );
            });
        }
    }
    block_on(async {
        let (database, provider) = fixture().await;
        let initial = desired(&provider, ModuleId::DeviceAuthorization).await;
        database.execute_sql("CREATE TRIGGER suppress_noop BEFORE INSERT ON nazo_module_events BEGIN SELECT RAISE(IGNORE); END;").unwrap();
        assert!(
            provider
                .compare_and_set_desired(change(&initial, initial.mode, at(30)))
                .await
                .is_err()
        );
        assert_eq!(desired(&provider, initial.module_id).await, initial);
    });
}

#[test]
fn ignored_instance_insert_update_and_stale_receipt_cannot_acknowledge_a_transition() {
    block_on(async {
        let (database, provider) = fixture().await;
        let target = desired(&provider, ModuleId::DeviceAuthorization).await;
        let first = mutation(
            "one",
            &target,
            None,
            ModuleState::Starting,
            ModuleEventType::TransitionStarted,
        );
        database.execute_sql("CREATE TRIGGER suppress_insert BEFORE INSERT ON nazo_module_instances BEGIN SELECT RAISE(IGNORE); END;").unwrap();
        assert!(
            provider
                .compare_and_set_instance(first.clone())
                .await
                .is_err()
        );
        assert_eq!(provider.page_events(0, 100).await.unwrap().total, 0);
        assert!(
            provider
                .read_instance("one", target.module_id)
                .await
                .unwrap()
                .is_none()
        );
        database
            .execute_sql("DROP TRIGGER suppress_insert")
            .unwrap();
        let starting = applied(
            provider
                .compare_and_set_instance(first.clone())
                .await
                .unwrap(),
        );
        let mut second = mutation(
            "one",
            &target,
            Some(&starting),
            ModuleState::Enabled,
            ModuleEventType::TransitionCompleted,
        );
        database.execute_sql("CREATE TRIGGER suppress_update BEFORE UPDATE ON nazo_module_instances BEGIN SELECT RAISE(IGNORE); END;").unwrap();
        assert!(
            provider
                .compare_and_set_instance(second.clone())
                .await
                .is_err()
        );
        assert_eq!(
            provider
                .read_instance("one", target.module_id)
                .await
                .unwrap(),
            Some(starting.clone())
        );
        assert_eq!(provider.page_events(0, 100).await.unwrap().total, 1);
        // Even an unchanged state with a new observation time needs its full stored receipt.
        second.change.next = starting.clone();
        second.change.next.updated_at = at(101);
        second.event.after = Some(ModuleEventState::Actual(starting.state));
        assert!(provider.compare_and_set_instance(second).await.is_err());
        database
            .execute_sql("DROP TRIGGER suppress_update")
            .unwrap();
        database.execute_sql("CREATE TRIGGER suppress_event BEFORE INSERT ON nazo_module_events BEGIN SELECT RAISE(IGNORE); END;").unwrap();
        let stale = mutation(
            "one",
            &target,
            None,
            ModuleState::Starting,
            ModuleEventType::TransitionStarted,
        );
        assert!(provider.compare_and_set_instance(stale).await.is_err());
        assert_eq!(provider.page_events(0, 100).await.unwrap().total, 1);
    });
}

#[test]
fn observations_are_append_only_state_preserving_and_event_pages_share_their_total() {
    block_on(async {
        let (database, provider) = fixture().await;
        let target = desired(&provider, ModuleId::DeviceAuthorization).await;
        let state = applied(
            provider
                .compare_and_set_instance(mutation(
                    "one",
                    &target,
                    None,
                    ModuleState::Starting,
                    ModuleEventType::TransitionStarted,
                ))
                .await
                .unwrap(),
        );
        let mut observation = InstanceStateObservation {
            event: ModuleEventRecord {
                event_id: Uuid::new_v4().to_string(),
                module_id: target.module_id,
                event_type: ModuleEventType::StaleTransitionDiscarded,
                revision: target.revision,
                instance_id: Some("one".into()),
                actor_id: None,
                reason: Some("superseded work".into()),
                before: Some(ModuleEventState::Actual(state.state)),
                after: Some(ModuleEventState::Actual(state.state)),
                outcome_code: Some("stale_revision".into()),
                occurred_at: at(101),
            },
        };
        provider
            .record_instance_observation(observation.clone())
            .await
            .unwrap();
        assert_eq!(
            provider
                .read_instance("one", target.module_id)
                .await
                .unwrap(),
            Some(state)
        );
        assert_eq!(desired(&provider, target.module_id).await, target);
        assert_eq!(
            provider.page_events(0, 1).await.unwrap().events,
            vec![observation.event.clone()]
        );
        let empty = provider.page_events(2, 1).await.unwrap();
        assert_eq!(empty.total, 2);
        assert!(empty.events.is_empty());
        for (offset, limit) in [(-1, 1), (0, 0), (0, 101)] {
            assert!(provider.page_events(offset, limit).await.is_err());
        }
        assert!(
            database
                .execute_sql("DELETE FROM nazo_module_events")
                .is_err()
        );
        assert!(
            database
                .execute_sql("UPDATE nazo_module_events SET record=record")
                .is_err()
        );
        assert!(
            provider
                .record_instance_observation(observation.clone())
                .await
                .is_err()
        );
        observation.event.event_id = Uuid::new_v4().to_string();
        observation.event.after = None;
        assert!(
            provider
                .record_instance_observation(observation.clone())
                .await
                .is_err()
        );
        observation.event.after = observation.event.before;
        database.execute_sql("CREATE TRIGGER suppress_observation BEFORE INSERT ON nazo_module_events BEGIN SELECT RAISE(IGNORE); END;").unwrap();
        assert!(
            provider
                .record_instance_observation(observation)
                .await
                .is_err()
        );
        assert_eq!(provider.page_events(0, 100).await.unwrap().total, 2);
    });
}

#[test]
fn persisted_revisions_and_timestamps_fail_closed_before_javascript_rounding() {
    block_on(async {
        let (database, provider) = fixture().await;
        let target = desired(&provider, ModuleId::DeviceAuthorization).await;
        let mut request = change(&target, DesiredMode::Disabled, at(10));
        request.next.revision = ModuleRevision::new(1 << 53);
        assert!(provider.compare_and_set_desired(request).await.is_err());
        let mut request = change(&target, DesiredMode::Disabled, at(10));
        request.next.updated_at = UNIX_EPOCH + Duration::from_micros(1 << 53);
        assert!(provider.compare_and_set_desired(request).await.is_err());
        let mut request = change(&target, DesiredMode::Disabled, at(10));
        request.next.actor_id = Some("not-an-actor-uuid".into());
        assert!(provider.compare_and_set_desired(request).await.is_err());
        let mut request = change(&target, DesiredMode::Disabled, at(10));
        request.next.reason = Some(" ".into());
        assert!(provider.compare_and_set_desired(request).await.is_err());
        assert_eq!(provider.page_events(0, 100).await.unwrap().total, 0);
        // This is an offline boundary fixture, not a runtime revision mutation.
        database
            .execute_sql("DROP TRIGGER nazo_module_desired_revision")
            .unwrap();
        database.execute_statement(
            "UPDATE nazo_module_desired SET revision=9007199254740991 WHERE tenant_id=?1 AND module_id=?2",
            vec![json!(provider.tenant_id),json!(target.module_id)],
        ).await.unwrap();
        let maximum = desired(&provider, target.module_id).await;
        assert_eq!(maximum.revision.get(), 9_007_199_254_740_991);
        assert!(
            provider
                .compare_and_set_desired(change(&maximum, DesiredMode::Disabled, at(10)))
                .await
                .is_err()
        );
        assert_eq!(desired(&provider, target.module_id).await, maximum);
    });
}

#[test]
fn bounded_cleanup_only_removes_old_instance_observations_without_live_deadlines() {
    block_on(async {
        let (database, provider) = fixture().await;
        let target = desired(&provider, ModuleId::DeviceAuthorization).await;
        for instance in ["old-one", "old-two", "future-deadline", "recent"] {
            let mut request = mutation(
                instance,
                &target,
                None,
                ModuleState::Draining,
                ModuleEventType::DrainStarted,
            );
            if instance == "future-deadline" {
                request.change.next.drain_deadline =
                    Some(SystemTime::now() + Duration::from_secs(3600));
            }
            if instance == "recent" {
                request.change.next.updated_at = SystemTime::now();
            }
            applied(provider.compare_and_set_instance(request).await.unwrap());
        }
        let other = D1Provider::new(database.clone(), TenantId::new(Uuid::new_v4()).unwrap());
        other.initialize_modules(&ModuleId::ALL).await.unwrap();
        let other_target = desired(&other, target.module_id).await;
        applied(
            other
                .compare_and_set_instance(mutation(
                    "other-tenant",
                    &other_target,
                    None,
                    ModuleState::Starting,
                    ModuleEventType::TransitionStarted,
                ))
                .await
                .unwrap(),
        );
        assert_eq!(provider.prune_expired(1).await.unwrap(), 1);
        assert_eq!(provider.prune_expired(1).await.unwrap(), 1);
        assert_eq!(provider.prune_expired(1).await.unwrap(), 0);
        assert!(
            provider
                .read_instance("future-deadline", target.module_id)
                .await
                .unwrap()
                .is_some()
        );
        assert!(
            provider
                .read_instance("recent", target.module_id)
                .await
                .unwrap()
                .is_some()
        );
        assert!(
            other
                .read_instance("other-tenant", target.module_id)
                .await
                .unwrap()
                .is_some()
        );
        assert_eq!(desired(&provider, target.module_id).await, target);
        assert_eq!(provider.page_events(0, 100).await.unwrap().total, 4);
        assert_eq!(rows(&database, "nazo_module_desired").await.len(), 32);
    });
}
