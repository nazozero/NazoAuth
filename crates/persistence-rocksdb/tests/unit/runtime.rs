use super::*;

use crate::support::database;

fn initialize(store: &RocksDb) {
    let tx = store.transaction();
    ensure_defaults_in_tx(&tx, store.tenant_id).unwrap();
    tx.commit().unwrap();
}

fn desired(revision: u64, mode: DesiredMode) -> DesiredStateChange {
    DesiredStateChange {
        expected_revision: Some(ModuleRevision::new(revision - 1)),
        next: DesiredStateRecord {
            module_id: ModuleId::DynamicClientRegistration,
            mode,
            revision: ModuleRevision::new(revision),
            actor_id: None,
            reason: Some("contract test".into()),
            updated_at: std::time::SystemTime::now(),
        },
    }
}

#[tokio::test]
async fn tenant_defaults_match_provisioning_and_seed_events_only_once() {
    let database = database::Database::new();
    let system = database.store();
    let tenant = system.for_tenant(Uuid::now_v7());
    initialize(system);
    initialize(&tenant);

    let system_records = system.read_all_desired().await.unwrap();
    assert_eq!(
        system_records
            .iter()
            .filter(|record| record.mode == DesiredMode::Disabled)
            .map(|record| record.module_id)
            .collect::<Vec<_>>(),
        vec![
            ModuleId::DynamicClientRegistration,
            ModuleId::AuthorizationDetails,
            ModuleId::HttpMessageSignatures,
            ModuleId::ScimSecurityEvents,
            ModuleId::NativeSso,
            ModuleId::Openid4vciIssuer,
            ModuleId::Openid4vpVerifier,
        ]
    );
    assert!(
        system_records
            .iter()
            .all(|record| record.reason.as_deref() == Some("clean install baseline"))
    );

    let tenant_records = tenant.read_all_desired().await.unwrap();
    assert_eq!(
        tenant_records
            .iter()
            .filter(|record| record.mode == DesiredMode::Disabled)
            .map(|record| record.module_id)
            .collect::<Vec<_>>(),
        vec![ModuleId::HttpMessageSignatures]
    );
    let events = tenant.page_events(0, 100).await.unwrap();
    assert_eq!(events.total, ModuleId::ALL.len() as i64);
    for record in &tenant_records {
        assert_eq!(record.reason.as_deref(), Some("tenant capability defaults"));
        assert_eq!(record.revision, ModuleRevision::new(1));
        assert!(events.events.iter().any(|event| {
            event.module_id == record.module_id
                && event.event_type == ModuleEventType::DesiredStateChanged
                && event.revision == record.revision
                && event.before.is_none()
                && event.after == Some(ModuleEventState::Desired(record.mode.into()))
                && event.reason == record.reason
        }));
    }

    tenant
        .compare_and_set_desired(desired(2, DesiredMode::Disabled))
        .await
        .unwrap();
    initialize(system);
    initialize(&tenant);
    assert_eq!(system.read_all_desired().await.unwrap(), system_records);
    assert_eq!(system.page_events(0, 100).await.unwrap().total, 16);
    let current = tenant
        .read_desired(ModuleId::DynamicClientRegistration)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(current.mode, DesiredMode::Disabled);
    assert_eq!(current.revision, ModuleRevision::new(2));
    assert_eq!(tenant.page_events(0, 100).await.unwrap().total, 17);
}

#[tokio::test]
async fn desired_cas_rechecks_dependency_guards_and_audits_only_accepted_intent() {
    let database = database::Database::new();
    let db = database.store();
    initialize(db);
    let baseline = db.page_events(0, 100).await.unwrap().total;
    let change = desired(2, DesiredMode::Enabled);
    let (left, right) = tokio::join!(
        db.compare_and_set_desired(change.clone()),
        db.compare_and_set_desired(change)
    );
    let outcomes = [left.unwrap(), right.unwrap()];
    assert_eq!(
        outcomes
            .iter()
            .filter(|o| matches!(o, CasOutcome::Applied(_)))
            .count(),
        1
    );
    assert_eq!(db.page_events(0, 100).await.unwrap().total, baseline + 1);
    let guarded = db
        .compare_and_set_desired_guarded(
            desired(3, DesiredMode::Disabled),
            vec![DesiredRevisionGuard {
                module_id: ModuleId::AuthorizationDetails,
                expected_revision: Some(ModuleRevision::new(99)),
            }],
        )
        .await
        .unwrap();
    assert!(matches!(guarded, CasOutcome::Stale { current: Some(ref c) } if c.revision.get() == 2));
    assert_eq!(db.page_events(0, 100).await.unwrap().total, baseline + 1);
    let current = db
        .read_desired(ModuleId::DynamicClientRegistration)
        .await
        .unwrap()
        .unwrap();
    let outcome = db
        .compare_and_set_desired(desired(3, DesiredMode::Enabled))
        .await
        .unwrap();
    assert_eq!(outcome, CasOutcome::Applied(current.clone()));
    assert_eq!(
        db.read_desired(ModuleId::DynamicClientRegistration)
            .await
            .unwrap()
            .unwrap(),
        current
    );
    let events = db.page_events(0, 100).await.unwrap();
    assert_eq!(events.total, baseline + 2);
    assert_eq!(events.events[0].outcome_code.as_deref(), Some("noop"));
    assert!(
        db.for_tenant(Uuid::new_v4())
            .read_desired(ModuleId::DynamicClientRegistration)
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn instance_mutation_rolls_back_on_event_conflict_and_records_stale_work() {
    let database = database::Database::new();
    let db = database.store();
    initialize(db);
    db.compare_and_set_desired(desired(2, DesiredMode::Enabled))
        .await
        .unwrap();
    let mut mutation = InstanceStateMutation {
        change: InstanceStateChange {
            expected_revision: None,
            next: InstanceStateRecord {
                instance_id: "instance".into(),
                module_id: ModuleId::DynamicClientRegistration,
                state: ModuleState::Starting,
                transition_revision: ModuleRevision::new(2),
                applied_revision: None,
                drain_deadline: None,
                error_code: None,
                updated_at: std::time::SystemTime::now(),
            },
        },
        event: ModuleEventRecord {
            event_id: Uuid::new_v4().to_string(),
            module_id: ModuleId::DynamicClientRegistration,
            event_type: ModuleEventType::TransitionStarted,
            revision: ModuleRevision::new(2),
            instance_id: Some("instance".into()),
            actor_id: None,
            reason: None,
            before: None,
            after: Some(ModuleEventState::Actual(ModuleState::Starting)),
            outcome_code: None,
            occurred_at: std::time::SystemTime::now(),
        },
    };
    assert!(matches!(
        db.compare_and_set_instance(mutation.clone()).await.unwrap(),
        CasOutcome::Applied(_)
    ));
    let peer = db.for_tenant(Uuid::now_v7());
    initialize(&peer);
    let mut reused_identity = mutation.clone();
    reused_identity.change.next.transition_revision = ModuleRevision::new(1);
    reused_identity.event.revision = ModuleRevision::new(1);
    assert_eq!(
        peer.compare_and_set_instance(reused_identity)
            .await
            .unwrap_err(),
        RepositoryError::Conflict
    );
    assert!(
        peer.read_instance("instance", ModuleId::DynamicClientRegistration)
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(peer.page_events(0, 100).await.unwrap().total, 16);
    let before = db
        .read_instance("instance", ModuleId::DynamicClientRegistration)
        .await
        .unwrap()
        .unwrap();
    let count = db.page_events(0, 100).await.unwrap().total;
    mutation.change.expected_revision = Some(ModuleRevision::new(2));
    mutation.change.next.state = ModuleState::Enabled;
    mutation.change.next.applied_revision = Some(ModuleRevision::new(2));
    mutation.event.event_type = ModuleEventType::TransitionCompleted;
    mutation.event.before = Some(ModuleEventState::Actual(ModuleState::Starting));
    mutation.event.after = Some(ModuleEventState::Actual(ModuleState::Enabled));
    assert_eq!(
        db.compare_and_set_instance(mutation.clone())
            .await
            .unwrap_err(),
        RepositoryError::Conflict
    );
    assert_eq!(
        db.read_instance("instance", ModuleId::DynamicClientRegistration)
            .await
            .unwrap()
            .unwrap(),
        before
    );
    assert_eq!(db.page_events(0, 100).await.unwrap().total, count);
    db.compare_and_set_desired(desired(3, DesiredMode::Disabled))
        .await
        .unwrap();
    mutation.event.event_id = Uuid::new_v4().to_string();
    assert!(matches!(
        db.compare_and_set_instance(mutation).await.unwrap(),
        CasOutcome::Stale { .. }
    ));
    assert_eq!(
        db.read_instance("instance", ModuleId::DynamicClientRegistration)
            .await
            .unwrap()
            .unwrap(),
        before
    );
    assert!(
        db.page_events(0, 100)
            .await
            .unwrap()
            .events
            .iter()
            .any(|event| event.event_type == ModuleEventType::StaleTransitionDiscarded)
    );
}
