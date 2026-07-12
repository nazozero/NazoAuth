use std::time::{Duration, SystemTime};

use diesel::{QueryableByName, sql_query, sql_types::BigInt};
use diesel_async::{AsyncConnection, AsyncPgConnection, RunQueryDsl};
use nazo_postgres::{RuntimeModuleRepository, create_pool};
use nazo_runtime_modules::{
    CasOutcome, DesiredMode, DesiredStateChange, DesiredStateRecord, InstanceStateChange,
    InstanceStateRecord, ModuleEventRecord, ModuleEventState, ModuleEventType, ModuleId,
    ModuleRevision, ModuleState, ModuleStateRepository,
};
use uuid::Uuid;

fn database_url() -> Option<String> {
    let url = std::env::var("NAZO_TEST_DATABASE_URL")
        .or_else(|_| std::env::var("DATABASE_URL"))
        .ok();
    if url.is_none() && std::env::var_os("CI").is_some() {
        panic!("CI runtime repository tests require NAZO_TEST_DATABASE_URL or DATABASE_URL");
    }
    url
}

fn desired(module_id: ModuleId, mode: DesiredMode, revision: u64) -> DesiredStateRecord {
    DesiredStateRecord {
        module_id,
        mode,
        revision: ModuleRevision::new(revision),
        actor_id: None,
        reason: Some("runtime repository integration test".to_owned()),
        updated_at: SystemTime::now(),
    }
}

fn instance(
    instance_id: &str,
    module_id: ModuleId,
    state: ModuleState,
    revision: u64,
) -> InstanceStateRecord {
    InstanceStateRecord {
        instance_id: instance_id.to_owned(),
        module_id,
        state,
        transition_revision: ModuleRevision::new(revision),
        applied_revision: None,
        drain_deadline: None,
        error_code: None,
        updated_at: SystemTime::now(),
    }
}

#[derive(QueryableByName)]
struct EventCount {
    #[diesel(sql_type = BigInt)]
    count: i64,
}

async fn event_count(connection: &mut AsyncPgConnection, module_id: &str) -> i64 {
    sql_query("SELECT COUNT(*) AS count FROM runtime_module_state_events WHERE module_id = $1")
        .bind::<diesel::sql_types::Text, _>(module_id)
        .get_result::<EventCount>(connection)
        .await
        .expect("event count should load")
        .count
}

async fn clear_module(database_url: &str, module_id: &str) {
    let mut connection = AsyncPgConnection::establish(database_url)
        .await
        .expect("test database should connect");
    for table in [
        "runtime_module_state_events",
        "runtime_module_instance_states",
        "runtime_module_desired_states",
    ] {
        sql_query(format!("DELETE FROM {table} WHERE module_id = $1"))
            .bind::<diesel::sql_types::Text, _>(module_id)
            .execute(&mut connection)
            .await
            .expect("runtime module fixture should clear");
    }
}

#[tokio::test]
async fn desired_state_cas_is_atomic_stale_safe_and_noop_audited() {
    let Some(database_url) = database_url() else {
        return;
    };
    nazo_postgres::run_pending_migrations(&database_url)
        .await
        .expect("migrations should apply");
    clear_module(&database_url, "ciba").await;
    let pool = create_pool(&database_url, 4).expect("pool should build");
    let repository = RuntimeModuleRepository::new(pool);
    let module_id = ModuleId::Ciba;

    let applied = repository
        .compare_and_set_desired(DesiredStateChange {
            expected_revision: None,
            next: desired(module_id, DesiredMode::Enabled, 1),
        })
        .await
        .expect("initial desired state should persist");
    assert!(
        matches!(applied, CasOutcome::Applied(record) if record.revision == ModuleRevision::new(1))
    );

    let stale = repository
        .compare_and_set_desired(DesiredStateChange {
            expected_revision: None,
            next: desired(module_id, DesiredMode::Disabled, 1),
        })
        .await
        .expect("stale desired CAS should be a typed outcome");
    assert!(
        matches!(stale, CasOutcome::Stale { current: Some(record) } if record.mode == DesiredMode::Enabled)
    );

    let noop = repository
        .compare_and_set_desired(DesiredStateChange {
            expected_revision: Some(ModuleRevision::new(1)),
            next: desired(module_id, DesiredMode::Enabled, 2),
        })
        .await
        .expect("same-mode desired CAS should be accepted");
    assert!(
        matches!(noop, CasOutcome::Applied(record) if record.revision == ModuleRevision::new(1))
    );
    assert_eq!(
        repository
            .read_desired(module_id)
            .await
            .expect("desired state should load")
            .expect("desired state should exist")
            .revision,
        ModuleRevision::new(1)
    );

    let mut connection = AsyncPgConnection::establish(&database_url)
        .await
        .expect("test database should connect");
    assert_eq!(event_count(&mut connection, "ciba").await, 2);
}

#[tokio::test]
async fn instance_completion_cannot_overwrite_a_newer_transition_revision() {
    let Some(database_url) = database_url() else {
        return;
    };
    nazo_postgres::run_pending_migrations(&database_url)
        .await
        .expect("migrations should apply");
    clear_module(&database_url, "token_exchange").await;
    let repository = RuntimeModuleRepository::new(create_pool(&database_url, 4).unwrap());
    let instance_id = format!("runtime-test-{}", Uuid::now_v7());
    let module_id = ModuleId::TokenExchange;

    repository
        .compare_and_set_instance(InstanceStateChange {
            expected_revision: None,
            next: instance(&instance_id, module_id, ModuleState::Starting, 7),
        })
        .await
        .expect("initial instance state should persist");
    repository
        .compare_and_set_instance(InstanceStateChange {
            expected_revision: Some(ModuleRevision::new(7)),
            next: instance(&instance_id, module_id, ModuleState::Starting, 8),
        })
        .await
        .expect("newer transition should persist");

    let stale = repository
        .compare_and_set_instance(InstanceStateChange {
            expected_revision: Some(ModuleRevision::new(7)),
            next: instance(&instance_id, module_id, ModuleState::Enabled, 7),
        })
        .await
        .expect("stale completion should be a typed outcome");
    assert!(
        matches!(stale, CasOutcome::Stale { current: Some(record) } if record.transition_revision == ModuleRevision::new(8) && record.state == ModuleState::Starting)
    );
}

#[tokio::test]
async fn audit_persistence_accepts_every_closed_event_kind() {
    let Some(database_url) = database_url() else {
        return;
    };
    nazo_postgres::run_pending_migrations(&database_url)
        .await
        .expect("migrations should apply");
    clear_module(&database_url, "jwt_bearer_grant").await;
    let repository = RuntimeModuleRepository::new(create_pool(&database_url, 4).unwrap());
    let module_id = ModuleId::JwtBearerGrant;
    repository
        .compare_and_set_desired(DesiredStateChange {
            expected_revision: None,
            next: desired(module_id, DesiredMode::Enabled, 1),
        })
        .await
        .expect("desired event should persist atomically");

    for (index, event_type) in ModuleEventType::ALL.into_iter().enumerate().skip(1) {
        repository
            .append_event(ModuleEventRecord {
                event_id: Uuid::now_v7().to_string(),
                module_id,
                event_type,
                revision: ModuleRevision::new((index + 1) as u64),
                instance_id: Some("runtime-audit-test".to_owned()),
                actor_id: None,
                reason: Some("closed event catalog test".to_owned()),
                before: Some(ModuleEventState::Actual(ModuleState::Starting)),
                after: Some(ModuleEventState::Actual(ModuleState::Enabled)),
                outcome_code: Some("ok".to_owned()),
                occurred_at: SystemTime::UNIX_EPOCH
                    + Duration::from_secs(1_800_000_000 + index as u64),
            })
            .await
            .expect("closed event kind should persist");
    }

    let mut connection = AsyncPgConnection::establish(&database_url)
        .await
        .expect("test database should connect");
    assert_eq!(event_count(&mut connection, "jwt_bearer_grant").await, 7);
}
