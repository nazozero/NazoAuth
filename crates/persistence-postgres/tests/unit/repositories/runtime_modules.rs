use super::desired::next_desired_revision;
use super::*;

#[test]
fn desired_revision_exhaustion_is_rejected_without_saturation() {
    assert_eq!(next_desired_revision(None).unwrap(), 1);
    assert_eq!(
        next_desired_revision(Some(ModuleRevision::new(41))).unwrap(),
        42
    );
    assert!(matches!(
        next_desired_revision(Some(ModuleRevision::new(u64::MAX))),
        Err(RepositoryError::Consistency(message))
            if message == "desired revision space is exhausted"
    ));
}

#[tokio::test]
async fn related_revision_guards_share_one_query_and_keep_stale_changes_uncommitted() {
    use crate::repositories::query_counter::QueryCounter;
    use diesel::{ExpressionMethods as _, QueryDsl as _};
    use diesel_async::{AsyncConnection as _, RunQueryDsl as _};
    use nazo_runtime_modules::DesiredMode;

    let Ok(url) =
        std::env::var("NAZO_TEST_DATABASE_URL").or_else(|_| std::env::var("DATABASE_URL"))
    else {
        assert!(
            std::env::var_os("CI").is_none(),
            "CI requires a test database"
        );
        return;
    };
    let pool = crate::create_pool(url, 1).unwrap();
    let repository = RuntimeModuleRepository::new(pool.clone());
    let counter = QueryCounter::new();
    let target = ModuleId::AuthorizationDetails;
    let first = ModuleId::HttpMessageSignatures;
    let second = ModuleId::FrontchannelLogout;
    let mut connection = crate::get_conn(&pool).await.unwrap();
    connection.begin_test_transaction().await.unwrap();
    use crate::schema::runtime_module_desired_states as states;
    let seeded = diesel::update(
        states::table
            .filter(states::tenant_id.eq(repository.tenant_id()))
            .filter(states::module_id.eq_any([
                "authorization_details",
                "http_message_signatures",
                "frontchannel_logout",
            ])),
    )
    .set((
        states::revision.eq(1_i64),
        states::desired_mode.eq("disabled"),
    ))
    .execute(&mut connection)
    .await
    .unwrap();
    assert_eq!(seeded, 3);
    connection.set_instrumentation(counter.clone());
    drop(connection);

    let change = || DesiredStateChange {
        expected_revision: Some(ModuleRevision::new(1)),
        next: DesiredStateRecord {
            module_id: target,
            mode: DesiredMode::Enabled,
            revision: ModuleRevision::new(2),
            actor_id: None,
            reason: None,
            updated_at: std::time::SystemTime::now(),
        },
    };
    let stale = DesiredRevisionGuard {
        module_id: first,
        expected_revision: Some(ModuleRevision::new(2)),
    };
    let baseline = counter.snapshot();
    let result = repository
        .compare_and_set_desired_guarded(change(), vec![stale])
        .await
        .unwrap();
    assert!(
        matches!(result, CasOutcome::Stale { current: Some(record) } if record.revision == ModuleRevision::new(1))
    );
    let one_guard = counter.since(baseline).data_queries;

    let baseline = counter.snapshot();
    let result = repository
        .compare_and_set_desired_guarded(
            change(),
            vec![
                DesiredRevisionGuard {
                    module_id: second,
                    expected_revision: Some(ModuleRevision::new(1)),
                },
                stale,
            ],
        )
        .await
        .unwrap();
    assert!(
        matches!(result, CasOutcome::Stale { current: Some(record) } if record.revision == ModuleRevision::new(1))
    );
    assert_eq!(
        counter.since(baseline).data_queries,
        one_guard,
        "target and guard rows are locked and read together regardless of guard count"
    );
    let result = repository
        .compare_and_set_desired_guarded(
            change(),
            [first, second]
                .into_iter()
                .map(|module_id| DesiredRevisionGuard {
                    module_id,
                    expected_revision: Some(ModuleRevision::new(1)),
                })
                .collect(),
        )
        .await
        .unwrap();
    assert!(
        matches!(result, CasOutcome::Applied(record) if record.revision == ModuleRevision::new(2))
    );
}
