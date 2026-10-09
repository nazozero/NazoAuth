use chrono::Utc;
use diesel::{QueryableByName, sql_query, sql_types};
use diesel_async::RunQueryDsl;
use nazo_postgres::{
    AuditLedgerRepository, SecurityAuditEvent, create_pool, get_conn, run_pending_migrations,
};
use serde_json::json;
use uuid::Uuid;

#[tokio::test]
async fn audit_hotpath_reuses_prepared_shapes_without_reusing_event_binds() {
    let url = std::env::var("NAZO_TEST_DATABASE_URL")
        .or_else(|_| std::env::var("DATABASE_URL"))
        .expect("isolated PostgreSQL requires NAZO_TEST_DATABASE_URL or DATABASE_URL");
    run_pending_migrations(&url).await.unwrap();
    let pool = create_pool(&url, 1).unwrap();
    let repository = AuditLedgerRepository::new(pool.clone());
    let mut events = Vec::new();
    for index in 0..3 {
        repository.check_available_with_policy(false).await.unwrap();
        let event = SecurityAuditEvent {
            event_id: Uuid::now_v7(),
            event_type: "token_issued".to_owned(),
            event_category: "token_lifecycle".to_owned(),
            payload: json!({"cache_probe":index}),
            occurred_at: Utc::now(),
        };
        repository.append(event.clone()).await.unwrap();
        events.push(event);
    }
    #[derive(QueryableByName)]
    struct Fact {
        #[diesel(sql_type=sql_types::Jsonb)]
        payload: serde_json::Value,
        #[diesel(sql_type=sql_types::Timestamptz)]
        occurred_at: chrono::DateTime<Utc>,
    }
    #[derive(QueryableByName)]
    struct Cache {
        #[diesel(sql_type=sql_types::BigInt)]
        preflight: i64,
        #[diesel(sql_type=sql_types::BigInt)]
        append: i64,
        #[diesel(sql_type=sql_types::BigInt)]
        executions: i64,
    }
    let mut c = get_conn(&pool).await.unwrap();
    for event in events {
        let row =
            sql_query("SELECT payload,occurred_at FROM security_audit_events WHERE event_id=$1")
                .bind::<sql_types::Uuid, _>(event.event_id)
                .get_result::<Fact>(&mut c)
                .await
                .unwrap();
        assert_eq!(row.payload, event.payload);
        assert_eq!(
            row.occurred_at.timestamp_micros(),
            event.occurred_at.timestamp_micros()
        );
    }
    let cache=sql_query("SELECT count(*) FILTER(WHERE statement LIKE 'SELECT policy_satisfied FROM public.nazo_security_audit_shared_privilege_preflight(%')::bigint AS preflight, count(*) FILTER(WHERE statement LIKE 'SELECT public.nazo_persist_security_audit_event(%')::bigint AS append, coalesce(sum(generic_plans+custom_plans),0)::bigint AS executions FROM pg_prepared_statements WHERE statement LIKE 'SELECT policy_satisfied FROM public.nazo_security_audit_shared_privilege_preflight(%' OR statement LIKE 'SELECT public.nazo_persist_security_audit_event(%'")
        .get_result::<Cache>(&mut c).await.unwrap();
    eprintln!(
        "HOTPATH_CACHE preflight={} append={} executions={} distinct_events=3",
        cache.preflight, cache.append, cache.executions
    );
    assert_eq!(
        (cache.preflight, cache.append),
        (1, 1),
        "constant function calls must reuse their two prepared shapes"
    );
    assert_eq!(cache.executions, 6);
}
