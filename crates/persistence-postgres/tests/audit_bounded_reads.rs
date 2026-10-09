//! Exercise the real exporter SQL with a small cached pending estimate and a large backlog.
use diesel::{
    QueryableByName, sql_query,
    sql_types::{Array, BigInt, Binary, Bool, Integer, Json, Uuid as SqlUuid},
};
use diesel_async::{AsyncConnection, AsyncPgConnection, RunQueryDsl, SimpleAsyncConnection};
use nazo_postgres::run_pending_migrations;
use serde_json::Value;
use uuid::Uuid;

#[derive(QueryableByName)]
struct EventId {
    #[diesel(sql_type = SqlUuid)]
    event_id: Uuid,
}
#[derive(QueryableByName)]
struct Generation {
    #[diesel(sql_type = BigInt)]
    generation: i64,
}
#[derive(QueryableByName)]
struct Boolean {
    #[diesel(sql_type = Bool)]
    value: bool,
}
#[derive(QueryableByName)]
struct Explain {
    #[diesel(column_name = "QUERY PLAN", sql_type = Json)]
    plan: Value,
}

const FINALIZE: &str =
    "SELECT public.nazo_finalize_security_audit_claim($1,$2,$3,$4,$5,$6,$7,$8,60) AS generation";
const ACK: &str = "SELECT public.nazo_ack_security_audit_batch($1,$2,$3,256,$4,$5,'bounded-read-fixture') AS value";

#[tokio::test]
async fn exporter_identity_reads_stay_bounded_when_pending_statistics_are_stale() {
    let Ok(url) = std::env::var("NAZO_AUDIT_TEST_DATABASE_URL") else {
        assert!(
            std::env::var_os("CI").is_none(),
            "CI requires the isolated audit database"
        );
        return;
    };
    assert!(
        url.contains("audit_test"),
        "never seed an application database"
    );
    run_pending_migrations(&url).await.unwrap();
    let mut connection = AsyncPgConnection::establish(&url).await.unwrap();
    // Replacing either function must preserve its identity, owner, ACL and
    // security mode; downgrade/upgrade must restore the exact candidate body.
    let identity = "SELECT json_agg(json_build_array(oid::bigint,proowner::bigint,proacl::text,prosecdef,proconfig,pg_get_functiondef(oid)) ORDER BY oid) AS identity FROM pg_proc WHERE oid IN ('public.nazo_stage_security_audit_chain(bigint,bytea,uuid[],bytea[])'::regprocedure,'public.nazo_ack_security_audit_batch(bigint,bigint,bigint,integer,bytea,bytea,text)'::regprocedure)";
    #[derive(QueryableByName)]
    struct Identity {
        #[diesel(sql_type = Json)]
        identity: Value,
    }
    let before = sql_query(identity)
        .get_result::<Identity>(&mut connection)
        .await
        .unwrap()
        .identity;
    connection.batch_execute("BEGIN").await.unwrap();
    connection
        .batch_execute(include_str!(
            "../../../migrations/20261008000100_audit_exporter_bounded_identity_reads/down.sql"
        ))
        .await
        .unwrap();
    connection
        .batch_execute(include_str!(
            "../../../migrations/20261008000100_audit_exporter_bounded_identity_reads/up.sql"
        ))
        .await
        .unwrap();
    let after = sql_query(identity)
        .get_result::<Identity>(&mut connection)
        .await
        .unwrap()
        .identity;
    connection.batch_execute("ROLLBACK").await.unwrap();
    assert_eq!(
        before, after,
        "migration round trip changed function identity or privileges"
    );
    // All fixture rows, planner statistics and table options roll back together.
    connection.batch_execute("BEGIN; SET LOCAL plan_cache_mode=force_generic_plan; SET LOCAL nazo.audit_reclaim='on'; ALTER TABLE public.security_audit_events SET (autovacuum_enabled=false); DELETE FROM public.security_audit_chain_entries; DELETE FROM public.security_audit_events; UPDATE public.security_audit_chain_state SET last_sequence=0,last_hash=decode(repeat('00',32),'hex'),anchor_deployment_id='bounded-read-fixture',anchor_sequence=0,anchor_hash=decode(repeat('00',32),'hex'),anchor_occurred_at=clock_timestamp(),anchor_accepted_at=clock_timestamp(),anchor_observed_at=clock_timestamp(),batch_first_sequence=NULL,batch_last_sequence=NULL,batch_event_count=NULL,batch_digest=NULL,batch_generation=0,batch_attempts=0,batch_available_at=NULL,batch_locked_until=NULL,batch_last_error=NULL,batch_blocked_reason=NULL WHERE singleton").await.unwrap();
    sql_query("INSERT INTO public.security_audit_events (event_id,event_type,event_category,payload,occurred_at,authorization_tenant_id,authorization_request_id,authorization_decision,authorization_valid_until,business_retain_until,exported_at) SELECT gen_random_uuid(),'authorization_decision_committed','authorization','{}'::jsonb,CURRENT_TIMESTAMP,'00000000-0000-0000-0000-000000000001'::uuid,'bounded-'||g,'deny',CURRENT_TIMESTAMP+interval '1 hour',CURRENT_TIMESTAMP+interval '2 hours',CURRENT_TIMESTAMP FROM generate_series(1,100000) g")
        .execute(&mut connection).await.unwrap();
    // Preserve realistic stale estimates after a delivered chain prefix leaves.
    sql_query("INSERT INTO public.security_audit_chain_entries(event_id,sequence,previous_hash,event_hash) SELECT event_id,row_number() OVER (ORDER BY event_id),decode(repeat('00',32),'hex'),decode(md5(event_id::text)||md5(event_id::text||'fixture'),'hex') FROM public.security_audit_events ORDER BY event_id LIMIT 20000").execute(&mut connection).await.unwrap();
    connection.batch_execute("ANALYZE public.security_audit_events,public.security_audit_chain_entries; DELETE FROM public.security_audit_chain_entries").await.unwrap();
    let warm = sql_query("INSERT INTO public.security_audit_events(event_id,event_type,event_category,payload,occurred_at) SELECT gen_random_uuid(),'token_issued','token_lifecycle','{}'::jsonb,CURRENT_TIMESTAMP+(g||' microseconds')::interval FROM generate_series(1,256) g RETURNING event_id")
        .load::<EventId>(&mut connection).await.unwrap().into_iter().map(|r|r.event_id).collect::<Vec<_>>();
    let hashes = warm
        .iter()
        .map(|id| blake3::hash(id.as_bytes()).as_bytes().to_vec())
        .collect::<Vec<_>>();
    let warm_head = hashes.last().unwrap().clone();
    let generation = sql_query(FINALIZE)
        .bind::<BigInt, _>(0_i64)
        .bind::<Binary, _>(vec![0_u8; 32])
        .bind::<Array<SqlUuid>, _>(&warm)
        .bind::<Array<Binary>, _>(&hashes)
        .bind::<BigInt, _>(1_i64)
        .bind::<BigInt, _>(256_i64)
        .bind::<Integer, _>(256_i32)
        .bind::<Binary, _>(vec![3_u8; 32])
        .get_result::<Generation>(&mut connection)
        .await
        .unwrap()
        .generation;
    assert!(
        sql_query(ACK)
            .bind::<BigInt, _>(generation)
            .bind::<BigInt, _>(1_i64)
            .bind::<BigInt, _>(256_i64)
            .bind::<Binary, _>(warm_head.clone())
            .bind::<Binary, _>(vec![3_u8; 32])
            .get_result::<Boolean>(&mut connection)
            .await
            .unwrap()
            .value
    );
    // Keep the cached plans/statistics from 256 pending rows while the actual
    // pending set grows. Retained decisions make a pending-index walk appear
    // cheaper than the primary-key lookup unless identity resolution is isolated.
    sql_query("INSERT INTO public.security_audit_events(event_id,event_type,event_category,payload,occurred_at) SELECT gen_random_uuid(),'token_issued','token_lifecycle','{}'::jsonb,CURRENT_TIMESTAMP+(g||' microseconds')::interval FROM generate_series(1,100000) g").execute(&mut connection).await.unwrap();
    let ids=sql_query("SELECT event_id FROM public.security_audit_events WHERE exported_at IS NULL ORDER BY occurred_at,event_id LIMIT 256").load::<EventId>(&mut connection).await.unwrap().into_iter().map(|r|r.event_id).collect::<Vec<_>>();
    connection
        .batch_execute("SET LOCAL statement_timeout='30s'")
        .await
        .unwrap();
    let hashes = ids
        .iter()
        .map(|id| blake3::hash(id.as_bytes()).as_bytes().to_vec())
        .collect::<Vec<_>>();
    let next_head = hashes.last().unwrap().clone();
    let staged = sql_query(format!("EXPLAIN (ANALYZE,BUFFERS,FORMAT JSON) {FINALIZE}"))
        .bind::<BigInt, _>(256_i64)
        .bind::<Binary, _>(warm_head.clone())
        .bind::<Array<SqlUuid>, _>(&ids)
        .bind::<Array<Binary>, _>(&hashes)
        .bind::<BigInt, _>(257_i64)
        .bind::<BigInt, _>(512_i64)
        .bind::<Integer, _>(256_i32)
        .bind::<Binary, _>(vec![4_u8; 32])
        .get_result::<Explain>(&mut connection)
        .await
        .unwrap()
        .plan;
    let acknowledged = sql_query(format!("EXPLAIN (ANALYZE,BUFFERS,FORMAT JSON) {ACK}"))
        .bind::<BigInt, _>(generation + 1)
        .bind::<BigInt, _>(257_i64)
        .bind::<BigInt, _>(512_i64)
        .bind::<Binary, _>(next_head)
        .bind::<Binary, _>(vec![4_u8; 32])
        .get_result::<Explain>(&mut connection)
        .await
        .unwrap()
        .plan;
    let checkpoint=sql_query("SELECT last_sequence=512 AND anchor_sequence=512 AND batch_last_sequence IS NULL AND (SELECT count(*) FROM public.security_audit_events WHERE exported_at IS NULL)=99744 AS value FROM public.security_audit_chain_state WHERE singleton").get_result::<Boolean>(&mut connection).await.unwrap().value;
    connection.batch_execute("ROLLBACK").await.unwrap();
    assert!(
        checkpoint,
        "the real finalize/ACK must consume exactly the selected prefix"
    );
    for (name, plan) in [("finalize", staged), ("ack", acknowledged)] {
        let node = &plan[0]["Plan"];
        let blocks = node["Shared Hit Blocks"].as_u64().unwrap()
            + node["Shared Read Blocks"].as_u64().unwrap();
        eprintln!("{name}: shared_blocks={blocks}; actual_plan={plan}");
        // Logical reads, not elapsed time: shared CPU scheduling cannot make
        // a correct 256-identity query read the entire 100k pending set.
        assert!(
            blocks < 32768,
            "{name} read {blocks} shared blocks for only 256 identities"
        );
    }
}
