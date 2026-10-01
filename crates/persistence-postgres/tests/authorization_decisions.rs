//! Focused decision-commit and retained audit-fact lifecycle coverage.
//! Requires an isolated test PostgreSQL with CREATE DATABASE permission.
//! Run serially; no deployment database or state store is used.

use chrono::{Duration, Utc};
use diesel::{QueryableByName, sql_query, sql_types};
use diesel_async::{AsyncConnection, AsyncPgConnection, RunQueryDsl, SimpleAsyncConnection};
use nazo_auth::{
    AuthorizationDecisionCommit, AuthorizationDecisionCommitResult as Outcome,
    AuthorizationDecisionKind as Kind, AuthorizationRepositoryPort,
};
use nazo_persistence::{SecurityAuditBatchAck, SecurityAuditBatchClaim};
use nazo_postgres::{
    AuditLedgerRepository, AuthorizationFlowRepository, DbPool, SecurityAuditEvent, create_pool,
};
use serde_json::json;
use uuid::Uuid;

const UP: &str =
    include_str!("../../../migrations/20261001000100_authorization_decision_facts/up.sql");
const DOWN: &str =
    include_str!("../../../migrations/20261001000100_authorization_decision_facts/down.sql");

#[test]
fn decision_migration_has_independent_fences_and_safe_retention() {
    for required in [
        "idx_authorization_decision_request",
        "idx_authorization_decision_par",
        "authorization_tenant_id IS NOT NULL",
        "authorization_request_id IS NOT NULL",
        "authorization_decision IS NOT NULL",
        "AND business_retain_until >= authorization_valid_until",
        "WHERE exported_at IS NULL",
        "'public.idx_security_audit_events_pending_order'::REGCLASS",
        "AND candidate.exported_at IS NULL",
        "audit chain event is missing or already exported",
        "OLD.exported_at IS NULL AND NEW.exported_at IS NOT NULL",
        "(to_jsonb(OLD) - 'exported_at') = (to_jsonb(NEW) - 'exported_at')",
        "LIMIT 256 FOR UPDATE SKIP LOCKED",
        "EXCEPTION WHEN SQLSTATE 'PZA01'",
    ] {
        assert!(UP.contains(required), "missing contract: {required}");
    }
    assert!(DOWN.contains("refusing unsafe downgrade"));
}

fn database_url() -> Option<String> {
    let url = std::env::var("NAZO_TEST_DATABASE_URL")
        .or_else(|_| std::env::var("DATABASE_URL"))
        .ok();
    if url.is_none() && std::env::var_os("CI").is_some() {
        panic!("CI decision tests require an isolated NAZO_TEST_DATABASE_URL or DATABASE_URL");
    }
    url
}

#[derive(QueryableByName)]
struct CountRow {
    #[diesel(sql_type = sql_types::BigInt)]
    count: i64,
}

#[derive(QueryableByName)]
struct Fixture {
    #[diesel(sql_type = sql_types::Uuid)]
    user_id: Uuid,
    #[diesel(sql_type = sql_types::Uuid)]
    client_id: Uuid,
    #[diesel(sql_type = sql_types::Text)]
    client_public_id: String,
    #[diesel(sql_type = sql_types::Uuid)]
    tenant_id: Uuid,
}

async fn fixture(connection: &mut AsyncPgConnection) -> Fixture {
    let suffix = Uuid::now_v7().simple().to_string();
    sql_query(format!(
        r#"
        WITH actor AS (
            INSERT INTO users (username, email, password_hash)
            VALUES ('decision-{suffix}', 'decision-{suffix}@example.test', 'test-only-hash')
            RETURNING id, tenant_id
        ), client AS (
            INSERT INTO oauth_clients (
                client_id, client_name, client_type, redirect_uris, scopes, grant_types,
                token_endpoint_auth_method, security_policy
            ) VALUES (
                'decision-{suffix}', 'Decision Atomicity Test', 'confidential',
                '["https://client.example/callback"]'::jsonb, '["openid"]'::jsonb,
                '["authorization_code"]'::jsonb, 'client_secret_basic',
                '{{"version":1,"assurance":"baseline","require_signed_authorization_request":false,"require_signed_authorization_response":false,"require_signed_introspection_response":false,"session_management":false,"allow_cross_device_flows":false,"allow_confidential_oidc_without_pkce":false}}'::jsonb
            ) RETURNING id, client_id
        )
        SELECT actor.id AS user_id, actor.tenant_id, client.id AS client_id,
               client.client_id AS client_public_id FROM actor CROSS JOIN client
        "#
    ))
    .get_result::<Fixture>(connection)
    .await
    .expect("decision fixture should insert")
}

fn decision(fixture: &Fixture, kind: Kind) -> AuthorizationDecisionCommit {
    let now = Utc::now();
    AuthorizationDecisionCommit {
        tenant_id: fixture.tenant_id,
        user_id: fixture.user_id,
        client_id: fixture.client_public_id.clone(),
        request_id: Uuid::now_v7().to_string(),
        pushed_request_uri: Some(format!(
            "urn:ietf:params:oauth:request_uri:{}",
            Uuid::now_v7()
        )),
        valid_until: now + Duration::minutes(5),
        retain_until: now + Duration::minutes(10),
        decision: kind,
        event_id: Uuid::now_v7(),
        occurred_at: now,
        audit_fields: if kind == Kind::Deny {
            json!({})
        } else {
            json!({
                "code_id": Uuid::now_v7().to_string(),
                "code_hash": "ab".repeat(32),
                "code_payload_digest": "cd".repeat(32),
            })
        },
        scopes: vec!["openid".to_owned()],
        resource_indicators: Vec::new(),
        authorization_details: json!([]),
    }
}

async fn fact_count(connection: &mut AsyncPgConnection, event_id: Uuid) -> i64 {
    sql_query(
        "SELECT COUNT(*)::bigint AS count FROM public.security_audit_events WHERE event_id = $1",
    )
    .bind::<sql_types::Uuid, _>(event_id)
    .get_result::<CountRow>(connection)
    .await
    .unwrap()
    .count
}

async fn grant_count(connection: &mut AsyncPgConnection, fixture: &Fixture) -> i64 {
    sql_query(
        "SELECT COALESCE(SUM(authorization_count), 0)::bigint AS count \
         FROM user_client_grants WHERE tenant_id = $1 AND user_id = $2 AND client_id = $3",
    )
    .bind::<sql_types::Uuid, _>(fixture.tenant_id)
    .bind::<sql_types::Uuid, _>(fixture.user_id)
    .bind::<sql_types::Uuid, _>(fixture.client_id)
    .get_result::<CountRow>(connection)
    .await
    .unwrap()
    .count
}

async fn cleanup(connection: &mut AsyncPgConnection) -> i64 {
    sql_query("SELECT public.nazo_cleanup_authorization_decisions() AS count")
        .get_result::<CountRow>(connection)
        .await
        .unwrap()
        .count
}

async fn wait_for_lock(connection: &mut AsyncPgConnection, application: &str) {
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            let row = sql_query(
                "SELECT COUNT(*)::bigint AS count FROM pg_stat_activity \
                 WHERE application_name = $1 AND wait_event_type = 'Lock'",
            )
            .bind::<sql_types::Text, _>(application)
            .get_result::<CountRow>(connection)
            .await
            .unwrap();
            if row.count > 0 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("decision transaction should reach its deliberate lock wait");
}

async fn acknowledge_all(audit: &AuditLedgerRepository) {
    tokio::time::timeout(std::time::Duration::from_secs(20), async {
        loop {
            match audit
                .claim_batch("decision-test", 256, 1024 * 1024, 30)
                .await
                .unwrap()
            {
                SecurityAuditBatchClaim::Claimed(batch) => {
                    audit
                        .ack_batch(SecurityAuditBatchAck {
                            generation: batch.generation,
                            deployment_id: "decision-test".to_owned(),
                            first_sequence: batch.first_sequence,
                            last_sequence: batch.last_sequence,
                            event_count: batch.event_count(),
                            last_hash: batch.last_hash,
                            batch_digest: batch.digest,
                        })
                        .await
                        .unwrap();
                }
                SecurityAuditBatchClaim::Empty => break,
                other => panic!("isolated audit claim must not be busy or blocked: {other:?}"),
            }
        }
    })
    .await
    .expect("bounded audit drain should finish");
}

async fn verify_upgrade_privileges(url: &str, connection: &mut AsyncPgConnection, pool: &DbPool) {
    let audit = AuditLedgerRepository::new(pool.clone());
    audit
        .append(SecurityAuditEvent {
            event_id: Uuid::now_v7(),
            event_type: "decision_upgrade_test".to_owned(),
            event_category: "authorization".to_owned(),
            payload: json!({"schema_version": "nazo.audit.v1"}),
            occurred_at: Utc::now(),
        })
        .await
        .unwrap();
    let SecurityAuditBatchClaim::Claimed(batch) = audit
        .claim_batch("decision-test", 256, 1024 * 1024, 30)
        .await
        .unwrap()
    else {
        panic!("upgrade fixture must own an in-flight batch");
    };
    // No decision facts exist yet. Move back to the real prior schema, with
    // its in-flight ordinary batch intact, then exercise the new migration.
    connection.batch_execute(DOWN).await.unwrap();
    let suffix = Uuid::now_v7().simple().to_string();
    let audit_only = format!("decision_audit_{suffix}");
    let insert_only = format!("decision_insert_{suffix}");
    let update_only = format!("decision_update_{suffix}");
    let runtime = format!("decision_runtime_{suffix}");
    connection.batch_execute(&format!(
        "CREATE ROLE {audit_only}; CREATE ROLE {insert_only}; \
         CREATE ROLE {update_only}; CREATE ROLE {runtime}; \
         GRANT EXECUTE ON FUNCTION public.nazo_persist_security_audit_event(UUID,TEXT,TEXT,JSONB,TIMESTAMPTZ) \
         TO {audit_only},{insert_only},{update_only},{runtime}; \
         GRANT SELECT ON public.users,public.oauth_clients TO {insert_only},{update_only},{runtime}; \
         GRANT INSERT ON public.user_client_grants TO {insert_only},{runtime}; \
         GRANT UPDATE ON public.user_client_grants TO {update_only},{runtime}"
    )).await.unwrap();
    connection.batch_execute(UP).await.unwrap();
    for (role, expected) in [
        (&audit_only, 0),
        (&insert_only, 0),
        (&update_only, 0),
        (&runtime, 1),
    ] {
        let row = sql_query(
            "SELECT COUNT(*)::bigint AS count FROM pg_roles WHERE rolname = $1 \
             AND has_function_privilege(oid, \
             'public.nazo_commit_authorization_decision(uuid,uuid,text,text,text,timestamptz,timestamptz,text,uuid,timestamptz,jsonb,jsonb,jsonb,jsonb)', 'EXECUTE')",
        ).bind::<sql_types::Text, _>(role).get_result::<CountRow>(connection).await.unwrap();
        assert_eq!(
            row.count, expected,
            "audit-only or partial grant roles must not acquire business authority"
        );
    }
    nazo_postgres::configure_runtime_role(url, &runtime)
        .await
        .unwrap();
    let boundaries = sql_query(
        "SELECT COUNT(*)::bigint AS count FROM pg_roles WHERE rolname = $1 \
         AND has_function_privilege(oid, \
         'public.nazo_commit_authorization_decision(uuid,uuid,text,text,text,timestamptz,timestamptz,text,uuid,timestamptz,jsonb,jsonb,jsonb,jsonb)', 'EXECUTE') \
         AND has_function_privilege(oid, 'public.nazo_cleanup_authorization_decisions()', 'EXECUTE') \
         AND NOT has_table_privilege(oid, 'public.security_audit_events', 'SELECT,INSERT,UPDATE,DELETE')",
    ).bind::<sql_types::Text, _>(&runtime).get_result::<CountRow>(connection).await.unwrap();
    assert_eq!(
        boundaries.count, 1,
        "runtime uses narrow APIs, never direct event-table DML"
    );
    // Exercise the real adapter under the production runtime grants, not the
    // migration owner. The pool's effective role is restricted on every checkout.
    let restricted_fixture = fixture(connection).await;
    let mut runtime_url = url::Url::parse(url).unwrap();
    runtime_url
        .query_pairs_mut()
        .append_pair("options", &format!("-crole={runtime}"));
    let runtime_pool = create_pool(runtime_url.to_string(), 1).unwrap();
    let restricted =
        AuthorizationFlowRepository::new(runtime_pool.clone(), restricted_fixture.tenant_id);
    assert_eq!(
        restricted
            .commit_decision(decision(&restricted_fixture, Kind::Approve))
            .await
            .unwrap(),
        Outcome::Committed
    );
    assert_eq!(
        restricted
            .commit_decision(decision(&restricted_fixture, Kind::PromptNone))
            .await
            .unwrap(),
        Outcome::Committed
    );
    assert_eq!(grant_count(connection, &restricted_fixture).await, 1);
    let mut restricted_connection = nazo_postgres::get_conn(&runtime_pool).await.unwrap();
    for statement in [
        "INSERT INTO public.security_audit_events (event_id,event_type,event_category,payload,occurred_at) VALUES (uuidv7(),'test','authorization','{}',CURRENT_TIMESTAMP)",
        "UPDATE public.security_audit_events SET event_category = 'test' WHERE FALSE",
        "DELETE FROM public.security_audit_events WHERE FALSE",
        "SELECT public.nazo_persist_security_audit_event(uuidv7(),'authorization_decision_committed','authorization','{}',CURRENT_TIMESTAMP)",
    ] {
        assert!(
            sql_query(statement)
                .execute(&mut restricted_connection)
                .await
                .is_err(),
            "restricted role must reject: {statement}"
        );
    }
    drop(restricted_connection);
    drop(restricted);
    drop(runtime_pool);
    audit
        .ack_batch(SecurityAuditBatchAck {
            generation: batch.generation,
            deployment_id: "decision-test".to_owned(),
            first_sequence: batch.first_sequence,
            last_sequence: batch.last_sequence,
            event_count: batch.event_count(),
            last_hash: batch.last_hash,
            batch_digest: batch.digest,
        })
        .await
        .unwrap();
    for role in [&audit_only, &insert_only, &update_only, &runtime] {
        connection
            .batch_execute(&format!("DROP OWNED BY {role}; DROP ROLE {role}"))
            .await
            .unwrap();
    }
}

async fn verify_atomicity(connection: &mut AsyncPgConnection, pool: &DbPool, fixture: &Fixture) {
    let repository = AuthorizationFlowRepository::new(pool.clone(), fixture.tenant_id);
    let approve = decision(fixture, Kind::Approve);
    let mut deny = decision(fixture, Kind::Deny);
    deny.pushed_request_uri = approve.pushed_request_uri.clone();
    let (approved, denied) = tokio::join!(
        repository.commit_decision(approve.clone()),
        repository.commit_decision(deny.clone()),
    );
    let approved = approved.unwrap();
    let denied = denied.unwrap();
    assert!(matches!(
        (approved, denied),
        (Outcome::Committed, Outcome::Conflict) | (Outcome::Conflict, Outcome::Committed)
    ));
    assert_eq!(
        fact_count(connection, approve.event_id).await
            + fact_count(connection, deny.event_id).await,
        1
    );
    assert_eq!(
        grant_count(connection, fixture).await,
        i64::from(approved == Outcome::Committed)
    );
    let winner = if approved == Outcome::Committed {
        approve
    } else {
        deny
    };
    let mut repeated_request = decision(fixture, Kind::Approve);
    repeated_request.request_id = winner.request_id.clone();
    assert_eq!(
        repository.commit_decision(repeated_request).await.unwrap(),
        Outcome::Conflict
    );

    // An explicit grant is counted exactly once; prompt-none uses the same
    // durable fence but the already granted coverage is not a new approval.
    let explicit = decision(fixture, Kind::Approve);
    assert_eq!(
        repository.commit_decision(explicit).await.unwrap(),
        Outcome::Committed
    );
    let before = grant_count(connection, fixture).await;
    let silent = decision(fixture, Kind::PromptNone);
    assert_eq!(
        repository.commit_decision(silent.clone()).await.unwrap(),
        Outcome::Committed
    );
    assert_eq!(grant_count(connection, fixture).await, before);
    assert_eq!(
        repository.commit_decision(silent).await.unwrap(),
        Outcome::Conflict
    );
    let mut uncovered = decision(fixture, Kind::PromptNone);
    uncovered.scopes.push("email".to_owned());
    assert_eq!(
        repository.commit_decision(uncovered.clone()).await.unwrap(),
        Outcome::GrantUnavailable
    );
    assert_eq!(fact_count(connection, uncovered.event_id).await, 0);
    let denied = decision(fixture, Kind::Deny);
    assert_eq!(
        repository.commit_decision(denied).await.unwrap(),
        Outcome::Committed
    );
    assert_eq!(grant_count(connection, fixture).await, before);

    let mut expired = decision(fixture, Kind::Approve);
    expired.valid_until = Utc::now() - Duration::seconds(1);
    assert_eq!(
        repository.commit_decision(expired.clone()).await.unwrap(),
        Outcome::Expired
    );
    assert_eq!(fact_count(connection, expired.event_id).await, 0);
    let mut foreign = decision(fixture, Kind::Approve);
    foreign.tenant_id = Uuid::now_v7();
    assert!(repository.commit_decision(foreign).await.is_err());
    sql_query("UPDATE users SET is_active = FALSE WHERE id = $1")
        .bind::<sql_types::Uuid, _>(fixture.user_id)
        .execute(connection)
        .await
        .unwrap();
    let disabled = decision(fixture, Kind::Approve);
    assert_eq!(
        repository.commit_decision(disabled.clone()).await.unwrap(),
        Outcome::ClientUnavailable
    );
    assert_eq!(fact_count(connection, disabled.event_id).await, 0);
    sql_query("UPDATE users SET is_active = TRUE WHERE id = $1")
        .bind::<sql_types::Uuid, _>(fixture.user_id)
        .execute(connection)
        .await
        .unwrap();

    // Force a database failure AFTER fact insertion, at the grant mutation.
    connection
        .batch_execute(
            "CREATE FUNCTION decision_test_fail_grant() RETURNS trigger LANGUAGE plpgsql AS $$ \
         BEGIN RAISE EXCEPTION 'injected grant failure'; END $$; \
         CREATE TRIGGER decision_test_fail_grant BEFORE INSERT OR UPDATE ON user_client_grants \
         FOR EACH ROW EXECUTE FUNCTION decision_test_fail_grant()",
        )
        .await
        .unwrap();
    let failed = decision(fixture, Kind::Approve);
    assert!(repository.commit_decision(failed.clone()).await.is_err());
    assert_eq!(fact_count(connection, failed.event_id).await, 0);
    assert_eq!(grant_count(connection, fixture).await, before);
    connection
        .batch_execute(
            "DROP TRIGGER decision_test_fail_grant ON user_client_grants; \
         DROP FUNCTION decision_test_fail_grant()",
        )
        .await
        .unwrap();
}

async fn verify_lock_expiry_and_cancellation(
    url: &str,
    connection: &mut AsyncPgConnection,
    fixture: &Fixture,
) {
    let mut tagged = url::Url::parse(url).unwrap();
    let application = format!("decision-lock-{}", Uuid::now_v7().simple());
    tagged
        .query_pairs_mut()
        .append_pair("application_name", &application);
    let pool = create_pool(tagged.to_string(), 1).unwrap();
    let repository = AuthorizationFlowRepository::new(pool.clone(), fixture.tenant_id);
    let mut blocker = AsyncPgConnection::establish(url).await.unwrap();
    blocker.batch_execute("BEGIN").await.unwrap();
    sql_query("SELECT authorization_count::bigint AS count FROM user_client_grants WHERE user_id = $1 FOR UPDATE")
        .bind::<sql_types::Uuid, _>(fixture.user_id).get_result::<CountRow>(&mut blocker).await.unwrap();
    let mut expiring = decision(fixture, Kind::Approve);
    expiring.valid_until = Utc::now() + Duration::milliseconds(800);
    let event_id = expiring.event_id;
    let writer = repository.clone();
    let pending = tokio::spawn(async move { writer.commit_decision(expiring).await });
    wait_for_lock(connection, &application).await;
    tokio::time::sleep(std::time::Duration::from_millis(850)).await;
    blocker.batch_execute("ROLLBACK").await.unwrap();
    assert_eq!(pending.await.unwrap().unwrap(), Outcome::Expired);
    assert_eq!(fact_count(connection, event_id).await, 0);

    // Wait on the PAR unique fence AFTER the candidate's early expiry check.
    // The blocking fact rolls back, so the candidate really inserts and mutates
    // the grant before its final PZA01 branch must roll both changes back.
    let mut late = decision(fixture, Kind::Approve);
    late.valid_until = Utc::now() + Duration::milliseconds(800);
    let event_id = late.event_id;
    let before = grant_count(connection, fixture).await;
    blocker.batch_execute("BEGIN").await.unwrap();
    sql_query(
        "INSERT INTO public.security_audit_events (event_id,event_type,event_category,payload,occurred_at, \
         authorization_tenant_id,authorization_request_id,authorization_par_uri,authorization_decision, \
         authorization_valid_until,business_retain_until) \
         VALUES ($1,'authorization_decision_committed','authorization','{}'::jsonb,CURRENT_TIMESTAMP, \
         $2,$3,$4,'deny',CURRENT_TIMESTAMP+interval '1 hour',CURRENT_TIMESTAMP+interval '1 hour')",
    ).bind::<sql_types::Uuid, _>(Uuid::now_v7())
        .bind::<sql_types::Uuid, _>(fixture.tenant_id)
        .bind::<sql_types::Text, _>(Uuid::now_v7().to_string())
        .bind::<sql_types::Nullable<sql_types::Text>, _>(late.pushed_request_uri.as_deref())
        .execute(&mut blocker).await.unwrap();
    let writer = repository.clone();
    let pending = tokio::spawn(async move { writer.commit_decision(late).await });
    wait_for_lock(connection, &application).await;
    tokio::time::sleep(std::time::Duration::from_millis(850)).await;
    blocker.batch_execute("ROLLBACK").await.unwrap();
    assert_eq!(pending.await.unwrap().unwrap(), Outcome::Expired);
    assert_eq!(fact_count(connection, event_id).await, 0);
    assert_eq!(grant_count(connection, fixture).await, before);

    blocker.batch_execute("BEGIN").await.unwrap();
    sql_query("SELECT authorization_count::bigint AS count FROM user_client_grants WHERE user_id = $1 FOR UPDATE")
        .bind::<sql_types::Uuid, _>(fixture.user_id).get_result::<CountRow>(&mut blocker).await.unwrap();
    let cancelled = decision(fixture, Kind::Approve);
    let event_id = cancelled.event_id;
    let writer = repository.clone();
    let pending = tokio::spawn(async move { writer.commit_decision(cancelled).await });
    wait_for_lock(connection, &application).await;
    pending.abort();
    assert!(pending.await.unwrap_err().is_cancelled());
    blocker.batch_execute("ROLLBACK").await.unwrap();
    // A one-connection pool remains usable; no uncertain transaction leaks
    // into this subsequent request or turns its cancellation into a commit.
    assert_eq!(
        repository
            .commit_decision(decision(fixture, Kind::Deny))
            .await
            .unwrap(),
        Outcome::Committed
    );
    assert_eq!(fact_count(connection, event_id).await, 0);
}

async fn verify_prompt_none_lock_order(
    url: &str,
    connection: &mut AsyncPgConnection,
    fixture: &Fixture,
) {
    let explicit = decision(fixture, Kind::Approve);
    let mut silent = decision(fixture, Kind::PromptNone);
    silent.pushed_request_uri = explicit.pushed_request_uri.clone();
    let barrier: i64 = 913_847;
    // Pause the approval after it owns the unique fence. With the wrong
    // grant/fence order, prompt-none now takes the grant and waits for this
    // fence; releasing the barrier then creates a real deadlock.
    connection
        .batch_execute(&format!(
            "CREATE FUNCTION decision_test_barrier() RETURNS trigger LANGUAGE plpgsql AS $$ \
         BEGIN PERFORM pg_advisory_xact_lock({barrier}); RETURN NEW; END $$; \
         CREATE TRIGGER decision_test_barrier AFTER INSERT ON public.security_audit_events \
         FOR EACH ROW WHEN (NEW.event_id = '{}') EXECUTE FUNCTION decision_test_barrier(); \
         SELECT pg_advisory_lock({barrier})",
            explicit.event_id,
        ))
        .await
        .unwrap();
    let mut explicit_url = url::Url::parse(url).unwrap();
    explicit_url
        .query_pairs_mut()
        .append_pair("application_name", "decision-explicit-order");
    let explicit_repo = AuthorizationFlowRepository::new(
        create_pool(explicit_url.to_string(), 1).unwrap(),
        fixture.tenant_id,
    );
    let mut silent_url = url::Url::parse(url).unwrap();
    silent_url
        .query_pairs_mut()
        .append_pair("application_name", "decision-silent-order");
    let silent_repo = AuthorizationFlowRepository::new(
        create_pool(silent_url.to_string(), 1).unwrap(),
        fixture.tenant_id,
    );
    let approving = tokio::spawn(async move { explicit_repo.commit_decision(explicit).await });
    wait_for_lock(connection, "decision-explicit-order").await;
    let prompting = tokio::spawn(async move { silent_repo.commit_decision(silent).await });
    wait_for_lock(connection, "decision-silent-order").await;
    connection
        .batch_execute(&format!("SELECT pg_advisory_unlock({barrier})"))
        .await
        .unwrap();
    assert_eq!(approving.await.unwrap().unwrap(), Outcome::Committed);
    assert_eq!(prompting.await.unwrap().unwrap(), Outcome::Conflict);
    connection
        .batch_execute(
            "DROP TRIGGER decision_test_barrier ON public.security_audit_events; \
         DROP FUNCTION decision_test_barrier()",
        )
        .await
        .unwrap();
}

async fn verify_audit_lifetime(
    connection: &mut AsyncPgConnection,
    pool: &DbPool,
    fixture: &Fixture,
) {
    let repository = AuthorizationFlowRepository::new(pool.clone(), fixture.tenant_id);
    let audit = AuditLedgerRepository::new(pool.clone());
    let mut retained = decision(fixture, Kind::Deny);
    retained.valid_until = Utc::now() + Duration::seconds(2);
    retained.audit_fields = json!({
        "request_id": "must-not-export-raw-handle",
        "authorization_details": {"private": "must-not-export"},
    });
    assert_eq!(
        repository.commit_decision(retained.clone()).await.unwrap(),
        Outcome::Committed
    );
    let mut short = decision(fixture, Kind::Deny);
    short.valid_until = Utc::now() + Duration::seconds(2);
    short.retain_until = short.valid_until;
    assert_eq!(
        repository.commit_decision(short.clone()).await.unwrap(),
        Outcome::Committed
    );
    tokio::time::sleep(std::time::Duration::from_millis(2050)).await;
    assert_eq!(
        cleanup(connection).await,
        0,
        "an unexported fact never expires away"
    );
    assert_eq!(fact_count(connection, short.event_id).await, 1);

    let reserved = SecurityAuditEvent {
        event_id: Uuid::now_v7(),
        event_type: "authorization_decision_committed".to_owned(),
        event_category: "authorization".to_owned(),
        payload: json!({}),
        occurred_at: Utc::now(),
    };
    assert!(audit.append(reserved.clone()).await.is_err());
    let ordinary = SecurityAuditEvent {
        event_id: Uuid::now_v7(),
        event_type: "decision_test".to_owned(),
        ..reserved.clone()
    };
    assert!(
        audit
            .append_batch(&[ordinary.clone(), reserved])
            .await
            .is_err()
    );
    assert_eq!(
        fact_count(connection, ordinary.event_id).await,
        0,
        "a rejected batch writes no prefix"
    );
    assert!(sql_query("SELECT public.nazo_persist_security_audit_event($1, 'authorization_decision_committed', 'authorization', '{}'::jsonb, CURRENT_TIMESTAMP)")
        .bind::<sql_types::Uuid, _>(Uuid::now_v7()).execute(connection).await.is_err());
    audit.append(ordinary.clone()).await.unwrap();
    // JSONB equality ignores numeric formatting while audit hashes bind
    // payload::TEXT. Even an otherwise authorized ACK may not rewrite 1 to 1.0.
    let numeric_id = Uuid::now_v7();
    sql_query(
        "INSERT INTO public.security_audit_events (event_id,event_type,event_category,payload,occurred_at, \
         authorization_tenant_id,authorization_request_id,authorization_decision,authorization_valid_until,business_retain_until) \
         VALUES ($1,'authorization_decision_committed','authorization','{\"metric\":1}'::jsonb,CURRENT_TIMESTAMP, \
         $2,$1::text,'deny',CURRENT_TIMESTAMP+interval '1 hour',CURRENT_TIMESTAMP+interval '1 hour')",
    ).bind::<sql_types::Uuid, _>(numeric_id).bind::<sql_types::Uuid, _>(fixture.tenant_id)
        .execute(connection).await.unwrap();
    connection
        .batch_execute("SET nazo.audit_ack = 'on'")
        .await
        .unwrap();
    assert!(
        sql_query(
            "UPDATE public.security_audit_events SET payload = '{\"metric\":1.0}'::jsonb, \
         exported_at = CURRENT_TIMESTAMP WHERE event_id = $1",
        )
        .bind::<sql_types::Uuid, _>(numeric_id)
        .execute(connection)
        .await
        .is_err()
    );
    connection
        .batch_execute("RESET nazo.audit_ack")
        .await
        .unwrap();
    acknowledge_all(&audit).await;
    assert_eq!(fact_count(connection, ordinary.event_id).await, 0);
    assert_eq!(fact_count(connection, retained.event_id).await, 1);
    let safe_payload = sql_query(
        "SELECT COUNT(*)::bigint AS count FROM public.security_audit_events \
         WHERE event_id = $1 AND payload ? 'request_id_hash' \
           AND NOT payload ?| ARRAY['request_id','pushed_request_uri','resource_indicators','authorization_details']",
    ).bind::<sql_types::Uuid, _>(retained.event_id)
        .get_result::<CountRow>(connection).await.unwrap();
    assert_eq!(
        safe_payload.count, 1,
        "export payload contains hashes, never raw private preparation"
    );
    assert_eq!(fact_count(connection, short.event_id).await, 1);
    assert!(!audit.anchor_health().await.unwrap().pending_exists);
    assert!(matches!(
        audit
            .claim_batch("decision-test", 256, 1024 * 1024, 30)
            .await
            .unwrap(),
        SecurityAuditBatchClaim::Empty
    ));

    // Authoritative append API also rejects exported rows, not just its reader.
    let health = audit.anchor_health().await.unwrap();
    assert!(
        sql_query("SELECT public.nazo_append_security_audit_chain($1,$2,$3,$4)")
            .bind::<sql_types::BigInt, _>(health.head_sequence)
            .bind::<sql_types::Binary, _>(health.head_hash)
            .bind::<sql_types::Array<sql_types::Uuid>, _>(vec![retained.event_id])
            .bind::<sql_types::Array<sql_types::Binary>, _>(vec![vec![7_u8; 32]])
            .execute(connection)
            .await
            .is_err()
    );
    connection
        .batch_execute("SET nazo.audit_ack = 'on'; SET nazo.audit_reclaim = 'on'")
        .await
        .unwrap();
    assert!(
        sql_query(
            "UPDATE public.security_audit_events SET payload = '{}'::jsonb WHERE event_id = $1"
        )
        .bind::<sql_types::Uuid, _>(retained.event_id)
        .execute(connection)
        .await
        .is_err()
    );
    assert!(sql_query("UPDATE public.security_audit_events SET business_retain_until = CURRENT_TIMESTAMP WHERE event_id = $1")
        .bind::<sql_types::Uuid, _>(retained.event_id).execute(connection).await.is_err());
    assert!(
        sql_query("UPDATE public.security_audit_events SET exported_at = NULL WHERE event_id = $1")
            .bind::<sql_types::Uuid, _>(retained.event_id)
            .execute(connection)
            .await
            .is_err()
    );
    assert!(
        sql_query("DELETE FROM public.security_audit_events WHERE event_id = $1")
            .bind::<sql_types::Uuid, _>(retained.event_id)
            .execute(connection)
            .await
            .is_err()
    );
    connection
        .batch_execute("RESET nazo.audit_ack; RESET nazo.audit_reclaim")
        .await
        .unwrap();
    assert_eq!(cleanup(connection).await, 1);
    assert_eq!(fact_count(connection, short.event_id).await, 0);
    assert_eq!(fact_count(connection, retained.event_id).await, 1);
    // Consent/code may expire before their original PAR. A new consent with
    // the same still-valid PAR must keep losing after ACK and cleanup.
    let mut another_consent = decision(fixture, Kind::Deny);
    another_consent.pushed_request_uri = retained.pushed_request_uri;
    assert_eq!(
        repository.commit_decision(another_consent).await.unwrap(),
        Outcome::Conflict
    );

    // Synthetic historical facts exercise the bounded cleanup budget without
    // sleeping through real business-retention windows. Above tests already
    // exercised commit -> actual ACK -> expiry for a genuine decision.
    let historical: Vec<Uuid> = (0..257).map(|_| Uuid::now_v7()).collect();
    sql_query(
        "INSERT INTO public.security_audit_events (event_id,event_type,event_category,payload,occurred_at, \
         authorization_tenant_id,authorization_request_id,authorization_decision, \
         authorization_valid_until,business_retain_until,exported_at) \
         SELECT id,'authorization_decision_committed','authorization','{}'::jsonb,CURRENT_TIMESTAMP-interval '3 hours', \
         $2,id::text,'deny',CURRENT_TIMESTAMP-interval '2 hours',CURRENT_TIMESTAMP-interval '1 hour', \
         CURRENT_TIMESTAMP-interval '30 minutes' FROM unnest($1::uuid[]) AS history(id)",
    ).bind::<sql_types::Array<sql_types::Uuid>, _>(historical)
        .bind::<sql_types::Uuid, _>(fixture.tenant_id).execute(connection).await.unwrap();
    connection
        .batch_execute("ANALYZE public.security_audit_events")
        .await
        .unwrap();
    let health = audit.anchor_health().await.unwrap();
    assert!(!health.pending_exists);
    assert_eq!(
        health.pending_estimate, 0,
        "retained rows must not inflate pending estimate"
    );
    assert_eq!(cleanup(connection).await, 256);
    assert_eq!(cleanup(connection).await, 1);
    assert_eq!(cleanup(connection).await, 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn authorization_decisions_commit_once_and_survive_export_ack() {
    let Some(base_url) = database_url() else {
        return;
    };
    let name = format!("authorization_decisions_{}", Uuid::now_v7().simple());
    let mut coordinator = AsyncPgConnection::establish(&base_url).await.unwrap();
    coordinator
        .batch_execute(&format!("CREATE DATABASE \"{name}\""))
        .await
        .unwrap();
    let mut isolated = url::Url::parse(&base_url).unwrap();
    isolated.set_path(&format!("/{name}"));
    let url = isolated.to_string();
    nazo_postgres::run_pending_migrations(&url).await.unwrap();
    let pool = create_pool(url.clone(), 4).unwrap();
    let mut connection = AsyncPgConnection::establish(&url).await.unwrap();
    verify_upgrade_privileges(&url, &mut connection, &pool).await;
    let fixture = fixture(&mut connection).await;
    verify_atomicity(&mut connection, &pool, &fixture).await;
    verify_lock_expiry_and_cancellation(&url, &mut connection, &fixture).await;
    verify_prompt_none_lock_order(&url, &mut connection, &fixture).await;
    verify_audit_lifetime(&mut connection, &pool, &fixture).await;
    drop(connection);
    drop(pool);
    coordinator
        .batch_execute(&format!("DROP DATABASE \"{name}\" WITH (FORCE)"))
        .await
        .unwrap();
}
