use std::collections::BTreeMap;

use diesel::{
    QueryableByName, sql_query,
    sql_types::{Text, Uuid as SqlUuid},
};
use diesel_async::RunQueryDsl;
use nazo_identity::{
    TenantContext, UserId,
    scim::{NormalizedScimUser, ScimPatch},
};
use nazo_postgres::{ScimEventRepository, ScimRepository, create_pool, get_conn};
use nazo_scim_events::{
    ACTIVATE_EVENT, DEACTIVATE_EVENT, DELETE_EVENT, EventReceiver, EventStorePort, MutationContext,
    PATCH_NOTICE_EVENT, PUT_NOTICE_EVENT, SetError, ValidatedPollRequest,
};
use uuid::Uuid;

#[derive(QueryableByName)]
struct TokenId {
    #[diesel(sql_type = SqlUuid)]
    id: Uuid,
}

fn database_url() -> Option<String> {
    let url = std::env::var("NAZO_TEST_DATABASE_URL")
        .or_else(|_| std::env::var("DATABASE_URL"))
        .ok();
    if url.is_none() && std::env::var_os("CI").is_some() {
        panic!("CI SCIM event tests require NAZO_TEST_DATABASE_URL or DATABASE_URL");
    }
    url
}

async fn insert_receiver(
    pool: &nazo_postgres::DbPool,
    tenant: TenantContext,
    label: &str,
) -> EventReceiver {
    let token_hash = blake3::hash(Uuid::now_v7().as_bytes()).to_hex().to_string();
    let audience = format!("https://receiver.example/{label}");
    let mut connection = get_conn(pool).await.unwrap();
    let token = sql_query(
        "INSERT INTO scim_tokens (tenant_id, token_hash, label, scopes, event_audience) \
         VALUES ($1, $2, $3, '[\"scim:events\"]'::jsonb, $4) RETURNING id",
    )
    .bind::<SqlUuid, _>(tenant.tenant_id.as_uuid())
    .bind::<Text, _>(token_hash)
    .bind::<Text, _>(label)
    .bind::<Text, _>(&audience)
    .get_result::<TokenId>(&mut connection)
    .await
    .unwrap();
    EventReceiver {
        token_id: token.id,
        tenant_id: tenant.tenant_id.as_uuid(),
        audience,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn scim_outbox_is_atomic_receiver_scoped_and_terminally_acknowledged() {
    let Some(database_url) = database_url() else {
        return;
    };
    nazo_postgres::run_pending_migrations(&database_url)
        .await
        .expect("SCIM event migration should apply");
    let pool = create_pool(&database_url, 4).expect("test pool should build");
    let tenant = TenantContext::default_system();
    let user_id = UserId::new(Uuid::now_v7()).unwrap();
    let suffix = user_id.as_uuid().simple();
    let mut connection = get_conn(&pool).await.unwrap();
    sql_query(
        "INSERT INTO users \
         (id, tenant_id, realm_id, organization_id, username, email, password_hash) \
         VALUES ($1, $2, $3, $4, $5, $6, 'test')",
    )
    .bind::<SqlUuid, _>(user_id.as_uuid())
    .bind::<SqlUuid, _>(tenant.tenant_id.as_uuid())
    .bind::<SqlUuid, _>(tenant.realm_id.as_uuid())
    .bind::<SqlUuid, _>(tenant.organization_id.as_uuid())
    .bind::<Text, _>(format!("scim-event-{suffix}"))
    .bind::<Text, _>(format!("scim-event-{suffix}@example.test"))
    .execute(&mut connection)
    .await
    .unwrap();
    drop(connection);

    let first = insert_receiver(&pool, tenant, "first receiver").await;
    let second = insert_receiver(&pool, tenant, "second receiver").await;
    let mutation = MutationContext::enabled();
    let transaction_id = mutation.transaction_id().unwrap();
    ScimRepository::new(pool.clone())
        .replace_with_mutation(
            tenant,
            user_id,
            NormalizedScimUser {
                user_name: format!("scim-event-replaced-{suffix}"),
                email: format!("scim-event-replaced-{suffix}@example.test"),
                active: false,
                display_name: None,
                given_name: None,
                family_name: None,
            },
            mutation,
        )
        .await
        .unwrap();

    let store = ScimEventRepository::new(pool.clone());
    let request = ValidatedPollRequest {
        max_events: 10,
        return_immediately: true,
        ack: Vec::new(),
        set_errors: BTreeMap::new(),
    };
    let first_page = store
        .apply_dispositions_and_poll(&first, &request)
        .await
        .unwrap();
    assert_eq!(first_page.events.len(), 1);
    let event = &first_page.events[0];
    assert_eq!(event.transaction_id, transaction_id);
    assert!(event.events.contains_key(PUT_NOTICE_EVENT));
    assert!(event.events.contains_key(DEACTIVATE_EVENT));

    let event_id = event.id;
    let acknowledged = ValidatedPollRequest {
        ack: vec![event_id],
        ..request.clone()
    };
    assert!(
        store
            .apply_dispositions_and_poll(&first, &acknowledged)
            .await
            .unwrap()
            .events
            .is_empty()
    );
    let attempted_rewrite = ValidatedPollRequest {
        set_errors: BTreeMap::from([(
            event_id,
            SetError {
                err: "jwtClaims".to_owned(),
                description: "should remain acknowledged".to_owned(),
            },
        )]),
        ..request.clone()
    };
    assert!(
        store
            .apply_dispositions_and_poll(&first, &attempted_rewrite)
            .await
            .unwrap()
            .events
            .is_empty()
    );
    assert_eq!(
        store
            .apply_dispositions_and_poll(&second, &request)
            .await
            .unwrap()
            .events
            .len(),
        1,
        "one receiver's acknowledgement must not consume another receiver's event"
    );

    let activate_mutation = MutationContext::enabled();
    ScimRepository::new(pool.clone())
        .patch_with_mutation(
            tenant,
            user_id,
            ScimPatch {
                active: Some(true),
                ..ScimPatch::default()
            },
            activate_mutation,
        )
        .await
        .unwrap();
    let activated = store
        .apply_dispositions_and_poll(&first, &request)
        .await
        .unwrap();
    assert_eq!(activated.events.len(), 1);
    assert_eq!(
        activated.events[0].transaction_id,
        activate_mutation.transaction_id().unwrap()
    );
    assert!(activated.events[0].events.contains_key(PATCH_NOTICE_EVENT));
    assert!(activated.events[0].events.contains_key(ACTIVATE_EVENT));
    let activated_id = activated.events[0].id;
    store
        .apply_dispositions_and_poll(
            &first,
            &ValidatedPollRequest {
                ack: vec![activated_id],
                ..request.clone()
            },
        )
        .await
        .unwrap();

    let deactivate_mutation = MutationContext::enabled();
    assert!(
        ScimRepository::new(pool.clone())
            .deactivate_with_mutation(tenant, user_id, deactivate_mutation)
            .await
            .unwrap()
    );
    let deactivated = store
        .apply_dispositions_and_poll(&first, &request)
        .await
        .unwrap();
    assert_eq!(deactivated.events.len(), 1);
    assert_eq!(
        deactivated.events[0].transaction_id,
        deactivate_mutation.transaction_id().unwrap()
    );
    assert_eq!(deactivated.events[0].events.len(), 1);
    assert!(deactivated.events[0].events.contains_key(DEACTIVATE_EVENT));
    assert!(!deactivated.events[0].events.contains_key(DELETE_EVENT));

    let mut connection = get_conn(&pool).await.unwrap();
    sql_query("DELETE FROM scim_tokens WHERE id = $1 OR id = $2")
        .bind::<SqlUuid, _>(first.token_id)
        .bind::<SqlUuid, _>(second.token_id)
        .execute(&mut connection)
        .await
        .unwrap();
    sql_query("DELETE FROM scim_security_events WHERE subject_uri = $1")
        .bind::<Text, _>(format!("/Users/{}", user_id.as_uuid()))
        .execute(&mut connection)
        .await
        .unwrap();
    sql_query("DELETE FROM users WHERE id = $1")
        .bind::<SqlUuid, _>(user_id.as_uuid())
        .execute(&mut connection)
        .await
        .unwrap();
}

#[derive(QueryableByName)]
struct ReceiptRow {
    #[diesel(sql_type = SqlUuid)]
    event_id: Uuid,
    #[diesel(sql_type = Text)]
    disposition: String,
    #[diesel(sql_type = diesel::sql_types::Nullable<Text>)]
    error_code: Option<String>,
    #[diesel(sql_type = diesel::sql_types::Nullable<Text>)]
    error_description: Option<String>,
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn batched_receipts_preserve_visibility_terminal_outcomes_and_receiver_isolation() {
    let Some(database_url) = database_url() else {
        return;
    };
    nazo_postgres::run_pending_migrations(&database_url)
        .await
        .unwrap();
    let pool = create_pool(&database_url, 4).unwrap();
    let tenant_id = Uuid::now_v7();
    let foreign_tenant_id = Uuid::now_v7();
    let now = chrono::Utc::now();
    let mut connection = get_conn(&pool).await.unwrap();
    for id in [tenant_id, foreign_tenant_id] {
        sql_query(
            "INSERT INTO tenants (id, slug, display_name) VALUES ($1, $1::text, 'SCIM batch test')",
        )
        .bind::<SqlUuid, _>(id)
        .execute(&mut connection)
        .await
        .unwrap();
    }
    let receiver = EventReceiver {
        token_id: Uuid::now_v7(),
        tenant_id,
        audience: "https://receiver.example/batch".to_owned(),
    };
    let other_receiver = EventReceiver {
        token_id: Uuid::now_v7(),
        ..receiver.clone()
    };
    for token in [&receiver, &other_receiver] {
        sql_query(
            "INSERT INTO scim_tokens (id, tenant_id, token_hash, label, scopes, event_audience, created_at) \
             VALUES ($1, $2, $3, 'SCIM batch receiver', '[\"scim:events\"]'::jsonb, $4, $5)",
        )
        .bind::<SqlUuid, _>(token.token_id)
        .bind::<SqlUuid, _>(tenant_id)
        .bind::<Text, _>(blake3::hash(token.token_id.as_bytes()).to_hex().to_string())
        .bind::<Text, _>(&token.audience)
        .bind::<diesel::sql_types::Timestamptz, _>(now - chrono::Duration::minutes(30))
        .execute(&mut connection)
        .await
        .unwrap();
    }
    let acknowledged = Uuid::now_v7();
    let failed = Uuid::now_v7();
    let expired = Uuid::now_v7();
    let before_receiver = Uuid::now_v7();
    let foreign = Uuid::now_v7();
    let pending = [Uuid::now_v7(), Uuid::now_v7()];
    for (id, tenant, occurred_minutes_ago, expires_minutes_from_now) in [
        (acknowledged, tenant_id, 1, 10),
        (failed, tenant_id, 1, 10),
        (expired, tenant_id, 20, -10),
        (before_receiver, tenant_id, 40, 10),
        (foreign, foreign_tenant_id, 1, 10),
        (pending[0], tenant_id, 1, 10),
        (pending[1], tenant_id, 1, 10),
    ] {
        sql_query(
            "INSERT INTO scim_security_events \
             (id, tenant_id, transaction_id, subject_uri, events, occurred_at, expires_at) \
             VALUES ($1, $2, $1, $3, '{\"test-event\":{}}'::jsonb, $4, $5)",
        )
        .bind::<SqlUuid, _>(id)
        .bind::<SqlUuid, _>(tenant)
        .bind::<Text, _>(format!("/Users/{id}"))
        .bind::<diesel::sql_types::Timestamptz, _>(
            now - chrono::Duration::minutes(occurred_minutes_ago),
        )
        .bind::<diesel::sql_types::Timestamptz, _>(
            now + chrono::Duration::minutes(expires_minutes_from_now),
        )
        .execute(&mut connection)
        .await
        .unwrap();
    }
    drop(connection);
    let store = ScimEventRepository::new(pool.clone());
    let poll = ValidatedPollRequest {
        max_events: 10,
        return_immediately: true,
        ack: Vec::new(),
        set_errors: BTreeMap::new(),
    };
    let first_page = store
        .apply_dispositions_and_poll(
            &receiver,
            &ValidatedPollRequest {
                max_events: 1,
                ..poll.clone()
            },
        )
        .await
        .unwrap();
    assert_eq!(first_page.events.len(), 1);
    assert!(first_page.more_available);
    let batch = ValidatedPollRequest {
        ack: vec![
            acknowledged,
            expired,
            before_receiver,
            foreign,
            Uuid::now_v7(),
        ],
        set_errors: BTreeMap::from([(
            failed,
            SetError {
                err: "jwtClaims".to_owned(),
                description: "invalid claims".to_owned(),
            },
        )]),
        ..poll.clone()
    };
    let page = store
        .apply_dispositions_and_poll(&receiver, &batch)
        .await
        .unwrap();
    assert_eq!(
        page.events.iter().map(|event| event.id).collect::<Vec<_>>(),
        pending
    );
    assert!(!page.more_available);
    let other_page = store
        .apply_dispositions_and_poll(&other_receiver, &poll)
        .await
        .unwrap();
    assert_eq!(other_page.events.len(), 4);
    let attempted_rewrite = ValidatedPollRequest {
        ack: vec![failed],
        set_errors: BTreeMap::from([(
            acknowledged,
            SetError {
                err: "jwtClaims".to_owned(),
                description: "must not overwrite acknowledgment".to_owned(),
            },
        )]),
        ..poll
    };
    let replay_page = store
        .apply_dispositions_and_poll(&receiver, &attempted_rewrite)
        .await
        .unwrap();
    assert_eq!(
        replay_page
            .events
            .iter()
            .map(|event| event.id)
            .collect::<Vec<_>>(),
        pending
    );
    let mut connection = get_conn(&pool).await.unwrap();
    let receipts = sql_query(
        "SELECT event_id, disposition, error_code, error_description \
         FROM scim_security_event_receipts WHERE scim_token_id = $1 ORDER BY event_id",
    )
    .bind::<SqlUuid, _>(receiver.token_id)
    .load::<ReceiptRow>(&mut connection)
    .await
    .unwrap();
    assert_eq!(
        receipts.len(),
        2,
        "ineligible events must never receive receipts"
    );
    let ack = receipts
        .iter()
        .find(|row| row.event_id == acknowledged)
        .unwrap();
    assert_eq!(ack.disposition, "acknowledged");
    assert_eq!(ack.error_code, None);
    assert_eq!(ack.error_description, None);
    let error = receipts.iter().find(|row| row.event_id == failed).unwrap();
    assert_eq!(error.disposition, "error");
    assert_eq!(error.error_code.as_deref(), Some("jwtClaims"));
    assert_eq!(error.error_description.as_deref(), Some("invalid claims"));

    for id in [tenant_id, foreign_tenant_id] {
        sql_query("DELETE FROM scim_tokens WHERE tenant_id = $1")
            .bind::<SqlUuid, _>(id)
            .execute(&mut connection)
            .await
            .unwrap();
        sql_query("DELETE FROM scim_security_events WHERE tenant_id = $1")
            .bind::<SqlUuid, _>(id)
            .execute(&mut connection)
            .await
            .unwrap();
        sql_query("DELETE FROM tenants WHERE id = $1")
            .bind::<SqlUuid, _>(id)
            .execute(&mut connection)
            .await
            .unwrap();
    }
}
