use chrono::{DateTime, Duration, Utc};
use diesel::{
    sql_query,
    sql_types::{Array, Timestamptz, Uuid as SqlUuid},
};
use diesel_async::RunQueryDsl;
use nazo_identity::{TenantId, ports::ScimListQuery};
use nazo_postgres::{ScimRepository, create_pool, get_conn, run_pending_migrations};
use uuid::Uuid;

#[tokio::test]
async fn tenant_pages_preserve_timestamp_ties_exact_totals_and_count_zero() {
    let database_url =
        match std::env::var("NAZO_TEST_DATABASE_URL").or_else(|_| std::env::var("DATABASE_URL")) {
            Ok(url) => url,
            Err(_) if std::env::var_os("CI").is_some() => {
                panic!("CI requires a PostgreSQL test database")
            }
            Err(_) => return,
        };
    run_pending_migrations(&database_url).await.unwrap();
    let pool = create_pool(database_url, 1).unwrap();
    let tenant = Uuid::now_v7();
    let foreign_tenant = Uuid::now_v7();
    let realms = [Uuid::now_v7(), Uuid::now_v7()];
    let organizations = [Uuid::now_v7(), Uuid::now_v7()];
    let mut ids = [Uuid::now_v7(), Uuid::now_v7(), Uuid::now_v7()];
    ids.sort();
    let later_id = Uuid::now_v7();
    let foreign_id = Uuid::now_v7();
    let created_at = DateTime::<Utc>::from_timestamp(1_700_000_000, 0).unwrap();
    let later_created_at = created_at + Duration::seconds(1);
    let mut connection = get_conn(&pool).await.unwrap();
    for (index, tenant_id) in [tenant, foreign_tenant].into_iter().enumerate() {
        sql_query("INSERT INTO tenants (id, slug, display_name) VALUES ($1, $1::text, 'SCIM pagination test')")
            .bind::<SqlUuid, _>(tenant_id).execute(&mut connection).await.unwrap();
        sql_query("INSERT INTO realms (id, tenant_id, slug, display_name) VALUES ($1, $2, 'default', 'SCIM pagination realm')")
            .bind::<SqlUuid, _>(realms[index]).bind::<SqlUuid, _>(tenant_id).execute(&mut connection).await.unwrap();
        sql_query("INSERT INTO organizations (id, tenant_id, slug, display_name) VALUES ($1, $2, 'default', 'SCIM pagination organization')")
            .bind::<SqlUuid, _>(organizations[index]).bind::<SqlUuid, _>(tenant_id).execute(&mut connection).await.unwrap();
    }
    // Insert the tied rows in reverse order, with a foreign tenant interleaved.
    for (id, owner, timestamp) in [
        (ids[2], 0, created_at),
        (foreign_id, 1, created_at),
        (ids[1], 0, created_at),
        (ids[0], 0, created_at),
        (later_id, 0, later_created_at),
    ] {
        sql_query("INSERT INTO users (id, tenant_id, realm_id, organization_id, username, email, password_hash, created_at) VALUES ($1, $2, $3, $4, $1::text, $1::text || '@example.com', 'unused-test-hash', $5)")
            .bind::<SqlUuid, _>(id).bind::<SqlUuid, _>([tenant, foreign_tenant][owner])
            .bind::<SqlUuid, _>(realms[owner]).bind::<SqlUuid, _>(organizations[owner])
            .bind::<Timestamptz, _>(timestamp).execute(&mut connection).await.unwrap();
    }
    drop(connection);

    let repository = ScimRepository::new(pool.clone());
    let query = ScimListQuery {
        tenant_id: TenantId::new(tenant).unwrap(),
        email: None,
        after: None,
        limit: 2,
        offset: 0,
    };
    let first = repository.list(query.clone()).await.unwrap();
    assert_eq!(first.total, 4);
    assert_eq!(
        first
            .users
            .iter()
            .map(|user| user.principal.user_id.as_uuid())
            .collect::<Vec<_>>(),
        ids[..2]
    );
    let second = repository
        .list(ScimListQuery {
            after: Some((created_at, ids[1])),
            ..query.clone()
        })
        .await
        .unwrap();
    assert_eq!(second.total, 4);
    assert_eq!(
        second
            .users
            .iter()
            .map(|user| user.principal.user_id.as_uuid())
            .collect::<Vec<_>>(),
        [ids[2], later_id]
    );
    let end = repository
        .list(ScimListQuery {
            after: Some((later_created_at, later_id)),
            ..query.clone()
        })
        .await
        .unwrap();
    assert_eq!(end.total, 4);
    assert!(end.users.is_empty());

    // The cursor and offset restrict rows, never the exact total. count=0
    // still returns that total even if its cursor is beyond the last row.
    let count_only = repository
        .list(ScimListQuery {
            limit: 0,
            offset: 99,
            after: Some((later_created_at, later_id)),
            ..query.clone()
        })
        .await
        .unwrap();
    assert_eq!(count_only.total, 4);
    assert!(count_only.users.is_empty());
    let indexed = repository
        .list(ScimListQuery {
            offset: 1,
            ..query.clone()
        })
        .await
        .unwrap();
    assert_eq!(indexed.total, 4);
    assert_eq!(
        indexed
            .users
            .iter()
            .map(|user| user.principal.user_id.as_uuid())
            .collect::<Vec<_>>(),
        ids[1..]
    );
    let filtered = repository
        .list(ScimListQuery {
            email: Some(format!("{}@example.com", ids[2])),
            after: Some((created_at, ids[1])),
            ..query.clone()
        })
        .await
        .unwrap();
    assert_eq!(filtered.total, 1);
    assert_eq!(filtered.users[0].principal.user_id.as_uuid(), ids[2]);
    let foreign = repository
        .list(ScimListQuery {
            tenant_id: TenantId::new(foreign_tenant).unwrap(),
            ..query
        })
        .await
        .unwrap();
    assert_eq!(foreign.total, 1);
    assert_eq!(foreign.users[0].principal.user_id.as_uuid(), foreign_id);

    let mut connection = get_conn(&pool).await.unwrap();
    for table in ["users", "organizations", "realms"] {
        sql_query(format!("DELETE FROM {table} WHERE tenant_id = ANY($1)"))
            .bind::<Array<SqlUuid>, _>(vec![tenant, foreign_tenant])
            .execute(&mut connection)
            .await
            .unwrap();
    }
    sql_query("DELETE FROM tenants WHERE id = ANY($1)")
        .bind::<Array<SqlUuid>, _>(vec![tenant, foreign_tenant])
        .execute(&mut connection)
        .await
        .unwrap();
}
