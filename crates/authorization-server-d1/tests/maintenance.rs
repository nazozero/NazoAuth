#![cfg(feature = "local-sqlite")]

use futures_executor::block_on;
use nazo_identity::TenantId;
use nazo_oauth_server_d1::{D1Provider, Database};
use uuid::Uuid;

struct Fixture {
    path: std::path::PathBuf,
    database: Database,
    provider: D1Provider,
    inspector: rusqlite::Connection,
    tenant: String,
}

impl Fixture {
    fn new() -> Self {
        let path =
            std::env::temp_dir().join(format!("nazo-d1-maintenance-{}.sqlite", Uuid::new_v4()));
        let database = Database::open(&path).unwrap();
        database.execute_schema().unwrap();
        let tenant = Uuid::from_u128(1);
        let provider = D1Provider::new(database.clone(), TenantId::new(tenant).unwrap());
        let inspector = rusqlite::Connection::open(&path).unwrap();
        Self {
            path,
            database,
            provider,
            inspector,
            tenant: tenant.to_string(),
        }
    }

    fn count(&self, table: &str) -> usize {
        self.inspector
            .query_row(
                &format!("SELECT count(*) FROM {table} WHERE tenant_id=?1"),
                [&self.tenant],
                |row| row.get::<_, i64>(0),
            )
            .unwrap() as usize
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

#[test]
fn cleanup_bounds_each_category_and_preserves_live_state_and_other_tenants() {
    let fixture = Fixture::new();
    let tenant = &fixture.tenant;
    fixture.database.execute_sql(&format!("
        INSERT INTO nazo_state VALUES ('{tenant}','session','live','null','v',unixepoch()+3600);
        INSERT INTO nazo_state VALUES ('other','session','expired','null','v',0);
        INSERT INTO nazo_state VALUES ('{tenant}','session','expired-1','null','v',0);
        INSERT INTO nazo_state VALUES ('{tenant}','session','expired-2','null','v',0);
        INSERT INTO nazo_state VALUES ('{tenant}','session','expired-3','null','v',0);
        INSERT INTO nazo_decisions VALUES ('{tenant}','live',NULL,'event-live',9000000000000000);
        INSERT INTO nazo_decisions VALUES ('{tenant}','expired-1',NULL,'event-1',0);
        INSERT INTO nazo_decisions VALUES ('{tenant}','expired-2',NULL,'event-2',0);
        INSERT INTO nazo_decisions VALUES ('{tenant}','expired-3',NULL,'event-3',0);
        INSERT INTO nazo_redemptions VALUES ('{tenant}','client','live','issue-live',NULL,'jti-live',9000000000000000,NULL,9000000000000000);
        INSERT INTO nazo_redemptions VALUES ('{tenant}','client','expired-1','issue-1',NULL,'jti-1',0,NULL,0);
        INSERT INTO nazo_redemptions VALUES ('{tenant}','client','expired-2','issue-2',NULL,'jti-2',0,NULL,0);
        INSERT INTO nazo_redemptions VALUES ('{tenant}','client','expired-3','issue-3',NULL,'jti-3',0,NULL,0);
        INSERT INTO nazo_revocations VALUES ('{tenant}','live','client',9000000000000000);
        INSERT INTO nazo_revocations VALUES ('{tenant}','expired-1','client',0);
        INSERT INTO nazo_revocations VALUES ('{tenant}','expired-2','client',0);
        INSERT INTO nazo_revocations VALUES ('{tenant}','expired-3','client',0);
    ")).unwrap();
    assert_eq!(block_on(fixture.provider.prune_expired(0)).unwrap(), 0);
    assert_eq!(block_on(fixture.provider.prune_expired(2)).unwrap(), 8);
    for table in [
        "nazo_state",
        "nazo_decisions",
        "nazo_redemptions",
        "nazo_revocations",
    ] {
        assert_eq!(fixture.count(table), 2, "{table}");
    }
    assert_eq!(block_on(fixture.provider.prune_expired(2)).unwrap(), 4);
    assert_eq!(block_on(fixture.provider.prune_expired(2)).unwrap(), 0);
    for table in [
        "nazo_state",
        "nazo_decisions",
        "nazo_redemptions",
        "nazo_revocations",
    ] {
        assert_eq!(fixture.count(table), 1, "{table}");
    }
    let other: i64 = fixture
        .inspector
        .query_row(
            "SELECT count(*) FROM nazo_state WHERE tenant_id='other'",
            [],
            |row| row.get::<_, i64>(0),
        )
        .unwrap();
    assert_eq!(other, 1);
}

#[test]
fn expired_families_do_not_cascade_live_or_over_budget_spent_proofs() {
    let fixture = Fixture::new();
    let tenant = &fixture.tenant;
    fixture.database.execute_sql(&format!("
        INSERT INTO nazo_refresh_families VALUES ('{tenant}','family','client',NULL,'{{}}','contract','{{}}','member','current-token',0,0,NULL);
        INSERT INTO nazo_refresh_spent VALUES ('{tenant}','expired-1','family','member-1','member-2',0,0);
        INSERT INTO nazo_refresh_spent VALUES ('{tenant}','expired-2','family','member-2','member-3',0,0);
        INSERT INTO nazo_refresh_spent VALUES ('{tenant}','expired-3','family','member-3','member-4',0,0);
        INSERT INTO nazo_refresh_spent VALUES ('{tenant}','live','family','member-4','member-5',0,9000000000000000);
    ")).unwrap();
    assert_eq!(block_on(fixture.provider.prune_expired(2)).unwrap(), 2);
    assert_eq!(fixture.count("nazo_refresh_spent"), 2);
    assert_eq!(fixture.count("nazo_refresh_families"), 1);
    assert_eq!(block_on(fixture.provider.prune_expired(2)).unwrap(), 1);
    assert_eq!(fixture.count("nazo_refresh_spent"), 1);
    assert_eq!(fixture.count("nazo_refresh_families"), 1);
    fixture
        .database
        .execute_sql("UPDATE nazo_refresh_spent SET expires_at=0")
        .unwrap();
    assert_eq!(block_on(fixture.provider.prune_expired(2)).unwrap(), 2);
    assert_eq!(fixture.count("nazo_refresh_spent"), 0);
    assert_eq!(fixture.count("nazo_refresh_families"), 0);
}

#[test]
fn cleanup_cap_and_expiry_indexes_bound_large_backlogs() {
    let fixture = Fixture::new();
    fixture.database.execute_sql(&format!("WITH RECURSIVE n(value) AS (SELECT 1 UNION ALL SELECT value+1 FROM n WHERE value<1005) INSERT INTO nazo_state SELECT '{}','replay',CAST(value AS TEXT),'null','',0 FROM n", fixture.tenant)).unwrap();
    assert_eq!(
        block_on(fixture.provider.prune_expired(usize::MAX)).unwrap(),
        1000
    );
    assert_eq!(fixture.count("nazo_state"), 5);
    let mut statement = fixture.inspector.prepare("EXPLAIN QUERY PLAN SELECT kind,key FROM nazo_state WHERE tenant_id=?1 AND expires_at<=unixepoch() ORDER BY expires_at LIMIT ?2").unwrap();
    let plans = statement
        .query_map(rusqlite::params![fixture.tenant, 1000], |row| {
            row.get::<_, String>(3)
        })
        .unwrap()
        .map(Result::unwrap)
        .collect::<Vec<_>>();
    assert!(plans.iter().any(|plan| plan.contains("nazo_state_expiry")));
    assert!(!plans.iter().any(|plan| plan.contains("TEMP B-TREE")));
}
