#![cfg(feature = "local-sqlite")]
mod support;

use futures_executor::block_on;
use nazo_oauth_server::ports::audit::SecurityAudit;
use nazo_persistence::{SecurityAuditEvent, SecurityAuditLedger};
use serde_json::{Map, json};
use support::fixture;

fn event(kind: &str) -> SecurityAuditEvent {
    SecurityAuditEvent {
        event_id: uuid::Uuid::new_v4(),
        event_type: kind.into(),
        event_category: "security".into(),
        occurred_at: jiff::Timestamp::now(),
        payload: json!({"schema_version": nazo_persistence::SECURITY_AUDIT_SCHEMA_VERSION}),
    }
}

#[test]
fn ignored_required_write_is_not_acknowledged() {
    block_on(async {
        let (db, provider) = fixture().await;
        db.execute_sql("CREATE TRIGGER ignore_audit BEFORE INSERT ON nazo_audit BEGIN SELECT RAISE(IGNORE); END").unwrap();
        assert!(provider.append(event("one")).await.is_err());
        assert!(
            provider
                .record_required("required", Map::new())
                .await
                .is_err()
        );
        db.execute_sql("DROP TRIGGER ignore_audit").unwrap();
        provider
            .record_required("required", Map::new())
            .await
            .unwrap();
        db.execute_sql("SELECT CASE WHEN (SELECT COUNT(*) FROM nazo_audit)=1 THEN 1 ELSE json_extract('audit result differs','$') END").unwrap();
    });
}

#[test]
fn ignored_batch_member_rolls_back_all_required_events() {
    block_on(async {
        let (db, provider) = fixture().await;
        db.execute_sql("CREATE TRIGGER ignore_audit BEFORE INSERT ON nazo_audit WHEN NEW.event_type='ignored' BEGIN SELECT RAISE(IGNORE); END").unwrap();
        let events = [event("first"), event("ignored"), event("last")];
        assert!(provider.append_batch(&events).await.is_err());
        db.execute_sql("SELECT CASE WHEN NOT EXISTS(SELECT 1 FROM nazo_audit) THEN 1 ELSE json_extract('partial audit batch survived','$') END").unwrap();
        db.execute_sql("DROP TRIGGER ignore_audit").unwrap();
        provider.append_batch(&events).await.unwrap();
        provider.append_batch(&[]).await.unwrap();
        db.execute_sql("SELECT CASE WHEN (SELECT COUNT(*) FROM nazo_audit)=3 THEN 1 ELSE json_extract('audit result differs','$') END").unwrap();
    });
}
