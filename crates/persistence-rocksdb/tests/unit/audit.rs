use super::*;
use crate::db::read;
use serde_json::json;
use uuid::Uuid;

use crate::support::database;

fn event() -> SecurityAuditEvent {
    SecurityAuditEvent {
        event_id: Uuid::now_v7(),
        event_type: "test_event".into(),
        event_category: "authentication".into(),
        occurred_at: jiff::Timestamp::now(),
        payload: json!({"schema_version":nazo_persistence::SECURITY_AUDIT_SCHEMA_VERSION,"tenant_id":Uuid::new_v4(),"outcome":"success"}),
    }
}

#[tokio::test]
async fn event_identity_is_global_and_conflicting_batch_rolls_back_every_write() {
    let database = database::Database::new();
    let db = database.store();
    let original = event();
    db.append(original.clone()).await.unwrap();
    db.append(original.clone()).await.unwrap();
    let mut changed = original.clone();
    changed.payload["tenant_id"] = json!(Uuid::new_v4());
    assert!(db.append(changed.clone()).await.is_err());
    let fresh = event();
    assert!(db.append_batch(&[fresh.clone(), changed]).await.is_err());
    let stored: AuditRow = read(
        &db.db,
        &key(EVENTS, Uuid::nil(), original.event_id.as_bytes()),
    )
    .unwrap()
    .unwrap();
    assert_eq!(stored.payload, original.payload);
    assert!(
        read::<AuditRow>(&db.db, &key(EVENTS, Uuid::nil(), fresh.event_id.as_bytes()))
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn generic_audit_cannot_fabricate_authorization_decision_evidence() {
    let database = database::Database::new();
    let db = database.store();
    let mut reserved = event();
    reserved.event_type = "authorization_decision_committed".into();
    assert!(db.append(reserved.clone()).await.is_err());
    assert!(
        read::<AuditRow>(
            &db.db,
            &key(EVENTS, Uuid::nil(), reserved.event_id.as_bytes())
        )
        .unwrap()
        .is_none()
    );
}
