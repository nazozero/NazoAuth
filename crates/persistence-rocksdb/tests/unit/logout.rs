use super::*;
use crate::db::read;
use jiff::{SignedDuration, Timestamp};

use crate::support::database;

fn delivery() -> IdempotentBackchannelLogoutDelivery {
    IdempotentBackchannelLogoutDelivery {
        tenant_id: Uuid::new_v4(),
        client_id: Uuid::new_v4(),
        client_public_id: "logout-client".into(),
        operation_key: "logout-operation".into(),
        logout_uri: "https://client.example/logout".into(),
        logout_token: "signed-logout-token".into(),
        expires_at: Timestamp::now() + SignedDuration::from_secs(300),
    }
}

#[tokio::test]
async fn duplicate_enqueue_and_concurrent_claim_have_one_owner_and_fence_old_attempts() {
    let database = database::Database::new();
    let db = database.store();
    let deliveries = [delivery()];
    let (a, b) = tokio::join!(
        db.enqueue_idempotent_batch(&deliveries),
        db.enqueue_idempotent_batch(&deliveries)
    );
    a.unwrap();
    b.unwrap();
    let (a, b) = tokio::join!(db.claim_due(10, 60), db.claim_due(10, 60));
    let mut claimed = a.unwrap();
    claimed.extend(b.unwrap());
    assert_eq!(claimed.len(), 1);
    let first = &claimed[0];
    assert_eq!(first.attempts, 1);
    let tx = db.transaction();
    let mut row: Delivery = read_tx(&tx, &delivery_key(first.id), true)
        .unwrap()
        .unwrap();
    let old_due = row.due;
    let past = Timestamp::now() - SignedDuration::from_secs(1);
    row.lease = Some(past);
    row.due = Some(past);
    store_delivery(&tx, &row, old_due).unwrap();
    tx.commit().unwrap();
    let second = db.claim_due(10, 60).await.unwrap().pop().unwrap();
    assert_eq!(second.id, first.id);
    assert_eq!(second.attempts, 2);
    db.complete(first.id, first.attempts).await.unwrap();
    db.fail(first.id, first.attempts, None, "stale failure")
        .await
        .unwrap();
    let retained: Delivery = read(&db.db, &delivery_key(first.id)).unwrap().unwrap();
    assert!(retained.pending);
    assert_eq!(retained.token, "signed-logout-token");
    db.complete(second.id, second.attempts).await.unwrap();
    let completed: Delivery = read(&db.db, &delivery_key(first.id)).unwrap().unwrap();
    assert!(!completed.pending);
    assert!(completed.token.is_empty());
    db.enqueue_idempotent_batch(&deliveries).await.unwrap();
    assert!(db.claim_due(10, 60).await.unwrap().is_empty());
}

#[tokio::test]
async fn retry_releases_its_lease_and_expired_delivery_never_exposes_a_token() {
    let database = database::Database::new();
    let db = database.store();
    let delivery = delivery();
    db.enqueue_idempotent_batch(std::slice::from_ref(&delivery))
        .await
        .unwrap();
    let first = db.claim_due(1, 60).await.unwrap().pop().unwrap();
    db.fail(
        first.id,
        first.attempts,
        Some(Timestamp::now()),
        "temporary",
    )
    .await
    .unwrap();
    let next = db.claim_due(1, 60).await.unwrap().pop().unwrap();
    assert_eq!(next.attempts, 2);
    let mut expired = delivery;
    expired.operation_key = "expired".into();
    expired.expires_at = Timestamp::now() - SignedDuration::from_secs(1);
    db.enqueue_idempotent_batch(&[expired.clone()])
        .await
        .unwrap();
    assert!(db.claim_due(10, 60).await.unwrap().is_empty());
    let id: Uuid = read(
        &db.db,
        &idempotent_key(expired.tenant_id, &expired.operation_key, expired.client_id),
    )
    .unwrap()
    .unwrap();
    let row: Delivery = read(&db.db, &delivery_key(id)).unwrap().unwrap();
    assert!(!row.pending);
    assert!(row.token.is_empty());
}
