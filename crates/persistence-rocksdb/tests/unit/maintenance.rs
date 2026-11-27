use super::*;
use crate::db::{expiry_key, key, put_expiring, read};
use uuid::Uuid;

#[tokio::test]
async fn expiry_cleanup_is_bounded_separates_history_and_keeps_renewed_records() {
    let path = std::env::temp_dir().join(format!("nazo-rocksdb-cleanup-{}", Uuid::new_v4()));
    let db = RocksDb::open(&path).unwrap();
    let tenant = Uuid::new_v4();
    let expired = jiff::Timestamp::now()
        .checked_sub(std::time::Duration::from_secs(60))
        .unwrap();
    let future = expired
        .checked_add(std::time::Duration::from_secs(3600))
        .unwrap();
    let tx = db.transaction();
    for index in 0..BATCH + 41 {
        put_expiring(
            &tx,
            &key(
                crate::tokens::REVOCATION,
                tenant,
                &(index as u64).to_be_bytes(),
            ),
            &(),
            expired,
        )
        .unwrap();
    }
    let remembered = key(crate::mfa::REMEMBERED, tenant, b"remembered");
    put_expiring(&tx, &remembered, &(), expired).unwrap();
    let renewed = key(crate::tokens::REVOCATION, tenant, b"renewed");
    put_expiring(&tx, &renewed, &(), future).unwrap();
    // An old candidate must not delete a replacement with a later expiry.
    tx.put(expiry_key(&renewed, expired.as_microsecond()), [])
        .unwrap();
    tx.commit().unwrap();

    let first = db.cleanup_batch(CleanupScope::ProtocolState).await.unwrap();
    assert_eq!(first.revocations, BATCH as u64);
    assert!(first.saturated);
    let second = db.cleanup_batch(CleanupScope::ProtocolState).await.unwrap();
    assert_eq!(second.revocations, 41);
    assert!(!second.saturated);
    assert!(read::<()>(&db.db, &remembered).unwrap().is_some());
    assert!(read::<()>(&db.db, &renewed).unwrap().is_some());
    let history = db
        .cleanup_batch(CleanupScope::IncludingHistory)
        .await
        .unwrap();
    assert_eq!(history.remembered_mfa_devices, 1);
    assert!(read::<()>(&db.db, &remembered).unwrap().is_none());
    assert!(read::<()>(&db.db, &renewed).unwrap().is_some());
    drop(db);
    std::fs::remove_dir_all(path).unwrap();
}
