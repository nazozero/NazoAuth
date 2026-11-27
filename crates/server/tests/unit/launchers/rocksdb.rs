use super::*;

#[tokio::test]
async fn server_rejects_unavailable_audit_postures_before_opening_database() {
    let source = ConfigSource::from_pairs_for_test([("DATABASE_URL", "unused-database")]);
    let error = RocksDbLauncher
        .server_bindings(&source)
        .await
        .err()
        .unwrap();
    assert!(
        error
            .to_string()
            .contains("SECURITY_AUDIT_REQUIRE_LEAST_PRIVILEGE=false")
    );
    let source = ConfigSource::from_pairs_for_test([
        ("DATABASE_URL", "unused-database"),
        ("SECURITY_AUDIT_REQUIRE_LEAST_PRIVILEGE", "false"),
        ("AUDIT_ANCHOR_MODE", "required"),
    ]);
    let error = RocksDbLauncher
        .server_bindings(&source)
        .await
        .err()
        .unwrap();
    assert!(
        error
            .to_string()
            .contains("AUDIT_ANCHOR_MODE must be disabled")
    );
}

#[tokio::test]
async fn offline_operator_does_not_load_or_activate_server_totp_keys() {
    let path = std::env::temp_dir().join(format!("nazo-rocksdb-launcher-{}", uuid::Uuid::now_v7()));
    let source = ConfigSource::from_owned_pairs_for_test([
        ("DATABASE_URL".into(), path.to_string_lossy().into_owned()),
        ("MFA_TOTP_ENCRYPTION_KEY_ID".into(), "existing-key".into()),
        (
            "MFA_TOTP_ENCRYPTION_KEY_FILE".into(),
            "unresolved-server-secret".into(),
        ),
    ]);
    let operator = RocksDbLauncher.operator_persistence(&source).await.unwrap();
    assert_eq!(operator.schema_revision().await.unwrap(), "rocksdb:1");
    drop(operator);
    std::fs::remove_dir_all(path).unwrap();
}
