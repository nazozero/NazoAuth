use super::*;

#[test]
fn directory_snapshot_maps_active_bindings_and_empty_directory() {
    let tenant = TenantContext::default_system();
    let snapshot = directory_snapshot(vec![TenantDirectoryRow {
        revision: 7,
        tenant_id: Some(tenant.tenant_id.as_uuid()),
        realm_id: Some(tenant.realm_id.as_uuid()),
        organization_id: Some(tenant.organization_id.as_uuid()),
        issuer: Some("https://auth.example".to_owned()),
        external_host: Some("auth.example".to_owned()),
        runtime_revision: Some(1),
    }])
    .expect("complete directory row should map");
    assert_eq!(snapshot.revision, 7);
    assert_eq!(snapshot.tenants.len(), 1);
    assert_eq!(snapshot.tenants[0].tenant, tenant);
    assert_eq!(snapshot.tenants[0].issuer, "https://auth.example");
    assert_eq!(snapshot.tenants[0].external_host, "auth.example");

    let empty = directory_snapshot(vec![TenantDirectoryRow {
        revision: 8,
        tenant_id: None,
        realm_id: None,
        organization_id: None,
        issuer: None,
        external_host: None,
        runtime_revision: None,
    }])
    .expect("directory state without active bindings should map");
    assert_eq!(empty.revision, 8);
    assert!(empty.tenants.is_empty());
}

#[test]
fn directory_snapshot_rejects_incomplete_rows() {
    let error = directory_snapshot(vec![TenantDirectoryRow {
        revision: 1,
        tenant_id: Some(Uuid::now_v7()),
        realm_id: None,
        organization_id: None,
        issuer: Some("https://auth.example".to_owned()),
        external_host: Some("auth.example".to_owned()),
        runtime_revision: Some(1),
    }])
    .expect_err("partial binding must fail closed");
    assert!(matches!(error, RepositoryError::Consistency(_)));
}

#[test]
fn directory_revision_rejects_negative_storage_values() {
    assert_eq!(decode_directory_revision(0), Ok(0));
    assert!(matches!(
        decode_directory_revision(-1),
        Err(RepositoryError::Consistency(_))
    ));
}

#[test]
fn query_errors_preserve_not_found_and_unexpected_semantics() {
    assert_eq!(
        map_query_error(diesel::result::Error::NotFound),
        RepositoryError::NotFound
    );
    assert!(matches!(
        map_query_error(diesel::result::Error::RollbackTransaction),
        RepositoryError::Unexpected(message) if message.contains("rollback")
    ));
}
