use super::*;

#[path = "../support/tenancy.rs"]
mod bindings;

async fn execute(
    store: &RocksDb,
    action: DirectoryControlAction,
    id: Uuid,
) -> Result<DirectoryControlOutcome, TenantDirectoryControlError> {
    store
        .execute_control_operation(DirectoryControlFrame {
            deployment_id: "boundary-test",
            jti: &id.to_string(),
            request_sha256: &"a".repeat(64),
            actor: &serde_json::json!({}),
            action,
        })
        .await
}

fn create(request: &TenantProvisioningRequest, revision: u64) -> DirectoryControlAction {
    DirectoryControlAction::Create {
        expected_revision: revision,
        provisioning: Box::new(request.clone()),
    }
}

#[tokio::test]
async fn boundary_metadata_and_slug_uniqueness_survive_reopen() {
    let path = std::env::temp_dir().join(format!("nazo-rocksdb-boundaries-{}", Uuid::new_v4()));
    let store = RocksDb::open(&path).unwrap();
    let system = TenantContext::default_system();
    store
        .initialize_tenant_directory(TenantDirectoryBinding {
            tenant: system,
            runtime_revision: 1,
            issuer: "https://default.example".into(),
            external_host: "default.example".into(),
        })
        .await
        .unwrap();
    let mut original = bindings::provisioning("alpha.example");
    original.tenant.slug = "Alpha".into();
    original.tenant.display_name = "Alpha tenant".into();
    original.realm.display_name = "Alpha realm".into();
    original.organization.display_name = "Alpha organization".into();
    execute(&store, create(&original, 1), Uuid::now_v7())
        .await
        .unwrap();
    for slug in ["aLPHA", "DEFAULT"] {
        let mut duplicate = bindings::provisioning("duplicate.example");
        duplicate.tenant.slug = slug.into();
        let id = Uuid::now_v7();
        assert_eq!(
            execute(&store, create(&duplicate, 2), id)
                .await
                .unwrap_err(),
            TenantDirectoryControlError::Unavailable
        );
        assert!(
            read::<TenantRecord>(&store.db, &key(TENANT, duplicate.tenant.id.as_uuid(), &[]))
                .unwrap()
                .is_none()
        );
        assert!(
            read::<OperationOutcome>(&store.db, &key(OUTCOME, Uuid::nil(), id.as_bytes()))
                .unwrap()
                .is_none()
        );
        assert_eq!(store.current_revision().await.unwrap(), 2);
    }
    // The same realm/organization slug belongs to independent tenant namespaces.
    let peer = bindings::provisioning("peer.example");
    execute(&store, create(&peer, 2), Uuid::now_v7())
        .await
        .unwrap();
    drop(store);
    let store = RocksDb::open(&path).unwrap();
    let row: TenantRecord = read(&store.db, &key(TENANT, original.tenant.id.as_uuid(), &[]))
        .unwrap()
        .unwrap();
    assert_eq!(row.slug, "Alpha");
    assert_eq!(row.display_name, "Alpha tenant");
    for (table, id, owner, slug, name) in [
        (
            REALM_OWNER,
            original.realm.id.as_uuid(),
            original.tenant.id.as_uuid(),
            "realm",
            "Alpha realm",
        ),
        (
            ORGANIZATION_OWNER,
            original.organization.id.as_uuid(),
            original.tenant.id.as_uuid(),
            "organization",
            "Alpha organization",
        ),
        (
            REALM_OWNER,
            system.realm_id.as_uuid(),
            system.tenant_id.as_uuid(),
            "default",
            "Default realm",
        ),
        (
            ORGANIZATION_OWNER,
            system.organization_id.as_uuid(),
            system.tenant_id.as_uuid(),
            "default",
            "Default organization",
        ),
    ] {
        let row: OwnedBoundary = read(&store.db, &key(table, Uuid::nil(), id.as_bytes()))
            .unwrap()
            .unwrap();
        assert_eq!(row.tenant_id, owner);
        assert_eq!(row.slug, slug);
        assert_eq!(row.display_name, name);
    }
    let row: TenantRecord = read(&store.db, &key(TENANT, system.tenant_id.as_uuid(), &[]))
        .unwrap()
        .unwrap();
    assert_eq!(
        (row.slug.as_str(), row.display_name.as_str()),
        ("default", "Default tenant")
    );
    // Existing boundary IDs retain their first metadata; provisioning is not rename.
    original.tenant.slug = "ignored-new-name".into();
    original.tenant.display_name = "Ignored".into();
    original.realm.display_name = "Ignored".into();
    execute(&store, create(&original, 3), Uuid::now_v7())
        .await
        .unwrap();
    assert_eq!(store.current_revision().await.unwrap(), 3);
    let row: TenantRecord = read(&store.db, &key(TENANT, original.tenant.id.as_uuid(), &[]))
        .unwrap()
        .unwrap();
    assert_eq!(
        (row.slug.as_str(), row.display_name.as_str()),
        ("Alpha", "Alpha tenant")
    );
    drop(store);
    std::fs::remove_dir_all(path).unwrap();
}

#[tokio::test]
async fn finalize_preserves_owned_boundary_slug_fences() {
    let database = crate::support::database::Database::new();
    let store = database.store();
    let original = bindings::provisioning("first.example");
    execute(store, create(&original, 0), Uuid::now_v7())
        .await
        .unwrap();
    let tenant = original.tenant.id;
    execute(
        store,
        DirectoryControlAction::Finalize {
            expected_revision: 1,
            tenant_id: tenant,
        },
        Uuid::now_v7(),
    )
    .await
    .unwrap();
    assert_eq!(
        execute(
            store,
            DirectoryControlAction::Finalize {
                expected_revision: 2,
                tenant_id: tenant
            },
            Uuid::now_v7()
        )
        .await
        .unwrap_err(),
        TenantDirectoryControlError::Rejected
    );
    let mut replacement = bindings::provisioning("replacement.example");
    replacement.tenant = original.tenant.clone();
    replacement.binding.tenant.tenant_id = tenant;
    replacement.realm.slug = "REALM".into();
    assert_eq!(
        execute(store, create(&replacement, 2), Uuid::now_v7())
            .await
            .unwrap_err(),
        TenantDirectoryControlError::Unavailable
    );
    replacement.realm.slug = "replacement-realm".into();
    replacement.organization.slug = "ORGANIZATION".into();
    assert_eq!(
        execute(store, create(&replacement, 2), Uuid::now_v7())
            .await
            .unwrap_err(),
        TenantDirectoryControlError::Unavailable
    );
    assert!(
        read::<OwnedBoundary>(
            &store.db,
            &key(
                REALM_OWNER,
                Uuid::nil(),
                replacement.realm.id.as_uuid().as_bytes()
            )
        )
        .unwrap()
        .is_none()
    );
    assert!(
        read::<Uuid>(
            &store.db,
            &key(REALM_SLUG, tenant.as_uuid(), b"replacement-realm")
        )
        .unwrap()
        .is_none()
    );
    assert_eq!(store.current_revision().await.unwrap(), 2);
    replacement.organization.slug = "replacement-organization".into();
    execute(store, create(&replacement, 2), Uuid::now_v7())
        .await
        .unwrap();
    assert_eq!(
        store.find_active_binding(tenant).await.unwrap(),
        Some(replacement.binding.clone())
    );
    execute(
        store,
        DirectoryControlAction::Disable {
            expected_revision: 3,
            tenant_id: tenant,
        },
        Uuid::now_v7(),
    )
    .await
    .unwrap();
    execute(
        store,
        DirectoryControlAction::Finalize {
            expected_revision: 4,
            tenant_id: tenant,
        },
        Uuid::now_v7(),
    )
    .await
    .unwrap();
    assert_eq!(
        execute(store, create(&replacement, 5), Uuid::now_v7())
            .await
            .unwrap_err(),
        TenantDirectoryControlError::Rejected
    );
}
