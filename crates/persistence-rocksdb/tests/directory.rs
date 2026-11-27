use nazo_identity::{
    OrganizationId, RealmId, TenantBoundaryDefinition, TenantContext, TenantDirectoryBinding,
    TenantId, TenantProvisioningRequest,
};
use nazo_persistence::{
    TenantDirectoryStore,
    directory_control::{
        DirectoryControlAction, DirectoryControlFrame, TenantDirectoryControlError,
        TenantDirectoryControlPort,
    },
};
use nazo_rocksdb::RocksDb;
use uuid::Uuid;

fn provisioning(host: &str) -> TenantProvisioningRequest {
    let tenant = TenantContext {
        tenant_id: TenantId::new(Uuid::now_v7()).unwrap(),
        realm_id: RealmId::new(Uuid::now_v7()).unwrap(),
        organization_id: OrganizationId::new(Uuid::now_v7()).unwrap(),
    };
    TenantProvisioningRequest {
        tenant: TenantBoundaryDefinition {
            id: tenant.tenant_id,
            slug: "tenant".into(),
            display_name: "Tenant".into(),
        },
        realm: TenantBoundaryDefinition {
            id: tenant.realm_id,
            slug: "realm".into(),
            display_name: "Realm".into(),
        },
        organization: TenantBoundaryDefinition {
            id: tenant.organization_id,
            slug: "organization".into(),
            display_name: "Organization".into(),
        },
        binding: TenantDirectoryBinding {
            tenant,
            runtime_revision: 1,
            issuer: format!("https://{host}"),
            external_host: host.into(),
        },
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn directory_revision_collision_and_receipt_survive_reopen() {
    let path = std::env::temp_dir().join(format!("nazo-rocksdb-directory-{}", Uuid::new_v4()));
    let store = RocksDb::open(&path).unwrap();
    let actor = serde_json::json!({"controller":"test"});
    let request_hash = "a".repeat(64);
    let first = provisioning("first.example.test");
    let second = provisioning("second.example.test");
    let first_id = Uuid::now_v7().to_string();
    let second_id = Uuid::now_v7().to_string();
    let left = DirectoryControlFrame {
        deployment_id: "directory-test",
        jti: &first_id,
        request_sha256: &request_hash,
        actor: &actor,
        action: DirectoryControlAction::Create {
            expected_revision: 0,
            provisioning: Box::new(first.clone()),
        },
    };
    let right = DirectoryControlFrame {
        deployment_id: "directory-test",
        jti: &second_id,
        request_sha256: &request_hash,
        actor: &actor,
        action: DirectoryControlAction::Create {
            expected_revision: 0,
            provisioning: Box::new(second.clone()),
        },
    };
    let (a, b) = tokio::join!(
        store.execute_control_operation(left),
        store.execute_control_operation(right)
    );
    assert_eq!(usize::from(a.is_ok()) + usize::from(b.is_ok()), 1);
    let (chosen, jti, outcome) = if let Ok(outcome) = a {
        assert_eq!(b.unwrap_err(), TenantDirectoryControlError::Conflict);
        (first, first_id, outcome)
    } else {
        (second, second_id, b.unwrap())
    };
    assert_eq!(store.current_revision().await.unwrap(), 1);
    drop(store);
    let store = RocksDb::open(&path).unwrap();
    let replay = store
        .execute_control_operation(DirectoryControlFrame {
            deployment_id: "directory-test",
            jti: &jti,
            request_sha256: &request_hash,
            actor: &actor,
            action: DirectoryControlAction::Create {
                expected_revision: 0,
                provisioning: Box::new(chosen.clone()),
            },
        })
        .await
        .unwrap();
    assert_eq!(replay, outcome);
    assert_eq!(
        store.load_active().await.unwrap().tenants,
        vec![chosen.binding.clone()]
    );
    let mut collision = provisioning(&chosen.binding.external_host);
    let collision_id = Uuid::now_v7().to_string();
    assert!(
        store
            .execute_control_operation(DirectoryControlFrame {
                deployment_id: "directory-test",
                jti: &collision_id,
                request_sha256: &request_hash,
                actor: &actor,
                action: DirectoryControlAction::Create {
                    expected_revision: 1,
                    provisioning: Box::new(collision.clone())
                }
            })
            .await
            .is_err()
    );
    assert_eq!(store.current_revision().await.unwrap(), 1);
    assert!(
        store
            .find_active_binding(collision.binding.tenant.tenant_id)
            .await
            .unwrap()
            .is_none()
    );
    collision.binding.external_host = "recovered.example.test".into();
    collision.binding.issuer = "https://recovered.example.test".into();
    store
        .execute_control_operation(DirectoryControlFrame {
            deployment_id: "directory-test",
            jti: &collision_id,
            request_sha256: &"b".repeat(64),
            actor: &actor,
            action: DirectoryControlAction::Create {
                expected_revision: 1,
                provisioning: Box::new(collision),
            },
        })
        .await
        .unwrap();
    assert_eq!(store.current_revision().await.unwrap(), 2);
    let disable_id = Uuid::now_v7().to_string();
    store
        .execute_control_operation(DirectoryControlFrame {
            deployment_id: "directory-test",
            jti: &disable_id,
            request_sha256: &request_hash,
            actor: &actor,
            action: DirectoryControlAction::Disable {
                expected_revision: 2,
                tenant_id: chosen.binding.tenant.tenant_id,
            },
        })
        .await
        .unwrap();
    assert!(
        store
            .find_active_binding(chosen.binding.tenant.tenant_id)
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(store.load_active().await.unwrap().tenants.len(), 1);
    drop(store);
    std::fs::remove_dir_all(path).unwrap();
}
