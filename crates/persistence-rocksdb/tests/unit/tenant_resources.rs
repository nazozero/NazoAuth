use super::*;
use nazo_identity::ports::ScimRepositoryPort;
use nazo_persistence::tenant_resources::{Openid4vcDatasetResourcePayload, UserResourcePayload};

use crate::support::clients;

struct Preparation;

impl TenantResourcePreparation for Preparation {
    fn hash_user_password<'a>(
        &'a self,
        _: String,
    ) -> BoxFuture<'a, Result<String, TenantResourcePreparationError>> {
        Box::pin(async { Ok("fixture-prepared-hash".into()) })
    }
    fn prepare_oauth_client<'a>(
        &'a self,
        _: nazo_auth::CreateClientRequest,
        _: Option<String>,
        _: TenantContext,
    ) -> BoxFuture<'a, Result<PreparedOAuthClient, TenantResourcePreparationError>> {
        Box::pin(async { Err(TenantResourcePreparationError::Rejected) })
    }
    fn prepare_mtls_trust_anchor<'a>(
        &'a self,
        _: String,
    ) -> BoxFuture<'a, Result<PreparedMtlsTrustAnchor, TenantResourcePreparationError>> {
        Box::pin(async { Err(TenantResourcePreparationError::Rejected) })
    }
}

fn user(digest: char) -> PreparedTenantResource {
    PreparedTenantResource {
        identity: TenantResourceIdentity {
            kind: TenantResourceKind::User,
            resource_id: "managed-user".into(),
            digest: digest.to_string().repeat(64),
        },
        payload: Some(TenantResourcePayload::User(Box::new(UserResourcePayload {
            username: "managed-user".into(),
            email: "managed@example.test".into(),
            password: "preparation-input".into(),
            email_verified: true,
            profile: UserProfileFields::default(),
        }))),
    }
}

fn dataset() -> PreparedTenantResource {
    PreparedTenantResource {
        identity: TenantResourceIdentity {
            kind: TenantResourceKind::Openid4vcDataset,
            resource_id: "dataset".into(),
            digest: "b".repeat(64),
        },
        payload: Some(TenantResourcePayload::Openid4vcDataset(
            Openid4vcDatasetResourcePayload {
                user_resource_id: "managed-user".into(),
                configuration_id: "employee".into(),
                claims: serde_json::json!({"name":"Managed"}),
            },
        )),
    }
}

async fn execute(
    executor: &RocksDbTenantResourceExecutor,
    operation: TenantResourceAction,
    resources: Vec<PreparedTenantResource>,
    jti: Uuid,
    actor: Value,
) -> Execution<ControlResultData> {
    let tenant = executor.tenant.tenant_id.as_uuid().to_string();
    executor
        .execute_control_operation(ControlTenantResourceFrame {
            deployment_id: "resource-test",
            jti: &jti.to_string(),
            request_sha256: &"a".repeat(64),
            actor: &actor,
            operation,
            tenant_id: &tenant,
            resources,
            selectors: &[],
        })
        .await
}

async fn fixture() -> (std::path::PathBuf, RocksDb, RocksDbTenantResourceExecutor) {
    let path = std::env::temp_dir().join(format!("nazo-rocksdb-resources-{}", Uuid::new_v4()));
    let store = RocksDb::open(&path).unwrap();
    let tenant = TenantContext::default_system();
    store
        .initialize_tenant_directory(nazo_identity::TenantDirectoryBinding {
            tenant,
            runtime_revision: 1,
            issuer: "https://resources.example.test".into(),
            external_host: "resources.example.test".into(),
        })
        .await
        .unwrap();
    let executor = RocksDbTenantResourceExecutor::new(
        store.clone(),
        tenant,
        Some([7; 32]),
        Some(Arc::new(Preparation)),
    );
    (path, store, executor)
}

#[tokio::test]
async fn audit_failure_rolls_back_resource_authority_and_receipt() {
    let (path, store, executor) = fixture().await;
    let operation_id = Uuid::now_v7();
    let tenant = executor.tenant.tenant_id.as_uuid();
    let error=execute(&executor,TenantResourceAction::Apply,vec![user('a')],operation_id,serde_json::json!({"oversized":"x".repeat(nazo_persistence::MAX_SECURITY_AUDIT_PAYLOAD_BYTES)})).await.unwrap_err();
    assert_eq!(error, TenantResourceExecutorError::Unavailable);
    assert!(
        read::<Uuid>(
            &store.db,
            &key(crate::users::USER_EMAIL, tenant, b"managed@example.test")
        )
        .unwrap()
        .is_none()
    );
    assert!(
        store
            .tenant_resource_control_outcome(
                executor.tenant.tenant_id,
                "resource-test",
                operation_id,
                &"a".repeat(64),
                TenantResourceAction::Apply
            )
            .await
            .unwrap()
            .is_none()
    );
    let result = execute(
        &executor,
        TenantResourceAction::Apply,
        vec![user('a')],
        operation_id,
        serde_json::json!({}),
    )
    .await
    .unwrap();
    assert!(matches!(
        result,
        ControlResultData::TenantResourceApply { revision: 1, .. }
    ));
    drop(executor);
    drop(store);
    std::fs::remove_dir_all(path).unwrap();
}

#[tokio::test]
async fn dependency_closure_ownership_reapply_and_exact_receipt_survive_restart() {
    let (path, store, executor) = fixture().await;
    let operation_id = Uuid::now_v7();
    let tenant = executor.tenant.tenant_id.as_uuid();
    let applied = execute(
        &executor,
        TenantResourceAction::Apply,
        vec![dataset(), user('a')],
        operation_id,
        serde_json::json!({}),
    )
    .await
    .unwrap();
    let ControlResultData::TenantResourceApply {
        resource_mappings,
        revision,
        ..
    } = &applied
    else {
        panic!("apply result");
    };
    assert_eq!(*revision, 1);
    let user_id = Uuid::parse_str(&resource_mappings[0].public_id).unwrap();
    let tx = store.transaction();
    assert!(managed_user_tx(&tx, tenant, user_id).unwrap());
    let administrator = crate::users::create_user_tx(
        &tx,
        nazo_identity::ports::NewUser {
            tenant: executor.tenant,
            username: "administrator".into(),
            email: "administrator@example.test".into(),
            password_hash: nazo_identity::ports::PasswordHashInput::new("fixture-verifier")
                .unwrap(),
            email_verified: true,
        },
        nazo_identity::UserRole::Admin { level: 3 },
    )
    .unwrap();
    tx.commit().unwrap();
    let user_id_typed = nazo_identity::UserId::new(user_id).unwrap();
    nazo_identity::ports::ProfileRepositoryPort::update_profile(
        &store,
        executor.tenant.tenant_id,
        user_id_typed,
        Default::default(),
    )
    .await
    .unwrap();
    assert_eq!(
        nazo_identity::ports::ProfileRepositoryPort::update_profile(
            &store,
            executor.tenant.tenant_id,
            user_id_typed,
            nazo_identity::ProfilePatch {
                display_name: Some("unmanaged change".into()),
                ..Default::default()
            }
        )
        .await
        .unwrap_err(),
        RepositoryError::Conflict
    );
    let update = |active| nazo_identity::ports::AdminUserUpdate {
        role: None,
        admin_level: None,
        active: Some(active),
    };
    assert!(matches!(
        nazo_identity::ports::AdminUserRepositoryPort::update_authorized_with_required_audit(
            &store,
            executor.tenant,
            administrator.principal.user_id,
            user_id_typed,
            update(true),
            "a".repeat(64)
        )
        .await
        .unwrap(),
        nazo_identity::AdminUserUpdateOutcome::Updated(_)
    ));
    assert_eq!(
        nazo_identity::ports::AdminUserRepositoryPort::update_authorized_with_required_audit(
            &store,
            executor.tenant,
            administrator.principal.user_id,
            user_id_typed,
            update(false),
            "a".repeat(64)
        )
        .await
        .unwrap_err(),
        RepositoryError::Conflict
    );
    {
        let scim = crate::scim::ScimRepository {
            store: store.clone(),
            retention_seconds: 600,
        };
        scim.patch(
            executor.tenant,
            user_id_typed,
            Default::default(),
            Default::default(),
        )
        .await
        .unwrap();
        assert_eq!(
            scim.patch(
                executor.tenant,
                user_id_typed,
                nazo_identity::scim::ScimPatch {
                    active: Some(false),
                    ..Default::default()
                },
                Default::default(),
            )
            .await
            .unwrap_err(),
            RepositoryError::Conflict
        );
        assert_eq!(
            scim.delete(executor.tenant, user_id_typed, Default::default())
                .await
                .unwrap_err(),
            RepositoryError::Conflict
        );
    }
    let revocation = |mut resource: PreparedTenantResource| {
        resource.payload = None;
        resource
    };
    assert_eq!(
        execute(
            &executor,
            TenantResourceAction::Revoke,
            vec![revocation(user('a'))],
            Uuid::now_v7(),
            serde_json::json!({})
        )
        .await
        .unwrap_err(),
        TenantResourceExecutorError::Rejected
    );
    let tx = store.transaction();
    assert!(
        crate::users::read_principal_tx(&tx, tenant, user_id, false)
            .unwrap()
            .unwrap()
            .active
    );
    drop(tx);
    execute(
        &executor,
        TenantResourceAction::Revoke,
        vec![revocation(dataset()), revocation(user('a'))],
        Uuid::now_v7(),
        serde_json::json!({}),
    )
    .await
    .unwrap();
    let tx = store.transaction();
    let revoked = crate::users::read_principal_tx(&tx, tenant, user_id, false)
        .unwrap()
        .unwrap();
    assert!(!revoked.active);
    assert!(revoked.authorization_epoch > 0);
    drop(tx);
    let reapplied = execute(
        &executor,
        TenantResourceAction::Apply,
        vec![user('c')],
        Uuid::now_v7(),
        serde_json::json!({}),
    )
    .await
    .unwrap();
    let ControlResultData::TenantResourceApply {
        resource_mappings, ..
    } = reapplied
    else {
        panic!("apply result");
    };
    assert_eq!(resource_mappings[0].public_id, user_id.to_string());
    drop(executor);
    drop(store);
    let store = RocksDb::open(&path).unwrap();
    let executor = RocksDbTenantResourceExecutor::new(
        store.clone(),
        TenantContext::default_system(),
        None,
        None,
    );
    assert_eq!(
        execute(
            &executor,
            TenantResourceAction::Apply,
            Vec::new(),
            operation_id,
            serde_json::json!({})
        )
        .await
        .unwrap(),
        applied
    );
    assert!(matches!(
        store
            .tenant_resource_control_outcome(
                executor.tenant.tenant_id,
                "another-deployment",
                operation_id,
                &"a".repeat(64),
                TenantResourceAction::Apply
            )
            .await,
        Err(TenantResourceExecutorError::Conflict)
    ));
    drop(executor);
    drop(store);
    std::fs::remove_dir_all(path).unwrap();
}

#[tokio::test]
async fn replaced_trust_policy_does_not_rebind_existing_client_or_presentation() {
    let (path, store, executor) = fixture().await;
    let tenant = executor.tenant.tenant_id.as_uuid();
    let client = clients::client(executor.tenant, "policy-client");
    let id = Uuid::now_v7();
    let digest = "a".repeat(64);
    let resource = "wallet-policy";
    let jwks = serde_json::json!({"keys":[{"kty":"EC","crv":"P-256","x":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","y":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","kid":"key"}]});
    let mut policy = Policy {
        id,
        resource: resource.into(),
        digest: digest.clone(),
        active: true,
        material: Openid4vcTrustPolicy {
            schema: 1,
            client_attestation_issuer: "https://issuer.example".into(),
            client_attestation_jwks: jwks.clone(),
            key_attestation_jwks: jwks,
            credential_trust_anchor_pem:
                "-----BEGIN CERTIFICATE-----\nMA==\n-----END CERTIFICATE-----\n".into(),
            wallet_authorization_origins: vec!["https://wallet.example".into()],
        },
    };
    let tx = store.transaction();
    crate::clients::insert_client_tx(&tx, &client, None, None, 0).unwrap();
    put(
        &tx,
        &key(TRUST_POLICY, tenant, resource.as_bytes()),
        &policy,
    )
    .unwrap();
    put(
        &tx,
        &key(CLIENT_POLICY, tenant, client.id.as_bytes()),
        &PolicyBinding {
            policy_id: id,
            resource: resource.into(),
            digest: digest.clone(),
            active: true,
        },
    )
    .unwrap();
    tx.commit().unwrap();
    assert!(matches!(
        store.for_client(tenant, &client.client_id).await.unwrap(),
        ClientTrustPolicy::Active(_)
    ));
    assert!(
        store
            .active_for_origin(tenant, resource, "https://wallet.example", &digest)
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        store
            .active_for_origin(tenant, resource, "https://another.example", &digest)
            .await
            .unwrap()
            .is_none()
    );
    let tx = store.transaction();
    assert!(
        trust_binding_current_tx(&tx, tenant, Some(id), Some(resource), Some(&digest)).unwrap()
    );
    assert!(!trust_binding_current_tx(&tx, tenant, Some(id), None, None).unwrap());
    drop(tx);
    policy.id = Uuid::now_v7();
    policy.digest = "b".repeat(64);
    let tx = store.transaction();
    put(
        &tx,
        &key(TRUST_POLICY, tenant, resource.as_bytes()),
        &policy,
    )
    .unwrap();
    tx.commit().unwrap();
    assert!(matches!(
        store.for_client(tenant, &client.client_id).await.unwrap(),
        ClientTrustPolicy::BoundInactive
    ));
    assert!(
        !trust_binding_current_snapshot(
            &store.db.snapshot(),
            tenant,
            Some(id),
            Some(resource),
            Some(&digest)
        )
        .unwrap()
    );
    drop(executor);
    drop(store);
    std::fs::remove_dir_all(path).unwrap();
}
