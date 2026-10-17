//! Real owner receipts: exact recovery, capability closure, conflicts and concurrent commit.
use diesel::{QueryableByName, sql_query, sql_types};
use diesel_async::{
    AsyncConnection as _, AsyncPgConnection, RunQueryDsl as _, SimpleAsyncConnection as _,
};
use nazo_identity::{TenantContext, TenantDirectoryBinding, TenantId};
use nazo_operator_protocol::ControlResultData;
use nazo_persistence::{
    directory_control::{DirectoryControlAction, DirectoryControlFrame},
    tenant_resources::{
        ControlTenantResourceFrame, TenantResourceAction, TenantResourceExecutorError,
        TenantResourceExecutorPort,
    },
};
use nazo_postgres::{
    DbPool, PostgresTenantResourceExecutor, TenantDirectoryControlRepository,
    TenantDirectoryRepository, TenantResourceRepository, create_pool,
};
use serde_json::{Value, json};
use uuid::Uuid;

struct Fixture {
    pool: DbPool,
    tenant: TenantContext,
    executor: PostgresTenantResourceExecutor,
}
struct Identity {
    jti: String,
    hash: String,
    tenant: String,
    actor: Value,
}

impl Fixture {
    fn identity(&self) -> Identity {
        Identity {
            jti: Uuid::now_v7().to_string(),
            hash: "a".repeat(64),
            tenant: self.tenant.tenant_id.as_uuid().to_string(),
            actor: json!({"kind":"controller"}),
        }
    }
    async fn receipt(
        &self,
        identity: &Identity,
        action: TenantResourceAction,
    ) -> Result<Option<ControlResultData>, TenantResourceExecutorError> {
        PostgresTenantResourceExecutor::control_outcome(
            &TenantResourceRepository::new(self.pool.clone()),
            self.tenant.tenant_id,
            "deployment-o03",
            Uuid::parse_str(&identity.jti).unwrap(),
            &identity.hash,
            action,
        )
        .await
    }
}

fn frame(identity: &Identity, operation: TenantResourceAction) -> ControlTenantResourceFrame<'_> {
    ControlTenantResourceFrame {
        deployment_id: "deployment-o03",
        jti: &identity.jti,
        request_sha256: &identity.hash,
        actor: &identity.actor,
        operation,
        tenant_id: &identity.tenant,
        resources: vec![],
        selectors: &[],
    }
}

async fn fixture() -> Fixture {
    let base = std::env::var("NAZO_TEST_DATABASE_URL")
        .or_else(|_| std::env::var("DATABASE_URL"))
        .expect("tenant-resource-control tests require an explicit isolated test database");
    // Directory revision triggers deliberately target public, so this owner
    // fixture needs its own database rather than only an application schema.
    let database = format!("tenant_resource_control_{}", Uuid::now_v7().simple());
    let mut coordinator = AsyncPgConnection::establish(&base).await.unwrap();
    coordinator
        .batch_execute(&format!("CREATE DATABASE \"{database}\";"))
        .await
        .unwrap();
    drop(coordinator);
    let separator = base.rfind('/').expect("test database URL has a path");
    let url = format!("{}/{}", &base[..separator], database);
    nazo_postgres::run_pending_migrations(&url).await.unwrap();
    let pool = create_pool(url, 4).unwrap();
    let tenant = TenantContext::default_system();
    TenantDirectoryRepository::new(pool.clone())
        .initialize(TenantDirectoryBinding {
            tenant,
            runtime_revision: 1,
            issuer: "https://operator.example".to_owned(),
            external_host: "operator.example".to_owned(),
        })
        .await
        .unwrap();
    let executor = PostgresTenantResourceExecutor::without_apply_preparation(
        TenantResourceRepository::new(pool.clone()),
        tenant,
    );
    Fixture {
        pool,
        tenant,
        executor,
    }
}

#[derive(QueryableByName)]
struct Count {
    #[diesel(sql_type = sql_types::BigInt)]
    value: i64,
}

async fn audit_count(fixture: &Fixture, identity: &Identity) -> i64 {
    let mut connection = fixture.pool.get().await.unwrap();
    sql_query("SELECT count(*)::bigint AS value FROM public.security_audit_events WHERE payload->>'jti' = $1")
        .bind::<sql_types::Text,_>(&identity.jti).get_result::<Count>(&mut connection).await.unwrap().value
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn enumerate_and_revoke_commit_without_apply_preparation() {
    let fixture = fixture().await;
    let enumerate = fixture.identity();
    let first = fixture
        .executor
        .execute_control_operation(frame(&enumerate, TenantResourceAction::Enumerate))
        .await
        .unwrap();
    assert!(matches!(
        first,
        ControlResultData::TenantResourceEnumerate { revision: 0, .. }
    ));
    assert_eq!(
        fixture
            .receipt(&enumerate, TenantResourceAction::Enumerate)
            .await
            .unwrap(),
        Some(first)
    );
    let revoke = fixture.identity();
    let second = fixture
        .executor
        .execute_control_operation(frame(&revoke, TenantResourceAction::Revoke))
        .await
        .unwrap();
    assert!(matches!(
        second,
        ControlResultData::TenantResourceRevoke { revision: 1, .. }
    ));
    assert_eq!(
        fixture
            .receipt(&revoke, TenantResourceAction::Revoke)
            .await
            .unwrap(),
        Some(second)
    );
    assert_eq!(audit_count(&fixture, &enumerate).await, 1);
    assert_eq!(audit_count(&fixture, &revoke).await, 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn revoke_checks_surviving_children_only_for_targeted_parents() {
    use chrono::{Duration, Utc};
    use nazo_operator_protocol::{TenantResourceIdentity, TenantResourceKind};
    use nazo_persistence::tenant_resources::PreparedTenantResource;
    use nazo_postgres::{
        NewStoredOpenid4vcTrustPolicy, Openid4vcTrustPolicyWrite, OperatorManagedTrustAnchor,
        insert_operator_managed_trust_anchor_on_connection, protect_dataset_claims,
        upsert_operator_managed_dataset_on_connection,
    };

    let fixture = fixture().await;
    let tenant_id = fixture.tenant.tenant_id.as_uuid();
    let user_id = Uuid::now_v7();
    let client_id = Uuid::now_v7();
    let digest = "a".repeat(64);
    let mut connection = fixture.pool.get().await.unwrap();
    sql_query(
        "INSERT INTO users (id, tenant_id, realm_id, organization_id, username, email, password_hash)
         VALUES ($1, $2, $3, $4, 'dependency-user', 'dependency@example.test', 'test-only')",
    )
    .bind::<sql_types::Uuid, _>(user_id)
    .bind::<sql_types::Uuid, _>(tenant_id)
    .bind::<sql_types::Uuid, _>(fixture.tenant.realm_id.as_uuid())
    .bind::<sql_types::Uuid, _>(fixture.tenant.organization_id.as_uuid())
    .execute(&mut connection)
    .await
    .unwrap();
    sql_query(
        "INSERT INTO oauth_clients
         (id, tenant_id, realm_id, organization_id, client_id, client_name, client_type,
          redirect_uris, scopes, grant_types, token_endpoint_auth_method, require_mtls_bound_tokens,
          security_policy)
         VALUES ($1, $2, $3, $4, 'dependency-client', 'dependency', 'confidential',
                 '[]', '[\"openid\"]', '[\"authorization_code\"]', 'private_key_jwt', TRUE, $5)",
    )
    .bind::<sql_types::Uuid, _>(client_id)
    .bind::<sql_types::Uuid, _>(tenant_id)
    .bind::<sql_types::Uuid, _>(fixture.tenant.realm_id.as_uuid())
    .bind::<sql_types::Uuid, _>(fixture.tenant.organization_id.as_uuid())
    .bind::<sql_types::Jsonb, _>(
        serde_json::to_value(nazo_auth::ClientSecurityPolicy::default()).unwrap(),
    )
    .execute(&mut connection)
    .await
    .unwrap();
    let Openid4vcTrustPolicyWrite::Applied(policy) =
        TenantResourceRepository::apply_openid4vc_trust_policy_on_connection(
            &mut connection,
            NewStoredOpenid4vcTrustPolicy {
                tenant_id,
                resource_id: "policy",
                resource_digest: &digest,
                public_material: &json!({}),
                wallet_origins: &["https://wallet.example/".to_owned()],
            },
        )
        .await
        .unwrap()
    else {
        panic!("fresh policy must be applied")
    };
    TenantResourceRepository::bind_openid4vc_trust_policy_client_on_connection(
        &mut connection,
        tenant_id,
        "policy",
        &digest,
        client_id,
    )
    .await
    .unwrap();
    let now = Utc::now();
    let anchor_id = insert_operator_managed_trust_anchor_on_connection(
        &mut connection,
        OperatorManagedTrustAnchor {
            tenant_id: fixture.tenant.tenant_id,
            client_id,
            certificate_pem: "-----BEGIN CERTIFICATE-----\ncHVibGlj\n-----END CERTIFICATE-----\n",
            certificate_sha256: &digest,
            subject_dn: "CN=dependency",
            not_before: now - Duration::minutes(1),
            not_after: now + Duration::hours(1),
        },
    )
    .await
    .unwrap();
    let ciphertext = protect_dataset_claims(
        &[1; 32],
        tenant_id,
        user_id,
        "credential",
        &json!({"given_name":"Nazo"}),
    )
    .unwrap();
    upsert_operator_managed_dataset_on_connection(
        &mut connection,
        tenant_id,
        user_id,
        "credential",
        ciphertext,
        None,
        None,
    )
    .await
    .unwrap();
    let entries = [
        (TenantResourceKind::User, "user", format!("user/{user_id}")),
        (
            TenantResourceKind::OauthClient,
            "oauth-client",
            format!("oauth-client/{client_id}"),
        ),
        (
            TenantResourceKind::Openid4vcTrustPolicy,
            "openid4vc-trust-policy",
            format!("openid4vc-trust-policy/{policy}"),
        ),
        (
            TenantResourceKind::MtlsTrustAnchor,
            "mtls-trust-anchor",
            format!("mtls-trust-anchor/{anchor_id}"),
        ),
        (
            TenantResourceKind::Openid4vcDataset,
            "openid4vc-dataset",
            format!("openid4vc-dataset/{user_id}/credential"),
        ),
    ];
    let mut identities = Vec::new();
    for (kind, name, locator) in entries {
        let resource_id = if kind == TenantResourceKind::Openid4vcTrustPolicy {
            "policy"
        } else {
            name
        };
        sql_query(
            "INSERT INTO tenant_resource_bindings
             (id, tenant_id, resource_kind, resource_id, resource_digest, active, locator)
             VALUES ($1, $2, $3, $4, $5, TRUE, $6)",
        )
        .bind::<sql_types::Uuid, _>(Uuid::now_v7())
        .bind::<sql_types::Uuid, _>(tenant_id)
        .bind::<sql_types::Text, _>(name)
        .bind::<sql_types::Text, _>(resource_id)
        .bind::<sql_types::Text, _>(&digest)
        .bind::<sql_types::Text, _>(&locator)
        .execute(&mut connection)
        .await
        .unwrap();
        identities.push(TenantResourceIdentity {
            kind,
            resource_id: resource_id.to_owned(),
            digest: digest.clone(),
        });
    }
    drop(connection);
    for parent in &identities[..3] {
        let identity = fixture.identity();
        let mut request = frame(&identity, TenantResourceAction::Revoke);
        request.resources = vec![PreparedTenantResource {
            identity: parent.clone(),
            payload: None,
        }];
        assert_eq!(
            fixture.executor.execute_control_operation(request).await,
            Err(TenantResourceExecutorError::Rejected),
            "surviving child must prevent revoking {:?}",
            parent.kind,
        );
        assert_eq!(audit_count(&fixture, &identity).await, 0);
    }
    // Revoking a dataset leaf leaves the unrelated client and its children active.
    let identity = fixture.identity();
    let mut request = frame(&identity, TenantResourceAction::Revoke);
    request.resources = vec![PreparedTenantResource {
        identity: identities.pop().unwrap(),
        payload: None,
    }];
    fixture
        .executor
        .execute_control_operation(request)
        .await
        .unwrap();
    assert_eq!(audit_count(&fixture, &identity).await, 1);

    let identity = fixture.identity();
    let mut request = frame(&identity, TenantResourceAction::Revoke);
    request.resources = identities
        .into_iter()
        .map(|identity| PreparedTenantResource {
            identity,
            payload: None,
        })
        .collect();
    let outcome = fixture
        .executor
        .execute_control_operation(request)
        .await
        .unwrap();
    let ControlResultData::TenantResourceRevoke {
        resources,
        resource_manifest_sha256,
        ..
    } = outcome
    else {
        panic!("expected revoke result");
    };
    assert_eq!(resources.len(), 4);
    assert_eq!(
        resource_manifest_sha256,
        nazo_persistence::tenant_resources::empty_manifest_sha256()
    );
    assert_eq!(audit_count(&fixture, &identity).await, 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn filtered_enumeration_keeps_the_complete_manifest_digest() {
    use nazo_operator_protocol::{
        TenantResourceIdentity, TenantResourceKind, TenantResourceSelector,
        canonical_tenant_resource_manifest_sha256,
    };

    let fixture = fixture().await;
    let resources = ["first", "second"].map(|name| TenantResourceIdentity {
        kind: TenantResourceKind::User,
        resource_id: name.to_owned(),
        digest: "a".repeat(64),
    });
    let digest = canonical_tenant_resource_manifest_sha256(&resources).unwrap();
    let mut connection = fixture.pool.get().await.unwrap();
    for resource in &resources {
        sql_query(
            "INSERT INTO tenant_resource_bindings
             (id, tenant_id, resource_kind, resource_id, resource_digest, active, locator)
             VALUES ($1, $2, 'user', $3, $4, TRUE, $5)",
        )
        .bind::<sql_types::Uuid, _>(Uuid::now_v7())
        .bind::<sql_types::Uuid, _>(fixture.tenant.tenant_id.as_uuid())
        .bind::<sql_types::Text, _>(&resource.resource_id)
        .bind::<sql_types::Text, _>(&resource.digest)
        .bind::<sql_types::Text, _>(format!("user/{}", Uuid::now_v7()))
        .execute(&mut connection)
        .await
        .unwrap();
    }
    sql_query(
        "INSERT INTO tenant_resource_states (tenant_id, revision, resource_manifest_sha256)
         VALUES ($1, 1, $2)",
    )
    .bind::<sql_types::Uuid, _>(fixture.tenant.tenant_id.as_uuid())
    .bind::<sql_types::Text, _>(&digest)
    .execute(&mut connection)
    .await
    .unwrap();
    drop(connection);

    let identity = fixture.identity();
    let selectors = [TenantResourceSelector {
        kind: TenantResourceKind::User,
        resource_id: "second".to_owned(),
    }];
    let mut request = frame(&identity, TenantResourceAction::Enumerate);
    request.selectors = &selectors;
    let outcome = fixture
        .executor
        .execute_control_operation(request)
        .await
        .unwrap();
    assert_eq!(
        outcome,
        ControlResultData::TenantResourceEnumerate {
            revision: 1,
            resources: vec![resources[1].clone()],
            resource_manifest_sha256: digest,
        }
    );
    assert_eq!(
        fixture
            .receipt(&identity, TenantResourceAction::Enumerate)
            .await
            .unwrap(),
        Some(outcome),
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn exact_receipt_survives_real_tenant_disable_and_rejects_identity_drift() {
    let fixture = fixture().await;
    let identity = fixture.identity();
    let expected = fixture
        .executor
        .execute_control_operation(frame(&identity, TenantResourceAction::Enumerate))
        .await
        .unwrap();
    let disable = fixture.identity();
    TenantDirectoryControlRepository::new(fixture.pool.clone())
        .execute_control_operation(DirectoryControlFrame {
            deployment_id: "deployment-o03",
            jti: &disable.jti,
            request_sha256: &disable.hash,
            actor: &disable.actor,
            action: DirectoryControlAction::Disable {
                expected_revision: 1,
                tenant_id: fixture.tenant.tenant_id,
            },
        })
        .await
        .unwrap();
    assert!(
        TenantDirectoryRepository::new(fixture.pool.clone())
            .load_active()
            .await
            .unwrap()
            .tenants
            .is_empty()
    );
    assert_eq!(
        fixture
            .receipt(&identity, TenantResourceAction::Enumerate)
            .await
            .unwrap(),
        Some(expected.clone())
    );
    assert_eq!(
        fixture
            .executor
            .execute_control_operation(frame(&identity, TenantResourceAction::Enumerate))
            .await
            .unwrap(),
        expected
    );
    assert_eq!(audit_count(&fixture, &identity).await, 1);
    let repository = TenantResourceRepository::new(fixture.pool.clone());
    for (tenant, hash, action) in [
        (
            fixture.tenant.tenant_id,
            "b".repeat(64),
            TenantResourceAction::Enumerate,
        ),
        (
            TenantId::new(Uuid::now_v7()).unwrap(),
            identity.hash.clone(),
            TenantResourceAction::Enumerate,
        ),
        (
            fixture.tenant.tenant_id,
            identity.hash.clone(),
            TenantResourceAction::Revoke,
        ),
    ] {
        assert!(matches!(
            PostgresTenantResourceExecutor::control_outcome(
                &repository,
                tenant,
                "deployment-o03",
                Uuid::parse_str(&identity.jti).unwrap(),
                &hash,
                action
            )
            .await,
            Err(TenantResourceExecutorError::Conflict)
        ));
    }
    let mut connection = fixture.pool.get().await.unwrap();
    // A committed outcome cannot be replaced, including by malformed JSON.
    assert!(sql_query("UPDATE tenant_resource_control_operations SET outcome = '{\"bogus\":true}'::jsonb WHERE operation_id=$1")
        .bind::<sql_types::Uuid,_>(Uuid::parse_str(&identity.jti).unwrap()).execute(&mut connection).await.is_err());
    // Seed a distinct schema-valid, wire-invalid row through fixture SQL.
    // Keep all append-only triggers enabled: this checks typed recovery of
    // pre-existing bad data, not permission to mutate an accepted receipt.
    let malformed = fixture.identity();
    sql_query("INSERT INTO tenant_resource_control_operations (operation_id, request_hash, tenant_id, operation, outcome) VALUES ($1, $2, $3, 'enumerate', '{\"bogus\":true}'::jsonb)")
        .bind::<sql_types::Uuid,_>(Uuid::parse_str(&malformed.jti).unwrap())
        .bind::<sql_types::Text,_>(&malformed.hash)
        .bind::<sql_types::Uuid,_>(fixture.tenant.tenant_id.as_uuid())
        .execute(&mut connection).await.unwrap();
    drop(connection);
    assert_eq!(
        fixture
            .receipt(&identity, TenantResourceAction::Enumerate)
            .await
            .unwrap(),
        Some(expected)
    );
    assert!(matches!(
        fixture
            .receipt(&malformed, TenantResourceAction::Enumerate)
            .await,
        Err(TenantResourceExecutorError::Unavailable)
    ));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrent_execution_commits_one_exact_receipt_and_audit() {
    let fixture = fixture().await;
    let identity = fixture.identity();
    let (left, right) = tokio::join!(
        fixture
            .executor
            .execute_control_operation(frame(&identity, TenantResourceAction::Enumerate)),
        fixture
            .executor
            .execute_control_operation(frame(&identity, TenantResourceAction::Enumerate))
    );
    let expected = left.unwrap();
    assert_eq!(right.unwrap(), expected);
    assert_eq!(
        fixture
            .receipt(&identity, TenantResourceAction::Enumerate)
            .await
            .unwrap(),
        Some(expected)
    );
    assert_eq!(audit_count(&fixture, &identity).await, 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn fresh_apply_without_required_preparation_is_rejected_without_receipt() {
    let fixture = fixture().await;
    let identity = fixture.identity();
    assert!(
        fixture
            .receipt(&identity, TenantResourceAction::Apply)
            .await
            .unwrap()
            .is_none()
    );
    assert!(matches!(
        fixture
            .executor
            .execute_control_operation(frame(&identity, TenantResourceAction::Apply))
            .await,
        Err(TenantResourceExecutorError::Rejected)
    ));
    assert!(
        fixture
            .receipt(&identity, TenantResourceAction::Apply)
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(audit_count(&fixture, &identity).await, 0);
}
