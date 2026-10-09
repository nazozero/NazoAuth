//! Real owner receipts: exact recovery, capability closure, conflicts and concurrent commit.
use diesel::{QueryableByName, sql_query, sql_types};
use diesel_async::{
    AsyncConnection as _, AsyncPgConnection, RunQueryDsl as _, SimpleAsyncConnection as _,
};
use nazo_identity::{TenantContext, TenantDirectoryBinding, TenantId};
use nazo_persistence::{
    directory_control::{DirectoryControlAction, DirectoryControlFrame},
    tenant_resources::{
        ControlTenantResourceFrame, ControlTenantResourceOutcome, TenantResourceAction,
        TenantResourceExecutorError, TenantResourceExecutorPort,
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
    ) -> Result<Option<ControlTenantResourceOutcome>, TenantResourceExecutorError> {
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
    assert_eq!(first.revision, 0);
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
    assert_eq!(second.revision, 1);
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
