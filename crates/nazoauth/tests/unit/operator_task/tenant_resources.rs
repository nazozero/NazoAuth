//! Capability composition and exact-receipt recovery through the real host dispatcher.

use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};

use futures_util::future::BoxFuture;
use nazo_identity::{TenantContext, TenantDirectoryBinding, TenantDirectorySnapshot, TenantId};
use nazo_operator_protocol::{ControlOperationPayload, TenantResourceIdentity, TenantResourceKind};
use nazo_persistence::tenant_resources::{
    ControlTenantResourceFrame, ControlTenantResourceOutcome, TenantResourceAction,
    TenantResourceExecutorError, TenantResourceExecutorPort, TenantResourcePreparation,
};
use tokio::sync::Notify;
use uuid::Uuid;

use super::super::{
    OperatorBackendFuture, OperatorPersistence, control_journal::SideEffectError, execution,
};

const OPERATION_ID: &str = "019c8ca2-30a6-7000-8000-00000000a061";

#[derive(Clone)]
enum Receipt {
    Hit(ControlTenantResourceOutcome),
    Miss,
    Conflict,
    Unavailable,
}

#[derive(Default)]
struct ReceiptReadBarrier {
    captured: Notify,
    release: Notify,
}

struct Directory {
    snapshot: Mutex<TenantDirectorySnapshot>,
    reads: AtomicUsize,
}

impl nazo_persistence::TenantDirectoryStore for Directory {
    fn current_revision(
        &self,
    ) -> BoxFuture<'_, Result<u64, nazo_identity::ports::RepositoryError>> {
        Box::pin(async { Ok(self.snapshot.lock().unwrap().revision) })
    }

    fn load_active(
        &self,
    ) -> BoxFuture<'_, Result<TenantDirectorySnapshot, nazo_identity::ports::RepositoryError>> {
        Box::pin(async {
            self.reads.fetch_add(1, Ordering::Relaxed);
            Ok(self.snapshot.lock().unwrap().clone())
        })
    }
}

struct Executor {
    outcome: ControlTenantResourceOutcome,
    calls: AtomicUsize,
}

impl TenantResourceExecutorPort for Executor {
    fn execute_control_operation<'a>(
        &'a self,
        frame: ControlTenantResourceFrame<'a>,
    ) -> BoxFuture<'a, Result<ControlTenantResourceOutcome, TenantResourceExecutorError>> {
        Box::pin(async move {
            assert!(matches!(
                frame.operation,
                TenantResourceAction::Enumerate | TenantResourceAction::Revoke
            ));
            assert!(
                frame
                    .resources
                    .iter()
                    .all(|resource| resource.payload.is_none())
            );
            assert_eq!(frame.jti, OPERATION_ID);
            self.calls.fetch_add(1, Ordering::Relaxed);
            Ok(self.outcome.clone())
        })
    }
}

struct Persistence {
    tenant: TenantContext,
    receipt: Mutex<Receipt>,
    receipt_reads: AtomicUsize,
    barrier: Option<Arc<ReceiptReadBarrier>>,
    directory: Arc<Directory>,
    executor: Arc<Executor>,
    compositions: AtomicUsize,
}

impl Persistence {
    fn new(receipt: Receipt, active: bool) -> Self {
        let tenant = TenantContext {
            tenant_id: TenantId::new(Uuid::now_v7()).unwrap(),
            realm_id: nazo_identity::RealmId::new(Uuid::now_v7()).unwrap(),
            organization_id: nazo_identity::OrganizationId::new(Uuid::now_v7()).unwrap(),
        };
        let binding = TenantDirectoryBinding {
            tenant,
            runtime_revision: 1,
            issuer: "https://operator.example".to_owned(),
            external_host: "operator.example".to_owned(),
        };
        Self {
            tenant,
            receipt: Mutex::new(receipt),
            receipt_reads: AtomicUsize::new(0),
            barrier: None,
            directory: Arc::new(Directory {
                snapshot: Mutex::new(TenantDirectorySnapshot {
                    revision: 1,
                    tenants: if active { vec![binding] } else { vec![] },
                }),
                reads: AtomicUsize::new(0),
            }),
            executor: Arc::new(Executor {
                outcome: outcome(7),
                calls: AtomicUsize::new(0),
            }),
            compositions: AtomicUsize::new(0),
        }
    }
}

impl OperatorPersistence for Persistence {
    fn signing_key_repository(
        &self,
        _: Uuid,
    ) -> Arc<dyn nazo_key_management::SigningKeyRepository> {
        panic!("this operation must not initialize key capabilities")
    }
    fn controller_registry(&self) -> Arc<dyn nazo_persistence::ControllerRegistryPort> {
        unimplemented!()
    }
    fn recovery_invalidations(&self) -> Arc<dyn nazo_persistence::RecoveryInvalidationStore> {
        unimplemented!()
    }
    fn admin_clients(&self) -> Arc<dyn nazo_auth::AdminClientRepositoryPort> {
        panic!("this operation must not initialize registration capabilities")
    }
    fn tenant_resource_control_outcome<'a>(
        &'a self,
        tenant_id: TenantId,
        deployment_id: &'a str,
        operation_id: Uuid,
        request_hash: &'a str,
        _: TenantResourceAction,
    ) -> BoxFuture<'a, Result<Option<ControlTenantResourceOutcome>, TenantResourceExecutorError>>
    {
        Box::pin(async move {
            assert_eq!(tenant_id, self.tenant.tenant_id);
            assert_eq!(deployment_id, "deployment-o03");
            assert_eq!(operation_id.to_string(), OPERATION_ID);
            assert_eq!(request_hash, "a".repeat(64));
            self.receipt_reads.fetch_add(1, Ordering::Relaxed);
            let receipt = self.receipt.lock().unwrap().clone();
            if let Some(barrier) = &self.barrier {
                barrier.captured.notify_one();
                tokio::time::timeout(
                    std::time::Duration::from_secs(2),
                    barrier.release.notified(),
                )
                .await
                .expect("receipt release");
            }
            match receipt {
                Receipt::Hit(outcome) => Ok(Some(outcome)),
                Receipt::Miss => Ok(None),
                Receipt::Conflict => Err(TenantResourceExecutorError::Conflict),
                Receipt::Unavailable => Err(TenantResourceExecutorError::Unavailable),
            }
        })
    }
    fn tenant_resource_executor(
        &self,
        tenant: TenantContext,
        data_key: Option<[u8; 32]>,
        preparation: Option<Arc<dyn TenantResourcePreparation>>,
    ) -> Arc<dyn TenantResourceExecutorPort> {
        assert_eq!(tenant, self.tenant);
        assert!(data_key.is_none());
        assert!(preparation.is_none());
        self.compositions.fetch_add(1, Ordering::Relaxed);
        self.executor.clone()
    }
    fn tenant_directory_executor(
        &self,
    ) -> Arc<dyn nazo_persistence::directory_control::TenantDirectoryControlPort> {
        unimplemented!()
    }
    fn tenant_directory(&self) -> Arc<dyn nazo_persistence::TenantDirectoryStore> {
        self.directory.clone()
    }
    fn run_migrations(&self) -> OperatorBackendFuture<'_, bool> {
        unimplemented!()
    }
    fn initialize_tenant_directory(
        &self,
        _: TenantDirectoryBinding,
    ) -> OperatorBackendFuture<'_, bool> {
        unimplemented!()
    }
}

fn outcome(revision: u64) -> ControlTenantResourceOutcome {
    ControlTenantResourceOutcome {
        revision,
        resources: vec![],
        resource_mappings: vec![],
        resource_manifest_sha256: nazo_persistence::tenant_resources::empty_manifest_sha256(),
    }
}

fn context(hash: &str) -> execution::ExecutionContext<'_> {
    execution::ExecutionContext {
        operation_id: OPERATION_ID,
        deployment_id: "deployment-o03",
        controller_id: "controller-o03",
        kid: "controller-key-o03",
        request_hash: hash,
    }
}

fn operation(action: TenantResourceAction, tenant_id: TenantId) -> ControlOperationPayload {
    let tenant_id = tenant_id.as_uuid().to_string();
    let resources = vec![TenantResourceIdentity {
        kind: TenantResourceKind::User,
        resource_id: "operator-user".to_owned(),
        digest: "b".repeat(64),
    }];
    match action {
        TenantResourceAction::Apply => ControlOperationPayload::TenantResourceApply {
            tenant_id,
            resources,
        },
        TenantResourceAction::Enumerate => ControlOperationPayload::TenantResourceEnumerate {
            tenant_id,
            selectors: vec![],
        },
        TenantResourceAction::Revoke => ControlOperationPayload::TenantResourceRevoke {
            tenant_id,
            resources,
        },
    }
}

#[tokio::test]
async fn exact_tenant_resource_receipts_skip_current_tenant_and_apply_dependencies() {
    let hash = "a".repeat(64);
    for action in [
        TenantResourceAction::Apply,
        TenantResourceAction::Enumerate,
        TenantResourceAction::Revoke,
    ] {
        let expected = outcome(5);
        let persistence = Persistence::new(Receipt::Hit(expected.clone()), false);
        let result = execution::execute_with_persistence(
            &operation(action, persistence.tenant.tenant_id),
            &context(&hash),
            &persistence,
        )
        .await
        .unwrap();
        assert_eq!(result, Some(expected.control_result_data(action)));
        assert_eq!(persistence.receipt_reads.load(Ordering::Relaxed), 1);
        assert_eq!(persistence.directory.reads.load(Ordering::Relaxed), 0);
        assert_eq!(persistence.compositions.load(Ordering::Relaxed), 0);
        assert_eq!(persistence.executor.calls.load(Ordering::Relaxed), 0);
    }
}

#[tokio::test]
async fn fresh_enumerate_and_revoke_require_active_tenant_without_apply_capabilities() {
    let hash = "a".repeat(64);
    for action in [
        TenantResourceAction::Enumerate,
        TenantResourceAction::Revoke,
    ] {
        let persistence = Persistence::new(Receipt::Miss, true);
        let result = execution::execute_with_persistence(
            &operation(action, persistence.tenant.tenant_id),
            &context(&hash),
            &persistence,
        )
        .await
        .unwrap();
        assert_eq!(
            result,
            Some(persistence.executor.outcome.control_result_data(action))
        );
        assert_eq!(persistence.directory.reads.load(Ordering::Relaxed), 1);
        assert_eq!(persistence.compositions.load(Ordering::Relaxed), 1);
        assert_eq!(persistence.executor.calls.load(Ordering::Relaxed), 1);
    }
}

#[tokio::test]
async fn missing_receipts_cannot_bypass_active_tenant_admission() {
    let hash = "a".repeat(64);
    for action in [
        TenantResourceAction::Apply,
        TenantResourceAction::Enumerate,
        TenantResourceAction::Revoke,
    ] {
        let persistence = Persistence::new(Receipt::Miss, false);
        let result = execution::execute_with_persistence(
            &operation(action, persistence.tenant.tenant_id),
            &context(&hash),
            &persistence,
        )
        .await;
        assert!(matches!(result, Err(SideEffectError::Terminal(_))));
        assert_eq!(persistence.directory.reads.load(Ordering::Relaxed), 1);
        assert_eq!(persistence.compositions.load(Ordering::Relaxed), 0);
    }
}

#[tokio::test]
async fn receipt_conflict_and_unavailability_keep_owned_error_classification() {
    let hash = "a".repeat(64);
    for receipt in [Receipt::Conflict, Receipt::Unavailable] {
        let retryable = matches!(receipt, Receipt::Unavailable);
        let persistence = Persistence::new(receipt, true);
        let result = execution::execute_with_persistence(
            &operation(TenantResourceAction::Apply, persistence.tenant.tenant_id),
            &context(&hash),
            &persistence,
        )
        .await;
        assert!(match result {
            Err(SideEffectError::Retryable(_)) => retryable,
            Err(SideEffectError::Terminal(_)) => !retryable,
            _ => false,
        });
        assert_eq!(persistence.directory.reads.load(Ordering::Relaxed), 0);
        assert_eq!(persistence.compositions.load(Ordering::Relaxed), 0);
    }
}

#[tokio::test]
async fn captured_receipt_survives_concurrent_tenant_disable_and_newer_outcome() {
    let expected = outcome(5);
    let barrier = Arc::new(ReceiptReadBarrier::default());
    let mut persistence = Persistence::new(Receipt::Hit(expected.clone()), true);
    persistence.barrier = Some(barrier.clone());
    let hash = "a".repeat(64);
    let operation = operation(TenantResourceAction::Apply, persistence.tenant.tenant_id);
    let context = context(&hash);
    let (result, ()) = tokio::join!(
        execution::execute_with_persistence(&operation, &context, &persistence),
        async {
            tokio::time::timeout(
                std::time::Duration::from_secs(2),
                barrier.captured.notified(),
            )
            .await
            .expect("captured receipt");
            persistence
                .directory
                .snapshot
                .lock()
                .unwrap()
                .tenants
                .clear();
            *persistence.receipt.lock().unwrap() = Receipt::Hit(outcome(9));
            barrier.release.notify_one();
        }
    );
    assert_eq!(
        result.unwrap(),
        Some(expected.control_result_data(TenantResourceAction::Apply))
    );
    assert_eq!(persistence.receipt_reads.load(Ordering::Relaxed), 1);
    assert_eq!(persistence.directory.reads.load(Ordering::Relaxed), 0);
    assert_eq!(persistence.compositions.load(Ordering::Relaxed), 0);
}
