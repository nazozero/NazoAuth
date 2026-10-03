use std::{
    path::PathBuf,
    sync::{Arc, Mutex},
};

use nazo_key_management::{
    PersistedSigningKeyset, SigningKeyRepository, SigningKeyRepositoryFuture,
    SigningKeysetCompareAndSwapResult, SigningKeysetCreateResult,
};
use url::Url;
use uuid::Uuid;

#[derive(Default)]
pub(super) struct MemorySigningKeyRepository {
    record: Mutex<Option<PersistedSigningKeyset>>,
    next_openid4vc_commit: Mutex<Option<Arc<Openid4vcCommitBarrier>>>,
}

#[derive(Default)]
pub(super) struct Openid4vcCommitBarrier {
    pub(super) applied: tokio::sync::Notify,
    pub(super) release: tokio::sync::Notify,
}

impl MemorySigningKeyRepository {
    pub(super) fn pause_next_openid4vc_commit(&self) -> Arc<Openid4vcCommitBarrier> {
        let barrier = Arc::new(Openid4vcCommitBarrier::default());
        *self.next_openid4vc_commit.lock().expect("barrier mutex") = Some(barrier.clone());
        barrier
    }
}

impl SigningKeyRepository for MemorySigningKeyRepository {
    fn load(&self) -> SigningKeyRepositoryFuture<'_, Option<PersistedSigningKeyset>> {
        Box::pin(async move { Ok(self.record.lock().expect("repository mutex").clone()) })
    }

    fn create_if_absent(
        &self,
        candidate: PersistedSigningKeyset,
    ) -> SigningKeyRepositoryFuture<'_, SigningKeysetCreateResult> {
        Box::pin(async move {
            let mut record = self.record.lock().expect("repository mutex");
            Ok(match record.clone() {
                Some(existing) => SigningKeysetCreateResult::Existing(existing),
                None => {
                    *record = Some(candidate.clone());
                    SigningKeysetCreateResult::Created(candidate)
                }
            })
        })
    }

    fn compare_and_swap(
        &self,
        expected_revision: i64,
        candidate: PersistedSigningKeyset,
    ) -> SigningKeyRepositoryFuture<'_, SigningKeysetCompareAndSwapResult> {
        Box::pin(async move {
            let result = {
                let mut record = self.record.lock().expect("repository mutex");
                let current = record
                    .clone()
                    .ok_or_else(|| anyhow::anyhow!("repository has no keyset"))?;
                if current.revision == expected_revision {
                    *record = Some(candidate.clone());
                    SigningKeysetCompareAndSwapResult::Applied(candidate)
                } else {
                    SigningKeysetCompareAndSwapResult::Conflict(current)
                }
            };
            let barrier = match &result {
                SigningKeysetCompareAndSwapResult::Applied(record)
                    if record.public_metadata.get("openid4vc").is_some() =>
                {
                    self.next_openid4vc_commit
                        .lock()
                        .expect("barrier mutex")
                        .take()
                }
                _ => None,
            };
            if let Some(barrier) = barrier {
                barrier.applied.notify_one();
                barrier.release.notified().await;
            }
            Ok(result)
        })
    }
}

pub(super) struct MemoryOperatorPersistence {
    pub(super) repository: Arc<MemorySigningKeyRepository>,
}

impl crate::operator_task::OperatorPersistence for MemoryOperatorPersistence {
    fn signing_key_repository(
        &self,
        _tenant_id: Uuid,
    ) -> Arc<dyn nazo_key_management::SigningKeyRepository> {
        self.repository.clone()
    }

    fn controller_registry(&self) -> Arc<dyn nazo_persistence::ControllerRegistryPort> {
        unimplemented!("keyctl tests do not use the controller registry")
    }

    fn recovery_invalidations(&self) -> Arc<dyn nazo_persistence::RecoveryInvalidationStore> {
        unimplemented!("keyctl tests do not use recovery invalidations")
    }

    fn admin_clients(&self) -> Arc<dyn nazo_auth::AdminClientRepositoryPort> {
        unimplemented!("keyctl tests do not use admin clients")
    }

    fn tenant_resource_executor(
        &self,
        _tenant: nazo_identity::TenantContext,
        _data_encryption_key: Option<[u8; 32]>,
        _preparation: Arc<dyn nazo_persistence::tenant_resources::TenantResourcePreparation>,
    ) -> Arc<dyn nazo_persistence::tenant_resources::TenantResourceExecutorPort> {
        unimplemented!("keyctl tests do not use tenant resources")
    }

    fn tenant_directory_executor(
        &self,
    ) -> Arc<dyn nazo_persistence::directory_control::TenantDirectoryControlPort> {
        unimplemented!("keyctl tests do not use tenant directory execution")
    }

    fn tenant_directory(&self) -> Arc<dyn nazo_persistence::TenantDirectoryStore> {
        unimplemented!("keyctl tests do not use tenant directory lookup")
    }

    fn run_migrations(&self) -> crate::operator_task::OperatorBackendFuture<'_, bool> {
        unimplemented!("keyctl tests do not run migrations")
    }

    fn initialize_tenant_directory(
        &self,
        _binding: nazo_identity::TenantDirectoryBinding,
    ) -> crate::operator_task::OperatorBackendFuture<'_, bool> {
        unimplemented!("keyctl tests do not initialize tenant directories")
    }
}

pub(super) fn temporary_directory(label: &str) -> PathBuf {
    std::env::temp_dir().join(format!("nazoauth-keyctl-{label}-{}", Uuid::now_v7()))
}

pub(super) fn tenant_binding(issuer: &str) -> nazo_identity::TenantDirectoryBinding {
    let tenant_id = Uuid::now_v7();
    let realm_id = Uuid::now_v7();
    let organization_id = Uuid::now_v7();
    let tenant = nazo_identity::TenantContext {
        tenant_id: nazo_identity::TenantId::new(tenant_id).expect("tenant id"),
        realm_id: nazo_identity::RealmId::new(realm_id).expect("realm id"),
        organization_id: nazo_identity::OrganizationId::new(organization_id)
            .expect("organization id"),
    };
    let host = Url::parse(issuer)
        .expect("issuer URL")
        .host_str()
        .expect("issuer host")
        .to_owned();
    nazo_identity::TenantDirectoryBinding {
        tenant,
        runtime_revision: 1,
        issuer: issuer.to_owned(),
        external_host: host,
    }
}
