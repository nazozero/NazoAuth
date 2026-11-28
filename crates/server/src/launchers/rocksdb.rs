//! Single-process native launcher. Offline operator commands use the same
//! directory lock as the server; they never open a second live writer.

use std::sync::Arc;

use crate::{
    cli::{LauncherFuture, PersistenceLauncher},
    config::ConfigSource,
    operator_task::{OperatorBackendFuture, OperatorPersistence},
};
use nazo_oauth_server::ports::persistence::ServerPersistenceBindings;
use nazo_rocksdb::{RocksDb, RocksDbTenantResourceExecutor};

async fn open(source: &ConfigSource) -> anyhow::Result<RocksDb> {
    let path = source.persistent_path("DATABASE_URL", Some("runtime/rocksdb"))?;
    if source
        .get("DATABASE_URL")
        .is_some_and(|value| value.contains("://"))
    {
        anyhow::bail!("nazoauth-rocksdb DATABASE_URL must name a local database directory");
    }
    Ok(tokio::task::spawn_blocking(move || RocksDb::open(path)).await??)
}

#[derive(Clone, Copy, Debug, Default)]
pub struct RocksDbLauncher;

impl PersistenceLauncher for RocksDbLauncher {
    fn default_database_url(&self) -> &'static str {
        "runtime/rocksdb"
    }

    fn server_bindings<'a>(
        &'a self,
        source: &'a ConfigSource,
    ) -> LauncherFuture<'a, crate::bootstrap::ServerPersistence> {
        Box::pin(async move {
            if source.bool("SECURITY_AUDIT_REQUIRE_LEAST_PRIVILEGE", true)? {
                anyhow::bail!(
                    "RocksDB has no database roles; single-process deployments require SECURITY_AUDIT_REQUIRE_LEAST_PRIVILEGE=false"
                );
            }
            if source
                .get("AUDIT_ANCHOR_MODE")
                .is_some_and(|value| value != "disabled")
            {
                anyhow::bail!(
                    "RocksDB does not support the independent audit-anchor-worker; AUDIT_ANCHOR_MODE must be disabled"
                );
            }
            let keys = crate::settings::mfa_totp_key_ring(source)?
                .map(|ring| {
                    let current =
                        nazo_rocksdb::MfaTotpKey::new(ring.current().id(), *ring.current().key())?;
                    let previous = ring
                        .previous()
                        .map(|key| nazo_rocksdb::MfaTotpKey::new(key.id(), *key.key()))
                        .transpose()?;
                    nazo_rocksdb::MfaTotpKeyRing::new(current, previous)
                })
                .transpose()?;
            let db = open(source).await?.with_totp_key_ring(keys);
            db.activate_totp_key().await?;
            let db = Arc::new(db);
            Ok(crate::bootstrap::ServerPersistence {
                application: ServerPersistenceBindings::new(db.clone()),
                tenant_directory: db.clone(),
                controller_registry: db.clone(),
                recovery_root: db,
            })
        })
    }

    fn operator_persistence<'a>(
        &'a self,
        source: &'a ConfigSource,
    ) -> LauncherFuture<'a, Arc<dyn OperatorPersistence>> {
        Box::pin(async move {
            Ok(Arc::new(RocksDbOperatorPersistence(open(source).await?))
                as Arc<dyn OperatorPersistence>)
        })
    }

    fn audit_exporter<'a>(
        &'a self,
        _database_url: &'a str,
        _database_max_connections: usize,
    ) -> LauncherFuture<'a, Arc<dyn nazo_persistence::SecurityAuditExporter>> {
        Box::pin(async {
            anyhow::bail!(
                "RocksDB is owned by one process; the independent audit-anchor-worker is unsupported"
            )
        })
    }

    fn admin_provisioner<'a>(
        &'a self,
        source: &'a ConfigSource,
    ) -> LauncherFuture<'a, Arc<dyn nazo_persistence::AdminProvisionStore>> {
        Box::pin(async move {
            Ok(Arc::new(open(source).await?) as Arc<dyn nazo_persistence::AdminProvisionStore>)
        })
    }
}

struct RocksDbOperatorPersistence(RocksDb);

impl OperatorPersistence for RocksDbOperatorPersistence {
    fn signing_key_repository(
        &self,
        tenant_id: uuid::Uuid,
    ) -> Arc<dyn nazo_key_management::SigningKeyRepository> {
        Arc::new(self.0.for_tenant(tenant_id))
    }
    fn controller_registry(&self) -> Arc<dyn nazo_persistence::ControllerRegistryPort> {
        Arc::new(self.0.clone())
    }
    fn recovery_invalidations(&self) -> Arc<dyn nazo_persistence::RecoveryInvalidationStore> {
        Arc::new(self.0.clone())
    }
    fn admin_clients(&self) -> Arc<dyn nazo_auth::AdminClientRepositoryPort> {
        Arc::new(self.0.clone())
    }

    fn tenant_resource_control_outcome<'a>(
        &'a self,
        tenant_id: nazo_identity::TenantId,
        deployment_id: &'a str,
        operation_id: uuid::Uuid,
        request_hash: &'a str,
        operation: nazo_persistence::tenant_resources::TenantResourceAction,
    ) -> futures_util::future::BoxFuture<
        'a,
        Result<
            Option<nazo_operator_protocol::ControlResultData>,
            nazo_persistence::tenant_resources::TenantResourceExecutorError,
        >,
    > {
        Box::pin(self.0.tenant_resource_control_outcome(
            tenant_id,
            deployment_id,
            operation_id,
            request_hash,
            operation,
        ))
    }

    fn tenant_resource_executor(
        &self,
        tenant: nazo_identity::TenantContext,
        data_encryption_key: Option<[u8; 32]>,
        preparation: Option<Arc<dyn nazo_persistence::tenant_resources::TenantResourcePreparation>>,
    ) -> Arc<dyn nazo_persistence::tenant_resources::TenantResourceExecutorPort> {
        Arc::new(RocksDbTenantResourceExecutor::new(
            self.0.clone(),
            tenant,
            data_encryption_key,
            preparation,
        ))
    }

    fn tenant_directory_executor(
        &self,
    ) -> Arc<dyn nazo_persistence::directory_control::TenantDirectoryControlPort> {
        Arc::new(self.0.clone())
    }
    fn tenant_directory(&self) -> Arc<dyn nazo_persistence::TenantDirectoryStore> {
        Arc::new(self.0.clone())
    }

    fn schema_revision(&self) -> OperatorBackendFuture<'_, String> {
        Box::pin(async { Ok("rocksdb:1".into()) })
    }
    fn run_migrations(&self) -> OperatorBackendFuture<'_, bool> {
        Box::pin(async { Ok(false) })
    }
    fn initialize_tenant_directory(
        &self,
        binding: nazo_identity::TenantDirectoryBinding,
    ) -> OperatorBackendFuture<'_, bool> {
        Box::pin(async move {
            self.0
                .initialize_tenant_directory(binding)
                .await
                .map_err(Into::into)
        })
    }
}

#[cfg(test)]
#[path = "../../tests/unit/launchers/rocksdb.rs"]
mod tests;
