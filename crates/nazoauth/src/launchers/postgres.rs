use std::sync::Arc;

use crate::{
    cli::{LauncherFuture, PersistenceLauncher},
    config::{self, ConfigSource},
    operator_task::{OperatorBackendFuture, OperatorPersistence},
};
use nazo_oauth_server::ports::persistence::ServerPersistenceBindings;
use nazo_oauth_server_postgres::PostgresProvider;
use nazo_postgres::{
    AdminProvisionRepository, AuditLedgerRepository, ControllerRegistryRepository, DbPool,
    OAuthClientRepository, PostgresTenantResourceExecutor, TenantDirectoryControlRepository,
    TenantDirectoryRepository, TenantResourceRepository, TokenRepository,
};

const DEFAULT_DATABASE_URL: &str = "postgresql://postgres:postgres@127.0.0.1:5432/oauth";
const OPERATOR_DATABASE_MAX_CONNECTIONS: usize = 2;
const ADMIN_PROVISION_DATABASE_MAX_CONNECTIONS: usize = 2;
const MIGRATION_RUNTIME_ROLE_ENV: &str = "NAZOAUTH_MIGRATION_RUNTIME_ROLE";

#[derive(Clone)]
struct PostgresOperatorPersistence {
    pool: DbPool,
    database_url: String,
}

impl OperatorPersistence for PostgresOperatorPersistence {
    fn signing_key_repository(
        &self,
        tenant_id: uuid::Uuid,
    ) -> Arc<dyn nazo_key_management::SigningKeyRepository> {
        Arc::new(nazo_postgres::SigningKeysetRepository::for_tenant(
            self.pool.clone(),
            tenant_id,
        ))
    }

    fn controller_registry(&self) -> Arc<dyn nazo_persistence::ControllerRegistryPort> {
        Arc::new(ControllerRegistryRepository::new(self.pool.clone()))
    }

    fn recovery_invalidations(&self) -> Arc<dyn nazo_persistence::RecoveryInvalidationStore> {
        Arc::new(TokenRepository::new(self.pool.clone()))
    }

    fn admin_clients(&self) -> Arc<dyn nazo_auth::AdminClientRepositoryPort> {
        Arc::new(OAuthClientRepository::new(self.pool.clone()))
    }

    fn tenant_resource_executor(
        &self,
        tenant: nazo_identity::TenantContext,
        data_encryption_key: Option<[u8; 32]>,
        preparation: Arc<dyn nazo_persistence::tenant_resources::TenantResourcePreparation>,
    ) -> Arc<dyn nazo_persistence::tenant_resources::TenantResourceExecutorPort> {
        Arc::new(PostgresTenantResourceExecutor::new(
            TenantResourceRepository::new(self.pool.clone()),
            tenant,
            data_encryption_key,
            preparation,
        ))
    }

    fn tenant_directory_executor(
        &self,
    ) -> Arc<dyn nazo_persistence::directory_control::TenantDirectoryControlPort> {
        Arc::new(TenantDirectoryControlRepository::new(self.pool.clone()))
    }

    fn tenant_directory(&self) -> Arc<dyn nazo_persistence::TenantDirectoryStore> {
        Arc::new(TenantDirectoryRepository::new(self.pool.clone()))
    }

    fn run_migrations(&self) -> OperatorBackendFuture<'_, bool> {
        Box::pin(async move {
            let runtime_role = std::env::var(MIGRATION_RUNTIME_ROLE_ENV)
                .map_err(|_| anyhow::anyhow!("{MIGRATION_RUNTIME_ROLE_ENV} is required"))?;
            let applied = nazo_postgres::run_pending_migrations(&self.database_url).await?;
            nazo_postgres::configure_runtime_role(&self.database_url, runtime_role.trim()).await?;
            nazo_postgres::cleanup_expired_security_state(&self.database_url).await?;
            Ok(applied)
        })
    }

    fn initialize_tenant_directory(
        &self,
        binding: nazo_identity::TenantDirectoryBinding,
    ) -> OperatorBackendFuture<'_, bool> {
        Box::pin(async move {
            Ok(TenantDirectoryRepository::new(self.pool.clone())
                .initialize(binding)
                .await?)
        })
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct PostgresLauncher;

impl PersistenceLauncher for PostgresLauncher {
    fn default_database_url(&self) -> &'static str {
        DEFAULT_DATABASE_URL
    }

    fn server_bindings<'a>(
        &'a self,
        source: &'a ConfigSource,
    ) -> LauncherFuture<'a, ServerPersistenceBindings> {
        Box::pin(async move {
            let database_url = config::database_url(source)?;
            let max_connections = config::database_max_connections(source)?;
            let pool = nazo_postgres::create_pool(database_url, max_connections)?;
            Ok(ServerPersistenceBindings::new(Arc::new(
                PostgresProvider::new(pool),
            )))
        })
    }

    fn operator_persistence<'a>(
        &'a self,
        source: &'a ConfigSource,
    ) -> LauncherFuture<'a, Arc<dyn OperatorPersistence>> {
        Box::pin(async move {
            let database_url = config::database_url(source)?;
            let pool = nazo_postgres::create_pool(
                database_url.clone(),
                OPERATOR_DATABASE_MAX_CONNECTIONS,
            )?;
            Ok(Arc::new(PostgresOperatorPersistence { pool, database_url })
                as Arc<dyn OperatorPersistence>)
        })
    }

    fn audit_exporter<'a>(
        &'a self,
        database_url: &'a str,
        database_max_connections: usize,
    ) -> LauncherFuture<'a, Arc<dyn nazo_persistence::SecurityAuditExporter>> {
        Box::pin(async move {
            let pool = nazo_postgres::create_pool(database_url, database_max_connections)?;
            Ok(Arc::new(AuditLedgerRepository::new(pool))
                as Arc<dyn nazo_persistence::SecurityAuditExporter>)
        })
    }

    fn admin_provisioner<'a>(
        &'a self,
        source: &'a ConfigSource,
    ) -> LauncherFuture<'a, Arc<dyn nazo_persistence::AdminProvisionStore>> {
        Box::pin(async move {
            let database_url = config::database_url(source)?;
            let pool =
                nazo_postgres::create_pool(database_url, ADMIN_PROVISION_DATABASE_MAX_CONNECTIONS)?;
            Ok(Arc::new(AdminProvisionRepository::new(pool))
                as Arc<dyn nazo_persistence::AdminProvisionStore>)
        })
    }
}
