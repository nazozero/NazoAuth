//! Native environment capabilities for the shared tenant runtime.
use std::sync::Arc;

use nazo_identity::TenantDirectoryBinding;
use nazoauth::runtime::{TenantRuntime, TenantRuntimeBuildFuture, TenantRuntimeBuildPort};

use super::{configuration::StartupConfiguration, services, *};

pub(super) struct ProcessRuntime {
    pub(super) config: ConfigSource,
    pub(super) signing_key_wrapping_keys: nazo_key_management::SigningKeyWrappingKeyRing,
    pub(super) persistence: nazo_oauth_server::ports::persistence::ServerPersistenceBindings,
    pub(super) state_backend: nazo_oauth_server::ports::transient_state::ServerStateBackendBindings,
    pub(super) avatar_object_store: super::super::ServerAvatarObjectStoreBindings,
    pub(super) deployment: Arc<nazoauth::capabilities::DeploymentCapabilities>,
    pub(super) direct_tls: Option<crate::bootstrap::transport::DirectTlsListeners>,
    pub(super) client_verifier: Option<Arc<dyn rustls::server::danger::ClientCertVerifier>>,
    pub(super) route_settings: Arc<Settings>,
}

pub(super) struct TenantRuntimeBuilder {
    process: Arc<ProcessRuntime>,
}

impl TenantRuntimeBuilder {
    pub(super) fn production(process: Arc<ProcessRuntime>) -> Arc<dyn TenantRuntimeBuildPort> {
        Arc::new(Self { process })
    }
}

impl TenantRuntimeBuildPort for TenantRuntimeBuilder {
    fn build(&self, binding: &TenantDirectoryBinding) -> TenantRuntimeBuildFuture<'_> {
        let process = self.process.clone();
        let binding = binding.clone();
        Box::pin(async move {
            let settings = Arc::new(Settings::from_directory_binding(&process.config, &binding)?);
            build_service_runtime(process, binding, settings).await
        })
    }
}

async fn build_service_runtime(
    process: Arc<ProcessRuntime>,
    binding: TenantDirectoryBinding,
    settings: Arc<Settings>,
) -> anyhow::Result<Arc<TenantRuntime>> {
    let transient_state = process
        .state_backend
        .for_tenant(settings.tenant.context.tenant_id)
        .map_err(|error| anyhow::anyhow!("tenant transient state binding failed: {error}"))?;
    let keyset = nazo_key_management::KeyManager::load_or_create_database(
        settings.key_settings(),
        settings.external_key_signer(),
        settings.tenant.context.tenant_id.as_uuid(),
        process
            .persistence
            .provider()
            .signing_key_repository(settings.tenant.context.tenant_id.as_uuid()),
        process.signing_key_wrapping_keys.clone(),
    )
    .await?;
    let avatar_storage = process
        .avatar_object_store
        .provider()
        .for_tenant(settings.tenant.context.tenant_id);
    if let super::super::ServerAvatarStorageCapability::Local { directory } = &avatar_storage {
        tokio::fs::create_dir_all(
            directory
                .as_ref()
                .unwrap_or(&settings.storage.avatar_storage_dir),
        )
        .await?;
    }
    let startup = StartupConfiguration {
        persistence: process.persistence.clone(),
        transient_state,
        avatar_storage,
        settings,
        deployment: process.deployment.clone(),
        certificate_verifier: process.client_verifier.clone().map(|verifier| {
            Arc::new(crate::adapters::transport_facts::RustlsCertificateVerifier(
                verifier,
            )) as Arc<dyn nazoauth::capabilities::CertificateChainVerifier>
        }),
        keyset,
    };
    let ciba = background::ciba_ping_worker(
        startup.transient_state.provider().ciba_ping_deliveries(),
        &startup.settings,
    )?;
    let keys = startup.keyset.clone();
    let prepublish_window = startup.settings.key_settings().prepublish_window;
    let application = services::build(startup).await?;
    let tasks = Arc::new(nazo_runtime_tokio::TenantTasks::new(
        application.clone(),
        keys,
        prepublish_window,
        ciba,
    ));
    Ok(Arc::new(TenantRuntime::new(binding, application, tasks)?))
}
