use super::tenant_runtime::{ProcessRuntime, TenantRuntimeBuilder};
use super::*;
use nazoauth::runtime::{TenantRuntimeRefresher, TenantRuntimeRegistry};

/// Tenant-scoped values used to assemble one immutable request graph.
pub(super) struct StartupConfiguration {
    pub(super) persistence: nazo_oauth_server::ports::persistence::ServerPersistenceBindings,
    pub(super) transient_state:
        nazo_oauth_server::ports::transient_state::ServerTransientStateBindings,
    pub(super) avatar_storage: super::super::ServerAvatarStorageCapability,
    pub(super) settings: Arc<Settings>,
    pub(super) deployment: Arc<nazoauth::capabilities::DeploymentCapabilities>,
    pub(super) certificate_verifier:
        Option<Arc<dyn nazoauth::capabilities::CertificateChainVerifier>>,
    pub(super) keyset: nazo_key_management::KeyManager,
}

/// Values which survive process startup. Tenant request graphs live only in
/// the immutable registry and can be replaced without restarting the server.
pub(super) struct StartupRuntime {
    pub(super) process: Arc<ProcessRuntime>,
    pub(super) registry: TenantRuntimeRegistry,
    pub(super) runtime: nazo_runtime_tokio::Runtime,
}

pub(super) async fn load(
    config: ConfigSource,
    persistence: ServerPersistence,
    transient_state_launcher: &dyn crate::cli::TransientStateLauncher,
    avatar_object_store_launcher: &dyn crate::cli::AvatarObjectStoreLauncher,
) -> anyhow::Result<StartupRuntime> {
    let ServerPersistence {
        application: persistence,
        tenant_directory,
        controller_registry,
        recovery_root,
    } = persistence;
    let password_hash_max_concurrency = config.parse::<usize>(
        "PASSWORD_HASH_MAX_CONCURRENCY",
        default_password_hash_max_concurrency(),
    )?;
    let password_hash_queue_timeout_ms = config.parse::<u64>(
        "PASSWORD_HASH_QUEUE_TIMEOUT_MS",
        default_password_hash_queue_timeout_ms(),
    )?;
    configure_password_hash_limits(
        password_hash_max_concurrency,
        password_hash_queue_timeout_ms,
    )?;
    initialize_dummy_password_hash()?;

    // Always read the authoritative snapshot first. The shared cache is never
    // trusted for a cold start, so a stale cache cannot resurrect a tenant.
    let database_snapshot = tenant_directory
        .load_active()
        .await
        .map_err(|error| anyhow::anyhow!("tenant directory initial read failed: {error}"))?;
    if database_snapshot.revision == 0 {
        anyhow::bail!(
            "tenant runtime directory is not initialized; run `nazoauth tenant-bootstrap` before starting the server"
        );
    }

    // This baseline is process identity only (static route set, module catalog,
    // control discovery). It never supplies request tenant settings or CORS.
    // Its issuer therefore remains stable when directory ordering changes.
    let route_settings = Arc::new(Settings::from_config(&config)?);
    // Deployment-global control routes never follow directory ordering. The
    // fixed system tenant is the only authority for deployment-level control.
    let control_tenant_id = nazo_identity::TenantContext::default_system().tenant_id;

    let audit_anchor_preflight = crate::adapters::audit_anchor::AuditAnchorPreflight::new(
        crate::adapters::audit_anchor::preflight_config_from_source(&config)?,
    )?;
    let control_discovery = crate::control_discovery::initialize(
        &route_settings.storage.data_dir,
        config
            .optional_string("INSTANCE_IDENTITY_DIR")
            .map(|_| config.persistent_path("INSTANCE_IDENTITY_DIR", None))
            .transpose()?
            .as_deref(),
        config.optional_string("DEPLOYMENT_ID").as_deref(),
        config.optional_string("RUNTIME_INSTANCE_ID").as_deref(),
        &route_settings.endpoint.issuer,
    )?;

    let require_audit_least_privilege =
        config.bool("SECURITY_AUDIT_REQUIRE_LEAST_PRIVILEGE", true)?;
    let audit_repository = persistence.provider().security_audit_ledger();
    audit_repository
        .check_available(require_audit_least_privilege)
        .await
        .map_err(|error| anyhow::anyhow!("security audit writer preflight failed: {error}"))?;
    crate::adapters::audit::install_persistent_audit_sink(
        audit_repository,
        require_audit_least_privilege,
        audit_anchor_preflight,
    )?;

    let state_backend = transient_state_launcher
        .server_bindings(&config, control_discovery.deployment_id())
        .await
        .map_err(|error| anyhow::anyhow!("transient-state deployment preflight failed: {error}"))?;
    let avatar_object_store = avatar_object_store_launcher
        .server_bindings(&config, control_discovery.deployment_id())
        .await
        .map_err(|error| {
            anyhow::anyhow!("avatar object-store deployment preflight failed: {error}")
        })?;

    let signing_key_wrapping_keys = crate::settings::signing_key_wrapping_key_ring(&config)?;
    let directory_cache = state_backend.tenant_directory_cache();
    let registry = TenantRuntimeRegistry::empty();
    let deployment = Arc::new(nazoauth::capabilities::DeploymentCapabilities {
        identity: control_discovery,
        control_tenant: control_tenant_id,
        tenants: registry.availability(),
        controller_registry,
        recovery_root,
    });
    let direct_tls = crate::bootstrap::direct_tls_listeners(&config, &route_settings)?;
    let client_verifier = match direct_tls.as_ref() {
        Some(listeners) => Some(listeners.client_verifier.clone()),
        None => config
            .optional_string("TLS_CLIENT_CA_FILE")
            .map(|path| {
                crate::bootstrap::transport::load_client_verifier(
                    std::path::Path::new(&path),
                    Arc::new(rustls::crypto::aws_lc_rs::default_provider()),
                )
            })
            .transpose()?,
    };
    let process = Arc::new(ProcessRuntime {
        config,
        signing_key_wrapping_keys,
        persistence,
        state_backend,
        avatar_object_store,
        deployment,
        direct_tls,
        client_verifier,
        route_settings,
    });

    let refresher = Arc::new(TenantRuntimeRefresher::new(
        registry.clone(),
        tenant_directory,
        directory_cache.clone(),
        TenantRuntimeBuilder::production(process.clone()),
    ));
    let workers = background::process_workers(&process.persistence, &process.route_settings)?;
    let runtime =
        nazo_runtime_tokio::Runtime::dynamic(refresher, database_snapshot, workers).await?;

    Ok(StartupRuntime {
        process,
        registry,
        runtime,
    })
}
