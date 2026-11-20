use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;

use nazo_oauth_server::contracts::runtime_modules::{
    RuntimeModuleAdminError, RuntimeModuleAdminFuture, RuntimeModuleAdministration,
};
use nazo_runtime_modules::{
    ActiveModuleSnapshot, CasOutcome, CatalogDurations, DesiredRevisionGuard, DesiredStateChange,
    DesiredStateRecord, DesiredStateUpdate, DesiredStateUpdateOutcome, InstanceStateMutation,
    InstanceStateRecord, ModuleCatalog, ModuleEventPage, ModuleId, ModuleLifecycle,
    ModuleReconcileState, ModuleRevision, ModuleStateRepository, RegistryError,
    RuntimeModuleManagement, RuntimeModuleManagementError, RuntimeModuleRegistry,
    RuntimeModuleView,
};

use crate::config::Configuration;

pub type ServerRuntimeModuleRegistry =
    RuntimeModuleRegistry<PersistenceRuntimeModuleRepository, dyn ModuleLifecycle>;

#[derive(Clone)]
pub struct PersistenceRuntimeModuleRepository {
    store: Arc<dyn nazo_persistence::RuntimeModuleStore>,
}

impl PersistenceRuntimeModuleRepository {
    pub fn new(store: Arc<dyn nazo_persistence::RuntimeModuleStore>) -> Self {
        Self { store }
    }
}

impl ModuleStateRepository for PersistenceRuntimeModuleRepository {
    type Error = nazo_identity::ports::RepositoryError;

    async fn read_desired(
        &self,
        module_id: ModuleId,
    ) -> Result<Option<DesiredStateRecord>, Self::Error> {
        self.store.read_desired(module_id).await
    }

    async fn read_all_desired(&self) -> Result<Vec<DesiredStateRecord>, Self::Error> {
        self.store.read_all_desired().await
    }

    async fn read_reconcile_state(
        &self,
        instance_id: &str,
    ) -> Result<Vec<ModuleReconcileState>, Self::Error> {
        self.store.read_reconcile_state(instance_id).await
    }

    async fn compare_and_set_desired(
        &self,
        change: DesiredStateChange,
    ) -> Result<CasOutcome<DesiredStateRecord>, Self::Error> {
        self.store.compare_and_set_desired(change).await
    }

    async fn compare_and_set_desired_guarded(
        &self,
        change: DesiredStateChange,
        required_revisions: Vec<DesiredRevisionGuard>,
    ) -> Result<CasOutcome<DesiredStateRecord>, Self::Error> {
        self.store
            .compare_and_set_desired_guarded(change, required_revisions)
            .await
    }

    async fn read_instance(
        &self,
        instance_id: &str,
        module_id: ModuleId,
    ) -> Result<Option<InstanceStateRecord>, Self::Error> {
        self.store.read_instance(instance_id, module_id).await
    }

    async fn read_all_instances(
        &self,
        instance_id: &str,
    ) -> Result<Vec<InstanceStateRecord>, Self::Error> {
        self.store.read_all_instances(instance_id).await
    }

    async fn page_events(&self, offset: i64, limit: i64) -> Result<ModuleEventPage, Self::Error> {
        self.store.page_events(offset, limit).await
    }

    async fn compare_and_set_instance(
        &self,
        mutation: InstanceStateMutation,
    ) -> Result<CasOutcome<InstanceStateRecord>, Self::Error> {
        self.store.compare_and_set_instance(mutation).await
    }

    async fn record_instance_observation(
        &self,
        observation: nazo_runtime_modules::InstanceStateObservation,
    ) -> Result<(), Self::Error> {
        self.store.record_instance_observation(observation).await
    }

    async fn validate_revision(
        &self,
        module_id: ModuleId,
        expected: ModuleRevision,
    ) -> Result<bool, Self::Error> {
        self.store.validate_revision(module_id, expected).await
    }
}

pub struct RuntimeModules {
    pub repository: Arc<PersistenceRuntimeModuleRepository>,
    pub registry: Arc<ServerRuntimeModuleRegistry>,
    pub catalog: ModuleCatalog,
    pub instance_id: String,
}

impl RuntimeModules {
    pub async fn initialize(
        store: Arc<dyn nazo_persistence::RuntimeModuleStore>,
        lifecycle: Arc<dyn ModuleLifecycle>,
        settings: &Configuration,
        instance_id: &str,
        constructed_availability: Option<&BTreeSet<ModuleId>>,
    ) -> anyhow::Result<Self> {
        let repository = Arc::new(PersistenceRuntimeModuleRepository::new(store));
        let mut catalog = module_catalog(settings)?;
        if let Some(available) = constructed_availability {
            catalog = catalog.with_constructed_availability(
                ModuleId::ALL
                    .into_iter()
                    .map(|id| (id, available.contains(&id))),
            );
        }
        let instance_id = instance_id.to_owned();
        let (accepting, draining) =
            load_explicit_desired_states(&repository, &catalog, &instance_id).await?;
        let registry = Arc::new(RuntimeModuleRegistry::new(
            repository.clone(),
            lifecycle,
            catalog.clone(),
            instance_id.clone(),
            ActiveModuleSnapshot {
                revision: ModuleRevision::new(0),
                accepting,
                draining,
            },
        ));
        let modules = Self {
            repository,
            registry,
            catalog,
            instance_id,
        };
        Ok(modules)
    }

    pub fn administration(&self) -> Arc<dyn RuntimeModuleAdministration> {
        Arc::new(ModuleAdministration {
            management: RuntimeModuleManagement::new(
                self.repository.clone(),
                self.registry.clone(),
                self.catalog.clone(),
                self.instance_id.clone(),
            ),
        })
    }
}

struct ModuleAdministration {
    management: RuntimeModuleManagement<PersistenceRuntimeModuleRepository, dyn ModuleLifecycle>,
}

impl RuntimeModuleAdministration for ModuleAdministration {
    fn list(&self) -> RuntimeModuleAdminFuture<'_, Vec<RuntimeModuleView>> {
        Box::pin(async { self.management.list().await.map_err(map_management_error) })
    }

    fn events(&self, offset: i64, limit: i64) -> RuntimeModuleAdminFuture<'_, ModuleEventPage> {
        Box::pin(async move {
            self.management
                .events(offset, limit)
                .await
                .map_err(map_management_error)
        })
    }

    fn update_desired(
        &self,
        update: DesiredStateUpdate,
    ) -> RuntimeModuleAdminFuture<'_, DesiredStateUpdateOutcome> {
        Box::pin(async move {
            self.management
                .update_desired(update)
                .await
                .map_err(map_management_error)
        })
    }
}

fn map_management_error(
    error: RuntimeModuleManagementError<nazo_identity::ports::RepositoryError>,
) -> RuntimeModuleAdminError {
    match error {
        RuntimeModuleManagementError::Repository(error)
        | RuntimeModuleManagementError::Registry(RegistryError::Repository(error)) => {
            tracing::warn!(%error, "runtime module administration repository failed");
            RuntimeModuleAdminError::Unavailable
        }
        RuntimeModuleManagementError::Registry(RegistryError::Compensation {
            operation,
            compensation,
        }) => {
            tracing::warn!(
                ?operation,
                ?compensation,
                "runtime module operation and admission compensation failed"
            );
            RuntimeModuleAdminError::Unavailable
        }
        RuntimeModuleManagementError::Registry(
            RegistryError::SynchronizationBusy | RegistryError::SynchronizationChanged,
        ) => RuntimeModuleAdminError::Unavailable,
        RuntimeModuleManagementError::Registry(RegistryError::ServiceNotConstructed(_)) => {
            RuntimeModuleAdminError::ServiceNotConstructed
        }
        RuntimeModuleManagementError::Registry(
            RegistryError::RuntimeDisableBlocked(_)
            | RegistryError::ActiveDependent { .. }
            | RegistryError::DependencyUnavailable { .. },
        ) => RuntimeModuleAdminError::PolicyConflict,
        RuntimeModuleManagementError::Registry(
            RegistryError::MissingDesiredState(_) | RegistryError::InconsistentDesiredState(_),
        )
        | RuntimeModuleManagementError::Registry(
            RegistryError::RevisionExhausted(_)
            | RegistryError::SnapshotRevisionExhausted
            | RegistryError::DrainDeadlineOverflow(_),
        )
        | RuntimeModuleManagementError::MissingDesiredState(_) => {
            tracing::error!(?error, "runtime module catalog is inconsistent");
            RuntimeModuleAdminError::CatalogInconsistent
        }
    }
}

pub fn module_catalog(settings: &Configuration) -> anyhow::Result<ModuleCatalog> {
    let protocol = &settings.protocol;
    let session = &settings.session;
    let mut catalog = ModuleCatalog::fixed(CatalogDurations {
        device_authorization: Duration::from_secs(settings.device.device_authorization_ttl_seconds),
        ciba: Duration::from_secs(settings.ciba.ciba_auth_req_id_ttl_seconds),
        authorization_code: Duration::from_secs(protocol.auth_code_ttl_seconds),
        refresh_token: Duration::from_secs(
            u64::try_from(protocol.refresh_token_ttl_seconds)
                .map_err(|_| anyhow::anyhow!("REFRESH_TOKEN_TTL_SECONDS cannot be negative"))?,
        ),
        session: Duration::from_secs(session.session_ttl_seconds),
        presentation_transaction: Duration::from_secs(
            settings.openid4vc.transaction_ttl_seconds.max(30),
        ),
        scim_security_events: Duration::from_secs(settings.storage.scim_event_retention_seconds),
    });
    catalog = catalog.with_constructed_availability([
        (
            ModuleId::Openid4vciIssuer,
            settings.modules.enable_openid4vci_issuer,
        ),
        (
            ModuleId::Openid4vpVerifier,
            settings.modules.enable_openid4vp_verifier,
        ),
    ]);
    let mut runtime_disable_blocked = BTreeSet::new();
    if protocol
        .authorization_server_profile
        .requires_signed_authorization_request()
    {
        runtime_disable_blocked.insert(ModuleId::RequestObjects);
    }
    if protocol
        .authorization_server_profile
        .requires_signed_authorization_response()
    {
        runtime_disable_blocked.insert(ModuleId::Jarm);
    }
    catalog = catalog
        .with_dependencies(ModuleId::ScimSecurityEvents, [ModuleId::Scim])?
        .with_dependencies(
            ModuleId::Openid4vciIssuer,
            [ModuleId::AuthorizationDetails, ModuleId::RequestObjects],
        )?
        .with_dependencies(ModuleId::Openid4vpVerifier, [ModuleId::RequestObjects])?
        .with_dependencies(ModuleId::NativeSso, [ModuleId::TokenExchange])?
        .with_runtime_disable_blocked(runtime_disable_blocked);
    Ok(catalog)
}

async fn load_explicit_desired_states(
    repository: &PersistenceRuntimeModuleRepository,
    catalog: &ModuleCatalog,
    instance_id: &str,
) -> anyhow::Result<(BTreeSet<ModuleId>, BTreeSet<ModuleId>)> {
    let states = repository.read_reconcile_state(instance_id).await?;
    initial_admission(catalog, states)
}

fn initial_admission(
    catalog: &ModuleCatalog,
    states: Vec<ModuleReconcileState>,
) -> anyhow::Result<(BTreeSet<ModuleId>, BTreeSet<ModuleId>)> {
    let mut accepting = BTreeSet::new();
    let mut draining = BTreeSet::new();
    let states = states
        .into_iter()
        .map(|state| (state.desired.module_id, state))
        .collect::<std::collections::BTreeMap<_, _>>();
    for module_id in ModuleId::ALL {
        let state = states
            .get(&module_id)
            .ok_or_else(|| anyhow::anyhow!("runtime desired state is missing"))?;
        let enabled = catalog.effective_enabled(module_id, state.desired.mode.is_enabled());
        if catalog.runtime_disable_blocked(module_id) && !enabled {
            anyhow::bail!(
                "runtime module {module_id:?} is required by the active security profile"
            );
        }
        if enabled {
            accepting.insert(module_id);
        } else if catalog.stored_transaction_admission(
            &state.desired,
            state.instance.as_ref(),
            web_time::SystemTime::now(),
        ) {
            draining.insert(module_id);
        }
    }
    for module_id in &accepting {
        if catalog
            .spec(*module_id)
            .dependencies
            .iter()
            .any(|dependency| !accepting.contains(dependency))
        {
            anyhow::bail!("runtime module {module_id:?} has an unavailable dependency");
        }
    }
    Ok((accepting, draining))
}

#[cfg(test)]
#[path = "../tests/unit/runtime_modules.rs"]
mod tests;
