use crate::settings::Settings;
use nazo_postgres::{DbPool, RuntimeModuleRepository};
use nazo_runtime_modules::{
    ActiveModuleSnapshot, ModuleId, ModuleLifecycle, ModuleRevision, RuntimeModuleRegistry,
};
use nazo_runtime_tokio::StoredTransactionLifecycle;
use nazoauth::test_support::runtime_modules::{
    PersistenceRuntimeModuleRepository, RuntimeModules, ServerRuntimeModuleRegistry, module_catalog,
};
use std::{collections::BTreeSet, sync::Arc};

pub(crate) fn runtime_module_registry_for_test(
    pool: DbPool,
    settings: &Settings,
) -> anyhow::Result<Arc<ServerRuntimeModuleRegistry>> {
    runtime_module_registry_with_modules_for_test(
        pool,
        settings,
        crate::test_support::persisted_runtime_modules_fixture(),
    )
}

pub(crate) fn runtime_module_registry_with_modules_for_test(
    pool: DbPool,
    settings: &Settings,
    active_modules: BTreeSet<ModuleId>,
) -> anyhow::Result<Arc<ServerRuntimeModuleRegistry>> {
    Ok(runtime_modules_with_modules_for_test(pool, settings, active_modules)?.registry)
}

pub(crate) fn runtime_modules_with_modules_for_test(
    pool: DbPool,
    settings: &Settings,
    active_modules: BTreeSet<ModuleId>,
) -> anyhow::Result<RuntimeModules> {
    let catalog = module_catalog(&settings.application_configuration())?;
    let store = Arc::new(RuntimeModuleRepository::new(pool));
    let repository = Arc::new(PersistenceRuntimeModuleRepository::new(store.clone()));
    let lifecycle: Arc<dyn ModuleLifecycle> = Arc::new(StoredTransactionLifecycle::new(store));
    let registry = Arc::new(RuntimeModuleRegistry::new(
        repository.clone(),
        lifecycle,
        catalog.clone(),
        "token-test".to_owned(),
        ActiveModuleSnapshot {
            revision: ModuleRevision::new(0),
            accepting: active_modules,
            draining: BTreeSet::new(),
        },
    ));
    Ok(RuntimeModules {
        repository,
        registry,
        catalog,
        instance_id: "token-test".to_owned(),
    })
}
