use super::*;
use crate::config::ConfigSource;

#[test]
fn catalog_keeps_static_module_dependencies() {
    let settings =
        Settings::from_config(&ConfigSource::default()).expect("default settings should load");
    let catalog = module_catalog(&settings).expect("module catalog should be valid");

    assert_eq!(
        catalog
            .spec(ModuleId::ScimSecurityEvents)
            .unwrap()
            .dependencies,
        BTreeSet::from([ModuleId::Scim])
    );
    assert_eq!(
        catalog.spec(ModuleId::NativeSso).unwrap().dependencies,
        BTreeSet::from([ModuleId::TokenExchange])
    );
}

#[tokio::test]
async fn reconciler_is_one_abortable_tenant_owned_task() {
    let settings =
        Settings::from_config(&ConfigSource::default()).expect("default settings should load");
    let catalog = module_catalog(&settings).expect("module catalog should be valid");
    let pool =
        nazo_postgres::create_pool("not a postgres url", 1).expect("a lazy test pool should build");
    let registry = test_support::runtime_module_registry_with_modules_for_test(
        pool.clone(),
        &settings,
        BTreeSet::new(),
    )
    .expect("test registry should build");
    let repository = Arc::new(PersistenceRuntimeModuleRepository::new(Arc::new(
        nazo_postgres::RuntimeModuleRepository::new(pool),
    )));
    let modules = web::Data::new(RuntimeModules {
        repository,
        registry,
        catalog,
        instance_id: "tenant-runtime-test".to_owned(),
    });

    let worker = RuntimeModules::spawn_reconciler(modules);
    tokio::time::sleep(Duration::from_millis(10)).await;
    worker.abort();
    let error = worker.await.expect_err("aborted reconciler should stop");
    assert!(error.is_cancelled());
}

#[test]
fn vp_drain_horizon_uses_the_constructed_transaction_ttl_instead_of_session_ttl() {
    let mut settings = Settings::from_config(&ConfigSource::default()).unwrap();
    settings.session.session_ttl_seconds = 60;
    settings.openid4vc.transaction_ttl_seconds = 300;
    settings.modules.enable_openid4vp_verifier = true;
    let catalog = module_catalog(&settings).unwrap();
    assert_eq!(
        catalog.effective_disable_policy(ModuleId::Openid4vpVerifier),
        Some(
            nazo_runtime_modules::DisablePolicy::DrainStoredTransactions {
                max_duration: Duration::from_secs(300)
            }
        )
    );
    settings.openid4vc.transaction_ttl_seconds = 1;
    let catalog = module_catalog(&settings).unwrap();
    assert_eq!(
        catalog.effective_disable_policy(ModuleId::Openid4vpVerifier),
        Some(
            nazo_runtime_modules::DisablePolicy::DrainStoredTransactions {
                max_duration: Duration::from_secs(30)
            }
        )
    );
}
