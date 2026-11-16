use super::*;

#[test]
fn catalog_keeps_static_module_dependencies() {
    let settings = Configuration::new(
        nazo_identity::TenantContext::default_system(),
        "http://127.0.0.1:18000",
        "runtime-module-test-secret-at-least-32-bytes",
    )
    .expect("default settings should load");
    let catalog = module_catalog(&settings).expect("module catalog should be valid");

    assert_eq!(
        catalog.spec(ModuleId::ScimSecurityEvents).dependencies,
        BTreeSet::from([ModuleId::Scim])
    );
    assert_eq!(
        catalog.spec(ModuleId::NativeSso).dependencies,
        BTreeSet::from([ModuleId::TokenExchange])
    );
}

#[test]
fn vp_drain_horizon_uses_the_constructed_transaction_ttl_instead_of_session_ttl() {
    let mut settings = Configuration::new(
        nazo_identity::TenantContext::default_system(),
        "http://127.0.0.1:18000",
        "runtime-module-test-secret-at-least-32-bytes",
    )
    .unwrap();
    settings.session.session_ttl_seconds = 60;
    settings.openid4vc.transaction_ttl_seconds = 300;
    settings.modules.enable_openid4vp_verifier = true;
    let catalog = module_catalog(&settings).unwrap();
    assert_eq!(
        catalog.effective_disable_policy(ModuleId::Openid4vpVerifier),
        nazo_runtime_modules::DisablePolicy::DrainStoredTransactions {
            max_duration: Duration::from_secs(300)
        }
    );
    settings.openid4vc.transaction_ttl_seconds = 1;
    let catalog = module_catalog(&settings).unwrap();
    assert_eq!(
        catalog.effective_disable_policy(ModuleId::Openid4vpVerifier),
        nazo_runtime_modules::DisablePolicy::DrainStoredTransactions {
            max_duration: Duration::from_secs(30)
        }
    );
}

#[test]
fn failed_operation_and_compensation_map_to_unavailable() {
    let error = RuntimeModuleManagementError::Registry(RegistryError::Compensation {
        operation: Box::new(RegistryError::Repository(
            nazo_identity::ports::RepositoryError::Unavailable,
        )),
        compensation: Box::new(RegistryError::MissingDesiredState(ModuleId::Ciba)),
    });
    assert!(matches!(
        map_management_error(error),
        RuntimeModuleAdminError::Unavailable
    ));
}
