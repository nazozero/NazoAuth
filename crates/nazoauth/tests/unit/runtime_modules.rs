use super::*;
use nazo_runtime_modules::ModuleState;

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

#[test]
fn cold_initial_admission_recovers_only_the_authoritative_live_drain_window() {
    let settings = Configuration::new(
        nazo_identity::TenantContext::default_system(),
        "http://127.0.0.1:18000",
        uuid::Uuid::now_v7().simple().to_string(),
    )
    .unwrap();
    let catalog = module_catalog(&settings).unwrap();
    let at = web_time::SystemTime::now();
    let mut states = ModuleId::ALL
        .into_iter()
        .map(|module_id| ModuleReconcileState {
            desired: DesiredStateRecord {
                module_id,
                mode: nazo_runtime_modules::DesiredMode::Disabled,
                revision: ModuleRevision::new(2),
                actor_id: None,
                reason: None,
                updated_at: web_time::SystemTime::UNIX_EPOCH,
            },
            instance: None,
        })
        .collect::<Vec<_>>();
    states[0].desired.updated_at = at;
    let (accepting, draining) = initial_admission(&catalog, states.clone()).unwrap();
    assert!(accepting.is_empty());
    assert_eq!(draining, BTreeSet::from([ModuleId::DeviceAuthorization]));

    states[0].instance = Some(InstanceStateRecord {
        instance_id: "recovered".into(),
        module_id: ModuleId::DeviceAuthorization,
        state: ModuleState::Draining,
        transition_revision: ModuleRevision::new(2),
        applied_revision: None,
        drain_deadline: Some(web_time::SystemTime::UNIX_EPOCH),
        error_code: None,
        updated_at: at,
    });
    assert!(
        initial_admission(&catalog, states.clone())
            .unwrap()
            .1
            .is_empty()
    );
    let instance = states[0].instance.as_mut().unwrap();
    instance.state = ModuleState::Disabled;
    instance.applied_revision = Some(ModuleRevision::new(2));
    instance.drain_deadline = None;
    assert!(initial_admission(&catalog, states).unwrap().1.is_empty());
}

#[test]
fn cold_initial_admission_rejects_a_missing_constructed_dependency() {
    let settings = Configuration::new(
        nazo_identity::TenantContext::default_system(),
        "http://127.0.0.1:18000",
        uuid::Uuid::now_v7().simple().to_string(),
    )
    .unwrap();
    let catalog = module_catalog(&settings)
        .unwrap()
        .with_constructed_availability([(ModuleId::TokenExchange, false)]);
    let states = ModuleId::ALL
        .into_iter()
        .map(|module_id| ModuleReconcileState {
            desired: DesiredStateRecord {
                module_id,
                mode: nazo_runtime_modules::DesiredMode::Enabled,
                revision: ModuleRevision::new(1),
                actor_id: None,
                reason: None,
                updated_at: web_time::SystemTime::UNIX_EPOCH,
            },
            instance: None,
        })
        .collect();
    assert!(initial_admission(&catalog, states).is_err());
}
