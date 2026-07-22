use super::*;
use crate::config::ConfigSource;

#[test]
fn instance_id_is_nonempty_and_storage_bounded() {
    let instance_id = runtime_instance_id().expect("default runtime instance id is valid");
    assert!(!instance_id.trim().is_empty());
    assert!(instance_id.len() <= 255);
}

#[test]
fn par_request_objects_enable_the_shared_request_object_capability() {
    let mut settings =
        Settings::from_config(&ConfigSource::default()).expect("default settings should load");
    settings.modules.enable_request_object = false;
    settings.modules.enable_par_request_object = true;

    assert!(inherited_enabled(&settings).contains(&ModuleId::RequestObjects));
}

#[test]
fn scim_security_events_are_default_closed_and_depend_on_scim() {
    let mut settings =
        Settings::from_config(&ConfigSource::default()).expect("default settings should load");
    assert!(!inherited_enabled(&settings).contains(&ModuleId::ScimSecurityEvents));

    settings.modules.enable_scim_security_events = true;
    let inherited = inherited_enabled(&settings);
    assert!(inherited.contains(&ModuleId::ScimSecurityEvents));
    let catalog = module_catalog(&settings, inherited).unwrap();
    assert_eq!(
        catalog
            .spec(ModuleId::ScimSecurityEvents)
            .unwrap()
            .dependencies,
        BTreeSet::from([ModuleId::Scim])
    );
    assert_eq!(
        catalog
            .spec(ModuleId::ScimSecurityEvents)
            .unwrap()
            .disable_policy,
        nazo_runtime_modules::DisablePolicy::DrainStoredTransactions {
            max_duration: Duration::from_secs(604_800)
        }
    );
}
