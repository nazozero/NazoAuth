//! Host regression fixtures using the production facade assembly.
use super::TestInfrastructure;
use nazo_oauth_server::ports::persistence::{ServerPersistenceBindings, ServerPersistenceProvider};
use nazoauth::{NazoAuth, NazoAuthBuilder};

use std::sync::Arc;

use nazo_auth::{
    AdminClientRepositoryPort, AdminGrantRepositoryPort, AuthorizationRepositoryPort,
    DeviceGrantRepositoryPort, DynamicRegistrationClientStore, LogoutClientRepositoryPort,
    TokenRepositoryPort,
};
use nazo_identity::ports::{
    AccessRequestRepositoryPort, AdminUserRepositoryPort, AuthorizedApplicationRepositoryPort,
    AvatarRepositoryPort, FederationLinkRepositoryPort, FederationLoginRepositoryPort,
    GrantSummaryRepositoryPort, LoginAccountRepositoryPort, MfaRepositoryPort,
    MtlsTrustAnchorStore, PasskeyAccountRepositoryPort, PasskeyRepositoryPort,
    ProfileRepositoryPort, RegistrationAccountRepositoryPort, RememberedMfaDevicePort,
    ScimCredentialPort, ScimRepositoryPort, SessionAccountPort,
};

#[derive(Default)]
pub(crate) struct PersistenceOverrides {
    pub(crate) accepting_modules:
        Option<std::collections::BTreeSet<nazo_runtime_modules::ModuleId>>,
    pub(crate) modules: Option<Arc<dyn nazo_persistence::RuntimeModuleStore>>,
    pub(crate) tokens: Option<Arc<dyn TokenRepositoryPort>>,
    pub(crate) authorization: Option<Arc<dyn AuthorizationRepositoryPort>>,
}

struct FixturePersistence {
    base: Arc<dyn ServerPersistenceProvider>,
    overrides: PersistenceOverrides,
}

impl ServerPersistenceProvider for FixturePersistence {
    fn tenant_directory(&self) -> Arc<dyn nazo_persistence::TenantDirectoryStore> {
        self.base.tenant_directory()
    }
    fn security_audit_ledger(&self) -> Arc<dyn nazo_persistence::SecurityAuditLedger> {
        self.base.security_audit_ledger()
    }
    fn database_health(&self) -> Arc<dyn nazo_persistence::DatabaseHealthPort> {
        self.base.database_health()
    }
    fn security_state_maintenance(
        &self,
    ) -> Arc<dyn nazo_persistence::SecurityStateMaintenancePort> {
        self.base.security_state_maintenance()
    }
    fn runtime_modules(
        &self,
        tenant_id: uuid::Uuid,
    ) -> Arc<dyn nazo_persistence::RuntimeModuleStore> {
        self.overrides
            .modules
            .clone()
            .unwrap_or_else(|| self.base.runtime_modules(tenant_id))
    }
    fn signing_key_repository(
        &self,
        tenant_id: uuid::Uuid,
    ) -> Arc<dyn nazo_key_management::SigningKeyRepository> {
        self.base.signing_key_repository(tenant_id)
    }
    fn authorization_repository(
        &self,
        tenant_id: uuid::Uuid,
    ) -> Arc<dyn AuthorizationRepositoryPort> {
        self.overrides
            .authorization
            .clone()
            .unwrap_or_else(|| self.base.authorization_repository(tenant_id))
    }
    fn device_grant_repository(&self, tenant_id: uuid::Uuid) -> Arc<dyn DeviceGrantRepositoryPort> {
        self.base.device_grant_repository(tenant_id)
    }
    fn token_repository(&self) -> Arc<dyn TokenRepositoryPort> {
        self.overrides
            .tokens
            .clone()
            .unwrap_or_else(|| self.base.token_repository())
    }
    fn access_token_revocations(
        &self,
    ) -> Arc<dyn nazo_resource_server::AccessTokenRevocationLookup> {
        self.base.access_token_revocations()
    }
    fn admin_clients(&self) -> Arc<dyn AdminClientRepositoryPort> {
        self.base.admin_clients()
    }
    fn dynamic_registration_clients(&self) -> Arc<dyn DynamicRegistrationClientStore> {
        self.base.dynamic_registration_clients()
    }
    fn logout_clients(&self) -> Arc<dyn LogoutClientRepositoryPort> {
        self.base.logout_clients()
    }
    fn authorized_applications(&self) -> Arc<dyn AuthorizedApplicationRepositoryPort> {
        self.base.authorized_applications()
    }
    fn grant_summaries(&self) -> Arc<dyn GrantSummaryRepositoryPort> {
        self.base.grant_summaries()
    }
    fn admin_grants(&self) -> Arc<dyn AdminGrantRepositoryPort> {
        self.base.admin_grants()
    }
    fn session_accounts(&self) -> Arc<dyn SessionAccountPort> {
        self.base.session_accounts()
    }
    fn login_accounts(&self) -> Arc<dyn LoginAccountRepositoryPort> {
        self.base.login_accounts()
    }
    fn registration_accounts(&self) -> Arc<dyn RegistrationAccountRepositoryPort> {
        self.base.registration_accounts()
    }
    fn admin_users(&self) -> Arc<dyn AdminUserRepositoryPort> {
        self.base.admin_users()
    }
    fn profiles(&self) -> Arc<dyn ProfileRepositoryPort> {
        self.base.profiles()
    }
    fn avatars(&self) -> Arc<dyn AvatarRepositoryPort> {
        self.base.avatars()
    }
    fn passkey_accounts(&self) -> Arc<dyn PasskeyAccountRepositoryPort> {
        self.base.passkey_accounts()
    }
    fn passkeys(&self) -> Arc<dyn PasskeyRepositoryPort> {
        self.base.passkeys()
    }
    fn ciba_accounts(&self) -> Arc<dyn nazo_persistence::CibaAccountStore> {
        self.base.ciba_accounts()
    }
    fn openid4vc_subjects(&self) -> Arc<dyn nazo_persistence::Openid4vcSubjectStore> {
        self.base.openid4vc_subjects()
    }
    fn mfa_repository(&self) -> Arc<dyn MfaRepositoryPort> {
        self.base.mfa_repository()
    }
    fn remembered_mfa_devices(&self) -> Arc<dyn RememberedMfaDevicePort> {
        self.base.remembered_mfa_devices()
    }
    fn federation_links(&self) -> Arc<dyn FederationLinkRepositoryPort> {
        self.base.federation_links()
    }
    fn federation_logins(&self) -> Arc<dyn FederationLoginRepositoryPort> {
        self.base.federation_logins()
    }
    fn access_requests(&self) -> Arc<dyn AccessRequestRepositoryPort> {
        self.base.access_requests()
    }
    fn admin_access_requests(&self) -> Arc<dyn nazo_persistence::AdminAccessRequestStore> {
        self.base.admin_access_requests()
    }
    fn scim_repository(&self, event_retention_seconds: u64) -> Arc<dyn ScimRepositoryPort> {
        self.base.scim_repository(event_retention_seconds)
    }
    fn scim_credentials(&self) -> Arc<dyn ScimCredentialPort> {
        self.base.scim_credentials()
    }
    fn scim_event_store(&self) -> Arc<dyn nazo_scim_events::EventStorePort> {
        self.base.scim_event_store()
    }
    fn logout_outbox(&self) -> Arc<dyn nazo_auth::BackchannelLogoutOutboxPort> {
        self.base.logout_outbox()
    }
    fn logout_delivery_store(&self) -> Arc<dyn nazo_persistence::BackchannelLogoutDeliveryStore> {
        self.base.logout_delivery_store()
    }
    fn controller_registry(&self) -> Arc<dyn nazo_persistence::ControllerRegistryPort> {
        self.base.controller_registry()
    }
    fn recovery_root(&self) -> Arc<dyn nazo_persistence::RecoveryRootPort> {
        self.base.recovery_root()
    }
    fn mtls_trust_anchors(&self) -> Arc<dyn MtlsTrustAnchorStore> {
        self.base.mtls_trust_anchors()
    }
    fn openid4vc_trust_policies(&self) -> Arc<dyn nazo_persistence::Openid4vcTrustPolicyStore> {
        self.base.openid4vc_trust_policies()
    }
    fn openid4vci_store(
        &self,
        data_key: [u8; 32],
        secret_verifier: Arc<dyn nazo_identity::ports::SecretVerifyPort>,
    ) -> Arc<dyn nazo_persistence::Openid4vciStore> {
        self.base.openid4vci_store(data_key, secret_verifier)
    }
    fn openid4vci_authorization_offers(
        &self,
        data_key: [u8; 32],
        secret_verifier: Arc<dyn nazo_identity::ports::SecretVerifyPort>,
    ) -> Arc<dyn nazo_openid4vci::AuthorizationOfferPort> {
        self.base
            .openid4vci_authorization_offers(data_key, secret_verifier)
    }
    fn openid4vci_datasets(
        &self,
        data_key: [u8; 32],
    ) -> Arc<dyn nazo_persistence::Openid4vciDatasetStore> {
        self.base.openid4vci_datasets(data_key)
    }
    fn openid4vp_store(
        &self,
        tenant_id: uuid::Uuid,
        data_key: [u8; 32],
    ) -> Arc<dyn nazo_persistence::Openid4vpStore> {
        self.base.openid4vp_store(tenant_id, data_key)
    }
}

pub(crate) fn capabilities(
    state: &TestInfrastructure,
    mut overrides: PersistenceOverrides,
) -> anyhow::Result<nazoauth::capabilities::Capabilities> {
    crate::adapters::security::initialize_dummy_password_hash()?;
    if std::env::var_os("NAZO_TEST_DATABASE_URL").is_some()
        || std::env::var_os("DATABASE_URL").is_some()
    {
        super::initialize_audit_dependencies(&state.diesel_db);
    }
    let base: Arc<dyn ServerPersistenceProvider> = Arc::new(
        nazo_oauth_server_postgres::PostgresProvider::new(state.diesel_db.clone(), None),
    );
    if overrides.modules.is_none() {
        overrides.modules = Some(Arc::new(ModuleSnapshot {
            base: base.runtime_modules(state.settings.tenant.context.tenant_id.as_uuid()),
            accepting: overrides
                .accepting_modules
                .take()
                .unwrap_or_else(super::persisted_runtime_modules_fixture),
        }));
    }
    let persistence =
        ServerPersistenceBindings::new(Arc::new(FixturePersistence { base, overrides }));
    // Match the existing namespaced state-store fixtures so setup writes and
    // the real facade read exactly the same tenant keys.
    let client = nazo_valkey::ValkeyClient::from_existing_client(
        state.valkey.clone(),
        "test",
        uuid::Uuid::from_u128(0x019c_8ca2_30a6_7000_8000_0000_0000_0001),
    )?;
    let transient = nazo_oauth_server_valkey::server_state_bindings(client)
        .for_tenant(state.settings.tenant.context.tenant_id)?;
    crate::bootstrap::test_support::application_capabilities(
        &state.settings,
        &persistence,
        &transient,
        state.keyset.clone(),
    )
}

pub(crate) fn builder(
    state: &TestInfrastructure,
    overrides: PersistenceOverrides,
) -> anyhow::Result<NazoAuthBuilder> {
    Ok(NazoAuthBuilder::new(
        state.settings.application_configuration(),
        capabilities(state, overrides)?,
        format!("test-{}", uuid::Uuid::now_v7()),
    )
    .with_avatar_storage(crate::adapters::avatar_files::LocalAvatarStorage::new(
        state.settings.storage.avatar_storage_dir.clone(),
    )))
}

pub(crate) async fn application(state: &TestInfrastructure) -> anyhow::Result<Arc<NazoAuth>> {
    Ok(Arc::new(
        builder(state, PersistenceOverrides::default())?
            .build()
            .await?,
    ))
}

struct ModuleSnapshot {
    base: Arc<dyn nazo_persistence::RuntimeModuleStore>,
    accepting: std::collections::BTreeSet<nazo_runtime_modules::ModuleId>,
}

impl nazo_persistence::RuntimeModuleStore for ModuleSnapshot {
    fn read_desired(
        &self,
        module_id: nazo_runtime_modules::ModuleId,
    ) -> futures_util::future::BoxFuture<
        '_,
        Result<
            Option<nazo_runtime_modules::DesiredStateRecord>,
            nazo_identity::ports::RepositoryError,
        >,
    > {
        self.base.read_desired(module_id)
    }
    fn read_all_desired(
        &self,
    ) -> futures_util::future::BoxFuture<
        '_,
        Result<
            Vec<nazo_runtime_modules::DesiredStateRecord>,
            nazo_identity::ports::RepositoryError,
        >,
    > {
        self.base.read_all_desired()
    }
    fn read_reconcile_state<'a>(
        &'a self,
        _instance_id: &'a str,
    ) -> futures_util::future::BoxFuture<
        'a,
        Result<
            Vec<nazo_runtime_modules::ModuleReconcileState>,
            nazo_identity::ports::RepositoryError,
        >,
    > {
        Box::pin(async {
            Ok(nazo_runtime_modules::ModuleId::ALL
                .into_iter()
                .map(|module_id| nazo_runtime_modules::ModuleReconcileState {
                    desired: nazo_runtime_modules::DesiredStateRecord {
                        module_id,
                        mode: if self.accepting.contains(&module_id) {
                            nazo_runtime_modules::DesiredMode::Enabled
                        } else {
                            nazo_runtime_modules::DesiredMode::Disabled
                        },
                        revision: nazo_runtime_modules::ModuleRevision::new(0),
                        actor_id: None,
                        reason: None,
                        updated_at: std::time::SystemTime::UNIX_EPOCH,
                    },
                    instance: None,
                })
                .collect())
        })
    }
    fn compare_and_set_desired(
        &self,
        change: nazo_runtime_modules::DesiredStateChange,
    ) -> futures_util::future::BoxFuture<
        '_,
        Result<
            nazo_runtime_modules::CasOutcome<nazo_runtime_modules::DesiredStateRecord>,
            nazo_identity::ports::RepositoryError,
        >,
    > {
        self.base.compare_and_set_desired(change)
    }
    fn compare_and_set_desired_guarded(
        &self,
        change: nazo_runtime_modules::DesiredStateChange,
        required_revisions: Vec<nazo_runtime_modules::DesiredRevisionGuard>,
    ) -> futures_util::future::BoxFuture<
        '_,
        Result<
            nazo_runtime_modules::CasOutcome<nazo_runtime_modules::DesiredStateRecord>,
            nazo_identity::ports::RepositoryError,
        >,
    > {
        self.base
            .compare_and_set_desired_guarded(change, required_revisions)
    }
    fn read_instance<'a>(
        &'a self,
        instance_id: &'a str,
        module_id: nazo_runtime_modules::ModuleId,
    ) -> futures_util::future::BoxFuture<
        'a,
        Result<
            Option<nazo_runtime_modules::InstanceStateRecord>,
            nazo_identity::ports::RepositoryError,
        >,
    > {
        self.base.read_instance(instance_id, module_id)
    }
    fn read_all_instances<'a>(
        &'a self,
        instance_id: &'a str,
    ) -> futures_util::future::BoxFuture<
        'a,
        Result<
            Vec<nazo_runtime_modules::InstanceStateRecord>,
            nazo_identity::ports::RepositoryError,
        >,
    > {
        self.base.read_all_instances(instance_id)
    }
    fn page_events(
        &self,
        offset: i64,
        limit: i64,
    ) -> futures_util::future::BoxFuture<
        '_,
        Result<nazo_runtime_modules::ModuleEventPage, nazo_identity::ports::RepositoryError>,
    > {
        self.base.page_events(offset, limit)
    }
    fn compare_and_set_instance(
        &self,
        mutation: nazo_runtime_modules::InstanceStateMutation,
    ) -> futures_util::future::BoxFuture<
        '_,
        Result<
            nazo_runtime_modules::CasOutcome<nazo_runtime_modules::InstanceStateRecord>,
            nazo_identity::ports::RepositoryError,
        >,
    > {
        self.base.compare_and_set_instance(mutation)
    }
    fn record_instance_observation(
        &self,
        observation: nazo_runtime_modules::InstanceStateObservation,
    ) -> futures_util::future::BoxFuture<'_, Result<(), nazo_identity::ports::RepositoryError>>
    {
        self.base.record_instance_observation(observation)
    }
    fn validate_revision(
        &self,
        module_id: nazo_runtime_modules::ModuleId,
        expected: nazo_runtime_modules::ModuleRevision,
    ) -> futures_util::future::BoxFuture<'_, Result<bool, nazo_identity::ports::RepositoryError>>
    {
        self.base.validate_revision(module_id, expected)
    }
}

#[path = "facade_rate_limit.rs"]
mod rate_limit;
pub(crate) use rate_limit::with_rate_limits;

pub(crate) async fn enable_credential_issuer(
    state: &mut TestInfrastructure,
) -> std::collections::BTreeSet<nazo_runtime_modules::ModuleId> {
    let (_, keys) =
        crate::domain::openid4vc_endpoints_openid4vp_tests::fixture_crypto_with_dns(true).await;
    let settings = Arc::make_mut(&mut state.settings);
    settings.endpoint.issuer = "https://issuer.example".to_owned();
    settings.session.cookie_secure = true;
    settings.modules.register_openid4vci_routes = true;
    settings.modules.enable_openid4vci_issuer = true;
    settings.openid4vc.data_encryption_key = Some([17; 32]);
    settings.openid4vc.issuer_management_token =
        Some("nonce-budget-management-token-0000000000000000".to_owned());
    settings.openid4vc.credential_configurations.insert(
        "unit-credential".to_owned(),
        crate::domain::openid4vci_endpoint_operations_tests::unit_configuration(),
    );
    state.keyset = keys;
    let mut modules = super::persisted_runtime_modules_fixture();
    modules.extend([
        nazo_runtime_modules::ModuleId::Openid4vciIssuer,
        nazo_runtime_modules::ModuleId::AuthorizationDetails,
    ]);
    modules
}
