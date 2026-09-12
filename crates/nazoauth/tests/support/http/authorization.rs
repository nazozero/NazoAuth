use super::{AuthorizationEndpoint, ClientIpConfig};
use nazo_oauth_server::{
    authorization::config::AuthorizationConfig, services::ServerAuthorizationService,
};
use nazo_runtime_modules::{ActiveModuleSnapshot, ModuleId};
use std::sync::Arc;

struct TestSecurityAudit;

impl nazo_oauth_server::ports::audit::SecurityAudit for TestSecurityAudit {
    fn ensure_storage(&self) -> nazo_oauth_server::ports::audit::AuditFuture<'_> {
        Box::pin(async { Ok(()) })
    }

    fn record(&self, _: &str, _: serde_json::Map<String, serde_json::Value>) {}

    fn record_required<'a>(
        &'a self,
        _: &'a str,
        _: serde_json::Map<String, serde_json::Value>,
    ) -> nazo_oauth_server::ports::audit::AuditFuture<'a> {
        Box::pin(async { Ok(()) })
    }
}

static TEST_SECURITY_AUDIT: TestSecurityAudit = TestSecurityAudit;

pub(crate) fn test_security_audit() -> &'static dyn nazo_oauth_server::ports::audit::SecurityAudit {
    &TEST_SECURITY_AUDIT
}

pub(crate) fn test_security_audit_arc() -> Arc<dyn nazo_oauth_server::ports::audit::SecurityAudit> {
    Arc::new(TestSecurityAudit)
}

pub(crate) struct AuthorizationTestFixture {
    pub(crate) service: Arc<ServerAuthorizationService>,
    pub(crate) config: AuthorizationConfig,
    pub(crate) client_ip: ClientIpConfig,
    pub(crate) sessions: Arc<nazo_oauth_server::sessions::SessionResolver>,
    pub(crate) session_http: crate::http::sessions::SessionHttpConfig,
    pub(crate) enabled_modules: std::collections::BTreeSet<ModuleId>,
    request_object_keys: nazo_key_management::KeyManager,
    tenant_id: uuid::Uuid,
    remote_client_documents:
        Arc<crate::adapters::remote_client_documents::RemoteClientDocumentResolver>,
    security_audit: Arc<dyn nazo_oauth_server::ports::audit::SecurityAudit>,
}

impl AuthorizationTestFixture {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        service: ServerAuthorizationService,
        config: AuthorizationConfig,
        client_ip: ClientIpConfig,
        sessions: Arc<nazo_oauth_server::sessions::SessionResolver>,
        session_http: crate::http::sessions::SessionHttpConfig,
        enabled_modules: std::collections::BTreeSet<ModuleId>,
        request_object_keys: nazo_key_management::KeyManager,
        tenant_id: uuid::Uuid,
    ) -> Self {
        Self {
            service: Arc::new(service),
            config,
            client_ip,
            sessions,
            session_http,
            enabled_modules,
            request_object_keys,
            tenant_id,
            remote_client_documents: Arc::new(
                crate::adapters::remote_client_documents::RemoteClientDocumentResolver::new(&[])
                    .expect("empty remote client document resolver should build"),
            ),
            security_audit: test_security_audit_arc(),
        }
    }

    pub(crate) fn config(&self) -> &AuthorizationConfig {
        &self.config
    }
    pub(crate) fn service(&self) -> &ServerAuthorizationService {
        &self.service
    }

    pub(crate) fn application(
        &self,
    ) -> Arc<nazo_oauth_server::authorization::AuthorizationApplication> {
        Arc::new(
            nazo_oauth_server::authorization::AuthorizationApplication::new(
                self.service.clone(),
                self.security_audit.clone(),
                Arc::new(self.config.clone()),
                self.sessions.clone(),
                Arc::new(nazo_runtime_modules::SnapshotStore::new(
                    ActiveModuleSnapshot {
                        revision: nazo_runtime_modules::ModuleRevision::new(0),
                        accepting: self.enabled_modules.clone(),
                        draining: std::collections::BTreeSet::new(),
                    },
                )),
                self.remote_client_documents.clone(),
                self.remote_client_documents.clone(),
                self.request_object_keys.clone(),
                self.tenant_id,
                None,
            ),
        )
    }

    pub(crate) fn endpoint(&self) -> AuthorizationEndpoint {
        AuthorizationEndpoint::new(
            self.application(),
            self.client_ip.clone(),
            self.session_http.clone(),
        )
    }

    pub(crate) fn without_module(mut self, module: ModuleId) -> Self {
        self.enabled_modules.remove(&module);
        self
    }

    pub(crate) fn rebind_storage(
        &self,
        database: nazo_postgres::DbPool,
        connection: &nazo_valkey::ValkeyConnection,
        keyset: nazo_key_management::KeyManager,
    ) -> Self {
        Self::new(
            ServerAuthorizationService::new(
                nazo_postgres::AuthorizationFlowRepository::new(database.clone(), self.tenant_id),
                Arc::new(nazo_valkey::AuthorizationStateAdapter::new(connection)),
                keyset,
            ),
            self.config.clone(),
            self.client_ip.clone(),
            Arc::new(nazo_oauth_server::sessions::SessionResolver::new(
                Arc::new(nazo_valkey::SessionStore::new(connection)),
                Arc::new(nazo_postgres::UserRepository::new(database)),
                nazo_identity::TenantId::new(self.tenant_id).expect("fixture tenant id"),
            )),
            self.session_http.clone(),
            self.enabled_modules.clone(),
            self.request_object_keys.clone(),
            self.tenant_id,
        )
    }
}

pub(crate) struct TestAuthorizationDependencies {
    pub(crate) fixture: AuthorizationTestFixture,
}
impl TestAuthorizationDependencies {
    pub(crate) fn new(state: &crate::test_support::TestInfrastructure) -> Self {
        let connection = state.valkey_connection();
        let session = &state.settings.session;
        Self {
            fixture: AuthorizationTestFixture::new(
                ServerAuthorizationService::new(
                    nazo_postgres::AuthorizationFlowRepository::new(
                        state.diesel_db.clone(),
                        state.settings.tenant.context.tenant_id.as_uuid(),
                    ),
                    Arc::new(nazo_valkey::AuthorizationStateAdapter::new(&connection)),
                    state.keyset.clone(),
                ),
                crate::http::authorization::authorization_config(state.settings.as_ref()),
                ClientIpConfig::new(
                    &state.settings.endpoint.trusted_proxy_cidrs,
                    state.settings.endpoint.client_ip_header_mode,
                ),
                Arc::new(nazo_oauth_server::sessions::SessionResolver::new(
                    Arc::new(nazo_valkey::SessionStore::new(&connection)),
                    Arc::new(nazo_postgres::UserRepository::new(state.diesel_db.clone())),
                    state.settings.tenant.context.tenant_id,
                )),
                crate::http::sessions::SessionHttpConfig::new(
                    &session.session_cookie_name,
                    &session.csrf_cookie_name,
                    session.cookie_secure,
                ),
                crate::test_support::persisted_runtime_modules_fixture(),
                state.keyset.clone(),
                state.settings.tenant.context.tenant_id.as_uuid(),
            ),
        }
    }

    pub(crate) fn application(
        &self,
    ) -> Arc<nazo_oauth_server::authorization::AuthorizationApplication> {
        self.fixture.application()
    }
    pub(crate) fn endpoint(&self) -> AuthorizationEndpoint {
        self.fixture.endpoint()
    }
}
