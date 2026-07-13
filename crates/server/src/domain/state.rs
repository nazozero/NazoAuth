//! 应用运行时共享状态。
// Actix application data 只保存可克隆句柄，不在 handler 中重新初始化外部资源。
use std::sync::Arc;

#[cfg(test)]
use nazo_valkey::test_support::Client as ValkeyTestClient;

use crate::settings::Settings;
use nazo_postgres::DbPool;

/// 每个 HTTP worker 共享的后端资源句柄。
#[derive(Clone)]
pub(crate) struct AppState {
    pub(crate) diesel_db: DbPool,
    #[cfg(not(test))]
    pub(crate) valkey: nazo_valkey::ValkeyConnection,
    #[cfg(test)]
    pub(crate) valkey: ValkeyTestClient,
    pub(crate) settings: Arc<Settings>,
    pub(crate) keyset: nazo_key_management::KeyManager,
    #[cfg(not(test))]
    pub(crate) runtime_modules: std::sync::Arc<crate::runtime_modules::ServerRuntimeModuleRegistry>,
}

impl AppState {
    pub(crate) fn valkey_connection(&self) -> nazo_valkey::ValkeyConnection {
        #[cfg(not(test))]
        return self.valkey.clone();
        #[cfg(test)]
        return nazo_valkey::ValkeyConnection::from_existing_client(self.valkey.clone());
    }

    pub(crate) fn module_admissible(
        &self,
        module_id: nazo_runtime_modules::ModuleId,
        admission: nazo_auth::CapabilityAdmission,
    ) -> bool {
        #[cfg(not(test))]
        {
            nazo_auth::module_admissible(&self.runtime_modules.snapshot(), module_id, admission)
        }
        #[cfg(test)]
        {
            let _ = admission;
            static_module_enabled(&self.settings, module_id)
        }
    }

    pub(crate) fn accepts_module(&self, module_id: nazo_runtime_modules::ModuleId) -> bool {
        self.module_admissible(module_id, nazo_auth::CapabilityAdmission::NewRequest)
    }

    pub(crate) fn permits_existing_module_transaction(
        &self,
        module_id: nazo_runtime_modules::ModuleId,
    ) -> bool {
        self.module_admissible(
            module_id,
            nazo_auth::CapabilityAdmission::ExistingTransaction,
        )
    }

    pub(crate) fn metadata_capabilities(&self) -> nazo_auth::MetadataCapabilities {
        #[cfg(not(test))]
        {
            nazo_auth::MetadataCapabilities::from_snapshot(&self.runtime_modules.snapshot())
        }
        #[cfg(test)]
        {
            let accepting = nazo_runtime_modules::ModuleId::ALL
                .into_iter()
                .filter(|module_id| static_module_enabled(&self.settings, *module_id))
                .collect();
            nazo_auth::MetadataCapabilities::from_snapshot(
                &nazo_runtime_modules::ActiveModuleSnapshot {
                    revision: nazo_runtime_modules::ModuleRevision::new(0),
                    accepting,
                    draining: std::collections::BTreeSet::new(),
                },
            )
        }
    }
}

#[cfg(test)]
fn static_module_enabled(settings: &Settings, module_id: nazo_runtime_modules::ModuleId) -> bool {
    use nazo_runtime_modules::ModuleId;
    match module_id {
        ModuleId::DeviceAuthorization => settings.enable_device_authorization_grant,
        ModuleId::TokenExchange | ModuleId::JwtBearerGrant | ModuleId::Jarm | ModuleId::Scim => {
            true
        }
        ModuleId::Ciba => settings.enable_ciba,
        ModuleId::DynamicClientRegistration => settings.enable_dynamic_client_registration,
        ModuleId::RequestObjects => settings.enable_request_object,
        ModuleId::AuthorizationDetails => settings.enable_authorization_details,
        ModuleId::HttpMessageSignatures => settings.enable_fapi_http_signatures,
        ModuleId::NativeSso => settings.enable_native_sso,
        ModuleId::FrontchannelLogout => settings.enable_frontchannel_logout,
        ModuleId::SessionManagement => settings.enable_session_management,
    }
}
