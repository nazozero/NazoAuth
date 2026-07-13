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
    pub(crate) fn active_module_snapshot(&self) -> nazo_runtime_modules::ActiveModuleSnapshot {
        #[cfg(not(test))]
        return self.runtime_modules.snapshot().as_ref().clone();
        #[cfg(test)]
        return self.test_module_snapshot();
    }

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
            nazo_auth::module_admissible(&self.active_module_snapshot(), module_id, admission)
        }
        #[cfg(test)]
        {
            nazo_auth::module_admissible(&self.test_module_snapshot(), module_id, admission)
        }
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
    #[cfg(test)]
    fn test_module_snapshot(&self) -> nazo_runtime_modules::ActiveModuleSnapshot {
        nazo_runtime_modules::ActiveModuleSnapshot {
            revision: nazo_runtime_modules::ModuleRevision::new(0),
            accepting: crate::runtime_modules::inherited_enabled(&self.settings),
            draining: std::collections::BTreeSet::new(),
        }
    }
}
