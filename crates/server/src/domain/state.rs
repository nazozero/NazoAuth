//! 应用运行时共享状态。
// Actix application data 只保存可克隆句柄，不在 handler 中重新初始化外部资源。
use std::sync::Arc;

#[cfg(test)]
use fred::prelude::Client as ValkeyClient;

use crate::settings::Settings;
use nazo_postgres::DbPool;

/// 每个 HTTP worker 共享的后端资源句柄。
#[derive(Clone)]
pub(crate) struct AppState {
    pub(crate) diesel_db: DbPool,
    #[cfg(not(test))]
    pub(crate) valkey: nazo_valkey::ValkeyConnection,
    #[cfg(test)]
    pub(crate) valkey: ValkeyClient,
    pub(crate) settings: Arc<Settings>,
    pub(crate) keyset: nazo_key_management::KeyManager,
}

impl AppState {
    pub(crate) fn valkey_connection(&self) -> nazo_valkey::ValkeyConnection {
        #[cfg(not(test))]
        return self.valkey.clone();
        #[cfg(test)]
        return nazo_valkey::ValkeyConnection::from_existing_client(self.valkey.clone());
    }
}
