//! 应用运行时共享状态。
// Actix application data 只保存可克隆句柄，不在 handler 中重新初始化外部资源。
use std::sync::Arc;

use fred::prelude::Client as ValkeyClient;

use crate::db::DbPool;
use crate::settings::Settings;

/// 每个 HTTP worker 共享的后端资源句柄。
#[derive(Clone)]
pub(crate) struct AppState {
    pub(crate) diesel_db: DbPool,
    pub(crate) valkey: ValkeyClient,
    pub(crate) settings: Arc<Settings>,
    pub(crate) keyset: nazo_key_management::KeyManager,
}
