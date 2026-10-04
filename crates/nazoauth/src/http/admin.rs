//! 管理端 HTTP handler 聚合模块。
// 每个子模块按一个管理资源拆分，路由层通过显式模块路径调用。
pub(crate) mod access_requests;
pub(crate) mod clients;
pub(crate) mod controller_recovery;
pub(crate) mod controller_registry;
pub(crate) mod federation;
pub(crate) mod grants;
pub(crate) mod mtls_trust;
pub(crate) mod openid4vc;
pub(crate) mod recovery_root;
pub(crate) mod users;

use actix_web::{HttpResponse, http::StatusCode};
use nazo_http_actix::oauth_error;

/// Current readiness for a command whose accepting owner also persists its
/// complete Required event. This does not emit an independently committed intent.
pub(crate) async fn require_transactional_audit_or_unavailable() -> Result<(), HttpResponse> {
    crate::adapters::audit::ensure_transactional_audit_ready()
        .await
        .map_err(|error| {
            tracing::error!(%error, "transactional security audit readiness failed");
            oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "Durable security audit storage is unavailable.",
            )
        })
}
