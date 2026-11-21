//! 管理端 HTTP handler 聚合模块。
use crate::http::Response as HttpResponse;
use http::StatusCode;
// 每个子模块按一个管理资源拆分，路由层通过显式模块路径调用。
pub mod access_requests;
pub mod clients;

#[cfg(feature = "deployment-control")]
pub mod controller_recovery;
#[cfg(feature = "deployment-control")]
pub mod controller_registry;
pub mod federation;
pub mod grants;
pub mod mtls_trust;
pub mod openid4vc;
#[cfg(feature = "deployment-control")]
pub mod recovery_root;

pub mod users;

use crate::http::oauth_error;

/// Current readiness for a command whose accepting owner also persists its
/// complete Required event. This does not emit an independently committed intent.
pub async fn require_transactional_audit_or_unavailable(
    audit: &dyn nazo_oauth_server::ports::audit::SecurityAudit,
) -> Result<(), HttpResponse> {
    audit.ensure_transactional_ready().await.map_err(|error| {
        tracing::error!(%error, "transactional security audit readiness failed");
        oauth_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "Durable security audit storage is unavailable.",
        )
    })
}
