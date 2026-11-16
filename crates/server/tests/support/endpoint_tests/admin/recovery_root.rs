// Native regression module: reexports the actual neutral implementation.
pub(crate) use nazoauth::test_support::endpoints::admin::recovery_root::*;
#[path = "../../../unit/http/admin/recovery_root.rs"]
pub(crate) mod tests;

use crate::http::sessions::AdminSessionHandles;
use crate::recovery_root::{RecoveryRootChangeRequest, RecoveryRootService};
use crate::test_support::http::ClientIpConfig;
use actix_web::http::StatusCode;
use actix_web::web::{Data, Json};
use actix_web::{HttpRequest, HttpResponse};

pub(crate) async fn admin_recovery_root_approval(
    admin_sessions: Data<AdminSessionHandles>,
    recovery: Data<RecoveryRootService>,
    client_ip_config: Data<ClientIpConfig>,
    req: HttpRequest,
    Json(body): Json<RecoveryRootChangeRequest>,
) -> HttpResponse {
    let request = crate::test_support::transport::request_with_client_ip(&req, &client_ip_config);
    nazo_http_actix::forward_response(
        nazoauth::test_support::endpoints::admin::recovery_root::admin_recovery_root_approval(
            &crate::adapters::audit::TenantSecurityAudit::new(
                nazo_identity::TenantId::new(nazo_identity::DEFAULT_TENANT_ID).unwrap(),
            ),
            admin_sessions.get_ref(),
            recovery.get_ref(),
            client_ip_config.get_ref(),
            &request,
            body,
        )
        .await,
    )
}

pub(crate) async fn admin_recovery_root_rotate(
    admin_sessions: Data<AdminSessionHandles>,
    recovery: Data<RecoveryRootService>,
    client_ip_config: Data<ClientIpConfig>,
    req: HttpRequest,
    Json(body): Json<RotateRecoveryRootBody>,
) -> HttpResponse {
    let request = crate::test_support::transport::request_with_client_ip(&req, &client_ip_config);
    nazo_http_actix::forward_response(
        nazoauth::test_support::endpoints::admin::recovery_root::admin_recovery_root_rotate(
            &crate::adapters::audit::TenantSecurityAudit::new(
                nazo_identity::TenantId::new(nazo_identity::DEFAULT_TENANT_ID).unwrap(),
            ),
            admin_sessions.get_ref(),
            recovery.get_ref(),
            client_ip_config.get_ref(),
            &request,
            body,
        )
        .await,
    )
}
