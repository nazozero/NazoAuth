// Native regression module: reexports the actual neutral implementation.
#[path = "../../../../unit/http/admin/clients/update.rs"]
pub(crate) mod tests;

use super::{AdminClientConfig, ServerAdminClientService};
use crate::http::sessions::AdminSessionHandles;
use actix_web::web::{Data, Json};
use actix_web::{HttpRequest, HttpResponse};
use nazo_auth::PatchClientRequest;

pub(crate) async fn admin_patch_client(
    admin_sessions: Data<AdminSessionHandles>,
    service: Data<ServerAdminClientService>,
    config: Data<AdminClientConfig>,
    req: HttpRequest,
    path: actix_web::web::Path<String>,
    Json(payload): Json<PatchClientRequest>,
) -> HttpResponse {
    let request = crate::test_support::transport::request_head(&req);
    nazo_http_actix::forward_response(
        nazoauth::test_support::endpoints::admin::clients::update::admin_patch_client(
            &crate::adapters::audit::TenantSecurityAudit::new(
                nazo_identity::TenantId::new(nazo_identity::DEFAULT_TENANT_ID).unwrap(),
            ),
            admin_sessions.get_ref(),
            service.get_ref(),
            config.get_ref(),
            &request,
            path.into_inner(),
            payload,
        )
        .await,
    )
}
