// Native regression module: reexports the actual neutral implementation.
#[path = "../../../unit/http/admin/openid4vc.rs"]
pub(crate) mod tests;

use crate::http::sessions::AdminSessionHandles;
use actix_web::{
    HttpRequest, HttpResponse,
    http::StatusCode,
    web::{Data, Json, Path},
};
use nazo_oauth_server::domain::openid4vc_endpoints::CredentialDatasetAdminService;
use nazo_oauth_server::domain::openid4vc_endpoints::PutCredentialDatasetRequest;
use nazo_openid4vci::application::CredentialHttpError;
use uuid::Uuid;

pub(crate) async fn admin_put_credential_dataset(
    sessions: Data<AdminSessionHandles>,
    endpoint: Data<CredentialDatasetAdminService>,
    request: HttpRequest,
    path: Path<(Uuid, String)>,
    Json(payload): Json<PutCredentialDatasetRequest>,
) -> HttpResponse {
    let request = crate::test_support::transport::request_head(&request);
    nazo_http_actix::forward_response(
        nazoauth::test_support::endpoints::admin::openid4vc::admin_put_credential_dataset(
            &crate::adapters::audit::TenantSecurityAudit::new(
                nazo_identity::TenantId::new(nazo_identity::DEFAULT_TENANT_ID).unwrap(),
            ),
            sessions.get_ref(),
            endpoint.get_ref(),
            &request,
            path.into_inner(),
            payload,
        )
        .await,
    )
}

pub(crate) async fn admin_get_credential_dataset(
    sessions: Data<AdminSessionHandles>,
    endpoint: Data<CredentialDatasetAdminService>,
    request: HttpRequest,
    path: Path<(Uuid, String)>,
) -> HttpResponse {
    let request = crate::test_support::transport::request_head(&request);
    nazo_http_actix::forward_response(
        nazoauth::test_support::endpoints::admin::openid4vc::admin_get_credential_dataset(
            sessions.get_ref(),
            endpoint.get_ref(),
            &request,
            path.into_inner(),
        )
        .await,
    )
}

pub(crate) async fn admin_delete_credential_dataset(
    sessions: Data<AdminSessionHandles>,
    endpoint: Data<CredentialDatasetAdminService>,
    request: HttpRequest,
    path: Path<(Uuid, String)>,
) -> HttpResponse {
    let request = crate::test_support::transport::request_head(&request);
    nazo_http_actix::forward_response(
        nazoauth::test_support::endpoints::admin::openid4vc::admin_delete_credential_dataset(
            &crate::adapters::audit::TenantSecurityAudit::new(
                nazo_identity::TenantId::new(nazo_identity::DEFAULT_TENANT_ID).unwrap(),
            ),
            sessions.get_ref(),
            endpoint.get_ref(),
            &request,
            path.into_inner(),
        )
        .await,
    )
}

pub(crate) fn dataset_error(error: CredentialHttpError) -> HttpResponse {
    nazo_http_actix::forward_response(
        nazoauth::test_support::endpoints::admin::openid4vc::dataset_error(error),
    )
}
