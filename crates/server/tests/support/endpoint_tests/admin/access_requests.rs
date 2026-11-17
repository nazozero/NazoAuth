// Native regression module: reexports the actual neutral implementation.
pub(crate) use nazoauth::test_support::endpoints::admin::access_requests::*;
#[path = "../../../unit/http/admin/access_requests.rs"]
pub(crate) mod tests;

use super::clients::ServerAdminClientService;
use crate::http::sessions::AdminSessionHandles;
use crate::test_support::http::ClientIpConfig;
use actix_web::http::StatusCode;
use actix_web::web::{Data, Json, Query};
use actix_web::{HttpRequest, HttpResponse};
use nazo_auth::CreateClientRequest;
use nazo_identity::ports::DeliveryStorePort;
use nazo_oauth_server::crypto::access_delivery_token;
use nazo_persistence::AdminAccessRequestStore;
use serde_json::{Value, json};
use std::collections::HashMap;
use uuid::Uuid;

pub(crate) async fn admin_access_requests(
    admin_sessions: Data<AdminSessionHandles>,
    repository: Data<dyn AdminAccessRequestStore>,
    req: HttpRequest,
    Query(q): Query<HashMap<String, String>>,
) -> HttpResponse {
    let request = crate::test_support::transport::request_head(&req);
    nazo_http_actix::forward_response(
        nazoauth::test_support::endpoints::admin::access_requests::admin_access_requests(
            admin_sessions.get_ref(),
            repository.get_ref(),
            &request,
            q,
        )
        .await,
    )
}

pub(crate) fn parse_access_request_status(
    q: &HashMap<String, String>,
) -> Result<Option<nazo_identity::AccessRequestStatus>, HttpResponse> {
    (nazoauth::test_support::endpoints::admin::access_requests::parse_access_request_status(q))
        .map_err(nazo_http_actix::forward_response)
}

pub(crate) fn access_requests_response(
    page: i32,
    page_size: i32,
    total: i64,
    rows: Vec<nazo_identity::AccessRequest>,
) -> HttpResponse {
    nazo_http_actix::forward_response(
        nazoauth::test_support::endpoints::admin::access_requests::access_requests_response(
            page, page_size, total, rows,
        ),
    )
}

pub(crate) async fn admin_approve_access_request(
    admin_sessions: Data<AdminSessionHandles>,
    dependencies: ApprovalDependencies,
    req: HttpRequest,
    path: actix_web::web::Path<Uuid>,
    Json(payload): Json<CreateClientRequest>,
) -> HttpResponse {
    let request = crate::test_support::transport::request_head(&req);
    nazo_http_actix::forward_response(
        nazoauth::test_support::endpoints::admin::access_requests::admin_approve_access_request(
            &crate::adapters::audit::TenantSecurityAudit::new(
                nazo_identity::TenantId::new(nazo_identity::DEFAULT_TENANT_ID).unwrap(),
            ),
            admin_sessions.get_ref(),
            (
                dependencies.0.get_ref(),
                dependencies.1.get_ref(),
                dependencies.2.get_ref(),
                dependencies.3.get_ref(),
                dependencies.4.get_ref(),
            ),
            &request,
            path.into_inner(),
            payload,
        )
        .await,
    )
}

pub(crate) async fn admin_reject_access_request(
    admin_sessions: Data<AdminSessionHandles>,
    repository: Data<dyn AdminAccessRequestStore>,
    req: HttpRequest,
    path: actix_web::web::Path<Uuid>,
    Json(payload): Json<RejectAccessRequest>,
) -> HttpResponse {
    let request = crate::test_support::transport::request_head(&req);
    nazo_http_actix::forward_response(
        nazoauth::test_support::endpoints::admin::access_requests::admin_reject_access_request(
            &crate::adapters::audit::TenantSecurityAudit::new(
                nazo_identity::TenantId::new(nazo_identity::DEFAULT_TENANT_ID).unwrap(),
            ),
            admin_sessions.get_ref(),
            repository.get_ref(),
            &request,
            path.into_inner(),
            payload,
        )
        .await,
    )
}

pub(crate) fn access_request_already_approved_response() -> HttpResponse {
    nazo_http_actix::forward_response(nazoauth::test_support::endpoints::admin::access_requests::access_request_already_approved_response())
}

pub(crate) fn access_request_approval_error_response(
    error: &nazo_identity::ports::RepositoryError,
) -> Option<HttpResponse> {
    (nazoauth::test_support::endpoints::admin::access_requests::access_request_approval_error_response(error)).map(nazo_http_actix::forward_response)
}

pub(crate) fn access_request_already_rejected_response() -> HttpResponse {
    nazo_http_actix::forward_response(nazoauth::test_support::endpoints::admin::access_requests::access_request_already_rejected_response())
}

type ApprovalDependencies = (
    Data<dyn AdminAccessRequestStore>,
    Data<dyn DeliveryStorePort>,
    Data<ServerAdminClientService>,
    Data<AdminAccessRequestConfig>,
    Data<ClientIpConfig>,
);
