// Native regression module: reexports the actual neutral implementation.
pub(crate) use nazoauth::test_support::endpoints::admin::mtls_trust::*;
#[path = "../../../unit/http/admin/mtls_trust.rs"]
pub(crate) mod tests;

use crate::http::sessions::AdminSessionHandles;
use actix_web::{
    HttpRequest, HttpResponse,
    web::{Data, Json, Path, Query},
};
use nazo_oauth_server::services::MtlsTrustAnchorService;
use std::collections::HashMap;
use uuid::Uuid;

pub(crate) async fn admin_mtls_trust_requests(
    sessions: Data<AdminSessionHandles>,
    service: Data<MtlsTrustAnchorService>,
    req: HttpRequest,
    Query(query): Query<HashMap<String, String>>,
) -> HttpResponse {
    let request = crate::test_support::transport::request_head(&req);
    nazo_http_actix::forward_response(
        nazoauth::test_support::endpoints::admin::mtls_trust::admin_mtls_trust_requests(
            sessions.get_ref(),
            service.get_ref(),
            &request,
            query,
        )
        .await,
    )
}

pub(crate) async fn admin_approve_mtls_trust_request(
    sessions: Data<AdminSessionHandles>,
    service: Data<MtlsTrustAnchorService>,
    req: HttpRequest,
    path: Path<Uuid>,
    Json(decision): Json<TrustDecision>,
) -> HttpResponse {
    let request = crate::test_support::transport::request_head(&req);
    nazo_http_actix::forward_response(
        nazoauth::test_support::endpoints::admin::mtls_trust::admin_approve_mtls_trust_request(
            &crate::adapters::audit::TenantSecurityAudit::new(
                nazo_identity::TenantId::new(nazo_identity::DEFAULT_TENANT_ID).unwrap(),
            ),
            sessions.get_ref(),
            service.get_ref(),
            &request,
            path.into_inner(),
            decision,
        )
        .await,
    )
}

pub(crate) async fn admin_reject_mtls_trust_request(
    sessions: Data<AdminSessionHandles>,
    service: Data<MtlsTrustAnchorService>,
    req: HttpRequest,
    path: Path<Uuid>,
    Json(decision): Json<TrustDecision>,
) -> HttpResponse {
    let request = crate::test_support::transport::request_head(&req);
    nazo_http_actix::forward_response(
        nazoauth::test_support::endpoints::admin::mtls_trust::admin_reject_mtls_trust_request(
            &crate::adapters::audit::TenantSecurityAudit::new(
                nazo_identity::TenantId::new(nazo_identity::DEFAULT_TENANT_ID).unwrap(),
            ),
            sessions.get_ref(),
            service.get_ref(),
            &request,
            path.into_inner(),
            decision,
        )
        .await,
    )
}

pub(crate) fn normalized_decision_note(
    note: Option<String>,
    approve: bool,
) -> Result<Option<String>, HttpResponse> {
    (nazoauth::test_support::endpoints::admin::mtls_trust::normalized_decision_note(note, approve))
        .map_err(nazo_http_actix::forward_response)
}

pub(crate) async fn admin_revoke_mtls_trust_anchor(
    sessions: Data<AdminSessionHandles>,
    service: Data<MtlsTrustAnchorService>,
    req: HttpRequest,
    path: Path<Uuid>,
    Json(payload): Json<TrustRevocation>,
) -> HttpResponse {
    let request = crate::test_support::transport::request_head(&req);
    nazo_http_actix::forward_response(
        nazoauth::test_support::endpoints::admin::mtls_trust::admin_revoke_mtls_trust_anchor(
            &crate::adapters::audit::TenantSecurityAudit::new(
                nazo_identity::TenantId::new(nazo_identity::DEFAULT_TENANT_ID).unwrap(),
            ),
            sessions.get_ref(),
            service.get_ref(),
            &request,
            path.into_inner(),
            payload,
        )
        .await,
    )
}

pub(crate) async fn admin_mtls_trust_bundle(
    sessions: Data<AdminSessionHandles>,
    service: Data<MtlsTrustAnchorService>,
    req: HttpRequest,
) -> HttpResponse {
    let request = crate::test_support::transport::request_head(&req);
    nazo_http_actix::forward_response(
        nazoauth::test_support::endpoints::admin::mtls_trust::admin_mtls_trust_bundle(
            &crate::adapters::audit::TenantSecurityAudit::new(
                nazo_identity::TenantId::new(nazo_identity::DEFAULT_TENANT_ID).unwrap(),
            ),
            sessions.get_ref(),
            service.get_ref(),
            &request,
        )
        .await,
    )
}
