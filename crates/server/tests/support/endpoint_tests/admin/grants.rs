// Native regression module: reexports the actual neutral implementation.
pub(crate) use nazoauth::test_support::endpoints::admin::grants::*;
#[path = "../../../unit/http/admin/grants.rs"]
pub(crate) mod tests;

use crate::http::sessions::AdminSessionHandles;
use actix_web::http::StatusCode;
use actix_web::web::{Data, Json, Query};
use actix_web::{HttpRequest, HttpResponse};
use nazo_auth::{AdminGrantRepositoryPort, AdminGrantRevokeError, AdminGrantView};
use serde_json::json;
use std::collections::HashMap;
use uuid::Uuid;

pub(crate) async fn admin_grants(
    admin_sessions: Data<AdminSessionHandles>,
    grants: Data<dyn AdminGrantRepositoryPort>,
    req: HttpRequest,
    Query(q): Query<HashMap<String, String>>,
) -> HttpResponse {
    let request = crate::test_support::transport::request_head(&req);
    nazo_http_actix::forward_response(
        nazoauth::test_support::endpoints::admin::grants::admin_grants(
            admin_sessions.get_ref(),
            grants.get_ref(),
            &request,
            q,
        )
        .await,
    )
}

pub(crate) fn grants_list_response(
    page: i32,
    page_size: i32,
    total: i64,
    rows: Vec<AdminGrantView>,
) -> HttpResponse {
    nazo_http_actix::forward_response(
        nazoauth::test_support::endpoints::admin::grants::grants_list_response(
            page, page_size, total, rows,
        ),
    )
}

pub(crate) async fn admin_revoke_grant(
    admin_sessions: Data<AdminSessionHandles>,
    grants: Data<dyn AdminGrantRepositoryPort>,
    req: HttpRequest,
    Json(payload): Json<GrantRevokeRequest>,
) -> HttpResponse {
    let request = crate::test_support::transport::request_head(&req);
    nazo_http_actix::forward_response(
        nazoauth::test_support::endpoints::admin::grants::admin_revoke_grant(
            &crate::adapters::audit::TenantSecurityAudit::new(
                nazo_identity::TenantId::new(nazo_identity::DEFAULT_TENANT_ID).unwrap(),
            ),
            admin_sessions.get_ref(),
            grants.get_ref(),
            &request,
            payload,
        )
        .await,
    )
}

pub(crate) fn grant_revocation_response(
    revoked_refresh_tokens: usize,
    removed_grants: usize,
) -> HttpResponse {
    nazo_http_actix::forward_response(
        nazoauth::test_support::endpoints::admin::grants::grant_revocation_response(
            revoked_refresh_tokens,
            removed_grants,
        ),
    )
}
