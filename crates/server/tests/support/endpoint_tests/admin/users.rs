// Native regression module: reexports the actual neutral implementation.
pub(crate) use nazoauth::test_support::endpoints::admin::users::*;
#[path = "../../../unit/http/admin/users.rs"]
pub(crate) mod tests;

use crate::http::sessions::AdminSessionHandles;
use crate::test_support::http::ClientIpConfig;
use actix_web::http::StatusCode;
use actix_web::web::{Data, Json, Query};
use actix_web::{HttpRequest, HttpResponse};
use nazo_identity::{
    PublicAccount,
    ports::{AdminUserRepositoryPort, RegistrationAccountRepositoryPort},
};
use std::collections::HashMap;
use uuid::Uuid;

pub(crate) async fn admin_users(
    admin_sessions: Data<AdminSessionHandles>,
    users: Data<dyn AdminUserRepositoryPort>,
    req: HttpRequest,
    Query(q): Query<HashMap<String, String>>,
) -> HttpResponse {
    let request = crate::test_support::transport::request_head(&req);
    nazo_http_actix::forward_response(
        nazoauth::test_support::endpoints::admin::users::admin_users(
            admin_sessions.get_ref(),
            users.get_ref(),
            &request,
            q,
        )
        .await,
    )
}

pub(crate) fn admin_users_list_response(
    page: i32,
    page_size: i32,
    total: i64,
    user_rows: Vec<PublicAccount>,
) -> HttpResponse {
    nazo_http_actix::forward_response(
        nazoauth::test_support::endpoints::admin::users::admin_users_list_response(
            page, page_size, total, user_rows,
        ),
    )
}

// This focused fixture preserves the production endpoint's independent capabilities.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn system_set_tenant_admin(
    admin_sessions: Data<AdminSessionHandles>,
    users: Data<dyn AdminUserRepositoryPort>,
    registry: Data<crate::bootstrap::test_support::TenantRuntimeRegistry>,
    control_tenant: Data<nazo_identity::TenantId>,
    client_ip_config: Data<ClientIpConfig>,
    req: HttpRequest,
    path: actix_web::web::Path<(Uuid, Uuid)>,
    Json(payload): Json<SetTenantAdminRequest>,
) -> HttpResponse {
    let request = crate::test_support::transport::request_with_client_ip(&req, &client_ip_config);
    nazo_http_actix::forward_response(
        nazoauth::test_support::endpoints::admin::users::system_set_tenant_admin(
            &crate::adapters::audit::TenantSecurityAudit::new(
                nazo_identity::TenantId::new(nazo_identity::DEFAULT_TENANT_ID).unwrap(),
            ),
            admin_sessions.get_ref(),
            users.get_ref(),
            registry.availability().as_ref(),
            *control_tenant.get_ref(),
            client_ip_config.get_ref(),
            &request,
            path.into_inner(),
            payload,
        )
        .await,
    )
}

pub(crate) async fn admin_create_user(
    admin_sessions: Data<AdminSessionHandles>,
    accounts: Data<dyn RegistrationAccountRepositoryPort>,
    client_ip_config: Data<ClientIpConfig>,
    req: HttpRequest,
    Json(payload): Json<CreateUserRequest>,
) -> HttpResponse {
    let request = crate::test_support::transport::request_with_client_ip(&req, &client_ip_config);
    nazo_http_actix::forward_response(
        nazoauth::test_support::endpoints::admin::users::admin_create_user(
            &crate::adapters::audit::TenantSecurityAudit::new(
                nazo_identity::TenantId::new(nazo_identity::DEFAULT_TENANT_ID).unwrap(),
            ),
            &crate::bootstrap::RegistrationSecretHasher,
            admin_sessions.get_ref(),
            accounts.get_ref(),
            client_ip_config.get_ref(),
            &request,
            payload,
        )
        .await,
    )
}

pub(crate) async fn admin_patch_user(
    admin_sessions: Data<AdminSessionHandles>,
    users: Data<dyn AdminUserRepositoryPort>,
    client_ip_config: Data<ClientIpConfig>,
    req: HttpRequest,
    path: actix_web::web::Path<Uuid>,
    Json(payload): Json<PatchUserRequest>,
) -> HttpResponse {
    let request = crate::test_support::transport::request_with_client_ip(&req, &client_ip_config);
    nazo_http_actix::forward_response(
        nazoauth::test_support::endpoints::admin::users::admin_patch_user(
            &crate::adapters::audit::TenantSecurityAudit::new(
                nazo_identity::TenantId::new(nazo_identity::DEFAULT_TENANT_ID).unwrap(),
            ),
            admin_sessions.get_ref(),
            users.get_ref(),
            client_ip_config.get_ref(),
            &request,
            path.into_inner(),
            payload,
        )
        .await,
    )
}

pub(crate) fn patch_user_validation_error(payload: &PatchUserRequest) -> Option<HttpResponse> {
    (nazoauth::test_support::endpoints::admin::users::patch_user_validation_error(payload))
        .map(nazo_http_actix::forward_response)
}
