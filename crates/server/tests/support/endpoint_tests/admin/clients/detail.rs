// Native regression module: reexports the actual neutral implementation.
#[path = "../../../../unit/http/admin/clients/detail.rs"]
pub(crate) mod tests;

use super::ServerAdminClientService;
use crate::http::sessions::AdminSessionHandles;
use actix_web::web::Data;
use actix_web::{HttpRequest, HttpResponse};

pub(crate) async fn admin_get_client(
    admin_sessions: Data<AdminSessionHandles>,
    service: Data<ServerAdminClientService>,
    req: HttpRequest,
    path: actix_web::web::Path<String>,
) -> HttpResponse {
    let request = crate::test_support::transport::request_head(&req);
    nazo_http_actix::forward_response(
        nazoauth::test_support::endpoints::admin::clients::detail::admin_get_client(
            admin_sessions.get_ref(),
            service.get_ref(),
            &request,
            path.into_inner(),
        )
        .await,
    )
}

pub(crate) fn client_detail_response(client: nazo_auth::OAuthClient) -> HttpResponse {
    nazo_http_actix::forward_response(
        nazoauth::test_support::endpoints::admin::clients::detail::client_detail_response(client),
    )
}

pub(crate) fn client_detail_not_found_response() -> HttpResponse {
    nazo_http_actix::forward_response(
        nazoauth::test_support::endpoints::admin::clients::detail::client_detail_not_found_response(
        ),
    )
}
