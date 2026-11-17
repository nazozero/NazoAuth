// Native regression module: reexports the actual neutral implementation.
#[path = "../../../../unit/http/admin/clients/list.rs"]
pub(crate) mod tests;

use super::ServerAdminClientService;
use crate::http::sessions::AdminSessionHandles;
use actix_web::web::{Data, Query};
use actix_web::{HttpRequest, HttpResponse};
use std::collections::HashMap;

pub(crate) async fn admin_clients(
    admin_sessions: Data<AdminSessionHandles>,
    service: Data<ServerAdminClientService>,
    req: HttpRequest,
    Query(query): Query<HashMap<String, String>>,
) -> HttpResponse {
    let request = crate::test_support::transport::request_head(&req);
    nazo_http_actix::forward_response(
        nazoauth::test_support::endpoints::admin::clients::list::admin_clients(
            admin_sessions.get_ref(),
            service.get_ref(),
            &request,
            query,
        )
        .await,
    )
}

pub(crate) fn clients_list_response(
    total: i64,
    page: i32,
    page_size: i32,
    clients: Vec<nazo_auth::OAuthClient>,
) -> HttpResponse {
    nazo_http_actix::forward_response(
        nazoauth::test_support::endpoints::admin::clients::list::clients_list_response(
            total, page, page_size, clients,
        ),
    )
}
