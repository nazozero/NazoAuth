// Native regression module: reexports the actual neutral implementation.
pub(crate) use nazoauth::test_support::endpoints::profile::access_requests::*;
#[path = "../../../unit/http/profile/access_requests.rs"]
pub(crate) mod tests;

use crate::http::sessions::SessionProfileHandles;
use actix_web::http::StatusCode;
use actix_web::web::{Data, Json};
use actix_web::{HttpRequest, HttpResponse};

pub(crate) async fn my_access_requests(
    sessions: Data<SessionProfileHandles>,
    service: Data<nazo_oauth_server::services::ClientAccessProfileService>,
    req: HttpRequest,
) -> HttpResponse {
    let request = crate::test_support::transport::request_head(&req);
    nazo_http_actix::forward_response(
        nazoauth::test_support::endpoints::profile::access_requests::my_access_requests(
            sessions.get_ref(),
            service.get_ref(),
            &request,
        )
        .await,
    )
}

pub(crate) fn access_request_items_response(items: Vec<UserAccessRequest>) -> HttpResponse {
    nazo_http_actix::forward_response(
        nazoauth::test_support::endpoints::profile::access_requests::access_request_items_response(
            items,
        ),
    )
}

pub(crate) async fn create_access_request(
    sessions: Data<SessionProfileHandles>,
    service: Data<nazo_oauth_server::services::ClientAccessProfileService>,
    req: HttpRequest,
    Json(payload): Json<CreateAccessRequest>,
) -> HttpResponse {
    let request = crate::test_support::transport::request_head(&req);
    nazo_http_actix::forward_response(
        nazoauth::test_support::endpoints::profile::access_requests::create_access_request(
            sessions.get_ref(),
            service.get_ref(),
            &request,
            payload,
        )
        .await,
    )
}

pub(crate) fn create_access_request_response(row: nazo_identity::AccessRequest) -> HttpResponse {
    nazo_http_actix::forward_response(
        nazoauth::test_support::endpoints::profile::access_requests::create_access_request_response(
            row,
        ),
    )
}
