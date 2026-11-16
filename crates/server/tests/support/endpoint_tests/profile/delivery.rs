// Native regression module: reexports the actual neutral implementation.
pub(crate) use nazoauth::test_support::endpoints::profile::delivery::*;
#[path = "../../../unit/http/profile/delivery.rs"]
pub(crate) mod tests;

use crate::http::sessions::SessionProfileHandles;
use actix_web::http::StatusCode;
use actix_web::web::{Data, Json};
use actix_web::{HttpRequest, HttpResponse};
use serde_json::Value;

pub(crate) async fn access_delivery(
    sessions: Data<SessionProfileHandles>,
    service: Data<nazo_oauth_server::services::ClientAccessProfileService>,
    req: HttpRequest,
    Json(payload): Json<AccessDeliveryRequest>,
) -> HttpResponse {
    let request = crate::test_support::transport::request_head(&req);
    nazo_http_actix::forward_response(
        nazoauth::test_support::endpoints::profile::delivery::access_delivery(
            sessions.get_ref(),
            service.get_ref(),
            &request,
            payload,
        )
        .await,
    )
}

pub(crate) fn delivery_value_response(value: Value) -> HttpResponse {
    nazo_http_actix::forward_response(
        nazoauth::test_support::endpoints::profile::delivery::delivery_value_response(value),
    )
}
