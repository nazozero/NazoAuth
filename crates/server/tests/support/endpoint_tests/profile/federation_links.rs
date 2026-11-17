// Native regression module: reexports the actual neutral implementation.
pub(crate) use nazoauth::test_support::endpoints::profile::federation_links::*;
#[path = "../../../unit/http/profile/federation_links.rs"]
pub(crate) mod tests;

use crate::http::sessions::SessionProfileHandles;
use actix_web::http::StatusCode;
use actix_web::web::Data;
use actix_web::web::Path;
use actix_web::{HttpRequest, HttpResponse};
use uuid::Uuid;

pub(crate) async fn unlink_my_federation_link(
    sessions: Data<SessionProfileHandles>,
    federation: Data<nazo_oauth_server::services::FederationProfileService>,
    req: HttpRequest,
    path: Path<Uuid>,
) -> HttpResponse {
    let request = crate::test_support::transport::request_head(&req);
    nazo_http_actix::forward_response(
        nazoauth::test_support::endpoints::profile::federation_links::unlink_my_federation_link(
            sessions.get_ref(),
            federation.get_ref(),
            &request,
            path.into_inner(),
        )
        .await,
    )
}
