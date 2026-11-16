// Native regression module: reexports the actual neutral implementation.
#[path = "../../../unit/http/authorization/consent.rs"]
pub(crate) mod tests;

use crate::http::sessions::SessionHttpConfig;
use actix_web::web::{Data, Query};
use actix_web::{HttpRequest, HttpResponse};
use nazo_auth::ConsentPayload;
use nazo_oauth_server::authorization::AuthorizationApplication;
use std::collections::HashMap;

pub(crate) fn consent_page_response(
    payload: ConsentPayload,
    csrf_token: Option<String>,
) -> HttpResponse {
    nazo_http_actix::forward_response(
        nazoauth::test_support::endpoints::authorization::consent::consent_page_response(
            payload, csrf_token,
        ),
    )
}

pub(crate) async fn authorize_consent_with_context(
    application: &AuthorizationApplication,
    session_http: &SessionHttpConfig,
    req: HttpRequest,
    q: HashMap<String, String>,
) -> HttpResponse {
    let request = crate::test_support::transport::request_head(&req);
    nazo_http_actix::forward_response(
        nazoauth::test_support::endpoints::authorization::consent::authorize_consent_with_context(
            application,
            session_http,
            &request,
            q,
        )
        .await,
    )
}
