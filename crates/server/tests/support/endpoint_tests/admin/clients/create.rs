// Native regression module: reexports the actual neutral implementation.
#[path = "../../../../unit/http/admin/clients/create.rs"]
pub(crate) mod tests;

use actix_web::HttpResponse;
use nazo_auth::AdminClientError;

pub(crate) fn create_error_response(error: AdminClientError) -> HttpResponse {
    nazo_http_actix::forward_response(
        nazoauth::test_support::endpoints::admin::clients::create::create_error_response(error),
    )
}
