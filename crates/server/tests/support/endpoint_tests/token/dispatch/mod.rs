// Native regression module: reexports the actual neutral implementation.
pub(crate) use nazoauth::test_support::endpoints::token::dispatch::*;
#[path = "../../../../unit/http/token/dispatch.rs"]
pub(crate) mod tests;

use crate::test_support::http::ClientIpConfig;
use actix_web::{
    HttpRequest, HttpResponse,
    web::{Bytes, Data},
};
use nazo_oauth_server::token::dispatch::TokenEndpointHandles;

pub(crate) async fn token_with_service(
    handles: Data<TokenEndpointHandles>,
    client_ip: Data<ClientIpConfig>,
    req: HttpRequest,
    body: Bytes,
) -> HttpResponse {
    let request = crate::test_support::transport::request_with_client_ip(&req, &client_ip);
    nazo_http_actix::forward_response(
        nazoauth::test_support::endpoints::token::dispatch::token_with_service(
            handles.get_ref(),
            client_ip.get_ref(),
            &request,
            &body,
        )
        .await,
    )
}
