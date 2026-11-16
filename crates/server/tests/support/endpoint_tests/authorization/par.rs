// Native regression module: reexports the actual neutral implementation.
pub(crate) use nazoauth::test_support::endpoints::authorization::par::*;
#[path = "../../../unit/http/authorization/par.rs"]
pub(crate) mod tests;

use super::AuthorizationEndpoint;
use actix_web::{
    HttpRequest, HttpResponse,
    http::{StatusCode, header},
    web::{Bytes, Data},
};
use nazo_auth::encode_resource_indicators;
use nazo_oauth_server::contracts::oauth_error::OAuthEndpointError;
use std::collections::HashMap;

pub(crate) async fn par(
    endpoint: Data<AuthorizationEndpoint>,
    req: HttpRequest,
    body: Bytes,
) -> HttpResponse {
    let request = crate::test_support::transport::request_with_client_ip(&req, &endpoint.client_ip);
    nazo_http_actix::forward_response(
        nazoauth::test_support::endpoints::authorization::par::par(
            endpoint.get_ref(),
            &request,
            &body,
        )
        .await,
    )
}
