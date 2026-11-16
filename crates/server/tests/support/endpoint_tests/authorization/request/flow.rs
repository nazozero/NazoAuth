// Native regression module: reexports the actual neutral implementation.

use super::super::AuthorizationEndpoint;
use actix_web::{
    HttpRequest, HttpResponse,
    web::{Bytes, Data},
};

pub(crate) async fn authorize_get(
    endpoint: Data<AuthorizationEndpoint>,
    req: HttpRequest,
) -> HttpResponse {
    let request = crate::test_support::transport::request_head(&req);
    nazo_http_actix::forward_response(
        nazoauth::test_support::endpoints::authorization::request::flow::authorize_get(
            endpoint.get_ref(),
            &request,
        )
        .await,
    )
}

pub(crate) async fn authorize_post(
    endpoint: Data<AuthorizationEndpoint>,
    req: HttpRequest,
    body: Bytes,
) -> HttpResponse {
    let request = crate::test_support::transport::request_head(&req);
    nazo_http_actix::forward_response(
        nazoauth::test_support::endpoints::authorization::request::flow::authorize_post(
            endpoint.get_ref(),
            &request,
            &body,
        )
        .await,
    )
}
