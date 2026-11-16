use super::*;
use actix_web::{
    HttpRequest, HttpResponse,
    web::{Bytes, Data},
};
pub(crate) async fn fapi_resource(
    endpoint: Data<FapiResourceEndpoint>,
    request: HttpRequest,
    body: Bytes,
) -> HttpResponse {
    let request = crate::test_support::transport::request_head(&request);
    nazo_http_actix::forward_response(
        nazoauth::test_support::http::fapi_resource(endpoint.get_ref(), &request, &body).await,
    )
}
