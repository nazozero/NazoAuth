use super::*;
use actix_web::{
    HttpRequest, HttpResponse,
    web::{Data, Json, Path},
};
use uuid::Uuid;
pub(crate) async fn passkey_login_begin(
    endpoint: Data<PasskeyLoginEndpoint>,
    request: HttpRequest,
    payload: Result<Json<PasskeyLoginBeginRequest>, actix_web::Error>,
) -> HttpResponse {
    let request = crate::test_support::transport::request_head(&request);
    nazo_http_actix::forward_response(
        nazoauth::test_support::http::passkey_login_begin(
            endpoint.get_ref(),
            &request,
            payload
                .map(actix_web::web::Json::into_inner)
                .map_err(|_| ()),
        )
        .await,
    )
}

pub(crate) async fn passkey_login_finish(
    endpoint: Data<PasskeyLoginEndpoint>,
    request: HttpRequest,
    payload: Result<Json<PasskeyLoginFinishRequest>, actix_web::Error>,
) -> HttpResponse {
    let request = crate::test_support::transport::request_head(&request);
    nazo_http_actix::forward_response(
        nazoauth::test_support::http::passkey_login_finish(
            endpoint.get_ref(),
            &request,
            payload
                .map(actix_web::web::Json::into_inner)
                .map_err(|_| ()),
        )
        .await,
    )
}

pub(crate) async fn passkey_registration_begin(
    endpoint: Data<PasskeyProfileEndpoint>,
    request: HttpRequest,
    payload: Result<Json<PasskeyRegistrationBeginRequest>, actix_web::Error>,
) -> HttpResponse {
    let request = crate::test_support::transport::request_head(&request);
    nazo_http_actix::forward_response(
        nazoauth::test_support::http::passkey_registration_begin(
            endpoint.get_ref(),
            &request,
            payload
                .map(actix_web::web::Json::into_inner)
                .map_err(|_| ()),
        )
        .await,
    )
}

pub(crate) async fn passkey_registration_finish(
    endpoint: Data<PasskeyProfileEndpoint>,
    request: HttpRequest,
    payload: Result<Json<PasskeyRegistrationFinishRequest>, actix_web::Error>,
) -> HttpResponse {
    let request = crate::test_support::transport::request_head(&request);
    nazo_http_actix::forward_response(
        nazoauth::test_support::http::passkey_registration_finish(
            endpoint.get_ref(),
            &request,
            payload
                .map(actix_web::web::Json::into_inner)
                .map_err(|_| ()),
        )
        .await,
    )
}

pub(crate) async fn passkey_list(
    endpoint: Data<PasskeyProfileEndpoint>,
    request: HttpRequest,
) -> HttpResponse {
    let request = crate::test_support::transport::request_head(&request);
    nazo_http_actix::forward_response(
        nazoauth::test_support::http::passkey_list(endpoint.get_ref(), &request).await,
    )
}

pub(crate) async fn passkey_delete(
    endpoint: Data<PasskeyProfileEndpoint>,
    request: HttpRequest,
    path: Path<Uuid>,
) -> HttpResponse {
    let request = crate::test_support::transport::request_head(&request);
    nazo_http_actix::forward_response(
        nazoauth::test_support::http::passkey_delete(
            endpoint.get_ref(),
            &request,
            path.into_inner(),
        )
        .await,
    )
}
