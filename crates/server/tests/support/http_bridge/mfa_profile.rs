use super::*;
use actix_web::{
    HttpRequest, HttpResponse,
    web::{Data, Json},
};

pub(crate) async fn mfa_totp_confirm(
    endpoint: Data<MfaProfileEndpoint>,
    request: HttpRequest,
    Json(payload): Json<ConfirmTotpRequest>,
) -> HttpResponse {
    let request = crate::test_support::transport::request_head(&request);
    nazo_http_actix::forward_response(
        nazoauth::test_support::http::mfa_totp_confirm(endpoint.get_ref(), &request, payload).await,
    )
}

pub(crate) async fn mfa_backup_codes_regenerate(
    endpoint: Data<MfaProfileEndpoint>,
    request: HttpRequest,
    Json(payload): Json<MfaProtectedRequest>,
) -> HttpResponse {
    let request = crate::test_support::transport::request_head(&request);
    nazo_http_actix::forward_response(
        nazoauth::test_support::http::mfa_backup_codes_regenerate(
            endpoint.get_ref(),
            &request,
            payload,
        )
        .await,
    )
}
