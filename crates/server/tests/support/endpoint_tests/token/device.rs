// Native regression module: reexports the actual neutral implementation.
pub(crate) use nazoauth::test_support::endpoints::token::device::*;
#[path = "../../../unit/http/token/device.rs"]
pub(crate) mod tests;

use super::device_config::DeviceHttpConfig;

use crate::http::sessions::SessionProfileHandles;
use actix_web::{
    HttpRequest, HttpResponse,
    http::{
        StatusCode,
        header::{self},
    },
    web::{Bytes, Data, Form, Query},
};
use nazo_auth::DeviceAuthorizationPayload;
use nazo_oauth_server::token::device::DeviceDecisionHandles;
use std::collections::HashMap;

pub(crate) async fn device_authorization(
    handles: Data<DeviceDecisionHandles>,
    config: Data<DeviceHttpConfig>,
    req: HttpRequest,
    body: Bytes,
) -> HttpResponse {
    let request = crate::test_support::transport::request_head(&req);
    nazo_http_actix::forward_response(
        nazoauth::test_support::endpoints::token::device::device_authorization(
            handles.get_ref(),
            config.get_ref(),
            &request,
            &body,
        )
        .await,
    )
}

pub(crate) async fn device_verification_page(
    handles: Data<DeviceDecisionHandles>,
    config: Data<DeviceHttpConfig>,
    Query(query): Query<HashMap<String, String>>,
) -> HttpResponse {
    nazo_http_actix::forward_response(
        nazoauth::test_support::endpoints::token::device::device_verification_page(
            handles.get_ref(),
            config.get_ref(),
            query,
        )
        .await,
    )
}

pub(crate) async fn device_verification(
    handles: Data<DeviceDecisionHandles>,
    sessions: Data<SessionProfileHandles>,
    req: HttpRequest,
    Query(query): Query<HashMap<String, String>>,
) -> HttpResponse {
    let request = crate::test_support::transport::request_head(&req);
    nazo_http_actix::forward_response(
        nazoauth::test_support::endpoints::token::device::device_verification(
            handles.get_ref(),
            sessions.get_ref(),
            &request,
            query,
        )
        .await,
    )
}

pub(crate) async fn device_decision(
    handles: Data<DeviceDecisionHandles>,
    sessions: Data<SessionProfileHandles>,
    config: Data<DeviceHttpConfig>,
    req: HttpRequest,
    Form(form): Form<DeviceDecisionForm>,
) -> HttpResponse {
    let request = crate::test_support::transport::request_head(&req);
    nazo_http_actix::forward_response(
        nazoauth::test_support::endpoints::token::device::device_decision(
            handles.get_ref(),
            sessions.get_ref(),
            config.get_ref(),
            &request,
            form,
        )
        .await,
    )
}

pub(crate) fn redirect_to_device_verification_ui(
    config: &DeviceHttpConfig,
    user_code: &str,
) -> HttpResponse {
    nazo_http_actix::forward_response(
        nazoauth::test_support::endpoints::token::device::redirect_to_device_verification_ui(
            config, user_code,
        ),
    )
}
