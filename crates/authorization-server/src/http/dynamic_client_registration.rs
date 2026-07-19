//! Test-only route adapters for the disabled dynamic-registration contract.
//!
//! Production requests use `nazo_http_actix::DynamicRegistrationEndpoint`.

use actix_web::{HttpResponse, http::StatusCode, web};

use crate::domain::DynamicRegistrationHandles;

fn disabled_response(handles: &DynamicRegistrationHandles) -> HttpResponse {
    debug_assert!(!handles.accepts_new_requests());
    HttpResponse::build(StatusCode::NOT_FOUND).finish()
}

pub(crate) async fn dynamic_client_registration(
    handles: web::Data<DynamicRegistrationHandles>,
) -> HttpResponse {
    disabled_response(&handles)
}

pub(crate) async fn client_configuration_get(
    handles: web::Data<DynamicRegistrationHandles>,
) -> HttpResponse {
    disabled_response(&handles)
}

pub(crate) async fn client_configuration_put(
    handles: web::Data<DynamicRegistrationHandles>,
) -> HttpResponse {
    disabled_response(&handles)
}

pub(crate) async fn client_configuration_delete(
    handles: web::Data<DynamicRegistrationHandles>,
) -> HttpResponse {
    disabled_response(&handles)
}
