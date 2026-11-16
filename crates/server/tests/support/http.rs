//! Thin transport adapters for the existing focused native tests.
pub(crate) use nazoauth::test_support::http::*;
#[path = "http_bridge/presenter.rs"]
mod presenter;
pub(crate) use presenter::{
    authorization_error_response, oauth_endpoint_error_response, oauth_error,
    pre_authorized_token_error_response, redirect_found, token_endpoint_success_response,
};
#[path = "http_bridge/dpop.rs"]
mod dpop;
pub(crate) use dpop::dpop_error_response;
#[path = "http_bridge/fapi_resource.rs"]
mod fapi_resource;
pub(crate) use fapi_resource::fapi_resource;
#[path = "http_bridge/form_post_response.rs"]
mod form_post_response;
pub(crate) use form_post_response::form_post_authorization_response;
#[path = "http_bridge/mfa_profile.rs"]
mod mfa_profile;
pub(crate) use mfa_profile::{mfa_backup_codes_regenerate, mfa_totp_confirm};
#[path = "http_bridge/passkey.rs"]
mod passkey;
pub(crate) use passkey::{
    passkey_delete, passkey_list, passkey_login_begin, passkey_login_finish,
    passkey_registration_begin, passkey_registration_finish,
};
#[path = "http_bridge/userinfo.rs"]
mod userinfo;
pub(crate) use userinfo::userinfo;

pub(crate) fn cookie_value(request: &actix_web::HttpRequest, name: &str) -> Option<String> {
    nazoauth::test_support::http::cookie_value(&super::transport::request_head(request), name)
}

pub(crate) fn client_ip_with_config(
    request: &actix_web::HttpRequest,
    config: &ClientIpConfig,
) -> String {
    nazoauth::test_support::http::client_ip_with_config(
        &super::transport::request_head(request),
        config,
    )
}
