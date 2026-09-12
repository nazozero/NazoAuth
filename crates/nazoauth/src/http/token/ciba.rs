//! CIBA transport parsing and presentation.
use super::client_auth_request_facts;
use crate::adapters::security::has_basic_authorization_scheme;
use actix_web::{
    HttpRequest, HttpResponse,
    http::StatusCode,
    web::{Data, Payload},
};
use futures_util::StreamExt;
use nazo_http_actix::{
    ClientIpConfig, client_ip_with_config, empty_response, json_response_no_store, oauth_error,
    request_uses_form_urlencoded,
};
use nazo_oauth_server::{
    contracts::ciba::BackchannelAuthenticationForm, token::ciba::parse_requested_expiry_string,
};
use serde_json::json;
use std::collections::HashSet;
#[path = "ciba/backchannel.rs"]
mod backchannel;
#[path = "ciba/decision.rs"]
mod decision;
mod request;
mod state;
pub(crate) use backchannel::backchannel_authentication;
pub(crate) use decision::{ciba_decision, ciba_verification, ciba_verification_page};
use request::parse_backchannel_authentication_form;
pub(crate) use state::ciba_config;
#[cfg(test)]
#[path = "../../../tests/unit/http/token/ciba/state.rs"]
mod state_tests;
#[cfg(test)]
#[path = "../../../tests/unit/http/token/ciba.rs"]
mod tests;
