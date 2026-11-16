//! CIBA transport parsing and presentation.
use super::client_auth_request_facts;
use crate::endpoints::security::has_basic_authorization_scheme;
use crate::http::Request as HttpRequest;
use crate::http::Response as HttpResponse;
use http::StatusCode;

use crate::http::{
    ClientIpConfig, client_ip_with_config, empty_response, json_response_no_store, oauth_error,
    request_uses_form_urlencoded,
};
use nazo_oauth_server::{
    contracts::ciba::BackchannelAuthenticationForm, token::ciba::parse_requested_expiry_string,
};
use serde_json::json;
use std::collections::HashSet;
#[path = "ciba/backchannel.rs"]
pub mod backchannel;
#[path = "ciba/decision.rs"]
pub mod decision;
pub mod request;
pub mod state;
pub use backchannel::backchannel_authentication;
pub use decision::{ciba_decision, ciba_verification, ciba_verification_page};
use request::parse_backchannel_authentication_form;
pub use state::ciba_config;
