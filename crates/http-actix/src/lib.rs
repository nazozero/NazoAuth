//! Actix transport adapters and protocol response presentation.
//!
//! This crate owns HTTP-framework details. Domain policy and infrastructure
//! access remain in their focused crates.

mod presenter;
mod request_context;

pub use presenter::{
    OAuthJsonErrorFields, authorization_error_response, bearer_challenge, bytes_response,
    empty_response, empty_response_no_store, is_oauth_error_description_byte, json_response,
    json_response_no_store, json_response_status, json_response_status_no_store,
    oauth_bearer_error, oauth_error, oauth_error_description, oauth_token_error, redirect_found,
};
pub use request_context::RequestContext;
