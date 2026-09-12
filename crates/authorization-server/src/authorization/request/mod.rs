pub(super) mod flow;
mod parameters;
mod policy;
mod prompt_none;
mod pushed;
mod reauth;
mod response;
use super::{
    AuthorizationOutcome, AuthorizationRequestContext, apply_request_object_with_context,
    is_pushed_authorization_request_uri, unverified_request_object_client_id,
};
pub(super) use parameters::authorization_duplicate_parameters;
use parameters::{
    authorization_login_query, authorization_login_url_for_frontend, claim_request_names,
    outer_request_uri_parameters_match_pushed, preserve_verified_dpop_binding,
    reauth_nonce_parameter,
};
use policy::{credential_configuration_ids, runtime_authorization_capability_error};
use prompt_none::{
    issue_authorization_code_without_interaction_with_context,
    user_grant_covers_requested_scopes_with_context,
};
use pushed::{
    PushedAuthorizationRequestConsumeError, authorization_oauth_error_redirect,
    consume_pushed_authorization_request_with_context,
};
use reauth::{authorization_login_url_with_context, consume_reauth_nonce_with_context};
use response::{
    AuthorizationResponseClientPolicy, AuthorizationResponseRedirect,
    authorization_response_redirect_with_context,
};

#[cfg(test)]
#[path = "../../../tests/unit/authorization/request.rs"]
mod tests;
