//! Actix transport adapters and protocol response presentation.
//!
//! This crate owns HTTP-framework details. Domain policy and infrastructure
//! access remain in their focused crates.

mod cookies;
mod cors;
mod csrf;
mod extract;
mod fapi_resource;
mod metadata;
mod middleware;
mod presenter;
mod request_context;
mod scim;
mod token_forms;

pub use cookies::{clear_cookie, cookie_value, make_cookie, with_cookie_headers};
pub use cors::{
    cors_admin, cors_auth_api, cors_browser_token_management, cors_browser_userinfo, cors_scim,
    cors_well_known,
};
pub use csrf::{csrf_error, has_valid_csrf_token_for_cookies};
pub use extract::{
    AccessTokenAuthScheme, ResourceAccessToken, authorization_access_token, mfa_json_config,
    mfa_method_not_allowed, mfa_options, request_uses_form_urlencoded, resource_access_token,
};
pub use fapi_resource::{
    FapiAuthorizationError, FapiFuture, FapiHttpMessageSignatures, FapiMtlsThumbprintResolver,
    FapiResourceAuthorizer, FapiResourceEndpoint, FapiResponseSignature,
    FapiSignatureOperationError, FapiSignatureVerificationError, fapi_resource,
};
pub use metadata::{
    MetadataEndpointConfig, MetadataHandles, MetadataSnapshot, MetadataSnapshotSource, discovery,
    jwks, oauth_authorization_server_metadata, oauth_protected_resource_metadata,
};
pub use middleware::{apply_security_headers, security_headers};
pub use presenter::{
    OAuthJsonErrorFields, authorization_error_response, bearer_challenge, bytes_response,
    empty_response, empty_response_no_store, is_oauth_error_description_byte, json_response,
    json_response_no_store, json_response_status, json_response_status_no_store,
    oauth_bearer_error, oauth_error, oauth_error_description, oauth_token_error, redirect_found,
};
pub use request_context::RequestContext;
pub use scim::{
    ScimAuthorizationError, ScimAuthorizedRequest, ScimBootstrapPasswordProvider,
    ScimCursorProtector, ScimDependencyError, ScimEndpoint, ScimFuture, ScimRequestAuthorizer,
    scim_create_user, scim_delete_user, scim_get_user, scim_list_users, scim_patch_user,
    scim_replace_user, scim_resource_types, scim_schemas, scim_service_provider_config,
};
pub use token_forms::{
    TokenForm, TokenFormError, TokenManagementFormError, TokenOnlyForm, parse_token_form,
    parse_token_management_form, token_management_form_error,
    token_management_has_conflicting_client_auth, token_management_oauth_error,
};
