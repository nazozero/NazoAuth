//! Actix transport adapters and protocol response presentation.
//!
//! This crate owns HTTP-framework details. Domain policy and infrastructure
//! access remain in their focused crates.

mod authorization_decision;
#[cfg(test)]
#[path = "../tests/unit/authorization_request_object.rs"]
mod authorization_request_object_tests;
mod cookies;
mod cors;
mod csrf;
mod dpop;
mod dynamic_client_registration;
mod extract;
mod fapi_resource;
mod form_post_response;
mod local_registration;
mod metadata;
mod mfa_profile;
mod middleware;
mod oidc_logout;
mod passkey;
mod password_login;
mod presenter;
mod profile_account;
mod runtime_modules;
mod scim;
mod session;
mod session_management;
mod token_client_auth;
mod token_forms;
mod token_management;
mod userinfo;

pub use presenter::{oauth_endpoint_error_response, pre_authorized_token_error_response};

pub use authorization_decision::{
    AuthorizationDecisionEndpoint, AuthorizationDecisionForm, authorize_decision,
};
pub use cookies::{clear_cookie, cookie_value, make_cookie, with_cookie_headers};
pub use cors::{
    cors_admin, cors_admin_with_origin_predicate, cors_auth_api,
    cors_auth_api_with_origin_predicate, cors_browser_token_management,
    cors_browser_token_management_with_origin_predicate, cors_browser_userinfo,
    cors_browser_userinfo_with_origin_predicate, cors_scim, cors_scim_with_origin_predicate,
    cors_well_known, cors_well_known_with_origin_predicate,
};
pub use csrf::{csrf_error, has_valid_csrf_token_for_cookies};
pub use dpop::{dpop_error_response, dpop_proof_header, dpop_proof_present};
pub use dynamic_client_registration::{
    ClientIpConfig, ClientIpHeaderMode, ClientIpParseError, DynamicRegistrationClientStore,
    DynamicRegistrationDependencyError, DynamicRegistrationEndpoint, DynamicRegistrationFuture,
    IpCidr, client_configuration_delete, client_configuration_get, client_configuration_put,
    client_ip_with_config, client_ip_with_context, dynamic_client_registration,
    parse_forwarded_for_value, parse_trusted_proxy_cidrs, request_from_trusted_proxy_cidrs,
};
pub use extract::{
    ResourceAccessToken, authorization_access_token, mfa_json_config, mfa_method_not_allowed,
    mfa_options, request_uses_form_urlencoded, resource_access_token,
};
pub use fapi_resource::{FapiResourceEndpoint, fapi_resource};
pub use form_post_response::form_post_authorization_response;
pub use local_registration::{
    LocalRegistrationEndpoint, RegisterRequest, SendCodeRequest, register, send_code,
};
pub use metadata::{
    MetadataHandles, discovery, jwks, oauth_authorization_server_metadata,
    oauth_protected_resource_metadata,
};
pub use mfa_profile::{
    MfaProfileConfig, MfaProfileEndpoint, configure_mfa_challenge_route,
    configure_mfa_profile_routes, mfa_backup_codes_regenerate, mfa_disable, mfa_step_up,
    mfa_totp_begin, mfa_totp_confirm, mfa_verify,
};
pub use middleware::{apply_security_headers, security_headers};
pub use oidc_logout::{OidcLogoutConfig, OidcLogoutEndpoint, oidc_logout};
pub use passkey::{
    PasskeyLoginBeginRequest, PasskeyLoginConfig, PasskeyLoginEndpoint, PasskeyLoginFinishRequest,
    PasskeyProfileConfig, PasskeyProfileEndpoint, PasskeyRegistrationBeginRequest,
    PasskeyRegistrationFinishRequest, configure_passkey_login_routes,
    configure_passkey_profile_routes, passkey_delete, passkey_list, passkey_login_begin,
    passkey_login_finish, passkey_registration_begin, passkey_registration_finish,
};
pub use password_login::{PasswordLoginConfig, PasswordLoginEndpoint, login};
pub use presenter::{
    authorization_error_response, bearer_challenge, bytes_response, empty_response,
    empty_response_no_store, is_oauth_error_description_byte, json_response,
    json_response_no_store, json_response_status, json_response_status_no_store,
    oauth_bearer_error, oauth_error, oauth_error_description, oauth_token_error, redirect_found,
    redirect_see_other,
};
pub use profile_account::{
    ProfileAccountEndpoint, UpdateProfileRequest, profile_applications, profile_me, profile_update,
};
pub use runtime_modules::{
    RuntimeModuleAdminEndpoint, RuntimeModuleEventPageQuery, RuntimeModulePatch,
    admin_patch_runtime_module, admin_runtime_module_events, admin_runtime_modules,
};
pub use scim::{
    ScimEndpoint, scim_create_user, scim_delete_user, scim_get_user, scim_list_users,
    scim_patch_user, scim_poll_security_events, scim_replace_user, scim_resource_types,
    scim_schemas, scim_service_provider_config,
};
pub use session::{
    SessionCookieConfig, SessionLogoutEndpoint, login_required_response, logout_response,
    profile_logout, session_lookup_error_response,
};
pub use session_management::{
    CheckSessionStatusQuery, SessionManagementConfig, SessionManagementEndpoint,
    check_session_iframe, check_session_status,
};
pub use token_client_auth::{TokenClientAuthForm, token_client_auth_transport_facts};
pub use token_forms::{
    parse_token_form, parse_token_form_with_pre_authorized, parse_token_management_form,
    token_management_form_error, token_management_has_conflicting_client_auth,
    token_management_oauth_error,
};
pub use token_management::{
    TokenManagementEndpoint, TokenManagementRequestFactsExtractor, introspect, revoke,
};
pub use userinfo::{UserinfoEndpoint, userinfo};

pub mod mtls;
pub use mtls::MtlsThumbprintExtractor;

pub use presenter::token_endpoint_success_response;
