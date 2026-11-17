//! Framework-neutral HTTP protocol parsing and presentation.

pub type Request = http::Request<bytes::Bytes>;
pub type Response = http::Response<bytes::Bytes>;
mod request;
#[cfg(feature = "test-support")]
pub use presenter::no_store;
pub use presenter::{finish, json};
pub use request::{collect_route_body, validate_json_head, validate_route_body_head};
pub use request::{parse_form, parse_json, parse_json_limit, parse_path, parse_query};

mod authorization_decision;
#[cfg(test)]
#[path = "../../tests/unit/http/authorization_request_object.rs"]
mod authorization_request_object_tests;
mod cookies;
mod cors;
mod csrf;
mod dpop;
mod dynamic_client_registration;
mod extract;
mod fapi_resource;
mod form_post_response;
mod html;
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

pub use presenter::oauth_endpoint_error_response;

pub use authorization_decision::{AuthorizationDecisionEndpoint, authorize_decision};
pub use cookies::{clear_cookie, cookie_value, make_cookie, with_cookie_headers};
pub use cors::{CorsPolicy, apply_cors_headers, cors_preflight};
pub use csrf::{csrf_error, has_valid_csrf_token_for_cookies};
pub use dpop::{
    dpop_error_response, dpop_proof_header, dpop_proof_present, dpop_request_authority,
};
pub use dynamic_client_registration::{
    ClientIpConfig, ClientIpHeaderMode, ClientIpParseError, DynamicRegistrationEndpoint, IpCidr,
    client_configuration_delete, client_configuration_get, client_configuration_put,
    client_ip_with_config, client_ip_with_context, dynamic_client_registration,
    parse_trusted_proxy_cidrs, request_from_trusted_proxy_cidrs,
};
pub use extract::{
    ResourceAccessToken, mfa_method_not_allowed, mfa_options, parse_mfa_json,
    request_uses_form_urlencoded, resource_access_token,
};
pub use fapi_resource::{FapiResourceEndpoint, fapi_resource};
pub use form_post_response::form_post_authorization_response;
pub use local_registration::{LocalRegistrationEndpoint, register, send_code};
pub use metadata::{
    MetadataHandles, discovery, jwks, oauth_authorization_server_metadata,
    oauth_protected_resource_metadata,
};
pub use mfa_profile::{
    MfaProfileConfig, MfaProfileEndpoint, mfa_backup_codes_regenerate, mfa_disable, mfa_step_up,
    mfa_totp_begin, mfa_totp_confirm, mfa_verify,
};
pub use middleware::apply_security_headers;
pub use oidc_logout::{OidcLogoutConfig, OidcLogoutEndpoint, oidc_logout};
pub use passkey::{
    PasskeyLoginConfig, PasskeyLoginEndpoint, PasskeyProfileConfig, PasskeyProfileEndpoint,
    passkey_delete, passkey_list, passkey_login_begin, passkey_login_finish,
    passkey_registration_begin, passkey_registration_finish,
};
pub use password_login::{PasswordLoginConfig, PasswordLoginEndpoint, login};
pub use presenter::{
    authorization_error_response, bytes_response, empty_response, empty_response_no_store,
    json_response, json_response_no_store, json_response_status, json_response_status_no_store,
    oauth_bearer_error, oauth_error, oauth_token_error, redirect_found, redirect_see_other,
};
pub use profile_account::{
    ProfileAccountEndpoint, profile_applications, profile_me, profile_update,
};
pub use runtime_modules::{
    RuntimeModuleAdminEndpoint, admin_patch_runtime_module, admin_runtime_module_events,
    admin_runtime_modules,
};
pub use scim::{
    ScimEndpoint, scim_create_user, scim_delete_user, scim_get_user, scim_list_users,
    scim_patch_user, scim_poll_security_events, scim_replace_user, scim_resource_types,
    scim_schemas, scim_service_provider_config,
};
pub use session::{
    SessionCookieConfig, SessionLogoutEndpoint, login_required_response, profile_logout,
};
pub use session_management::{
    SessionManagementConfig, SessionManagementEndpoint, check_session_iframe, check_session_status,
};
pub use token_client_auth::{
    TokenClientAuthForm, basic_authorization_credentials, token_client_auth_transport_facts,
};
pub use token_forms::{
    parse_token_form_with_pre_authorized, parse_token_management_form, token_management_form_error,
    token_management_has_conflicting_client_auth, token_management_oauth_error,
};
pub use token_management::{
    TokenManagementEndpoint, TokenManagementRequestFactsExtractor, introspect, revoke,
};
pub use userinfo::{UserinfoEndpoint, userinfo};

pub mod mtls;
#[cfg(feature = "test-support")]
pub use mtls::MtlsThumbprintExtractor;

pub use presenter::token_endpoint_success_response;

#[cfg(test)]
#[path = "../../tests/transport/mod.rs"]
mod transport_tests;

#[cfg(feature = "test-support")]
pub use presenter::pre_authorized_token_error_response;

#[cfg(feature = "test-support")]
pub use dynamic_client_registration::{
    DynamicRegistrationClientStore, DynamicRegistrationDependencyError, DynamicRegistrationFuture,
};

#[cfg(feature = "test-support")]
pub use extract::authorization_access_token;

#[cfg(feature = "test-support")]
pub use local_registration::{RegisterRequest, SendCodeRequest};

#[cfg(feature = "test-support")]
pub use mfa_profile::{ConfirmTotpRequest, MfaChallengeRequest, MfaProtectedRequest};

#[cfg(feature = "test-support")]
pub use passkey::{
    PasskeyLoginBeginRequest, PasskeyLoginFinishRequest, PasskeyRegistrationBeginRequest,
    PasskeyRegistrationFinishRequest,
};

#[cfg(feature = "test-support")]
pub use profile_account::UpdateProfileRequest;

#[cfg(feature = "test-support")]
pub use runtime_modules::{RuntimeModuleEventPageQuery, RuntimeModulePatch};

#[cfg(feature = "test-support")]
pub use session::logout_response;

#[cfg(feature = "test-support")]
pub use session_management::CheckSessionStatusQuery;

#[cfg(any(test, feature = "test-support"))]
pub use authorization_decision::AuthorizationDecisionForm;

#[cfg(any(test, feature = "test-support"))]
pub use dynamic_client_registration::parse_forwarded_for_value;

#[cfg(any(test, feature = "test-support"))]
pub use presenter::{bearer_challenge, is_oauth_error_description_byte, oauth_error_description};

#[cfg(any(test, feature = "test-support"))]
pub use token_forms::parse_token_form;
