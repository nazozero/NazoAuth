//! OAuth/OIDC token 相关 HTTP handler 聚合模块。
// 子模块按 grant type 或端点职责拆分，路由层通过显式模块路径调用。
pub(crate) mod authorization_code;
pub(crate) mod ciba;
pub(crate) mod client_auth;
pub(crate) mod client_credentials;
pub(crate) mod device;
pub(crate) mod dispatch;
pub(crate) mod introspect;
pub(crate) mod issue;
pub(crate) mod jwt_bearer;
pub(crate) mod native_sso;
pub(crate) mod refresh;
pub(crate) mod revoke;
pub(crate) mod token_exchange;
pub(crate) mod userinfo;

use authorization_code::token_authorization_code_with_service;
use ciba::{CIBA_GRANT_TYPE, token_ciba};
use client_auth::{
    TokenManagementClientAuthError, authenticate_introspection_client,
    authenticate_revocation_client, consume_token_client_assertion,
    consume_token_management_client_assertion, token_management_auth_error,
    token_management_client_auth_error, verify_confidential_client,
};
use client_credentials::{client_credentials_issue_request, token_client_credentials};
use device::{DEVICE_CODE_GRANT_TYPE, token_device_code};
use dispatch::validate_token_request_profile;
#[cfg(test)]
use issue::access_token_subject_key;
use issue::{
    issue_token_response, mark_failed_authorization_code, revoke_issued_authorization_code_tokens,
    should_issue_refresh_token,
};
use jwt_bearer::{JWT_BEARER_GRANT_TYPE, token_jwt_bearer};
use native_sso::{
    native_sso_profile_requested, native_sso_requested, new_native_sso_token_binding,
    persist_native_sso_device_secret, token_native_sso_exchange,
};
pub(crate) use nazo_http_actix::{
    TokenForm, TokenFormError, parse_token_form, parse_token_management_form,
    token_management_form_error, token_management_has_conflicting_client_auth,
    token_management_oauth_error,
};
use refresh::token_refresh_with_service;
use token_exchange::{TOKEN_EXCHANGE_GRANT_TYPE, token_exchange};

pub(crate) type ServerTokenService = nazo_auth::TokenService<
    nazo_postgres::TokenIssuanceRepository,
    nazo_valkey::TokenIssuanceStateAdapter,
    nazo_key_management::KeyManager,
>;

#[cfg(test)]
use crate::support::CLIENT_ASSERTION_TYPE_JWT_BEARER;
#[cfg(test)]
use actix_web::{
    HttpRequest, HttpResponse,
    http::{
        StatusCode,
        header::{self, HeaderValue},
    },
    web::Bytes,
};
#[cfg(test)]
use nazo_http_actix::{TokenManagementFormError, TokenOnlyForm};
#[cfg(test)]
use serde_json::Value;

#[cfg(test)]
#[path = "../../tests/in_source/src/http/token/tests/forms.rs"]
mod forms_tests;
