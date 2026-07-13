//! OAuth/OIDC token 相关 HTTP handler 聚合模块。
// 子模块按 grant type 或端点职责拆分，路由层通过显式模块路径调用。
pub(crate) mod authorization_code;
pub(crate) mod ciba;
pub(crate) mod client_auth;
pub(crate) mod client_credentials;
pub(crate) mod device;
pub(crate) mod device_config;
pub(crate) mod device_issuance;
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
    TokenManagementClientAuthError, authenticate_introspection_client_with_dependencies,
    authenticate_revocation_client_with_dependencies, consume_token_client_assertion,
    token_management_auth_error, token_management_client_auth_error,
};
#[cfg(test)]
use client_credentials::client_credentials_issue_request;
use client_credentials::{
    client_credentials_issue_request_with_default_audience, token_client_credentials_with_service,
};
use device::DEVICE_CODE_GRANT_TYPE;
use device_issuance::token_device_code_with_service;
use dispatch::validate_token_request_profile;
#[cfg(test)]
use issue::access_token_subject_key;
#[cfg(test)]
use issue::issue_token_response;
use issue::{
    mark_failed_authorization_code, revoke_issued_authorization_code_tokens,
    should_issue_refresh_token,
};
use jwt_bearer::{JWT_BEARER_GRANT_TYPE, token_jwt_bearer_with_service};
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

#[cfg(test)]
mod lifecycle_boundary_tests {
    #[test]
    fn token_lifecycle_handlers_use_focused_dependencies() {
        for (name, source) in [
            ("introspection", include_str!("token/introspect.rs")),
            ("revocation", include_str!("token/revoke.rs")),
        ] {
            for forbidden in [
                "AppState",
                "nazo_postgres",
                "nazo_valkey",
                "diesel_db",
                "decode_access_claims",
                "TokenRepository::new",
                "OAuthClientRepository::new",
            ] {
                assert!(
                    !source.contains(forbidden),
                    "{name} handler reintroduced forbidden dependency {forbidden}"
                );
            }
        }
    }

    #[test]
    fn userinfo_transport_does_not_construct_storage_adapters() {
        let source = include_str!("token/userinfo.rs");
        assert!(source.contains("handles: Data<UserinfoHandles>"));
        for forbidden in [
            "Data<AppState>",
            "Settings",
            "KeyManager",
            "nazo_postgres",
            "nazo_valkey",
            "diesel_db",
            "TokenRepository::new",
            "OAuthClientRepository::new",
            "UserRepository::new",
            "TokenStateStore::new",
        ] {
            assert!(
                !source.contains(forbidden),
                "userinfo handler reintroduced forbidden dependency {forbidden}"
            );
        }
    }

    #[test]
    fn client_authentication_handlers_use_the_focused_authorization_boundary() {
        for (name, source) in [
            ("token", include_str!("token/dispatch.rs")),
            ("ciba", include_str!("token/ciba.rs")),
            ("device", include_str!("token/device.rs")),
            ("par", include_str!("authorization/par.rs")),
            ("introspection", include_str!("token/introspect.rs")),
            ("revocation", include_str!("token/revoke.rs")),
        ] {
            assert!(
                !source.contains("OAuthClientRepository::new"),
                "{name} reintroduced a direct PostgreSQL client-auth dependency"
            );
        }
        let auth_source = include_str!("token/client_auth.rs");
        for forbidden in [
            "match client.token_endpoint_auth_method.as_str()",
            ".expect(\"private_key_jwt",
            ".expect(\"secret-based client credentials",
            ".expect(\"mTLS client credentials",
        ] {
            assert!(
                !auth_source.contains(forbidden),
                "client authentication adapter reintroduced policy or panic: {forbidden}"
            );
        }
    }

    #[test]
    fn ciba_transport_uses_composition_root_handles() {
        let source = include_str!("token/ciba.rs");
        for forbidden in [
            "CibaStore::new",
            "OAuthClientRepository::new",
            "UserRepository::new",
            "state.diesel_db",
            "state.valkey_connection()",
        ] {
            assert!(
                !source.contains(forbidden),
                "CIBA transport reintroduced composition dependency {forbidden}"
            );
        }
        assert!(!source.contains(
            "pub(crate) async fn backchannel_authentication(\n    state: Data<AppState>"
        ));
        assert!(
            !source.contains("pub(crate) async fn ciba_verification(\n    state: Data<AppState>")
        );
    }

    #[test]
    fn shared_issuance_core_uses_typed_context_and_existing_service() {
        let source = include_str!("token/issue.rs");
        let core = source
            .split("pub(crate) async fn issue_token_response_with_service")
            .nth(1)
            .and_then(|source| source.split("#[cfg(test)]").next())
            .expect("issuance core must precede test-only compatibility code");
        for forbidden in [
            "AppState",
            "state.settings",
            "state.diesel_db",
            "state.valkey_connection",
            "TokenIssuanceRepository::new",
            "TokenIssuanceStateAdapter::new",
        ] {
            assert!(
                !core.contains(forbidden),
                "shared issuance core reintroduced {forbidden}"
            );
        }
    }

    #[test]
    fn device_transport_uses_focused_composition_root_dependencies() {
        let source = include_str!("token/device.rs");
        for forbidden in [
            "Data<AppState>",
            "Settings",
            "DeviceStore::new",
            "AuthorizationFlowRepository::new",
            "state.diesel_db",
            "state.valkey_connection()",
        ] {
            assert!(
                !source.contains(forbidden),
                "device transport reintroduced composition dependency {forbidden}"
            );
        }
        for required in [
            "Data<ServerDeviceGrantService>",
            "Data<DeviceHttpConfig>",
            "Data<SessionProfileHandles>",
            "Data<TokenManagementRequestLimiter>",
            "Data<ServerRuntimeModuleRegistry>",
        ] {
            assert!(
                source.contains(required),
                "device transport lost focused dependency {required}"
            );
        }
    }

    #[test]
    fn device_token_issuance_handoff_uses_focused_context_and_services() {
        let source = include_str!("token/device_issuance.rs");
        assert!(source.contains("device_service: &ServerDeviceGrantService"));
        assert!(source.contains("token_service: &ServerTokenService"));
        assert!(source.contains("issuance: &TokenIssuanceContext<'_>"));
        assert!(source.contains("issue_token_response_with_service"));
        assert!(source.contains("validate_dpop_proof_with_authorization_service"));
        assert!(source.contains("consume_token_client_assertion_with_authorization_service"));
        for forbidden in [
            "AppState",
            "Settings",
            "state.settings",
            "DeviceStore::new",
            "DeviceGrantService::new",
            "TokenIssuanceRepository::new",
            "TokenIssuanceStateAdapter::new",
            "nazo_postgres",
            "nazo_valkey",
        ] {
            assert!(
                !source.contains(forbidden),
                "device issuance handoff reintroduced direct infrastructure {forbidden}"
            );
        }
    }
}
