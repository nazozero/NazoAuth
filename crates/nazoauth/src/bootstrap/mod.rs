//! 应用启动入口。
// 负责组装配置、外部连接、共享状态和 Actix HTTP server。

mod authentication_services;
mod cors;
mod federation_services;
mod object_store;
mod observability;
mod passkey_services;
mod profile_services;
mod registration_services;
pub(crate) mod routes;
mod startup;
mod transport;
mod ui_release;
pub(crate) use authentication_services::{LoginPasswordVerifier, TracingAuthenticationAudit};
pub(crate) use federation_services::{FederationBootstrapPasswordHasher, TracingFederationAudit};
pub use object_store::{
    ServerAvatarObjectStoreBindings, ServerAvatarObjectStoreProvider, ServerAvatarStorageCapability,
};
pub(crate) use passkey_services::TracingPasskeyAudit;
pub(crate) use profile_services::AvatarProfileService;
pub(crate) use registration_services::RegistrationSecretHasher;
pub use startup::run;
pub(crate) use startup::tenant_runtime::TenantRuntimeRegistry;

use std::{path::PathBuf, sync::Arc};

use crate::adapters::email::{SmtpVerificationEmailDelivery, email_delivery_configured};
use crate::adapters::security::ServerMfaSecretHasher;
use crate::adapters::security::ServerScimBootstrapPasswordProvider;
use crate::adapters::security::{
    configure_password_hash_limits, default_password_hash_max_concurrency,
    default_password_hash_queue_timeout_ms, dummy_password_hash, initialize_dummy_password_hash,
};
use crate::config::ConfigSource;
use crate::http::admin::access_requests::AdminAccessRequestConfig;
use crate::http::admin::clients::{
    AdminClientConfig, ServerAdminClientCrypto, ServerAdminClientService, admin_client_policy,
};
use crate::http::admin::federation::AdminFederationConfig;
use crate::http::auth::MFA_REMEMBERED_COOKIE_NAME;
use crate::http::auth::MFA_REMEMBERED_TTL_SECONDS;
use crate::http::auth::csrf::CsrfHttpConfig;
use crate::http::auth::federation::{
    FEDERATION_STATE_TTL_SECONDS, FederationHttpConfig, SAML_REPLAY_TTL_SECONDS,
};
use crate::http::authorization::{AuthorizationEndpoint, authorization_config};
use crate::http::mtls::ServerMtlsThumbprintExtractor;
use crate::http::sessions::{AdminSessionHandles, SessionHttpConfig, SessionProfileHandles};
#[cfg(not(test))]
use crate::http::token::ServerTokenManagementRequestFactsExtractor;
use crate::http::token::ciba::ciba_config;
use crate::http::token::device_config::DeviceHttpConfig;
use crate::http::token::issue::token_issuance_config;
use crate::runtime_modules::{RuntimeModules, ServerRuntimeModuleRegistry};
use crate::settings::{Settings, mfa_totp_key_ring, token_issuance_response_key_ring};
use actix_files::{Files, NamedFile};
#[cfg(test)]
#[allow(unused_imports)]
use actix_web::{App, middleware::from_fn};
use actix_web::{
    HttpResponse,
    dev::{ServiceRequest, ServiceResponse, fn_service},
    web,
};
use nazo_http_actix::ClientIpConfig;
use nazo_http_actix::{
    AuthorizationDecisionEndpoint, LocalRegistrationEndpoint, MfaProfileConfig, MfaProfileEndpoint,
    OidcLogoutConfig as OidcLogoutHttpConfig, OidcLogoutEndpoint, PasskeyLoginConfig,
    PasskeyLoginEndpoint, PasskeyProfileConfig, PasskeyProfileEndpoint, PasswordLoginConfig,
    PasswordLoginEndpoint, ProfileAccountEndpoint, RuntimeModuleAdminEndpoint, SessionCookieConfig,
    SessionLogoutEndpoint, SessionManagementConfig, SessionManagementEndpoint, security_headers,
};
use nazo_oauth_server::authorization::config::AuthorizationConfig;
use nazo_oauth_server::domain::authorization_decision::ServerAuthorizationDecisionOperations;
use nazo_oauth_server::domain::dynamic_registration::DynamicRegistrationConfig;
use nazo_oauth_server::domain::local_registration::ServerAuthenticationRateLimit;
use nazo_oauth_server::domain::local_registration::ServerLocalRegistrationOperations;
use nazo_oauth_server::domain::metadata::MetadataConfig;
use nazo_oauth_server::domain::mfa_profile::ServerMfaProfileOperations;
use nazo_oauth_server::domain::oidc_logout::OidcLogoutConfig;
use nazo_oauth_server::domain::oidc_logout::OidcLogoutHandles;
use nazo_oauth_server::domain::openid4vc::Openid4vcCredentialCrypto;
use nazo_oauth_server::domain::openid4vc::Openid4vcProofValidator;
use nazo_oauth_server::domain::openid4vc_endpoints::CredentialDatasetAdminService;
use nazo_oauth_server::domain::openid4vc_endpoints::PresentationVerifierConfig;
use nazo_oauth_server::domain::openid4vc_endpoints::ServerCredentialIssuerOperations;
use nazo_oauth_server::domain::openid4vc_endpoints::ServerPresentationOperations;
use nazo_oauth_server::domain::passkey::PasskeyOperationsProvider;
use nazo_oauth_server::domain::password_login::ServerPasswordLoginOperations;
use nazo_oauth_server::domain::profile_account::ServerProfileAccountOperations;
use nazo_oauth_server::domain::resource_server::{
    ResourceServerConfig, ServerFapiHttpMessageSignatures, ServerFapiResourceAuthorizer,
};
use nazo_oauth_server::domain::scim::ServerScimCursorProtector;
use nazo_oauth_server::domain::scim::ServerScimEventSigner;
use nazo_oauth_server::domain::scim::ServerScimRequestAuthorizer;
use nazo_oauth_server::domain::session_management::ServerSessionManagementOperations;
#[cfg(not(test))]
use nazo_oauth_server::domain::token_management::ServerTokenManagementOperations;
#[cfg(not(test))]
use nazo_oauth_server::domain::token_management::ServerTokenManagementRequestGuard;
use nazo_oauth_server::domain::userinfo::ServerUserinfoOperations;
use nazo_oauth_server::domain::userinfo::UserinfoConfig;
use nazo_oauth_server::domain::userinfo::UserinfoHandles;
use nazo_oauth_server::rate_limit::{AuthRequestLimiter, TokenManagementRequestLimiter};
use nazo_oauth_server::token::ciba::state::CibaTokenHandles;
use nazo_oauth_server::token::device::DeviceDecisionHandles;
use nazo_oauth_server::token::dispatch::{
    Openid4vcTokenHandles, TokenCoreHandles, TokenEndpointHandles,
};
use nazo_oauth_server::token::issue::TokenIssuanceConfig;
use nazo_openid4vc_http_actix::{CredentialIssuerEndpoint, PresentationEndpoint};
#[cfg(test)]
use transport::DirectTlsReload;
use transport::{direct_tls_listeners, spawn_direct_tls_reloader};

fn ui_static_files(root: PathBuf) -> Files {
    let index = root.join("index.html");
    Files::new("/ui", root)
        .index_file("index.html")
        .disable_content_disposition()
        .default_handler(fn_service(move |request: ServiceRequest| {
            let index = index.clone();
            async move {
                let missing_asset = request
                    .path()
                    .rsplit('/')
                    .next()
                    .is_some_and(|segment| segment.contains('.'));
                let (request, _) = request.into_parts();
                if missing_asset {
                    return Ok(ServiceResponse::new(
                        request,
                        HttpResponse::NotFound().finish(),
                    ));
                }
                let file = match NamedFile::open(index) {
                    Ok(file) => file,
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                        return Ok(ServiceResponse::new(
                            request,
                            HttpResponse::NotFound().finish(),
                        ));
                    }
                    Err(error) => return Err(error.into()),
                };
                let response = file.into_response(&request);
                Ok(ServiceResponse::new(request, response))
            }
        }))
}

#[cfg(test)]
#[path = "../../tests/unit/bootstrap.rs"]
mod tests;
