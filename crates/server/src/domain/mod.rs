//! 领域类型聚合模块。
// 每个子模块只描述一种领域概念，本模块只负责向 crate 内部 re-export。
#[cfg(test)]
#[path = "../../tests/in_source/src/domain/database_user_fixture.rs"]
mod database_user_fixture;
mod dynamic_registration;
mod local_registration;
mod metadata;
mod mfa;
mod oauth;
mod oidc_logout;
mod profile_account;
mod resource_server;
mod rows;
#[cfg(not(test))]
mod scim;
#[cfg(test)]
mod state;
#[cfg(not(test))]
mod token_management;
mod userinfo;

#[cfg(test)]
pub(crate) use database_user_fixture::{
    DatabaseExternalIdentityFixture, DatabasePasskeyFixture, DatabaseUserFixture,
};
pub(crate) use dynamic_registration::DynamicRegistrationConfig;
#[cfg(test)]
pub(crate) use dynamic_registration::DynamicRegistrationHandles;
#[cfg(not(test))]
pub(crate) use dynamic_registration::dynamic_registration_endpoint;
pub(crate) use local_registration::{
    ServerAuthenticationRateLimit, ServerLocalRegistrationOperations,
};
pub(crate) use metadata::{MetadataConfig, ServerMetadataSnapshotSource};
pub(crate) use mfa::{MfaProfileConfig, MfaProfileHandles};
#[cfg(test)]
pub(crate) use nazo_key_management::KeySnapshot;
pub(crate) use oauth::{
    AuthorizationCodeState, CodePayload, ConsentPayload, ConsumedAuthorizationCode,
    NativeSsoTokenBinding, PushedAuthorizationRequest, RefreshTokenPolicy, TokenIssue,
};
pub(crate) use oidc_logout::{OidcLogoutConfig, OidcLogoutHandles};
pub(crate) use profile_account::ServerProfileAccountOperations;
pub(crate) use resource_server::ResourceServerConfig;
#[cfg(test)]
pub(crate) use resource_server::ResourceServerHandles;
#[cfg(not(test))]
pub(crate) use resource_server::{
    ServerFapiHttpMessageSignatures, ServerFapiMtlsResolver, ServerFapiResourceAuthorizer,
};
pub(crate) use rows::{ClientRow, TokenRow};
#[cfg(not(test))]
pub(crate) use scim::{
    ServerScimBootstrapPasswordProvider, ServerScimCursorProtector, ServerScimRequestAuthorizer,
};
#[cfg(test)]
pub(crate) use state::AppState;
#[cfg(not(test))]
pub(crate) use token_management::{
    ServerTokenManagementOperations, ServerTokenManagementRequestGuard,
};
pub(crate) use userinfo::{ServerUserinfoOperations, UserinfoConfig, UserinfoHandles};
