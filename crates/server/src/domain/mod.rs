//! 领域类型聚合模块。
// 每个子模块只描述一种领域概念，本模块只负责向 crate 内部 re-export。
#[cfg(test)]
#[path = "../../tests/in_source/src/domain/database_user_fixture.rs"]
mod database_user_fixture;
mod dynamic_registration;
mod metadata;
mod mfa;
mod oauth;
mod oidc_logout;
mod resource_server;
mod rows;
#[cfg(test)]
mod state;
mod userinfo;

#[cfg(test)]
pub(crate) use database_user_fixture::{
    DatabaseExternalIdentityFixture, DatabasePasskeyFixture, DatabaseUserFixture,
};
pub(crate) use dynamic_registration::{DynamicRegistrationConfig, DynamicRegistrationHandles};
pub(crate) use metadata::{MetadataConfig, ServerMetadataSnapshotSource};
pub(crate) use mfa::{MfaProfileConfig, MfaProfileHandles};
#[cfg(test)]
pub(crate) use nazo_key_management::KeySnapshot;
pub(crate) use oauth::{
    AuthorizationCodeState, CodePayload, ConsentPayload, ConsumedAuthorizationCode,
    NativeSsoTokenBinding, PushedAuthorizationRequest, RefreshTokenPolicy, TokenIssue,
};
pub(crate) use oidc_logout::{OidcLogoutConfig, OidcLogoutHandles};
pub(crate) use resource_server::{ResourceServerConfig, ResourceServerHandles};
pub(crate) use rows::{ClientRow, TokenRow};
#[cfg(test)]
pub(crate) use state::AppState;
pub(crate) use userinfo::{UserinfoConfig, UserinfoHandles};
