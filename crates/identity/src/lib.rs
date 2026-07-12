#![forbid(unsafe_code)]

mod access_request;
pub mod email;
pub mod federation;
pub mod mfa;
mod model;
pub mod passkey;
pub mod ports;
pub mod scim;
pub mod session;
pub mod tenancy;

pub use access_request::{AccessRequest, AccessRequestPage, AccessRequestStatus, NewAccessRequest};
pub use model::{
    AccountIdentity, AuthMethod, AuthenticationContext, AuthenticationIdentity, IdentityModelError,
    LoginIdentity, PasswordHash, PostalAddress, Principal, PublicAccount, SubjectClaims,
    UserProfile, UserRole,
};
pub use tenancy::{OrganizationId, RealmId, TenantContext, TenantId, UserId};
