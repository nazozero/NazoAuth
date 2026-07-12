#![forbid(unsafe_code)]

pub mod email;
pub mod federation;
pub mod mfa;
mod model;
pub mod passkey;
pub mod ports;
pub mod scim;
pub mod session;
pub mod tenancy;

pub use model::{
    AuthMethod, AuthenticationContext, IdentityModelError, IdentityUser, LoginIdentity,
    PasswordHash, PostalAddress, Principal, SubjectClaims, UserProfile, UserRole,
};
pub use tenancy::{OrganizationId, RealmId, TenantContext, TenantId, UserId};
