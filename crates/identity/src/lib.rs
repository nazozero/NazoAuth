#![forbid(unsafe_code)]

mod access_request;
mod admin;
mod audit;
pub mod email;
pub mod federation;
pub mod mfa;
mod model;
pub mod passkey;
pub mod ports;
pub mod profile;
pub mod registration;
pub mod scim;
pub mod session;
pub mod tenancy;

pub use access_request::{AccessRequest, AccessRequestPage, AccessRequestStatus, NewAccessRequest};
pub use admin::{
    AdminPolicyError, AdminUserUpdateOutcome, ResolvedAdminUserUpdate, authorize_admin_update,
};
pub use audit::{
    IdentitySecurityEvent, IdentitySecurityEventType, IdentitySecurityOutcome,
    IdentitySecurityReason,
};
pub use model::{
    AccountIdentity, AuthMethod, AuthenticationContext, AuthenticationIdentity, IdentityModelError,
    LoginIdentity, PasswordHash, PostalAddress, Principal, PublicAccount, SubjectClaims,
    UserProfile, UserRole,
};
pub use profile::{
    AccessRequestListError, AccessRequestWithDelivery, AccountOverview, AccountProfileService,
    AvailableDelivery, ClientAccessService, DeliveryReadError, FederationLinksService,
    NewAccessRequestInput, ProfilePatch, ProfileValidationError, UpdateProfileError,
    access_delivery_token,
};
pub use registration::{
    RegisterLocalAccountError, RegisterLocalAccountInput, RegistrationService,
    RegistrationServiceConfig, SendVerificationCodeError, SendVerificationCodeOutcome,
};
pub use tenancy::{OrganizationId, RealmId, TenantContext, TenantId, UserId};
