//! Application service bindings contain only semantic capabilities.
use std::sync::Arc;

use nazo_identity::ports::{
    AuthenticationAuditPort, DeliveryStorePort, EmailVerificationStorePort, FederationAuditPort,
    FederationPasswordHasherPort, FederationStatePort, LoginSessionPort, LoginThrottlePort,
    PasskeyAuditPort, PasskeyCeremonyPort, SecretHashPort, SecretVerifyPort,
    VerificationEmailDeliveryPort,
};

pub type LocalAuthenticationService = nazo_identity::AuthenticationService<
    Arc<dyn LoginThrottlePort>,
    Arc<dyn SecretVerifyPort>,
    Arc<dyn LoginSessionPort>,
    Arc<dyn AuthenticationAuditPort>,
>;
pub type LocalRegistrationService = nazo_identity::RegistrationService<
    Arc<dyn EmailVerificationStorePort>,
    Arc<dyn SecretHashPort>,
    Arc<dyn VerificationEmailDeliveryPort>,
>;
pub type LocalPasskeyService = nazo_identity::PasskeyService<
    Arc<dyn PasskeyCeremonyPort>,
    Arc<dyn LoginSessionPort>,
    Arc<dyn PasskeyAuditPort>,
>;
pub type LocalFederationService = nazo_identity::FederationService<
    Arc<dyn FederationStatePort>,
    Arc<dyn FederationPasswordHasherPort>,
    Arc<dyn LoginSessionPort>,
    Arc<dyn FederationAuditPort>,
>;

pub const PASSKEY_CEREMONY_TTL_SECONDS: u64 = 300;

pub type AccountProfileService = nazo_identity::AccountProfileService;
pub type ClientAccessProfileService =
    nazo_identity::ClientAccessService<Arc<dyn DeliveryStorePort>>;
pub type FederationProfileService = nazo_identity::FederationLinksService;
pub type MtlsTrustAnchorService = dyn nazo_identity::ports::MtlsTrustAnchorStore;

pub type ServerAuthorizationService = nazo_auth::AuthorizationService<
    Arc<dyn nazo_auth::AuthorizationStateStorePort>,
    nazo_key_management::KeyManager,
>;
pub type ServerTokenService = nazo_auth::TokenService<
    Arc<dyn nazo_auth::TokenStateStorePort>,
    nazo_key_management::KeyManager,
>;
pub type ServerCibaService = nazo_auth::CibaService<
    Arc<dyn nazo_auth::CibaStateStorePort<Version = nazo_auth::CibaStateVersion>>,
>;
pub type ServerDeviceGrantService = nazo_auth::DeviceGrantService<
    Arc<dyn nazo_auth::DeviceStateStorePort<Version = nazo_auth::DeviceStateVersion>>,
>;
