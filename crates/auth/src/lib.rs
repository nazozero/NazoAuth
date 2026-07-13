#![forbid(unsafe_code)]

//! Runtime- and infrastructure-free authorization-server policy.

mod authorization_details;
mod authorization_service;
mod ciba;
mod claims;
mod client;
mod client_registration;
mod device;
mod error;
mod grant;
mod metadata;
mod profile;
mod resource_indicator;
mod sender_constraint;
mod signing;
mod token;
mod transaction;
mod uri_policy;

pub use authorization_details::{
    AuthorizationDetailsError, SUPPORTED_AUTHORIZATION_DETAILS_TYPES, authorization_details_empty,
    canonical_authorization_details, deserialize_authorization_details,
    empty_authorization_details, high_risk_authorization_details, normalize_authorization_details,
    parse_authorization_details,
};
pub use authorization_service::{
    AuthorizationFuture, AuthorizationPortError, AuthorizationRateDimension,
    AuthorizationRepositoryPort, AuthorizationResponseSignInput, AuthorizationResponseSignerPort,
    AuthorizationService, AuthorizationStateStorePort, GrantWrite, StoredAuthorizationGrant,
    stored_grant_covers_requested_authorization,
};
pub use ciba::{CibaRequestState, CibaStatus};
pub use claims::{
    AccessTokenClaimsInput, AuthorizationResponseClaimsInput, BackchannelLogoutClaimsInput, Claims,
    ConfirmationClaims, IdTokenClaimsInput, OidcClaimRequest, access_token_claims,
    authorization_response_jwt_claims, backchannel_logout_token_claims, id_token_claims,
};
pub use client::{ClientProfile, validate_token_request_profile};
pub use client_registration::{ApprovedClient, OAuthClient, ValidatedClientRegistration};
pub use device::{
    DeviceAuthorizationApproval, DeviceAuthorizationPayload, DeviceAuthorizationState,
};
pub use error::{ProtocolError, ProtocolErrorCode};
pub use grant::GrantType;
pub use metadata::{CapabilityAdmission, MetadataCapabilities, module_admissible};
pub use profile::SecurityProfile;
pub use resource_indicator::{ResourceIndicatorError, parse_resource_indicators};
pub use sender_constraint::{
    SenderConstraintPolicy, is_valid_dpop_jkt, normalize_sha256_thumbprint,
};
pub use signing::{SignError, SignRequest, Signature, Signer, SigningPurpose};
pub use token::{
    BackchannelLogoutDelivery, LostResponseRetry, NewRefreshToken, RefreshToken,
    RefreshTokenPersistResult,
};
pub use transaction::{
    AuthorizationCodeState, CodePayload, ConsentPayload, ConsumedAuthorizationCode,
    PushedAuthorizationRequest,
};
pub use uri_policy::{
    is_loopback_http_url, oauth_redirect_uri_matches, validate_cors_origin,
    validate_frontend_base_url, validate_issuer_url, validate_oauth_redirect_uri,
    validate_protected_resource_identifier,
};
