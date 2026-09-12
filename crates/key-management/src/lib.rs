mod authorization_response;
mod client_registration;
mod crypto;
mod database;
mod external;
mod external_signer;
pub use external_signer::{ExternalKeySigner, ExternalSignRequest};
mod jwks;
mod lifecycle;
mod local;
mod model;
mod mtls_trust;
mod repository;
mod request_object_encryption;
mod serialization;
mod token;

#[cfg(any(test, feature = "test-support"))]
pub mod test_support;

pub use client_registration::{
    ClientRegistrationCrypto, SUPPORTED_CLIENT_JWT_SIGNING_ALGS, client_jwks_contains_signing_key,
    client_jwks_contains_signing_key_for_algorithm, client_jwks_matching_encryption_key_count,
    rfc4514_dn_matches, validate_client_jwks, validate_rfc4514_dn, validate_self_signed_mtls_jwks,
};
#[cfg(feature = "test-support")]
pub use model::TestSigningBehavior;
pub use model::{
    ExternalKeyRegistration, HttpSigningLease, KeyHealth, KeyHealthStatus, KeyManager, KeyRecord,
    KeyRecordStatus, KeySettings, KeySnapshot, KeyState, LocalKeyRegistration, ManagedKey,
    Openid4vcMaterial, Openid4vcPublicMaterial, Openid4vcSigningLease, Openid4vcState,
    VerificationKey,
};
pub use mtls_trust::{MtlsTrustAnchorError, ValidatedMtlsTrustAnchor, validate_mtls_trust_anchor};
pub use repository::{
    PersistedSigningKeyset, SealedKeyMaterial, SigningKeyRepository, SigningKeyRepositoryFuture,
    SigningKeyWrappingKeyError, SigningKeyWrappingKeyRing, SigningKeysetCompareAndSwapResult,
    SigningKeysetCreateResult,
};
pub use serialization::{signing_algorithm_from_name, signing_algorithm_name};

#[cfg(test)]
#[path = "../tests/unit/key_repository.rs"]
mod key_repository_tests;

#[cfg(test)]
#[path = "../tests/unit/purpose_scoped_keys.rs"]
mod purpose_scoped_keys_tests;
