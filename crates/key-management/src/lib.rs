mod authorization_response;
mod client_registration;
mod database;
mod external;
mod external_signer;
pub use external_signer::{ExternalKeySigner, ExternalSignRequest};
mod jwks;
mod lifecycle;
mod model;
mod mtls_trust;
mod repository;
mod request_object_encryption;
mod serialization;
mod token;

#[cfg(any(test, feature = "test-support"))]
pub mod test_support;

pub use client_registration::{
    ClientRegistrationCrypto, SUPPORTED_CLIENT_JWT_SIGNING_ALGS, client_secret_digest,
    client_secret_matches_digest, inspect_client_jwks, rfc4514_dn_from_der, rfc4514_dn_matches,
    validate_client_jwks, validate_rfc4514_dn,
};
#[cfg(feature = "test-support")]
pub use model::TestSigningBehavior;
pub use model::{
    ExternalKeyRegistration, HttpSigningLease, KeyHealth, KeyHealthStatus, KeyManager, KeyRecord,
    KeyRecordStatus, KeySettings, KeySnapshot, KeyState, LocalKeyRegistration, ManagedKey,
    MdocCrlMaterial, Openid4vcMaterial, Openid4vcPublicMaterial, Openid4vcSigningLease,
    Openid4vcState, VerificationKey,
};
pub use mtls_trust::{MtlsTrustAnchorError, ValidatedMtlsTrustAnchor, validate_mtls_trust_anchor};
pub use repository::{
    PersistedSigningKeyset, SigningKeyRepository, SigningKeyRepositoryFuture,
    SigningKeyRepositoryUnavailable, SigningKeyWrappingKeyError, SigningKeyWrappingKeyRing,
    SigningKeysetCompareAndSwapResult, SigningKeysetCreateResult,
};
pub use serialization::{signing_algorithm_from_name, signing_algorithm_name};

#[cfg(test)]
#[path = "../tests/support/crypto.rs"]
mod crypto_test_support;

#[cfg(test)]
#[path = "../tests/unit/key_repository.rs"]
mod key_repository_tests;

#[cfg(test)]
#[path = "../tests/unit/purpose_scoped_keys.rs"]
mod purpose_scoped_keys_tests;
