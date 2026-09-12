pub mod client_attestation;
mod credential_crypto;
mod crypto_helpers;
mod proof_validator;

pub use credential_crypto::{Openid4vcCredentialCrypto, parse_scoped_credential_trust_anchors};
pub use proof_validator::Openid4vcProofValidator;

#[cfg(test)]
#[path = "../../../tests/unit/domain/openid4vc.rs"]
mod tests;
