//! JWT decoding and verification-key construction behind the crypto boundary.
//!
//! The four JOSE data/policy types are the same upstream types the codebase
//! already used; reusing them avoids inventing a parallel JWT model. The
//! backend key object itself is opaque.

pub use jsonwebtoken::{Algorithm, Header, TokenData, Validation};

use crate::CryptoError;

/// Records header-member presence, including `null` and empty values.
/// JOSE consumers that implement no critical extensions reject any `crit`.
pub fn deserialize_present_header<'de, D>(d: D) -> Result<bool, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let _ = <serde::de::IgnoredAny as serde::Deserialize>::deserialize(d)?;
    Ok(true)
}

#[derive(Clone)]
pub struct VerificationKey {
    pub(crate) inner: jsonwebtoken::DecodingKey,
}

impl std::fmt::Debug for VerificationKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("VerificationKey(..)")
    }
}

impl VerificationKey {
    pub fn from_rsa_components(n: &str, e: &str) -> crate::Result<Self> {
        jsonwebtoken::DecodingKey::from_rsa_components(n, e)
            .map(|inner| Self { inner })
            .map_err(|_| CryptoError::InvalidKey)
    }

    pub fn from_ec_components(x: &str, y: &str) -> crate::Result<Self> {
        jsonwebtoken::DecodingKey::from_ec_components(x, y)
            .map(|inner| Self { inner })
            .map_err(|_| CryptoError::InvalidKey)
    }

    pub fn from_ed_components(x: &str) -> crate::Result<Self> {
        jsonwebtoken::DecodingKey::from_ed_components(x)
            .map(|inner| Self { inner })
            .map_err(|_| CryptoError::InvalidKey)
    }

    /// Reuses RSA components already decoded for the caller's key policy.
    #[must_use]
    pub fn from_rsa_raw_components(n: &[u8], e: &[u8]) -> Self {
        Self {
            inner: jsonwebtoken::DecodingKey::from_rsa_raw_components(n, e),
        }
    }

    #[must_use]
    pub fn from_ed25519_bytes(bytes: &[u8; 32]) -> Self {
        Self {
            inner: jsonwebtoken::DecodingKey::from_ed_der(bytes),
        }
    }

    #[must_use]
    pub fn from_p256_coordinates(x: &[u8; 32], y: &[u8; 32]) -> Self {
        let mut point = [0_u8; 65];
        point[0] = 4;
        point[1..33].copy_from_slice(x);
        point[33..].copy_from_slice(y);
        Self::from_ec_sec1(&point)
    }

    /// Builds a verification key from a certificate's raw SEC1 public point.
    #[must_use]
    pub fn from_ec_sec1(bytes: &[u8]) -> Self {
        Self {
            inner: jsonwebtoken::DecodingKey::from_ec_der(bytes),
        }
    }
}

pub fn decode_header(token: &str) -> crate::Result<Header> {
    jsonwebtoken::decode_header(token).map_err(token_error)
}

pub fn decode<T: serde::de::DeserializeOwned>(
    token: &str,
    key: &VerificationKey,
    validation: &Validation,
) -> crate::Result<TokenData<T>> {
    jsonwebtoken::decode(token, &key.inner, validation).map_err(token_error)
}

pub mod dangerous {
    pub fn insecure_decode<T: serde::de::DeserializeOwned>(
        token: &str,
    ) -> crate::Result<super::TokenData<T>> {
        jsonwebtoken::dangerous::insecure_decode(token).map_err(super::token_error)
    }
}

fn token_error(error: jsonwebtoken::errors::Error) -> CryptoError {
    match error.kind() {
        jsonwebtoken::errors::ErrorKind::InvalidSignature => CryptoError::InvalidSignature,
        jsonwebtoken::errors::ErrorKind::InvalidAlgorithm => CryptoError::UnsupportedAlgorithm,
        jsonwebtoken::errors::ErrorKind::InvalidKeyFormat => CryptoError::InvalidKey,
        jsonwebtoken::errors::ErrorKind::Provider(_) => CryptoError::OperationFailed,
        _ => CryptoError::InvalidToken,
    }
}
