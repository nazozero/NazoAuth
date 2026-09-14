//! Raw JWS signature generation and verification for the four supported
//! algorithms (EdDSA, RS256, PS256, ES256).

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use p256::elliptic_curve::Generate as _;
use p256::pkcs8::EncodePrivateKey as _;

use crate::CryptoError;
use crate::jwt::{Algorithm, VerificationKey};

pub fn sign(algorithm: Algorithm, private_der: &[u8], message: &[u8]) -> crate::Result<Vec<u8>> {
    let key = encoding_key(algorithm, private_der)?;
    let encoded = jsonwebtoken::crypto::sign(message, &key, algorithm)
        .map_err(|_| CryptoError::OperationFailed)?;
    URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| CryptoError::OperationFailed)
}

pub fn verify(
    algorithm: Algorithm,
    key: &VerificationKey,
    message: &[u8],
    signature: &[u8],
) -> crate::Result<()> {
    match algorithm {
        Algorithm::EdDSA | Algorithm::RS256 | Algorithm::PS256 | Algorithm::ES256 => {}
        _ => return Err(CryptoError::UnsupportedAlgorithm),
    }
    let encoded = URL_SAFE_NO_PAD.encode(signature);
    match jsonwebtoken::crypto::verify(&encoded, message, &key.inner, algorithm) {
        Ok(true) => Ok(()),
        Ok(false) => Err(CryptoError::InvalidSignature),
        Err(_) => Err(CryptoError::InvalidInput),
    }
}

pub fn generate_private_key(algorithm: Algorithm) -> crate::Result<Vec<u8>> {
    match algorithm {
        Algorithm::EdDSA => {
            let seed: [u8; 32] = rand::random();
            Ok(ed25519_pkcs8_private_der(&seed))
        }
        Algorithm::RS256 | Algorithm::PS256 => {
            let pkcs8 = crate::key_wrap::generate_rsa_pkcs8_der(2048)?;
            let private_key = pkcs8::PrivateKeyInfoRef::try_from(pkcs8.as_slice())
                .map_err(|_| CryptoError::OperationFailed)?;
            Ok(private_key.private_key.as_bytes().to_vec())
        }
        Algorithm::ES256 => {
            let secret_key =
                p256::SecretKey::try_generate().map_err(|_| CryptoError::OperationFailed)?;
            Ok(secret_key
                .to_pkcs8_der()
                .map_err(|_| CryptoError::OperationFailed)?
                .as_bytes()
                .to_vec())
        }
        _ => Err(CryptoError::UnsupportedAlgorithm),
    }
}

pub fn public_jwk(algorithm: Algorithm, private_der: &[u8]) -> crate::Result<serde_json::Value> {
    match algorithm {
        Algorithm::EdDSA => {
            let seed = ed25519_seed_from_pkcs8(private_der).ok_or(CryptoError::InvalidKey)?;
            let public_key = ed25519_dalek::SigningKey::from_bytes(&seed)
                .verifying_key()
                .to_bytes();
            Ok(serde_json::json!({
                "kty": "OKP",
                "crv": "Ed25519",
                "x": URL_SAFE_NO_PAD.encode(public_key),
            }))
        }
        Algorithm::RS256 | Algorithm::PS256 | Algorithm::ES256 => {
            let key = encoding_key(algorithm, private_der)?;
            let jwk = jsonwebtoken::jwk::Jwk::from_encoding_key(&key, algorithm)
                .map_err(|_| CryptoError::InvalidKey)?;
            let value = serde_json::to_value(jwk).map_err(|_| CryptoError::OperationFailed)?;
            let object = value.as_object().ok_or(CryptoError::OperationFailed)?;
            let mut public = serde_json::Map::new();
            for member in ["kty", "n", "e", "crv", "x", "y"] {
                if let Some(value) = object.get(member) {
                    public.insert(member.to_owned(), value.clone());
                }
            }
            Ok(serde_json::Value::Object(public))
        }
        _ => Err(CryptoError::UnsupportedAlgorithm),
    }
}

fn encoding_key(
    algorithm: Algorithm,
    private_der: &[u8],
) -> crate::Result<jsonwebtoken::EncodingKey> {
    match algorithm {
        Algorithm::EdDSA => Ok(jsonwebtoken::EncodingKey::from_ed_der(private_der)),
        Algorithm::RS256 | Algorithm::PS256 => {
            Ok(jsonwebtoken::EncodingKey::from_rsa_der(private_der))
        }
        Algorithm::ES256 => Ok(jsonwebtoken::EncodingKey::from_ec_der(private_der)),
        _ => Err(CryptoError::UnsupportedAlgorithm),
    }
}

fn ed25519_pkcs8_private_der(seed: &[u8; 32]) -> Vec<u8> {
    let mut der = Vec::with_capacity(48);
    der.extend_from_slice(&[
        0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04,
        0x20,
    ]);
    der.extend_from_slice(seed);
    der
}

fn ed25519_seed_from_pkcs8(der: &[u8]) -> Option<[u8; 32]> {
    const PREFIX: &[u8] = &[
        0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04,
        0x20,
    ];
    if der.len() != PREFIX.len() + 32 || !der.starts_with(PREFIX) {
        return None;
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&der[PREFIX.len()..]);
    Some(seed)
}
