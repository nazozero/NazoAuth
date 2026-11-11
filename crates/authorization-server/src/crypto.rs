use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use nazo_auth::Claims;
pub use nazo_auth::{client_jwt_decoding_key, jwt_decoding_key_from_jwk};
use nazo_crypto::jwt::{Algorithm, VerificationKey as JwtVerificationKey};
pub use nazo_key_management::{client_secret_digest, client_secret_matches_digest};
use nazo_openid4vci::ProofError;
use serde_json::Value;
use sha2::{Digest, Sha256};
use uuid::Uuid;

pub fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right.iter())
        .fold(0u8, |acc, (a, b)| acc | (a ^ b))
        == 0
}

pub fn access_delivery_token(secret: &str, user_id: Uuid, request_id: Uuid) -> String {
    nazo_identity::access_delivery_token(secret, user_id, request_id)
}

pub fn blake3_hex(value: &str) -> String {
    blake3::hash(value.as_bytes()).to_hex().to_string()
}

pub fn access_token_tenant_id(claims: &Claims) -> Option<Uuid> {
    claims.tenant_id.parse::<Uuid>().ok()
}

pub fn random_urlsafe_token() -> String {
    URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>())
}

pub fn pkce_s256(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

pub fn decoding_key(jwk: &Value, algorithm: Algorithm) -> Result<JwtVerificationKey, ProofError> {
    match algorithm {
        Algorithm::ES256 => JwtVerificationKey::from_ec_components(
            jwk.get("x")
                .and_then(Value::as_str)
                .ok_or(ProofError::InvalidSignature)?,
            jwk.get("y")
                .and_then(Value::as_str)
                .ok_or(ProofError::InvalidSignature)?,
        )
        .map_err(|_| ProofError::InvalidSignature),
        Algorithm::EdDSA => JwtVerificationKey::from_ed_components(
            jwk.get("x")
                .and_then(Value::as_str)
                .ok_or(ProofError::InvalidSignature)?,
        )
        .map_err(|_| ProofError::InvalidSignature),
        _ => Err(ProofError::UnsupportedType),
    }
}
