use crate::domain::rows::ClientRow;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use nazo_auth::{Claims, rsa_public_key_components_are_safe};
use nazo_crypto::jwt::{Algorithm, VerificationKey as JwtVerificationKey};
pub use nazo_key_management::{client_secret_digest, client_secret_matches_digest};
use nazo_openid4vci::ProofError;
use serde_json::Value;
use sha2::{Digest, Sha256};
use uuid::Uuid;

enum SupportedClientJwtAlgorithm {
    EdDsa,
    Rsa,
    Ec,
}

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

pub fn client_jwt_decoding_key(
    client: &ClientRow,
    kid: &str,
    alg: Algorithm,
) -> Option<JwtVerificationKey> {
    let keys = client.jwks.as_deref()?.get("keys")?.as_array()?;
    let key = keys
        .iter()
        .find(|key| key.get("kid").and_then(Value::as_str) == Some(kid))?;
    jwt_decoding_key_from_jwk(key, alg)
}

pub fn jwt_decoding_key_from_jwk(key: &Value, alg: Algorithm) -> Option<JwtVerificationKey> {
    let (expected_alg, supported_alg) = supported_client_jwt_algorithm(alg)?;
    if let Some(key_alg) = key.get("alg").and_then(Value::as_str)
        && key_alg != expected_alg
    {
        return None;
    }
    if key.get("d").is_some() {
        return None;
    }
    if let Some(use_) = key.get("use").and_then(Value::as_str)
        && use_ != "sig"
    {
        return None;
    }
    match supported_alg {
        SupportedClientJwtAlgorithm::EdDsa => {
            if key.get("kty").and_then(Value::as_str) != Some("OKP")
                || key.get("crv").and_then(Value::as_str) != Some("Ed25519")
            {
                return None;
            }
            let x = key.get("x").and_then(Value::as_str)?;
            let mut bytes = [0_u8; 32];
            if URL_SAFE_NO_PAD.decode_slice(x, &mut bytes).ok()? != bytes.len() {
                return None;
            }
            Some(JwtVerificationKey::from_ed25519_bytes(&bytes))
        }
        SupportedClientJwtAlgorithm::Rsa => {
            if key.get("kty").and_then(Value::as_str) != Some("RSA") {
                return None;
            }
            let n = key.get("n").and_then(Value::as_str)?;
            let e = key.get("e").and_then(Value::as_str)?;
            let modulus = URL_SAFE_NO_PAD.decode(n).ok()?;
            let exponent = URL_SAFE_NO_PAD.decode(e).ok()?;
            if !rsa_public_key_components_are_safe(&modulus, &exponent) {
                return None;
            }
            Some(JwtVerificationKey::from_rsa_raw_components(
                &modulus, &exponent,
            ))
        }
        SupportedClientJwtAlgorithm::Ec => {
            if key.get("kty").and_then(Value::as_str) != Some("EC")
                || key.get("crv").and_then(Value::as_str) != Some("P-256")
            {
                return None;
            }
            let x = key.get("x").and_then(Value::as_str)?;
            let y = key.get("y").and_then(Value::as_str)?;
            let mut x_bytes = [0_u8; 32];
            let mut y_bytes = [0_u8; 32];
            if URL_SAFE_NO_PAD.decode_slice(x, &mut x_bytes).ok()? != x_bytes.len()
                || URL_SAFE_NO_PAD.decode_slice(y, &mut y_bytes).ok()? != y_bytes.len()
            {
                return None;
            }
            Some(JwtVerificationKey::from_p256_coordinates(
                &x_bytes, &y_bytes,
            ))
        }
    }
}

fn supported_client_jwt_algorithm(
    alg: Algorithm,
) -> Option<(&'static str, SupportedClientJwtAlgorithm)> {
    match alg {
        Algorithm::EdDSA => Some(("EdDSA", SupportedClientJwtAlgorithm::EdDsa)),
        Algorithm::RS256 => Some(("RS256", SupportedClientJwtAlgorithm::Rsa)),
        Algorithm::ES256 => Some(("ES256", SupportedClientJwtAlgorithm::Ec)),
        Algorithm::PS256 => Some(("PS256", SupportedClientJwtAlgorithm::Rsa)),
        _ => None,
    }
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
