//! Public JOSE verification keys and shared RSA component bounds.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::Value;

use crate::jwt::{Algorithm, VerificationKey as JwtVerificationKey};

pub const RSA_PUBLIC_KEY_MIN_BITS: usize = 2_048;
pub const RSA_PUBLIC_KEY_MAX_BITS: usize = 8_192;

pub fn jwt_decoding_key_from_jwks(
    jwks: &Value,
    kid: &str,
    algorithm: Algorithm,
) -> Option<JwtVerificationKey> {
    let keys = jwks.get("keys")?.as_array()?;
    let mut matching = keys
        .iter()
        .filter(|key| key.get("kid").and_then(Value::as_str) == Some(kid));
    let selected = matching.next()?;
    if matching.next().is_some() {
        return None;
    }
    jwt_decoding_key_from_jwk(selected, algorithm)
}

pub fn jwt_decoding_key_from_jwk(key: &Value, algorithm: Algorithm) -> Option<JwtVerificationKey> {
    let (expected_algorithm, key_type) = verification_key_algorithm(algorithm)?;
    if key
        .get("alg")
        .is_some_and(|registered| registered.as_str() != Some(expected_algorithm))
        || ["d", "p", "q", "dp", "dq", "qi", "oth", "k"]
            .iter()
            .any(|parameter| key.get(*parameter).is_some())
        || key
            .get("use")
            .is_some_and(|use_| use_.as_str() != Some("sig"))
        || !valid_verification_key_ops(key.get("key_ops"))
    {
        return None;
    }
    match key_type {
        VerificationKeyAlgorithm::EdDsa => {
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
        VerificationKeyAlgorithm::Rsa => {
            if key.get("kty").and_then(Value::as_str) != Some("RSA") {
                return None;
            }
            let modulus = key.get("n").and_then(Value::as_str)?;
            let exponent = key.get("e").and_then(Value::as_str)?;
            let modulus = URL_SAFE_NO_PAD.decode(modulus).ok()?;
            let exponent_bytes = URL_SAFE_NO_PAD.decode(exponent).ok()?;
            if !rsa_public_key_components_are_safe(&modulus, &exponent_bytes) {
                return None;
            }
            Some(JwtVerificationKey::from_rsa_raw_components(
                &modulus,
                &exponent_bytes,
            ))
        }
        VerificationKeyAlgorithm::Ec => {
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

fn valid_verification_key_ops(key_ops: Option<&Value>) -> bool {
    match key_ops {
        None => true,
        Some(Value::Array(operations)) => {
            operations.len() == 1 && operations[0].as_str() == Some("verify")
        }
        Some(_) => false,
    }
}

enum VerificationKeyAlgorithm {
    EdDsa,
    Rsa,
    Ec,
}

fn verification_key_algorithm(
    algorithm: Algorithm,
) -> Option<(&'static str, VerificationKeyAlgorithm)> {
    match algorithm {
        Algorithm::EdDSA => Some(("EdDSA", VerificationKeyAlgorithm::EdDsa)),
        Algorithm::RS256 => Some(("RS256", VerificationKeyAlgorithm::Rsa)),
        Algorithm::ES256 => Some(("ES256", VerificationKeyAlgorithm::Ec)),
        Algorithm::PS256 => Some(("PS256", VerificationKeyAlgorithm::Rsa)),
        _ => None,
    }
}

#[must_use]
pub fn rsa_public_key_components_are_safe(modulus: &[u8], exponent: &[u8]) -> bool {
    let modulus_bits = unsigned_integer_bit_length(modulus);
    (RSA_PUBLIC_KEY_MIN_BITS..=RSA_PUBLIC_KEY_MAX_BITS).contains(&modulus_bits)
        && valid_rsa_public_exponent(exponent)
}

fn unsigned_integer_bit_length(bytes: &[u8]) -> usize {
    let Some((offset, first)) = bytes.iter().enumerate().find(|(_, byte)| **byte != 0) else {
        return 0;
    };
    (bytes.len() - offset - 1) * 8 + (u8::BITS - first.leading_zeros()) as usize
}

fn valid_rsa_public_exponent(bytes: &[u8]) -> bool {
    let Some((offset, _)) = bytes.iter().enumerate().find(|(_, byte)| **byte != 0) else {
        return false;
    };
    let value = &bytes[offset..];
    (value.len() > 1 || value[0] >= 3) && value.last().is_some_and(|last| last & 1 == 1)
}
