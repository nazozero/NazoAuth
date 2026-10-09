use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use nazo_crypto::jwt::{Algorithm, VerificationKey as JwtVerificationKey};
use serde_json::Value;

#[derive(Clone, Debug)]
pub(super) struct PreparedVerificationKey {
    pub(super) algorithm: Algorithm,
    pub(super) key: JwtVerificationKey,
}

pub(super) fn prepare_verification_key(key: &Value) -> Option<PreparedVerificationKey> {
    let algorithm = match key.get("alg").and_then(Value::as_str)? {
        "EdDSA" => Algorithm::EdDSA,
        "RS256" => Algorithm::RS256,
        "ES256" => Algorithm::ES256,
        "PS256" => Algorithm::PS256,
        _ => return None,
    };
    Some(PreparedVerificationKey {
        algorithm,
        key: decoding_key(key, algorithm)?,
    })
}

enum SupportedJwkAlgorithm {
    EdDsa,
    Rsa,
    Ec,
}

pub(super) fn decoding_key(key: &Value, alg: Algorithm) -> Option<JwtVerificationKey> {
    let (expected_alg, supported_alg) = supported_algorithm(alg)?;
    if key.get("alg").and_then(Value::as_str) != Some(expected_alg) {
        return None;
    }
    if key.get("d").is_some() {
        return None;
    }
    if key
        .get("use")
        .and_then(Value::as_str)
        .is_some_and(|use_| use_ != "sig")
    {
        return None;
    }
    match supported_alg {
        SupportedJwkAlgorithm::EdDsa => {
            if key.get("kty").and_then(Value::as_str) != Some("OKP")
                || key.get("crv").and_then(Value::as_str) != Some("Ed25519")
            {
                return None;
            }
            let x = key.get("x").and_then(Value::as_str)?;
            let bytes = URL_SAFE_NO_PAD.decode(x).ok()?;
            if bytes.len() != 32 {
                return None;
            }
            JwtVerificationKey::from_ed_components(x).ok()
        }
        SupportedJwkAlgorithm::Rsa => {
            if key.get("kty").and_then(Value::as_str) != Some("RSA") {
                return None;
            }
            let n = key.get("n").and_then(Value::as_str)?;
            let e = key.get("e").and_then(Value::as_str)?;
            let modulus = URL_SAFE_NO_PAD.decode(n).ok()?;
            let exponent = URL_SAFE_NO_PAD.decode(e).ok()?;
            if modulus.len() < 256 || exponent.is_empty() {
                return None;
            }
            JwtVerificationKey::from_rsa_components(n, e).ok()
        }
        SupportedJwkAlgorithm::Ec => {
            if key.get("kty").and_then(Value::as_str) != Some("EC")
                || key.get("crv").and_then(Value::as_str) != Some("P-256")
            {
                return None;
            }
            let x = key.get("x").and_then(Value::as_str)?;
            let y = key.get("y").and_then(Value::as_str)?;
            let x_bytes = URL_SAFE_NO_PAD.decode(x).ok()?;
            let y_bytes = URL_SAFE_NO_PAD.decode(y).ok()?;
            if x_bytes.len() != 32 || y_bytes.len() != 32 {
                return None;
            }
            JwtVerificationKey::from_ec_components(x, y).ok()
        }
    }
}

fn supported_algorithm(alg: Algorithm) -> Option<(&'static str, SupportedJwkAlgorithm)> {
    match alg {
        Algorithm::EdDSA => Some(("EdDSA", SupportedJwkAlgorithm::EdDsa)),
        Algorithm::RS256 => Some(("RS256", SupportedJwkAlgorithm::Rsa)),
        Algorithm::ES256 => Some(("ES256", SupportedJwkAlgorithm::Ec)),
        Algorithm::PS256 => Some(("PS256", SupportedJwkAlgorithm::Rsa)),
        _ => None,
    }
}

#[cfg(test)]
#[path = "../tests/unit/jwk.rs"]
mod tests;
