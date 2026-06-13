use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use jsonwebtoken::{Algorithm, DecodingKey};
use serde_json::Value;

pub(super) fn decoding_key(key: &Value, alg: Algorithm) -> Option<DecodingKey> {
    let expected_alg = algorithm_name(alg)?;
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
    match alg {
        Algorithm::EdDSA => {
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
            DecodingKey::from_ed_components(x).ok()
        }
        Algorithm::RS256 | Algorithm::PS256 => {
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
            DecodingKey::from_rsa_components(n, e).ok()
        }
        Algorithm::ES256 => {
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
            DecodingKey::from_ec_components(x, y).ok()
        }
        _ => None,
    }
}

pub(super) fn algorithm_name(alg: Algorithm) -> Option<&'static str> {
    match alg {
        Algorithm::EdDSA => Some("EdDSA"),
        Algorithm::RS256 => Some("RS256"),
        Algorithm::ES256 => Some("ES256"),
        Algorithm::PS256 => Some("PS256"),
        _ => None,
    }
}
