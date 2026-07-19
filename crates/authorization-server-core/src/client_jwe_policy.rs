use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::Value;

pub const SUPPORTED_CLIENT_JWE_KEY_MANAGEMENT_ALGS: &[&str] = &[
    "RSA-OAEP-256",
    "ECDH-ES",
    "ECDH-ES+A128KW",
    "ECDH-ES+A256KW",
];
pub const SUPPORTED_CLIENT_JWE_CONTENT_ENC_ALGS: &[&str] = &["A256GCM"];
pub const RSA_PUBLIC_KEY_MIN_BITS: usize = 2_048;
pub const RSA_PUBLIC_KEY_MAX_BITS: usize = 8_192;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClientJweKeyManagement {
    RsaOaep256,
    EcdhEsDirect,
    EcdhEsA128Kw,
    EcdhEsA256Kw,
}

impl ClientJweKeyManagement {
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::RsaOaep256 => "RSA-OAEP-256",
            Self::EcdhEsDirect => "ECDH-ES",
            Self::EcdhEsA128Kw => "ECDH-ES+A128KW",
            Self::EcdhEsA256Kw => "ECDH-ES+A256KW",
        }
    }
}

#[must_use]
pub fn client_jwe_key_management_from_name(value: &str) -> Option<ClientJweKeyManagement> {
    match value {
        "RSA-OAEP-256" => Some(ClientJweKeyManagement::RsaOaep256),
        "ECDH-ES" => Some(ClientJweKeyManagement::EcdhEsDirect),
        "ECDH-ES+A128KW" => Some(ClientJweKeyManagement::EcdhEsA128Kw),
        "ECDH-ES+A256KW" => Some(ClientJweKeyManagement::EcdhEsA256Kw),
        _ => None,
    }
}

#[must_use]
pub fn client_jwe_encryption_key_matches_alg(key: &Value, alg: &str) -> bool {
    key.get("use").and_then(Value::as_str) == Some("enc")
        && key.get("alg").and_then(Value::as_str) == Some(alg)
        && match client_jwe_key_management_from_name(alg) {
            Some(ClientJweKeyManagement::RsaOaep256) => valid_rsa_jwe_encryption_key(key),
            Some(
                ClientJweKeyManagement::EcdhEsDirect
                | ClientJweKeyManagement::EcdhEsA128Kw
                | ClientJweKeyManagement::EcdhEsA256Kw,
            ) => valid_p256_jwe_encryption_key(key),
            None => false,
        }
}

#[must_use]
pub fn valid_rsa_jwe_encryption_key(key: &Value) -> bool {
    if key.get("kty").and_then(Value::as_str) != Some("RSA") || key.get("d").is_some() {
        return false;
    }
    let Some(n) = key.get("n").and_then(Value::as_str) else {
        return false;
    };
    let Some(e) = key.get("e").and_then(Value::as_str) else {
        return false;
    };
    let Ok(modulus) = URL_SAFE_NO_PAD.decode(n) else {
        return false;
    };
    let Ok(exponent) = URL_SAFE_NO_PAD.decode(e) else {
        return false;
    };
    rsa_public_key_components_are_safe(&modulus, &exponent)
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

#[must_use]
pub fn valid_p256_jwe_encryption_key(key: &Value) -> bool {
    if key.get("kty").and_then(Value::as_str) != Some("EC")
        || key.get("crv").and_then(Value::as_str) != Some("P-256")
        || key.get("d").is_some()
    {
        return false;
    }
    let Some(x) = key.get("x").and_then(Value::as_str) else {
        return false;
    };
    let Some(y) = key.get("y").and_then(Value::as_str) else {
        return false;
    };
    let Ok(x) = URL_SAFE_NO_PAD.decode(x) else {
        return false;
    };
    let Ok(y) = URL_SAFE_NO_PAD.decode(y) else {
        return false;
    };
    if x.len() != 32 || y.len() != 32 {
        return false;
    }
    let mut point = [0_u8; 65];
    point[0] = 4;
    point[1..33].copy_from_slice(&x);
    point[33..].copy_from_slice(&y);
    p256::PublicKey::from_sec1_bytes(&point).is_ok()
}
