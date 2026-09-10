//! Database-keyset payload encoding and validation helpers.

use std::collections::BTreeSet;

use anyhow::{Context, anyhow};
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use chrono::{DateTime, Utc};
use ed25519_dalek::SigningKey;
use jsonwebtoken::jwk::{Jwk, PublicKeyUse};
use nazo_auth::SigningPurpose;
use p256::elliptic_curve::{Generate, pkcs8::EncodePrivateKey as EncodeEcPrivateKey};
use serde_json::{Value, json};

pub(crate) const KEYSET_SCHEMA_VERSION: &str = "nazo.keyset.v1";

pub(crate) fn key_entry_purposes(
    entry: &Value,
) -> anyhow::Result<Option<BTreeSet<SigningPurpose>>> {
    let Some(raw) = entry.get("purposes") else {
        return Ok(None);
    };
    let values = raw
        .as_array()
        .ok_or_else(|| anyhow!("purposes must be an array"))?;
    if values.is_empty() {
        anyhow::bail!("purposes must not be empty");
    }
    let mut purposes = BTreeSet::new();
    for value in values {
        let name = value
            .as_str()
            .ok_or_else(|| anyhow!("purpose names must be strings"))?;
        let purpose = SigningPurpose::from_name(name)
            .ok_or_else(|| anyhow!("unsupported signing purpose {name}"))?;
        if !purposes.insert(purpose) {
            anyhow::bail!("duplicate signing purpose {name}");
        }
    }
    Ok(Some(purposes))
}

pub(crate) struct GeneratedKeyMaterial {
    pub(crate) private_pkcs8_der: Vec<u8>,
}

pub(crate) fn generate_key_material(
    alg: jsonwebtoken::Algorithm,
) -> anyhow::Result<GeneratedKeyMaterial> {
    let private_pkcs8_der = match alg {
        jsonwebtoken::Algorithm::EdDSA => {
            let seed: [u8; 32] = rand::random();
            ed25519_pkcs8_private_der(&seed)
        }
        jsonwebtoken::Algorithm::RS256 | jsonwebtoken::Algorithm::PS256 => {
            crate::crypto::generate_rsa_pkcs1_der(2048)?
        }
        jsonwebtoken::Algorithm::ES256 => {
            let secret_key = p256::SecretKey::try_generate()?;
            secret_key.to_pkcs8_der()?.as_bytes().to_vec()
        }
        _ => anyhow::bail!("unsupported server signing alg"),
    };
    Ok(GeneratedKeyMaterial { private_pkcs8_der })
}

fn public_key_from_ed_private_der(private_pkcs8_der: &[u8]) -> Option<[u8; 32]> {
    let seed = ed25519_seed_from_pkcs8(private_pkcs8_der)?;
    Some(SigningKey::from_bytes(&seed).verifying_key().to_bytes())
}

pub(crate) fn public_jwk_from_private_der(
    kid: &str,
    alg: jsonwebtoken::Algorithm,
    private_pkcs8_der: &[u8],
) -> anyhow::Result<Value> {
    let mut jwk = match alg {
        jsonwebtoken::Algorithm::EdDSA => {
            let public_key = public_key_from_ed_private_der(private_pkcs8_der)
                .ok_or_else(|| anyhow!("invalid Ed25519 private key"))?;
            json!({
                "kty": "OKP",
                "crv": "Ed25519",
                "x": URL_SAFE_NO_PAD.encode(public_key),
                "use": "sig",
                "alg": "EdDSA",
                "kid": kid
            })
        }
        jsonwebtoken::Algorithm::RS256 | jsonwebtoken::Algorithm::PS256 => {
            public_jwk_from_encoding_key(
                kid,
                alg,
                &jsonwebtoken::EncodingKey::from_rsa_der(private_pkcs8_der),
            )?
        }
        jsonwebtoken::Algorithm::ES256 => public_jwk_from_encoding_key(
            kid,
            alg,
            &jsonwebtoken::EncodingKey::from_ec_der(private_pkcs8_der),
        )?,
        _ => anyhow::bail!("unsupported server signing alg"),
    };
    jwk["kid"] = json!(kid);
    jwk["use"] = json!("sig");
    Ok(jwk)
}

fn public_jwk_from_encoding_key(
    kid: &str,
    alg: jsonwebtoken::Algorithm,
    encoding_key: &jsonwebtoken::EncodingKey,
) -> anyhow::Result<Value> {
    let mut jwk = Jwk::from_encoding_key(encoding_key, alg)?;
    jwk.common.key_id = Some(kid.to_owned());
    jwk.common.public_key_use = Some(PublicKeyUse::Signature);
    Ok(serde_json::to_value(jwk)?)
}

pub fn signing_algorithm_name(alg: jsonwebtoken::Algorithm) -> Option<&'static str> {
    match alg {
        jsonwebtoken::Algorithm::EdDSA => Some("EdDSA"),
        jsonwebtoken::Algorithm::RS256 => Some("RS256"),
        jsonwebtoken::Algorithm::ES256 => Some("ES256"),
        jsonwebtoken::Algorithm::PS256 => Some("PS256"),
        _ => None,
    }
}

pub fn signing_algorithm_from_name(value: &str) -> Option<jsonwebtoken::Algorithm> {
    match value {
        "EdDSA" => Some(jsonwebtoken::Algorithm::EdDSA),
        "RS256" => Some(jsonwebtoken::Algorithm::RS256),
        "ES256" => Some(jsonwebtoken::Algorithm::ES256),
        "PS256" => Some(jsonwebtoken::Algorithm::PS256),
        _ => None,
    }
}

pub(crate) fn key_entry_algorithm(entry: &Value) -> anyhow::Result<jsonwebtoken::Algorithm> {
    let value = entry
        .get("alg")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("key entry missing alg"))?;
    signing_algorithm_from_name(value)
        .ok_or_else(|| anyhow!("key entry has unsupported alg {value}"))
}

pub(crate) fn reject_private_jwk_members(
    jwk: &serde_json::Map<String, Value>,
) -> anyhow::Result<()> {
    const PRIVATE_JWK_MEMBERS: &[&str] = &["d", "p", "q", "dp", "dq", "qi", "oth", "k"];
    if let Some(member) = PRIVATE_JWK_MEMBERS
        .iter()
        .find(|member| jwk.contains_key(**member))
    {
        anyhow::bail!(
            "public_jwk must not contain private or symmetric key material member {member}"
        );
    }
    Ok(())
}

pub(crate) fn external_public_jwk(entry: &Value) -> anyhow::Result<Value> {
    let kid = entry
        .get("kid")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("key entry missing kid"))?;
    let alg = entry
        .get("alg")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("key {kid} missing alg"))?;
    let jwk = entry
        .get("public_jwk")
        .and_then(Value::as_object)
        .ok_or_else(|| anyhow!("public_jwk must be an object"))?;
    reject_private_jwk_members(jwk)?;
    let jwk = Value::Object(jwk.clone());
    match jwk.get("kid").and_then(Value::as_str) {
        Some(value) if value != kid => anyhow::bail!("public_jwk kid does not match key entry"),
        Some(_) => {}
        None => anyhow::bail!("public_jwk missing kid"),
    }
    match jwk.get("alg").and_then(Value::as_str) {
        Some(value) if value != alg => anyhow::bail!("public_jwk alg does not match key entry"),
        Some(_) => {}
        None => anyhow::bail!("public_jwk missing alg"),
    }
    match jwk.get("use").and_then(Value::as_str) {
        Some("sig") => {}
        Some(_) => anyhow::bail!("public_jwk use must be sig"),
        None => anyhow::bail!("public_jwk missing use"),
    }
    Ok(jwk)
}

pub(crate) fn key_entry_retire_at(entry: &Value) -> anyhow::Result<Option<DateTime<Utc>>> {
    let value = entry
        .get("retire_at")
        .ok_or_else(|| anyhow!("key entry missing retire_at"))?;
    if value.is_null() {
        return Ok(None);
    }
    let raw = value
        .as_str()
        .ok_or_else(|| anyhow!("retire_at must be RFC3339 or null"))?;
    let retire_at = DateTime::parse_from_rfc3339(raw)
        .with_context(|| format!("retire_at is not RFC3339: {raw}"))?
        .with_timezone(&Utc);
    Ok(Some(retire_at))
}

pub(crate) fn key_entry_created_at(entry: &Value) -> anyhow::Result<DateTime<Utc>> {
    let value = entry
        .get("created_at")
        .ok_or_else(|| anyhow!("key entry missing created_at"))?;
    let raw = value
        .as_str()
        .ok_or_else(|| anyhow!("created_at must be RFC3339"))?;
    let created_at = DateTime::parse_from_rfc3339(raw)
        .with_context(|| format!("created_at is not RFC3339: {raw}"))?
        .with_timezone(&Utc);
    Ok(created_at)
}

pub(crate) fn ed25519_pkcs8_private_der(seed: &[u8; 32]) -> Vec<u8> {
    let mut der = Vec::with_capacity(48);
    der.extend_from_slice(&[
        0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04,
        0x20,
    ]);
    der.extend_from_slice(seed);
    der
}

pub(crate) fn ed25519_seed_from_pkcs8(der: &[u8]) -> Option<[u8; 32]> {
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

pub(crate) fn der_to_pem(der: &[u8], label: &str) -> String {
    let encoded = STANDARD.encode(der);
    let mut pem = format!("-----BEGIN {label}-----\n");
    for chunk in encoded.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(chunk).unwrap_or_default());
        pem.push('\n');
    }
    pem.push_str(&format!("-----END {label}-----\n"));
    pem
}

pub(crate) fn pem_to_der(pem: &str) -> Option<Vec<u8>> {
    let body: String = pem
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .map(str::trim)
        .collect();
    STANDARD.decode(body).ok()
}
