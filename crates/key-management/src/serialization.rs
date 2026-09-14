//! Database-keyset payload encoding and validation helpers.

use std::collections::BTreeSet;

use anyhow::{Context, anyhow};
use base64::{Engine, engine::general_purpose::STANDARD};
use chrono::{DateTime, Utc};
use nazo_auth::SigningPurpose;
use nazo_crypto::jwt::Algorithm;
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

pub(crate) fn generate_key_material(alg: Algorithm) -> anyhow::Result<GeneratedKeyMaterial> {
    Ok(GeneratedKeyMaterial {
        private_pkcs8_der: nazo_crypto::signature::generate_private_key(alg)?,
    })
}

pub(crate) fn public_jwk_from_private_der(
    kid: &str,
    alg: Algorithm,
    private_pkcs8_der: &[u8],
) -> anyhow::Result<Value> {
    let name =
        signing_algorithm_name(alg).ok_or_else(|| anyhow!("unsupported server signing alg"))?;
    let mut jwk = nazo_crypto::signature::public_jwk(alg, private_pkcs8_der)?;
    jwk["kid"] = json!(kid);
    jwk["use"] = json!("sig");
    jwk["alg"] = json!(name);
    Ok(jwk)
}

pub fn signing_algorithm_name(alg: Algorithm) -> Option<&'static str> {
    match alg {
        Algorithm::EdDSA => Some("EdDSA"),
        Algorithm::RS256 => Some("RS256"),
        Algorithm::ES256 => Some("ES256"),
        Algorithm::PS256 => Some("PS256"),
        _ => None,
    }
}

pub fn signing_algorithm_from_name(value: &str) -> Option<Algorithm> {
    match value {
        "EdDSA" => Some(Algorithm::EdDSA),
        "RS256" => Some(Algorithm::RS256),
        "ES256" => Some(Algorithm::ES256),
        "PS256" => Some(Algorithm::PS256),
        _ => None,
    }
}

pub(crate) fn key_entry_algorithm(entry: &Value) -> anyhow::Result<Algorithm> {
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

pub(crate) fn generate_rsa_pkcs8_pem(bits: usize) -> anyhow::Result<Vec<u8>> {
    let der = nazo_crypto::key_wrap::generate_rsa_pkcs8_der(bits)?;
    Ok(pem::encode(&pem::Pem::new("PRIVATE KEY", der)).into_bytes())
}

pub(crate) fn rsa_pkcs8_from_pem(value: &[u8]) -> anyhow::Result<Vec<u8>> {
    let pem = pem::parse(value).context("invalid private key PEM")?;
    if pem.tag() != "PRIVATE KEY" {
        return Err(anyhow!("RSA private key must use PKCS#8 PRIVATE KEY PEM"));
    }
    Ok(pem.into_contents())
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
