//! JWT key inspection and external signing-key registration CLI implementation.

use std::path::PathBuf;

use anyhow::{Context, bail};
use chrono::{DateTime, SecondsFormat, Utc};
use serde_json::{Value, json};

use crate::config::ConfigSource;
use crate::settings::Settings;
use crate::support::{
    reject_private_jwk_members, signing_algorithm_from_name, signing_algorithm_name,
    write_json_atomic,
};

pub async fn run(args: impl IntoIterator<Item = String>) -> anyhow::Result<()> {
    let mut args = args.into_iter();
    let _program = args.next();
    let Some(command) = args.next() else {
        bail!("usage: nazo-oauth-keyctl <list|register-external|validate>");
    };
    match command.as_str() {
        "list" => {
            let settings = load_settings()?;
            list_keys(&settings).await
        }
        "register-external" => {
            let options = parse_register_external_args(args.collect::<Vec<_>>())?;
            let settings = load_settings()?;
            register_external_key(&settings, options).await
        }
        "validate" => {
            let settings = load_settings()?;
            validate_keyset(&settings).await
        }
        _ => bail!("unknown keyctl command {command}"),
    }
}

fn load_settings() -> anyhow::Result<Settings> {
    let config = ConfigSource::load()?;
    Settings::from_config(&config)
}

async fn list_keys(settings: &Settings) -> anyhow::Result<()> {
    let keyset = load_keyset_json(settings).await?;
    let active_kid = active_kid(&keyset)?;
    let keys = keys_array(&keyset)?;
    for key in keys {
        let kid = key.get("kid").and_then(Value::as_str).unwrap_or("");
        let alg = key.get("alg").and_then(Value::as_str).unwrap_or("EdDSA");
        let backend = key
            .get("backend")
            .and_then(Value::as_str)
            .unwrap_or("local-pem");
        let locator = key
            .get("file")
            .or_else(|| key.get("key_ref"))
            .and_then(Value::as_str)
            .unwrap_or("");
        let retire_at = key.get("retire_at").and_then(Value::as_str).unwrap_or("");
        let status = if kid == active_kid {
            "active"
        } else if key_is_retired(key)? {
            "retired"
        } else if key_retire_at(key)?.is_some() {
            "grace"
        } else {
            "prepublished"
        };
        println!("{kid}\t{status}\t{alg}\t{backend}\t{locator}\t{retire_at}");
    }
    Ok(())
}

#[derive(Debug)]
struct RegisterExternalKeyOptions {
    kid: String,
    alg: jsonwebtoken::Algorithm,
    key_ref: String,
    public_jwk_file: PathBuf,
}

async fn register_external_key(
    settings: &Settings,
    options: RegisterExternalKeyOptions,
) -> anyhow::Result<()> {
    let alg_name = signing_algorithm_name(options.alg)
        .ok_or_else(|| anyhow::anyhow!("unsupported signing alg"))?;
    let public_jwk_raw = tokio::fs::read_to_string(&options.public_jwk_file)
        .await
        .with_context(|| format!("failed to read {}", options.public_jwk_file.display()))?;
    let public_jwk: Value = serde_json::from_str(&public_jwk_raw)
        .with_context(|| format!("failed to parse {}", options.public_jwk_file.display()))?;
    let mut keyset = if keyset_path(settings).exists() {
        load_keyset_json(settings).await?
    } else {
        json!({
            "active_kid": options.kid,
            "keys": []
        })
    };
    let entry = json!({
        "kid": options.kid,
        "alg": alg_name,
        "backend": "external-command",
        "key_ref": options.key_ref,
        "public_jwk": public_jwk,
        "created_at": Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
        "retire_at": null
    });
    keys_array_mut(&mut keyset)?.push(entry);
    validate_keyset_json(&keyset)?;
    write_json_atomic(&keyset_path(settings), &keyset).await?;
    println!("{}", options.kid);
    Ok(())
}

async fn validate_keyset(settings: &Settings) -> anyhow::Result<()> {
    nazo_key_management::KeyManager::validate(&settings.key_settings()).await?;
    println!("ok");
    Ok(())
}

async fn load_keyset_json(settings: &Settings) -> anyhow::Result<Value> {
    let path = keyset_path(settings);
    let raw = tokio::fs::read_to_string(&path)
        .await
        .with_context(|| format!("failed to read {}", path.display()))?;
    let value = serde_json::from_str(&raw)
        .with_context(|| format!("failed to parse {}", path.display()))?;
    validate_keyset_json(&value)?;
    Ok(value)
}

fn validate_keyset_json(value: &Value) -> anyhow::Result<()> {
    let active = active_kid(value)?;
    let mut seen = std::collections::HashSet::new();
    let mut active_exists = false;
    for key in keys_array(value)? {
        let kid = key
            .get("kid")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow::anyhow!("key entry missing kid"))?;
        if !seen.insert(kid) {
            bail!("duplicate key kid {kid}");
        }
        let backend = key
            .get("backend")
            .and_then(Value::as_str)
            .unwrap_or("local-pem");
        let alg = key.get("alg").and_then(Value::as_str).unwrap_or("EdDSA");
        if signing_algorithm_from_name(alg).is_none() {
            bail!("key {kid} has unsupported alg {alg}");
        }
        match backend {
            "local-pem" => {
                if key.get("file").and_then(Value::as_str).is_none() {
                    bail!("key {kid} missing file");
                }
            }
            "external-command" => {
                if key.get("key_ref").and_then(Value::as_str).is_none() {
                    bail!("key {kid} missing key_ref");
                }
                if key.get("public_jwk").and_then(Value::as_object).is_none() {
                    bail!("key {kid} missing public_jwk");
                }
                validate_public_jwk_metadata(key, kid, alg)?;
            }
            _ => bail!("key {kid} has unsupported backend {backend}"),
        }
        if kid == active {
            active_exists = true;
            if key_retire_at(key)?.is_some() {
                bail!("active key {kid} cannot have retire_at");
            }
            continue;
        }
        let _ = key_retire_at(key)?;
    }
    if !active_exists {
        bail!("active key {active} does not exist");
    }
    Ok(())
}

fn parse_register_external_args(args: Vec<String>) -> anyhow::Result<RegisterExternalKeyOptions> {
    let mut kid = None;
    let mut alg = None;
    let mut key_ref = None;
    let mut public_jwk_file = None;
    let mut iter = args.into_iter();
    while let Some(flag) = iter.next() {
        let value = iter
            .next()
            .ok_or_else(|| anyhow::anyhow!("missing value for {flag}"))?;
        match flag.as_str() {
            "--kid" => kid = Some(value),
            "--alg" => {
                alg = Some(
                    signing_algorithm_from_name(&value)
                        .ok_or_else(|| anyhow::anyhow!("unsupported signing alg {value}"))?,
                );
            }
            "--key-ref" => key_ref = Some(value),
            "--public-jwk" => public_jwk_file = Some(PathBuf::from(value)),
            _ => bail!("unknown register-external option {flag}"),
        }
    }
    Ok(RegisterExternalKeyOptions {
        kid: kid.ok_or_else(|| anyhow::anyhow!("register-external requires --kid"))?,
        alg: alg.ok_or_else(|| anyhow::anyhow!("register-external requires --alg"))?,
        key_ref: key_ref.ok_or_else(|| anyhow::anyhow!("register-external requires --key-ref"))?,
        public_jwk_file: public_jwk_file
            .ok_or_else(|| anyhow::anyhow!("register-external requires --public-jwk"))?,
    })
}

fn validate_public_jwk_metadata(key: &Value, kid: &str, alg: &str) -> anyhow::Result<()> {
    let public_jwk = key
        .get("public_jwk")
        .and_then(Value::as_object)
        .ok_or_else(|| anyhow::anyhow!("key {kid} missing public_jwk"))?;
    if public_jwk
        .get("kid")
        .and_then(Value::as_str)
        .is_some_and(|value| value != kid)
    {
        bail!("key {kid} public_jwk kid mismatch");
    }
    if public_jwk
        .get("alg")
        .and_then(Value::as_str)
        .is_some_and(|value| value != alg)
    {
        bail!("key {kid} public_jwk alg mismatch");
    }
    if public_jwk
        .get("use")
        .and_then(Value::as_str)
        .is_some_and(|value| value != "sig")
    {
        bail!("key {kid} public_jwk use must be sig");
    }
    reject_private_jwk_members(public_jwk)?;
    Ok(())
}

fn keyset_path(settings: &Settings) -> PathBuf {
    settings.jwk_keys_dir.join("keyset.json")
}

fn active_kid(value: &Value) -> anyhow::Result<&str> {
    value
        .get("active_kid")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("keyset.json missing active_kid"))
}

fn keys_array(value: &Value) -> anyhow::Result<&Vec<Value>> {
    value
        .get("keys")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow::anyhow!("keyset.json missing keys array"))
}

fn keys_array_mut(value: &mut Value) -> anyhow::Result<&mut Vec<Value>> {
    value
        .get_mut("keys")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| anyhow::anyhow!("keyset.json missing keys array"))
}

fn key_retire_at(key: &Value) -> anyhow::Result<Option<DateTime<Utc>>> {
    let Some(value) = key.get("retire_at") else {
        return Ok(None);
    };
    if value.is_null() {
        return Ok(None);
    }
    let raw = value
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("key retire_at must be RFC3339 or null"))?;
    let retire_at = DateTime::parse_from_rfc3339(raw)
        .with_context(|| format!("key retire_at is not RFC3339: {raw}"))?
        .with_timezone(&Utc);
    Ok(Some(retire_at))
}

fn key_is_retired(key: &Value) -> anyhow::Result<bool> {
    Ok(key_retire_at(key)?.is_some_and(|retire_at| retire_at <= Utc::now()))
}

#[cfg(test)]
#[path = "../tests/in_source/src/keyctl/tests/keyctl.rs"]
mod tests;
