//! Ed25519 key rotation CLI implementation.

use std::path::PathBuf;

use anyhow::{Context, bail};
use chrono::{SecondsFormat, Utc};
use serde_json::{Value, json};
use uuid::Uuid;

use crate::config::ConfigSource;
use crate::settings::Settings;
use crate::support::{
    create_new_keyset, der_to_pem, ed25519_pkcs8_private_der, try_load_keyset, write_json_atomic,
    write_private_key_pem_atomic,
};

pub async fn run(args: impl IntoIterator<Item = String>) -> anyhow::Result<()> {
    let mut args = args.into_iter();
    let _program = args.next();
    let Some(command) = args.next() else {
        bail!("usage: nazo-oauth-keyctl <list|generate|activate|retire|validate>");
    };
    let config = ConfigSource::load()?;
    let settings = Settings::from_config(&config)?;
    match command.as_str() {
        "list" => list_keys(&settings).await,
        "generate" => generate_key(&settings).await,
        "activate" => {
            let kid = args
                .next()
                .ok_or_else(|| anyhow::anyhow!("usage: nazo-oauth-keyctl activate <kid>"))?;
            activate_key(&settings, &kid).await
        }
        "retire" => {
            let kid = args.next().ok_or_else(|| {
                anyhow::anyhow!("usage: nazo-oauth-keyctl retire <kid> --at <rfc3339>")
            })?;
            let flag = args.next().ok_or_else(|| {
                anyhow::anyhow!("usage: nazo-oauth-keyctl retire <kid> --at <rfc3339>")
            })?;
            if flag != "--at" {
                bail!("usage: nazo-oauth-keyctl retire <kid> --at <rfc3339>");
            }
            let at = args.next().ok_or_else(|| {
                anyhow::anyhow!("usage: nazo-oauth-keyctl retire <kid> --at <rfc3339>")
            })?;
            retire_key(&settings, &kid, &at).await
        }
        "validate" => validate_keyset(&settings).await,
        _ => bail!("unknown keyctl command {command}"),
    }
}

async fn list_keys(settings: &Settings) -> anyhow::Result<()> {
    let keyset = load_keyset_json(settings).await?;
    let active_kid = active_kid(&keyset)?;
    let keys = keys_array(&keyset)?;
    for key in keys {
        let kid = key.get("kid").and_then(Value::as_str).unwrap_or("");
        let file = key.get("file").and_then(Value::as_str).unwrap_or("");
        let retire_at = key.get("retire_at").and_then(Value::as_str).unwrap_or("");
        let status = if kid == active_kid {
            "active"
        } else if key_is_retired(key) {
            "retired"
        } else {
            "previous"
        };
        println!("{kid}\t{status}\t{file}\t{retire_at}");
    }
    Ok(())
}

async fn generate_key(settings: &Settings) -> anyhow::Result<()> {
    if !keyset_path(settings).exists() {
        let keyset = create_new_keyset(settings).await?;
        println!("{}", keyset.active_kid);
        return Ok(());
    }

    let mut keyset = load_keyset_json(settings).await?;
    let kid = format!("ed25519-{}", Uuid::now_v7());
    let file_name = format!("{kid}.pem");
    let private_pkcs8_der = ed25519_pkcs8_private_der(&rand::random());
    let pem = der_to_pem(&private_pkcs8_der, "PRIVATE KEY");
    write_private_key_pem_atomic(&settings.jwk_keys_dir.join(&file_name), &pem).await?;
    let entry = json!({
        "kid": kid,
        "file": file_name,
        "created_at": Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
        "retire_at": null
    });
    keys_array_mut(&mut keyset)?.push(entry);
    validate_keyset_json(&keyset)?;
    write_json_atomic(&keyset_path(settings), &keyset).await?;
    println!("{kid}");
    Ok(())
}

async fn activate_key(settings: &Settings, kid: &str) -> anyhow::Result<()> {
    let mut keyset = load_keyset_json(settings).await?;
    let key = keys_array(&keyset)?
        .iter()
        .find(|key| key.get("kid").and_then(Value::as_str) == Some(kid))
        .ok_or_else(|| anyhow::anyhow!("key {kid} does not exist"))?;
    if key_is_retired(key) {
        bail!("retired key {kid} cannot be activated");
    }
    keyset["active_kid"] = json!(kid);
    validate_keyset_json(&keyset)?;
    write_json_atomic(&keyset_path(settings), &keyset).await?;
    println!("{kid}");
    Ok(())
}

async fn retire_key(settings: &Settings, kid: &str, at: &str) -> anyhow::Result<()> {
    chrono::DateTime::parse_from_rfc3339(at).context("--at must be RFC3339")?;
    let mut keyset = load_keyset_json(settings).await?;
    if active_kid(&keyset)? == kid {
        bail!("active key {kid} cannot be retired");
    }
    let key = keys_array_mut(&mut keyset)?
        .iter_mut()
        .find(|key| key.get("kid").and_then(Value::as_str) == Some(kid))
        .ok_or_else(|| anyhow::anyhow!("key {kid} does not exist"))?;
    key["retire_at"] = json!(at);
    validate_keyset_json(&keyset)?;
    write_json_atomic(&keyset_path(settings), &keyset).await?;
    println!("{kid}");
    Ok(())
}

async fn validate_keyset(settings: &Settings) -> anyhow::Result<()> {
    if try_load_keyset(settings, &keyset_path(settings))
        .await?
        .is_none()
    {
        bail!("keyset.json does not exist");
    }
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
        if key.get("file").and_then(Value::as_str).is_none() {
            bail!("key {kid} missing file");
        }
        if kid == active {
            active_exists = true;
            if key_is_retired(key) {
                bail!("active key {kid} cannot be retired");
            }
        }
    }
    if !active_exists {
        bail!("active key {active} does not exist");
    }
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

fn key_is_retired(key: &Value) -> bool {
    key.get("retire_at")
        .and_then(Value::as_str)
        .and_then(|value| chrono::DateTime::parse_from_rfc3339(value).ok())
        .is_some_and(|retire_at| retire_at.with_timezone(&Utc) <= Utc::now())
}
