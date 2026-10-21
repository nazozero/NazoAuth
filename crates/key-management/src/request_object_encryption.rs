use anyhow::{Context, anyhow};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::Deserialize;
use serde_json::Value;
use sha2::Digest as _;

use crate::KeyManager;

pub(crate) fn request_object_encryption_jwk(private_key_der: &[u8]) -> anyhow::Result<Value> {
    let (n, e, public_der) = nazo_crypto::key_wrap::rsa_public_components(private_key_der)?;
    let kid = format!(
        "request-object-{}",
        URL_SAFE_NO_PAD.encode(&sha2::Sha256::digest(&public_der)[..12])
    );
    Ok(serde_json::json!({
        "kty": "RSA",
        "use": "enc",
        "alg": "RSA-OAEP-256",
        "kid": kid,
        "n": URL_SAFE_NO_PAD.encode(n),
        "e": URL_SAFE_NO_PAD.encode(e)
    }))
}

#[derive(Clone)]
pub(crate) struct RetainedEncryptionKey {
    kid: String,
    key: std::sync::Arc<nazo_crypto::key_wrap::RsaOaep256PrivateKey>,
    retire_at: Option<chrono::DateTime<chrono::Utc>>,
}

fn private_key(pem: &Value) -> anyhow::Result<Vec<u8>> {
    let pem = URL_SAFE_NO_PAD.decode(
        pem.as_str()
            .ok_or_else(|| anyhow!("missing request object private key"))?,
    )?;
    crate::serialization::rsa_pkcs8_from_pem(&pem)
}

fn retained_entry(pem: Value, created_at: Value, retire_at: Value) -> anyhow::Result<Value> {
    let jwk = request_object_encryption_jwk(&private_key(&pem)?)?;
    Ok(
        serde_json::json!({"private_pem":pem, "kid":jwk["kid"], "created_at":created_at, "retire_at":retire_at}),
    )
}

pub(crate) fn load_retained_keys(payload: &Value) -> anyhow::Result<Vec<RetainedEncryptionKey>> {
    // TODO remove this legacy empty-ring read once every persisted keyset has
    // completed lifecycle maintenance with request_object_retained_keys present.
    let Some(entries) = payload.get("request_object_retained_keys") else {
        return Ok(Vec::new());
    };
    let now = chrono::Utc::now();
    let mut loaded = Vec::new();
    for entry in entries
        .as_array()
        .ok_or_else(|| anyhow!("invalid request object key ring"))?
    {
        let retire_at = crate::serialization::key_entry_retire_at(entry)?;
        if retire_at.is_some_and(|deadline| deadline <= now) {
            continue;
        }
        let der = private_key(&entry["private_pem"])?;
        let jwk = request_object_encryption_jwk(&der)?;
        let kid = jwk["kid"].as_str().unwrap().to_owned();
        if entry["kid"] != kid
            || loaded
                .iter()
                .any(|key: &RetainedEncryptionKey| key.kid == kid)
        {
            anyhow::bail!("invalid or duplicate retained request object kid");
        }
        loaded.push(RetainedEncryptionKey {
            kid,
            key: std::sync::Arc::new(nazo_crypto::key_wrap::RsaOaep256PrivateKey::from_pkcs8(
                &der,
            )?),
            retire_at,
        });
    }
    Ok(loaded)
}

pub(crate) fn next_encryption_check(
    payload: &Value,
    settings: &crate::KeySettings,
) -> anyhow::Result<Option<chrono::DateTime<chrono::Utc>>> {
    let Some(created) = payload.get("request_object_created_at") else {
        return Ok(Some(chrono::Utc::now()));
    };
    let due = created
        .as_str()
        .ok_or_else(|| anyhow!("invalid request object creation time"))?
        .parse::<chrono::DateTime<chrono::Utc>>()?
        + settings.rotation_interval;
    let entries = payload["request_object_retained_keys"]
        .as_array()
        .ok_or_else(|| anyhow!("invalid request object key ring"))?;
    let mut candidate = None;
    let mut retirement = None;
    let now = chrono::Utc::now();
    for entry in entries {
        match crate::serialization::key_entry_retire_at(entry)? {
            Some(time) if time > now => {
                retirement = Some(
                    retirement.map_or(time, |existing: chrono::DateTime<chrono::Utc>| {
                        existing.min(time)
                    }),
                )
            }
            Some(_) => {}
            None => {
                if candidate
                    .replace(crate::serialization::key_entry_created_at(entry)?)
                    .is_some()
                {
                    anyhow::bail!("duplicate pending request object key");
                }
            }
        }
    }
    let rotation = candidate.map_or(due - settings.prepublish_window, |created| {
        due.max(created + settings.prepublish_window)
    });
    Ok(Some(retirement.map_or(rotation, |time| time.min(rotation))))
}

pub(crate) fn maintain_encryption_keys(
    payload: &mut Value,
    settings: &crate::KeySettings,
) -> anyhow::Result<bool> {
    use crate::serialization::{key_entry_created_at, key_entry_retire_at};
    use chrono::Utc;
    use serde_json::json;
    let now = Utc::now();
    let mut changed = false;
    if payload.get("request_object_created_at").is_none() {
        // The old format has no creation time. Start its rotation schedule at
        // this durable migration boundary rather than inventing a historical age.
        payload["request_object_created_at"] = json!(now.to_rfc3339());
        payload["request_object_retained_keys"] = json!([]);
        changed = true;
    }
    let due = payload["request_object_created_at"]
        .as_str()
        .ok_or_else(|| anyhow!("invalid request object creation time"))?
        .parse::<chrono::DateTime<Utc>>()?
        + settings.rotation_interval;
    let entries = payload["request_object_retained_keys"]
        .as_array()
        .ok_or_else(|| anyhow!("invalid request object key ring"))?;
    let candidate = entries
        .iter()
        .position(|entry| entry["retire_at"].is_null());
    if let Some(index) = candidate {
        if now >= due && now >= key_entry_created_at(&entries[index])? + settings.prepublish_window
        {
            let old = retained_entry(
                payload["request_object_private_pem"].clone(),
                payload["request_object_created_at"].clone(),
                json!(
                    (now + settings.verification_grace
                        + crate::lifecycle::MAX_DATABASE_SNAPSHOT_STALENESS)
                        .to_rfc3339()
                ),
            )?;
            let mut candidate = payload["request_object_retained_keys"]
                .as_array_mut()
                .unwrap()
                .remove(index);
            payload["request_object_private_pem"] = candidate["private_pem"].take();
            payload["request_object_created_at"] = candidate["created_at"].take();
            payload["request_object_retained_keys"]
                .as_array_mut()
                .unwrap()
                .push(old);
            changed = true;
        }
    } else if now >= due - settings.prepublish_window {
        let candidate = retained_entry(
            json!(URL_SAFE_NO_PAD.encode(crate::serialization::generate_rsa_pkcs8_pem(3072)?)),
            json!(now.to_rfc3339()),
            Value::Null,
        )?;
        payload["request_object_retained_keys"]
            .as_array_mut()
            .unwrap()
            .push(candidate);
        changed = true;
    }
    for entry in payload["request_object_retained_keys"]
        .as_array_mut()
        .unwrap()
    {
        if key_entry_retire_at(entry)?.is_some_and(|deadline| deadline <= now) {
            changed |= entry
                .as_object_mut()
                .unwrap()
                .remove("private_pem")
                .is_some();
        }
    }
    Ok(changed)
}

#[derive(Deserialize)]
struct ProtectedHeader {
    alg: String,
    enc: String,
    kid: Option<String>,
    cty: Option<String>,
    #[serde(
        rename = "crit",
        default,
        deserialize_with = "nazo_crypto::deserialize_present_header"
    )]
    critical_extension_present: bool,
}

impl KeyManager {
    /// Decrypts an RSA-OAEP-256/A256GCM Request Object and returns the nested JWT.
    ///
    /// The dedicated recipient key is intentionally separate from protocol
    /// signing keys. Reusing a signing key here would collapse two independent
    /// key purposes and make rotation or external signing unsafe.
    pub fn decrypt_request_object(&self, compact: &str) -> anyhow::Result<String> {
        let mut segments = compact.split('.');
        let protected = segments.next().expect("split always yields a segment");
        let encrypted_key = segments
            .next()
            .ok_or_else(|| anyhow!("missing encrypted key"))?;
        let iv = segments.next().ok_or_else(|| anyhow!("missing iv"))?;
        let ciphertext = segments
            .next()
            .ok_or_else(|| anyhow!("missing ciphertext"))?;
        let tag = segments
            .next()
            .ok_or_else(|| anyhow!("missing authentication tag"))?;
        if segments.next().is_some() {
            return Err(anyhow!("request object JWE must contain five segments"));
        }

        let header: ProtectedHeader = serde_json::from_slice(
            &URL_SAFE_NO_PAD
                .decode(protected)
                .context("invalid protected header encoding")?,
        )
        .context("invalid protected header")?;
        let generation = self.inner.generation.load();
        if generation.is_expired() || !self.is_healthy() {
            return Err(anyhow!("request object key lifecycle is unhealthy"));
        }
        let expected = &generation.loaded.request_object_encryption_jwk;
        if header.critical_extension_present
            || header.alg != "RSA-OAEP-256"
            || header.enc != "A256GCM"
            || header.cty.as_deref() != Some("JWT")
        {
            return Err(anyhow!("unsupported request object JWE header"));
        }

        let encrypted_key = URL_SAFE_NO_PAD
            .decode(encrypted_key)
            .context("invalid encrypted key encoding")?;
        // Without kid the currently advertised recipient is the default. A
        // cached prior recipient must identify its key during the grace period.
        let key = match header.kid.as_deref() {
            None => &generation.loaded.request_object_decryption_key,
            Some(kid) if expected["kid"].as_str() == Some(kid) => {
                &generation.loaded.request_object_decryption_key
            }
            Some(kid) => {
                &generation
                    .loaded
                    .request_object_retained_keys
                    .iter()
                    .find(|key| {
                        key.kid == kid
                            && key
                                .retire_at
                                .is_none_or(|deadline| deadline > chrono::Utc::now())
                    })
                    .ok_or_else(|| anyhow!("unsupported request object JWE recipient"))?
                    .key
            }
        };
        let cek = key
            .decrypt(&encrypted_key)
            .context("RSA-OAEP-256 decryption failed")?;
        if cek.len() != 32 {
            return Err(anyhow!(
                "request object content encryption key must be 256 bits"
            ));
        }

        let mut decoded_iv = [0_u8; 12];
        let iv_len = URL_SAFE_NO_PAD
            .decode_slice(iv, &mut decoded_iv)
            .context("invalid iv encoding or length")?;
        let mut plaintext = URL_SAFE_NO_PAD
            .decode(ciphertext)
            .context("invalid ciphertext encoding")?;
        let mut decoded_tag = [0_u8; 16];
        let tag_len = URL_SAFE_NO_PAD
            .decode_slice(tag, &mut decoded_tag)
            .context("invalid tag encoding or length")?;
        if iv_len != decoded_iv.len() || tag_len != decoded_tag.len() {
            return Err(anyhow!("invalid A256GCM iv or tag length"));
        }
        nazo_crypto::aead::decrypt_in_place(
            &cek,
            &decoded_iv,
            protected.as_bytes(),
            &mut plaintext,
            &decoded_tag,
        )
        .context("request object authentication failed")?;
        String::from_utf8(plaintext).context("request object plaintext is not UTF-8")
    }
}

#[cfg(test)]
#[path = "../tests/unit/request_object_encryption.rs"]
mod tests;
