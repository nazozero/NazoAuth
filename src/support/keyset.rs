//! JWT JWK/PEM 密钥管理。
// 负责加载、生成和编码 OAuth/OIDC 签名密钥。

use std::io::ErrorKind;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, anyhow};
use jsonwebtoken::jwk::{Jwk, PublicKeyUse};
use openssl::rsa::Rsa;
use p256::elliptic_curve::pkcs8::EncodePrivateKey as EncodeEcPrivateKey;
use rand_core::OsRng;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::Command;
use tokio::time;

use super::prelude::*;

pub(crate) async fn load_or_create_keyset(settings: &Settings) -> anyhow::Result<Keyset> {
    tokio::fs::create_dir_all(&settings.jwk_keys_dir).await?;
    let keyset_path = settings.jwk_keys_dir.join("keyset.json");
    if let Some(keyset) = try_load_keyset(settings, &keyset_path).await? {
        Ok(keyset)
    } else {
        create_new_keyset(settings).await
    }
}

pub(crate) async fn try_load_keyset(
    settings: &Settings,
    keyset_path: &PathBuf,
) -> anyhow::Result<Option<Keyset>> {
    let raw = match tokio::fs::read_to_string(keyset_path).await {
        Ok(raw) => raw,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error).with_context(|| format!("failed to read {}", keyset_path.display()));
        }
    };
    let payload = serde_json::from_str::<Value>(&raw)
        .with_context(|| format!("failed to parse {}", keyset_path.display()))?;
    let active_kid = payload
        .get("active_kid")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("keyset.json missing active_kid"))?;
    let keys = payload
        .get("keys")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("keyset.json missing keys array"))?;
    let mut active_signing_key = None;
    let mut active_alg = None;
    let mut seen_kids = std::collections::HashSet::new();
    let mut verification_keys = Vec::new();

    for entry in keys {
        let kid = entry
            .get("kid")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("keyset entry missing kid"))?;
        if !seen_kids.insert(kid) {
            anyhow::bail!("keyset.json contains duplicate kid {kid}");
        }
        let is_active = kid == active_kid;
        if key_entry_is_retired(entry) {
            if is_active {
                anyhow::bail!("keyset.json active key {kid} is retired");
            }
            continue;
        }

        let alg = key_entry_algorithm(entry)
            .with_context(|| format!("keyset entry {kid} has unsupported alg"))?;
        let backend = key_entry_backend(entry);
        let (public_jwk, signing_key) = match backend {
            "local-pem" => {
                let file_name = entry
                    .get("file")
                    .and_then(Value::as_str)
                    .ok_or_else(|| anyhow!("keyset entry {kid} missing file"))?;
                let raw_key = tokio::fs::read_to_string(settings.jwk_keys_dir.join(file_name))
                    .await
                    .with_context(|| {
                        format!("failed to read keyset entry {kid} from {file_name}")
                    })?;
                let der = pem_to_der(&raw_key)
                    .with_context(|| format!("keyset entry {kid} is not valid PEM"))?;
                let public_jwk =
                    public_jwk_from_private_der(kid, alg, &der).with_context(|| {
                        format!("keyset entry {kid} private key does not match alg")
                    })?;
                (public_jwk, Some(ActiveSigningKey::LocalPkcs8Der(der)))
            }
            "external-command" => {
                let public_jwk = external_public_jwk(entry)
                    .with_context(|| format!("keyset entry {kid} missing public_jwk"))?;
                let key_ref = entry
                    .get("key_ref")
                    .and_then(Value::as_str)
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .ok_or_else(|| anyhow!("keyset entry {kid} missing key_ref"))?;
                let signing_key = if is_active {
                    if settings.signing_external_command.is_empty() {
                        anyhow::bail!(
                            "SIGNING_EXTERNAL_COMMAND is required for active external-command key {kid}"
                        );
                    }
                    Some(ActiveSigningKey::ExternalCommand(ExternalSigningKey {
                        command: Arc::new(settings.signing_external_command.clone()),
                        key_ref: key_ref.to_owned(),
                        timeout: Duration::from_millis(settings.signing_external_timeout_ms),
                    }))
                } else {
                    None
                };
                (public_jwk, signing_key)
            }
            _ => anyhow::bail!("keyset entry {kid} has unsupported backend {backend}"),
        };
        if is_active {
            active_signing_key = signing_key;
            active_alg = Some(alg);
        }
        verification_keys.push(VerificationKey {
            kid: kid.to_owned(),
            public_jwk,
        });
    }

    Ok(Some(Keyset {
        active_kid: active_kid.to_owned(),
        active_alg: active_alg
            .ok_or_else(|| anyhow!("keyset.json active_kid does not reference a live key"))?,
        active_signing_key: active_signing_key
            .ok_or_else(|| anyhow!("keyset.json active_kid does not reference a live key"))?,
        verification_keys,
    }))
}

pub(crate) async fn create_new_keyset(settings: &Settings) -> anyhow::Result<Keyset> {
    let generated = generate_key_material(jsonwebtoken::Algorithm::RS256)?;
    let private_pkcs8_der = generated.private_pkcs8_der;
    let kid = format!("rs256-{}", Uuid::now_v7());
    let file_name = format!("{kid}.pem");
    let pem = der_to_pem(&private_pkcs8_der, "PRIVATE KEY");
    write_private_key_pem_atomic(&settings.jwk_keys_dir.join(&file_name), &pem).await?;
    let now = Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let payload = json!({
        "active_kid": kid,
        "keys": [{
            "kid": kid,
            "alg": "RS256",
            "file": file_name,
            "created_at": now,
            "retire_at": null
        }]
    });
    write_json_atomic(&settings.jwk_keys_dir.join("keyset.json"), &payload).await?;
    let public_jwk =
        public_jwk_from_private_der(&kid, jsonwebtoken::Algorithm::RS256, &private_pkcs8_der)?;
    Ok(Keyset {
        active_kid: kid.clone(),
        active_alg: jsonwebtoken::Algorithm::RS256,
        active_signing_key: ActiveSigningKey::LocalPkcs8Der(private_pkcs8_der),
        verification_keys: vec![VerificationKey { kid, public_jwk }],
    })
}

pub(crate) async fn write_json_atomic(path: &Path, value: &Value) -> anyhow::Result<()> {
    let body = serde_json::to_string_pretty(value)?;
    write_file_atomic(path, body.as_bytes()).await
}

pub(crate) async fn write_private_key_pem_atomic(path: &Path, pem: &str) -> anyhow::Result<()> {
    write_file_atomic(path, pem.as_bytes()).await?;
    set_private_key_permissions(path).await
}

async fn write_file_atomic(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("target file must have a parent directory"))?;
    tokio::fs::create_dir_all(parent).await?;
    let tmp_path = parent.join(format!(
        ".{}.{}.tmp",
        path.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("keyset"),
        Uuid::now_v7()
    ));
    tokio::fs::write(&tmp_path, bytes).await?;
    tokio::fs::rename(&tmp_path, path).await.with_context(|| {
        format!(
            "failed to atomically rename {} to {}",
            tmp_path.display(),
            path.display()
        )
    })?;
    Ok(())
}

#[cfg(unix)]
async fn set_private_key_permissions(path: &Path) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let permissions = std::fs::Permissions::from_mode(0o600);
    tokio::fs::set_permissions(path, permissions).await?;
    Ok(())
}

#[cfg(not(unix))]
async fn set_private_key_permissions(_path: &Path) -> anyhow::Result<()> {
    Ok(())
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
            Rsa::generate(2048)?.private_key_to_der()?
        }
        jsonwebtoken::Algorithm::ES256 => {
            let secret_key = p256::SecretKey::random(&mut OsRng);
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

pub(crate) fn signing_algorithm_name(alg: jsonwebtoken::Algorithm) -> Option<&'static str> {
    match alg {
        jsonwebtoken::Algorithm::EdDSA => Some("EdDSA"),
        jsonwebtoken::Algorithm::RS256 => Some("RS256"),
        jsonwebtoken::Algorithm::ES256 => Some("ES256"),
        jsonwebtoken::Algorithm::PS256 => Some("PS256"),
        _ => None,
    }
}

pub(crate) fn signing_algorithm_from_name(value: &str) -> Option<jsonwebtoken::Algorithm> {
    match value {
        "EdDSA" => Some(jsonwebtoken::Algorithm::EdDSA),
        "RS256" => Some(jsonwebtoken::Algorithm::RS256),
        "ES256" => Some(jsonwebtoken::Algorithm::ES256),
        "PS256" => Some(jsonwebtoken::Algorithm::PS256),
        _ => None,
    }
}

fn key_entry_algorithm(entry: &Value) -> anyhow::Result<jsonwebtoken::Algorithm> {
    entry
        .get("alg")
        .and_then(Value::as_str)
        .map(signing_algorithm_from_name)
        .unwrap_or(Some(jsonwebtoken::Algorithm::EdDSA))
        .ok_or_else(|| anyhow!("unsupported signing alg"))
}

fn key_entry_backend(entry: &Value) -> &str {
    entry
        .get("backend")
        .and_then(Value::as_str)
        .unwrap_or("local-pem")
}

fn external_public_jwk(entry: &Value) -> anyhow::Result<Value> {
    let kid = entry
        .get("kid")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("key entry missing kid"))?;
    let alg = entry.get("alg").and_then(Value::as_str).unwrap_or("EdDSA");
    let jwk = entry
        .get("public_jwk")
        .and_then(Value::as_object)
        .ok_or_else(|| anyhow!("public_jwk must be an object"))?;
    let mut jwk = Value::Object(jwk.clone());
    match jwk.get("kid").and_then(Value::as_str) {
        Some(value) if value != kid => anyhow::bail!("public_jwk kid does not match key entry"),
        Some(_) => {}
        None => jwk["kid"] = json!(kid),
    }
    match jwk.get("alg").and_then(Value::as_str) {
        Some(value) if value != alg => anyhow::bail!("public_jwk alg does not match key entry"),
        Some(_) => {}
        None => jwk["alg"] = json!(alg),
    }
    match jwk.get("use").and_then(Value::as_str) {
        Some("sig") => {}
        Some(_) => anyhow::bail!("public_jwk use must be sig"),
        None => jwk["use"] = json!("sig"),
    }
    Ok(jwk)
}

fn key_entry_is_retired(entry: &Value) -> bool {
    entry
        .get("retire_at")
        .and_then(Value::as_str)
        .and_then(|value| chrono::DateTime::parse_from_rfc3339(value).ok())
        .is_some_and(|retire_at| retire_at.with_timezone(&Utc) <= Utc::now())
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

impl Keyset {
    pub(crate) fn jwks(&self) -> Value {
        let keys = self
            .verification_keys
            .iter()
            .map(|key| key.public_jwk.clone())
            .collect::<Vec<_>>();
        json!({
            "keys": keys
        })
    }

    pub(crate) fn verification_key(&self, kid: &str) -> Option<&VerificationKey> {
        self.verification_keys.iter().find(|key| key.kid == kid)
    }

    pub(crate) async fn sign_jwt<T: Serialize>(
        &self,
        header: &jsonwebtoken::Header,
        claims: &T,
    ) -> jsonwebtoken::errors::Result<String> {
        if header.alg != self.active_alg || header.kid.as_deref() != Some(&self.active_kid) {
            return Err(jsonwebtoken::errors::ErrorKind::InvalidAlgorithm.into());
        }
        let encoded_header = URL_SAFE_NO_PAD.encode(serde_json::to_vec(header)?);
        let encoded_claims = URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims)?);
        let signing_input = format!("{encoded_header}.{encoded_claims}");
        let signature = match &self.active_signing_key {
            ActiveSigningKey::LocalPkcs8Der(private_pkcs8_der) => {
                sign_local_jwt_input(self.active_alg, private_pkcs8_der, signing_input.as_bytes())?
            }
            ActiveSigningKey::ExternalCommand(external) => {
                sign_external_jwt_input(
                    external,
                    &self.active_kid,
                    self.active_alg,
                    signing_input.as_str(),
                )
                .await?
            }
        };
        Ok(format!("{signing_input}.{signature}"))
    }
}

fn sign_local_jwt_input(
    alg: jsonwebtoken::Algorithm,
    private_pkcs8_der: &[u8],
    signing_input: &[u8],
) -> jsonwebtoken::errors::Result<String> {
    let key = match alg {
        jsonwebtoken::Algorithm::EdDSA => jsonwebtoken::EncodingKey::from_ed_der(private_pkcs8_der),
        jsonwebtoken::Algorithm::RS256 | jsonwebtoken::Algorithm::PS256 => {
            jsonwebtoken::EncodingKey::from_rsa_der(private_pkcs8_der)
        }
        jsonwebtoken::Algorithm::ES256 => jsonwebtoken::EncodingKey::from_ec_der(private_pkcs8_der),
        _ => return Err(jsonwebtoken::errors::ErrorKind::InvalidAlgorithm.into()),
    };
    jsonwebtoken::crypto::sign(signing_input, &key, alg)
}

async fn sign_external_jwt_input(
    external: &ExternalSigningKey,
    kid: &str,
    alg: jsonwebtoken::Algorithm,
    signing_input: &str,
) -> jsonwebtoken::errors::Result<String> {
    let alg_name =
        signing_algorithm_name(alg).ok_or(jsonwebtoken::errors::ErrorKind::InvalidAlgorithm)?;
    let request = json!({
        "version": 1,
        "kid": kid,
        "alg": alg_name,
        "key_ref": external.key_ref,
        "signing_input": signing_input
    });
    let mut child = Command::new(
        external
            .command
            .as_slice()
            .first()
            .ok_or_else(|| jwt_provider_error("external signer command is empty"))?,
    )
    .args(external.command.iter().skip(1))
    .stdin(std::process::Stdio::piped())
    .stdout(std::process::Stdio::piped())
    .stderr(std::process::Stdio::piped())
    .spawn()
    .map_err(|error| jwt_provider_error(format!("failed to spawn external signer: {error}")))?;
    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| jwt_provider_error("external signer stdin unavailable"))?;
    let mut stdout = child
        .stdout
        .take()
        .ok_or_else(|| jwt_provider_error("external signer stdout unavailable"))?;
    let mut stderr = child
        .stderr
        .take()
        .ok_or_else(|| jwt_provider_error("external signer stderr unavailable"))?;
    let stdout_task = tokio::spawn(async move {
        let mut output = Vec::new();
        stdout.read_to_end(&mut output).await.map(|_| output)
    });
    let stderr_task = tokio::spawn(async move {
        let mut output = Vec::new();
        stderr.read_to_end(&mut output).await.map(|_| output)
    });
    stdin
        .write_all(serde_json::to_string(&request)?.as_bytes())
        .await
        .map_err(|error| {
            jwt_provider_error(format!("failed to write external signer request: {error}"))
        })?;
    drop(stdin);
    let status = match time::timeout(external.timeout, child.wait()).await {
        Ok(result) => result
            .map_err(|error| jwt_provider_error(format!("external signer failed: {error}")))?,
        Err(_) => {
            let _ = child.kill().await;
            return Err(jwt_provider_error("external signer timed out"));
        }
    };
    let stdout = stdout_task
        .await
        .map_err(|error| {
            jwt_provider_error(format!("external signer stdout join failed: {error}"))
        })?
        .map_err(|error| jwt_provider_error(format!("external signer failed: {error}")))?;
    let stderr = stderr_task
        .await
        .map_err(|error| {
            jwt_provider_error(format!("external signer stderr join failed: {error}"))
        })?
        .map_err(|error| jwt_provider_error(format!("external signer failed: {error}")))?;
    if !status.success() {
        return Err(jwt_provider_error(format!(
            "external signer exited with status {}: {}",
            status,
            String::from_utf8_lossy(&stderr)
        )));
    }
    let response: Value = serde_json::from_slice(&stdout)?;
    let signature = response
        .get("signature")
        .and_then(Value::as_str)
        .ok_or_else(|| jwt_provider_error("external signer response missing signature"))?;
    let decoded = URL_SAFE_NO_PAD.decode(signature).map_err(|error| {
        jwt_provider_error(format!(
            "external signer returned invalid signature: {error}"
        ))
    })?;
    if decoded.is_empty() {
        return Err(jwt_provider_error(
            "external signer returned empty signature",
        ));
    }
    Ok(signature.to_owned())
}

fn jwt_provider_error(message: impl Into<String>) -> jsonwebtoken::errors::Error {
    jsonwebtoken::errors::ErrorKind::Provider(message.into()).into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use std::path::PathBuf;

    use crate::settings::{EmailDelivery, EmailSettings, RateLimitSettings};
    use crate::support::ClientIpHeaderMode;

    #[test]
    fn jwks_publishes_active_and_previous_verification_keys() {
        let active_der = ed25519_pkcs8_private_der(&[1u8; 32]);
        let previous_der = ed25519_pkcs8_private_der(&[2u8; 32]);
        let keyset = Keyset {
            active_kid: "active".to_owned(),
            active_alg: jsonwebtoken::Algorithm::EdDSA,
            active_signing_key: ActiveSigningKey::LocalPkcs8Der(active_der.clone()),
            verification_keys: vec![
                VerificationKey {
                    kid: "active".to_owned(),
                    public_jwk: public_jwk_from_private_der(
                        "active",
                        jsonwebtoken::Algorithm::EdDSA,
                        &active_der,
                    )
                    .unwrap(),
                },
                VerificationKey {
                    kid: "previous".to_owned(),
                    public_jwk: public_jwk_from_private_der(
                        "previous",
                        jsonwebtoken::Algorithm::EdDSA,
                        &previous_der,
                    )
                    .unwrap(),
                },
            ],
        };

        let jwks = keyset.jwks();
        assert_eq!(jwks["keys"].as_array().unwrap().len(), 2);
        assert!(keyset.verification_key("previous").is_some());
    }

    #[test]
    fn retired_non_active_key_entries_are_detected() {
        let retired = json!({"retire_at": "2000-01-01T00:00:00Z"});
        let live = json!({"retire_at": "2999-01-01T00:00:00Z"});

        assert!(key_entry_is_retired(&retired));
        assert!(!key_entry_is_retired(&live));
    }

    proptest! {
        #[test]
        fn ed25519_pkcs8_seed_roundtrips_through_der(seed in any::<[u8; 32]>()) {
            let der = ed25519_pkcs8_private_der(&seed);

            prop_assert_eq!(ed25519_seed_from_pkcs8(&der), Some(seed));
            prop_assert!(public_jwk_from_private_der(
                "kid-1",
                jsonwebtoken::Algorithm::EdDSA,
                &der
            ).is_ok());
        }

        #[test]
        fn pem_der_roundtrip_preserves_key_material(seed in any::<[u8; 32]>()) {
            let der = ed25519_pkcs8_private_der(&seed);
            let pem = der_to_pem(&der, "PRIVATE KEY");
            let decoded = pem_to_der(&pem);

            prop_assert_eq!(decoded.as_deref(), Some(der.as_slice()));
        }

        #[test]
        fn unsupported_keyset_algorithms_are_rejected(alg in "[A-Z0-9]{1,12}") {
            prop_assume!(!matches!(alg.as_str(), "EdDSA" | "RS256" | "ES256" | "PS256"));
            let entry = json!({"alg": alg});

            prop_assert!(key_entry_algorithm(&entry).is_err());
        }
    }

    #[tokio::test]
    async fn missing_keyset_file_allows_initial_creation() {
        let keys_dir = temp_keys_dir("missing");
        tokio::fs::create_dir_all(&keys_dir).await.unwrap();
        let settings = test_settings(keys_dir.clone());
        let keyset_path = keys_dir.join("keyset.json");

        let result = try_load_keyset(&settings, &keyset_path).await.unwrap();
        let _ = tokio::fs::remove_dir_all(&keys_dir).await;

        assert!(result.is_none());
    }

    #[tokio::test]
    async fn created_keyset_uses_oidc_mandatory_default_signing_alg() {
        let keys_dir = temp_keys_dir("create_default_alg");
        tokio::fs::create_dir_all(&keys_dir).await.unwrap();
        let settings = test_settings(keys_dir.clone());

        let keyset = create_new_keyset(&settings).await.unwrap();
        let keyset_json = tokio::fs::read_to_string(keys_dir.join("keyset.json"))
            .await
            .unwrap();
        let payload: Value = serde_json::from_str(&keyset_json).unwrap();
        let _ = tokio::fs::remove_dir_all(&keys_dir).await;

        assert!(keyset.active_kid.starts_with("rs256-"));
        assert_eq!(keyset.active_alg, jsonwebtoken::Algorithm::RS256);
        assert_eq!(payload["keys"][0]["alg"], "RS256");
        assert_eq!(keyset.jwks()["keys"][0]["alg"], "RS256");
    }

    #[tokio::test]
    async fn duplicate_keyset_kids_are_rejected() {
        let keys_dir = temp_keys_dir("duplicate_kid");
        tokio::fs::create_dir_all(&keys_dir).await.unwrap();
        let first_der = ed25519_pkcs8_private_der(&[1u8; 32]);
        let second_der = ed25519_pkcs8_private_der(&[2u8; 32]);
        tokio::fs::write(
            keys_dir.join("first.pem"),
            der_to_pem(&first_der, "PRIVATE KEY"),
        )
        .await
        .unwrap();
        tokio::fs::write(
            keys_dir.join("second.pem"),
            der_to_pem(&second_der, "PRIVATE KEY"),
        )
        .await
        .unwrap();
        tokio::fs::write(
            keys_dir.join("keyset.json"),
            serde_json::to_string_pretty(&json!({
                "active_kid": "duplicate",
                "keys": [
                    {"kid": "duplicate", "file": "first.pem", "retire_at": null},
                    {"kid": "duplicate", "file": "second.pem", "retire_at": null}
                ]
            }))
            .unwrap(),
        )
        .await
        .unwrap();
        let settings = test_settings(keys_dir.clone());
        let keyset_path = keys_dir.join("keyset.json");

        let result = try_load_keyset(&settings, &keyset_path).await;
        let _ = tokio::fs::remove_dir_all(&keys_dir).await;

        match result {
            Ok(_) => panic!("duplicate keyset kid should be rejected"),
            Err(error) => assert!(format!("{error:#}").contains("duplicate kid duplicate")),
        }
    }

    #[tokio::test]
    async fn live_previous_key_entry_must_load_successfully() {
        let keys_dir = temp_keys_dir("missing_previous");
        tokio::fs::create_dir_all(&keys_dir).await.unwrap();
        let active_der = ed25519_pkcs8_private_der(&[1u8; 32]);
        tokio::fs::write(
            keys_dir.join("active.pem"),
            der_to_pem(&active_der, "PRIVATE KEY"),
        )
        .await
        .unwrap();
        tokio::fs::write(
            keys_dir.join("keyset.json"),
            serde_json::to_string_pretty(&json!({
                "active_kid": "active",
                "keys": [
                    {"kid": "active", "file": "active.pem", "retire_at": null},
                    {"kid": "previous", "file": "missing.pem", "retire_at": null}
                ]
            }))
            .unwrap(),
        )
        .await
        .unwrap();
        let settings = test_settings(keys_dir.clone());
        let keyset_path = keys_dir.join("keyset.json");

        let result = try_load_keyset(&settings, &keyset_path).await;
        let _ = tokio::fs::remove_dir_all(&keys_dir).await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn retired_previous_key_entry_is_skipped() {
        let keys_dir = temp_keys_dir("retired_previous");
        tokio::fs::create_dir_all(&keys_dir).await.unwrap();
        let active_der = ed25519_pkcs8_private_der(&[1u8; 32]);
        tokio::fs::write(
            keys_dir.join("active.pem"),
            der_to_pem(&active_der, "PRIVATE KEY"),
        )
        .await
        .unwrap();
        tokio::fs::write(
            keys_dir.join("keyset.json"),
            serde_json::to_string_pretty(&json!({
                "active_kid": "active",
                "keys": [
                    {"kid": "active", "file": "active.pem", "retire_at": null},
                    {
                        "kid": "previous",
                        "file": "missing.pem",
                        "retire_at": "2000-01-01T00:00:00Z"
                    }
                ]
            }))
            .unwrap(),
        )
        .await
        .unwrap();
        let settings = test_settings(keys_dir.clone());
        let keyset_path = keys_dir.join("keyset.json");

        let keyset = try_load_keyset(&settings, &keyset_path)
            .await
            .unwrap()
            .unwrap();
        let _ = tokio::fs::remove_dir_all(&keys_dir).await;

        assert_eq!(keyset.active_kid, "active");
        assert_eq!(keyset.verification_keys.len(), 1);
    }

    #[tokio::test]
    async fn retired_active_key_entry_is_rejected() {
        let keys_dir = temp_keys_dir("retired_active");
        tokio::fs::create_dir_all(&keys_dir).await.unwrap();
        let active_der = ed25519_pkcs8_private_der(&[1u8; 32]);
        tokio::fs::write(
            keys_dir.join("active.pem"),
            der_to_pem(&active_der, "PRIVATE KEY"),
        )
        .await
        .unwrap();
        tokio::fs::write(
            keys_dir.join("keyset.json"),
            serde_json::to_string_pretty(&json!({
                "active_kid": "active",
                "keys": [
                    {
                        "kid": "active",
                        "file": "active.pem",
                        "retire_at": "2000-01-01T00:00:00Z"
                    }
                ]
            }))
            .unwrap(),
        )
        .await
        .unwrap();
        let settings = test_settings(keys_dir.clone());
        let keyset_path = keys_dir.join("keyset.json");

        let result = try_load_keyset(&settings, &keyset_path).await;
        let _ = tokio::fs::remove_dir_all(&keys_dir).await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn active_external_command_key_requires_signer_command() {
        let keys_dir = temp_keys_dir("external_missing_command");
        tokio::fs::create_dir_all(&keys_dir).await.unwrap();
        let active_der = generate_key_material(jsonwebtoken::Algorithm::RS256)
            .unwrap()
            .private_pkcs8_der;
        let public_jwk = public_jwk_from_private_der(
            "external-active",
            jsonwebtoken::Algorithm::RS256,
            &active_der,
        )
        .unwrap();
        tokio::fs::write(
            keys_dir.join("keyset.json"),
            serde_json::to_string_pretty(&json!({
                "active_kid": "external-active",
                "keys": [{
                    "kid": "external-active",
                    "alg": "RS256",
                    "backend": "external-command",
                    "key_ref": "kms://tenant/signing/external-active",
                    "public_jwk": public_jwk,
                    "retire_at": null
                }]
            }))
            .unwrap(),
        )
        .await
        .unwrap();
        let settings = test_settings(keys_dir.clone());
        let keyset_path = keys_dir.join("keyset.json");

        let result = try_load_keyset(&settings, &keyset_path).await;
        let _ = tokio::fs::remove_dir_all(&keys_dir).await;

        match result {
            Ok(_) => panic!("active external-command key without command should fail"),
            Err(error) => assert!(format!("{error:#}").contains("SIGNING_EXTERNAL_COMMAND")),
        }
    }

    #[tokio::test]
    async fn external_command_signer_produces_verifiable_jwt() {
        let keys_dir = temp_keys_dir("external_signer");
        tokio::fs::create_dir_all(&keys_dir).await.unwrap();
        let active_der = generate_key_material(jsonwebtoken::Algorithm::RS256)
            .unwrap()
            .private_pkcs8_der;
        let private_pem = der_to_pem(&active_der, "RSA PRIVATE KEY");
        let public_jwk = public_jwk_from_private_der(
            "external-active",
            jsonwebtoken::Algorithm::RS256,
            &active_der,
        )
        .unwrap();
        let private_key_path = keys_dir.join("external-active.pem");
        tokio::fs::write(&private_key_path, &private_pem)
            .await
            .unwrap();
        let signer = keys_dir.join("signer.sh");
        tokio::fs::write(
            &signer,
            r#"#!/bin/sh
set -eu
key_file="$1"
request=$(cat)
signing_input=$(printf '%s' "$request" | sed -n 's/.*"signing_input":"\([^"]*\)".*/\1/p')
signature=$(printf '%s' "$signing_input" | openssl dgst -sha256 -sign "$key_file" -binary | openssl base64 -A | tr '+/' '-_' | tr -d '=')
printf '{"signature":"%s"}' "$signature"
"#
            ,
        )
        .await
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            tokio::fs::set_permissions(&signer, std::fs::Permissions::from_mode(0o700))
                .await
                .unwrap();
        }
        tokio::fs::write(
            keys_dir.join("keyset.json"),
            serde_json::to_string_pretty(&json!({
                "active_kid": "external-active",
                "keys": [{
                    "kid": "external-active",
                    "alg": "RS256",
                    "backend": "external-command",
                    "key_ref": "test-ed25519",
                    "public_jwk": public_jwk,
                    "retire_at": null
                }]
            }))
            .unwrap(),
        )
        .await
        .unwrap();
        let mut settings = test_settings(keys_dir.clone());
        settings.signing_external_command = vec![
            signer.display().to_string(),
            private_key_path.display().to_string(),
        ];
        let keyset_path = keys_dir.join("keyset.json");
        let keyset = try_load_keyset(&settings, &keyset_path)
            .await
            .unwrap()
            .unwrap();
        let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
        header.kid = Some("external-active".to_owned());
        let claims = json!({"sub": "subject-1", "exp": 4_102_444_800_i64});

        let token = keyset.sign_jwt(&header, &claims).await.unwrap();
        let decoding_key =
            crate::support::jwt_decoding_key_from_jwk(&keyset.jwks()["keys"][0], header.alg)
                .unwrap();
        let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256);
        validation.validate_exp = false;
        let decoded = jsonwebtoken::decode::<Value>(&token, &decoding_key, &validation).unwrap();
        let _ = tokio::fs::remove_dir_all(&keys_dir).await;

        assert_eq!(decoded.claims["sub"], "subject-1");
    }

    fn temp_keys_dir(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "nazo_keyset_{label}_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    fn test_settings(jwk_keys_dir: PathBuf) -> Settings {
        Settings {
            issuer: "https://issuer.example".to_owned(),
            mtls_endpoint_base_url: "https://issuer.example".to_owned(),
            frontend_base_url: "https://frontend.example".to_owned(),
            cors_allowed_origins: vec!["https://frontend.example".to_owned()],
            default_audience: "resource://default".to_owned(),
            authorization_server_profile:
                crate::settings::AuthorizationServerProfile::Oauth2Baseline,
            dpop_nonce_policy: crate::settings::DpopNoncePolicy::Required,
            request_object_jti_policy: crate::settings::RequestObjectJtiPolicy::Optional,
            session_cookie_name: "session".to_owned(),
            csrf_cookie_name: "csrf".to_owned(),
            cookie_secure: true,
            session_ttl_seconds: 28_800,
            auth_code_ttl_seconds: 300,
            access_token_ttl_seconds: 300,
            id_token_ttl_seconds: 600,
            refresh_token_ttl_seconds: 2_592_000,
            avatar_max_bytes: 2_097_152,
            client_delivery_ttl_seconds: 86_400,
            rate_limit: RateLimitSettings {
                window_seconds: 60,
                auth_max_requests: 30,
                token_max_requests: 60,
                token_management_max_requests: 120,
            },
            email: EmailSettings {
                delivery: EmailDelivery::Disabled,
                code_ttl_seconds: 900,
                send_cooldown_seconds: 60,
                send_peer_cooldown_seconds: 5,
            },
            email_code_dev_response_enabled: false,
            avatar_storage_dir: jwk_keys_dir.join("avatars"),
            jwk_keys_dir,
            signing_external_command: Vec::new(),
            signing_external_timeout_ms: 2_000,
            trusted_proxy_cidrs: Vec::new(),
            client_ip_header_mode: ClientIpHeaderMode::None,
            subject_type: crate::settings::SubjectType::Public,
            pairwise_subject_secret: None,
            par_ttl_seconds: 90,
            require_pushed_authorization_requests: false,
        }
    }
}
