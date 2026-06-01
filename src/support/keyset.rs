//! JWT JWK/PEM 密钥管理。
// 负责加载、生成和编码 OAuth/OIDC 签名密钥。

use std::io::ErrorKind;
use std::path::Path;

use anyhow::{Context, anyhow};
use jsonwebtoken::jwk::{Jwk, PublicKeyUse};
use p256::elliptic_curve::pkcs8::EncodePrivateKey as EncodeEcPrivateKey;
use rand_core::OsRng;
use rsa::RsaPrivateKey;

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
    let mut active_private_pkcs8_der = None;
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

        let file_name = entry
            .get("file")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("keyset entry {kid} missing file"))?;
        let raw_key = tokio::fs::read_to_string(settings.jwk_keys_dir.join(file_name))
            .await
            .with_context(|| format!("failed to read keyset entry {kid} from {file_name}"))?;
        let alg = key_entry_algorithm(entry)
            .with_context(|| format!("keyset entry {kid} has unsupported alg"))?;
        let der =
            pem_to_der(&raw_key).with_context(|| format!("keyset entry {kid} is not valid PEM"))?;
        let public_jwk = public_jwk_from_private_der(kid, alg, &der)
            .with_context(|| format!("keyset entry {kid} private key does not match alg"))?;
        if is_active {
            active_private_pkcs8_der = Some(der);
            active_alg = Some(alg);
        }
        verification_keys.push(VerificationKey {
            kid: kid.to_owned(),
            alg,
            public_jwk,
        });
    }

    Ok(Some(Keyset {
        active_kid: active_kid.to_owned(),
        active_alg: active_alg
            .ok_or_else(|| anyhow!("keyset.json active_kid does not reference a live key"))?,
        active_private_pkcs8_der: active_private_pkcs8_der
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
        active_private_pkcs8_der: private_pkcs8_der,
        verification_keys: vec![VerificationKey {
            kid,
            alg: jsonwebtoken::Algorithm::RS256,
            public_jwk,
        }],
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
            let private_key = RsaPrivateKey::new(&mut OsRng, 2048)?;
            private_key.to_pkcs8_der()?.as_bytes().to_vec()
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

fn public_jwk_from_private_der(
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

    pub(crate) fn active_encoding_key(&self) -> jsonwebtoken::EncodingKey {
        match self.active_alg {
            jsonwebtoken::Algorithm::EdDSA => {
                jsonwebtoken::EncodingKey::from_ed_der(&self.active_private_pkcs8_der)
            }
            jsonwebtoken::Algorithm::RS256 | jsonwebtoken::Algorithm::PS256 => {
                jsonwebtoken::EncodingKey::from_rsa_der(&self.active_private_pkcs8_der)
            }
            jsonwebtoken::Algorithm::ES256 => {
                jsonwebtoken::EncodingKey::from_ec_der(&self.active_private_pkcs8_der)
            }
            _ => unreachable!("active signing algorithm is validated during keyset loading"),
        }
    }

    pub(crate) fn signing_alg_values_supported(&self) -> Vec<&'static str> {
        let mut values = self
            .verification_keys
            .iter()
            .filter_map(|key| signing_algorithm_name(key.alg))
            .collect::<Vec<_>>();
        values.sort_unstable();
        values.dedup();
        values
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
            active_private_pkcs8_der: active_der.clone(),
            verification_keys: vec![
                VerificationKey {
                    kid: "active".to_owned(),
                    alg: jsonwebtoken::Algorithm::EdDSA,
                    public_jwk: public_jwk_from_private_der(
                        "active",
                        jsonwebtoken::Algorithm::EdDSA,
                        &active_der,
                    )
                    .unwrap(),
                },
                VerificationKey {
                    kid: "previous".to_owned(),
                    alg: jsonwebtoken::Algorithm::EdDSA,
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
            frontend_base_url: "https://frontend.example".to_owned(),
            cors_allowed_origins: vec!["https://frontend.example".to_owned()],
            default_audience: "resource://default".to_owned(),
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
            trusted_proxy_cidrs: Vec::new(),
            client_ip_header_mode: ClientIpHeaderMode::None,
            subject_type: crate::settings::SubjectType::Public,
            pairwise_subject_secret: None,
            par_ttl_seconds: 90,
            require_pushed_authorization_requests: false,
        }
    }
}
