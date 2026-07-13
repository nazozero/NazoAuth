//! OAuth 作用域、audience 与授权关系工具。
use crate::domain::ClientRow;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::Value;
// 只处理 OAuth 语义中的集合判断和授权记录 upsert。

use super::{
    mtls::certificate_x5c_thumbprint,
    security::{
        SUPPORTED_CLIENT_JWE_KEY_MANAGEMENT_ALGS, SUPPORTED_CLIENT_JWT_SIGNING_ALGS,
        client_jwt_algorithm_from_name, jwt_decoding_key_from_jwk,
        supported_client_jwt_algorithm_name,
    },
};
use nazo_auth::oauth_redirect_uri_matches;
pub(crate) use nazo_auth::{ResourceIndicatorError, parse_resource_indicators};

fn ensure_public_client_jwk(jwk: &serde_json::Map<String, Value>) -> anyhow::Result<()> {
    const PRIVATE_MEMBERS: &[&str] = &["d", "p", "q", "dp", "dq", "qi", "oth", "k"];
    if let Some(member) = PRIVATE_MEMBERS
        .iter()
        .find(|member| jwk.contains_key(**member))
    {
        anyhow::bail!(
            "public JWK must not contain private or symmetric key material member {member}"
        );
    }
    Ok(())
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum RedirectUriError {
    Missing,
    Invalid,
}

pub(crate) trait StringArraySource {
    fn strings(&self) -> Vec<String>;
}

impl StringArraySource for Value {
    fn strings(&self) -> Vec<String> {
        self.as_array()
            .map(|items| {
                items
                    .iter()
                    .filter_map(|value| value.as_str().map(ToOwned::to_owned))
                    .collect()
            })
            .unwrap_or_default()
    }
}

impl StringArraySource for Vec<String> {
    fn strings(&self) -> Vec<String> {
        self.clone()
    }
}

pub(crate) fn json_array_to_strings(value: &impl StringArraySource) -> Vec<String> {
    value.strings()
}

pub(crate) fn parse_scope(raw: &str) -> Vec<String> {
    raw.split_whitespace()
        .map(ToOwned::to_owned)
        .filter(|v| !v.is_empty())
        .collect()
}

pub(crate) fn resource_indicators_from_parameter_value(
    value: Option<&str>,
) -> Result<Vec<String>, ResourceIndicatorError> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    if let Ok(values) = serde_json::from_str::<Vec<String>>(value) {
        return parse_resource_indicators(&values);
    }
    parse_resource_indicators(&[value.to_owned()])
}

pub(crate) fn encoded_resource_indicators(values: &[String]) -> Option<String> {
    (!values.is_empty()).then(|| {
        serde_json::to_string(values).expect("resource indicator serialization must be infallible")
    })
}

pub(crate) fn is_subset(requested: &[String], allowed: &[String]) -> bool {
    requested.iter().all(|s| allowed.contains(s))
}

pub(crate) fn client_supports_grant(client: &ClientRow, grant_type: &str) -> bool {
    json_array_to_strings(&client.grant_types)
        .iter()
        .any(|grant| grant == grant_type)
}

pub(crate) fn audience_allowed(client: &ClientRow, audience: &str) -> bool {
    json_array_to_strings(&client.allowed_audiences)
        .iter()
        .any(|allowed| allowed == audience)
}

pub(crate) fn audiences_allowed(client: &ClientRow, audiences: &[String]) -> bool {
    !audiences.is_empty()
        && audiences
            .iter()
            .all(|audience| audience_allowed(client, audience))
}

pub(crate) fn token_audience_values(audience: &Value) -> Vec<String> {
    match audience {
        Value::String(value) => vec![value.clone()],
        Value::Array(values) => values
            .iter()
            .filter_map(|value| value.as_str().map(ToOwned::to_owned))
            .collect(),
        _ => Vec::new(),
    }
}

pub(crate) fn token_audience_contains(audience: &Value, expected: &str) -> bool {
    token_audience_values(audience)
        .iter()
        .any(|audience| audience == expected)
}

pub(crate) fn has_duplicate_oauth_parameter(raw_query: &str, parameter_names: &[&str]) -> bool {
    let mut seen = std::collections::HashSet::new();
    for (key, _) in url::form_urlencoded::parse(raw_query.as_bytes()) {
        if parameter_names.contains(&key.as_ref()) && !seen.insert(key.into_owned()) {
            return true;
        }
    }
    false
}

pub(crate) fn registered_redirect_uri(
    client: &ClientRow,
    requested_redirect_uri: Option<&str>,
) -> Result<String, RedirectUriError> {
    let registered = json_array_to_strings(&client.redirect_uris);
    if let Some(value) = requested_redirect_uri {
        return registered
            .iter()
            .any(|registered| oauth_redirect_uri_matches(&client.client_type, registered, value))
            .then(|| value.to_owned())
            .ok_or(RedirectUriError::Invalid);
    }
    match registered.as_slice() {
        [only] => Ok(only.clone()),
        _ => Err(RedirectUriError::Missing),
    }
}

pub(crate) fn is_valid_pkce_value(value: &str) -> bool {
    let len = value.len();
    (43..=128).contains(&len)
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~'))
}

pub(crate) fn client_jwks_matching_encryption_key_count(jwks: &Value, alg: &str) -> usize {
    jwks.get("keys")
        .and_then(Value::as_array)
        .map_or(0, |keys| {
            keys.iter()
                .filter(|key| {
                    key.get("use").and_then(Value::as_str) == Some("enc")
                        && key.get("alg").and_then(Value::as_str) == Some(alg)
                        && valid_rsa_jwe_encryption_key(key)
                })
                .count()
        })
}

pub(crate) fn client_jwks_contains_signing_key(jwks: &Value) -> bool {
    jwks.get("keys")
        .and_then(Value::as_array)
        .is_some_and(|keys| {
            keys.iter().any(|key| {
                let public_key_use = key.get("use").and_then(Value::as_str).unwrap_or("sig");
                let Some(alg) = key.get("alg").and_then(Value::as_str) else {
                    return false;
                };
                let Some(algorithm) = client_jwt_algorithm_from_name(alg) else {
                    return false;
                };
                public_key_use == "sig"
                    && supported_client_jwt_algorithm_name(algorithm) == Some(alg)
                    && jwt_decoding_key_from_jwk(key, algorithm).is_some()
            })
        })
}

#[cfg(test)]
pub(crate) fn validate_client_jwks(jwks: &Value) -> anyhow::Result<()> {
    validate_client_jwks_with_policy(
        jwks,
        ClientJwksValidationPolicy {
            allow_missing_kid: false,
        },
    )
}

struct ClientJwksValidationPolicy {
    allow_missing_kid: bool,
}

fn validate_client_jwks_with_policy(
    jwks: &Value,
    policy: ClientJwksValidationPolicy,
) -> anyhow::Result<()> {
    let keys = jwks
        .get("keys")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow::anyhow!("jwks 必须包含 keys 数组"))?;
    if keys.is_empty() {
        anyhow::bail!("jwks.keys 不能为空");
    }
    let mut seen_kids = std::collections::HashSet::new();
    let mut signing_key_count = 0usize;
    let mut kidless_signing_key_count = 0usize;
    for key in keys {
        let key_object = key
            .as_object()
            .ok_or_else(|| anyhow::anyhow!("jwks 公钥必须是 JSON object"))?;
        ensure_public_client_jwk(key_object)
            .map_err(|_| anyhow::anyhow!("jwks 不能包含私钥材料或对称密钥材料"))?;
        let kid = key.get("kid").and_then(Value::as_str).unwrap_or_default();
        let public_key_use = key.get("use").and_then(Value::as_str).unwrap_or("sig");
        if public_key_use == "sig" {
            signing_key_count += 1;
        }
        if kid.trim().is_empty() {
            if public_key_use == "enc" {
                anyhow::bail!("jwks 加密公钥必须包含 kid");
            }
            if !policy.allow_missing_kid {
                anyhow::bail!("jwks 公钥必须包含 kid");
            }
            kidless_signing_key_count += 1;
        } else if !seen_kids.insert(kid) {
            anyhow::bail!("jwks kid 不能重复: {kid}");
        }
        let Some(alg) = key.get("alg").and_then(Value::as_str) else {
            anyhow::bail!("jwks 公钥必须声明 alg");
        };
        match public_key_use {
            "sig" => {
                let Some(algorithm) = client_jwt_algorithm_from_name(alg) else {
                    anyhow::bail!(
                        "jwks alg 必须是 {} 或 {}",
                        SUPPORTED_CLIENT_JWT_SIGNING_ALGS.join(", "),
                        SUPPORTED_CLIENT_JWE_KEY_MANAGEMENT_ALGS.join(", ")
                    );
                };
                if supported_client_jwt_algorithm_name(algorithm) != Some(alg)
                    || jwt_decoding_key_from_jwk(key, algorithm).is_none()
                {
                    anyhow::bail!("jwks 公钥材料与 alg 不匹配");
                }
            }
            "enc" => {
                if !SUPPORTED_CLIENT_JWE_KEY_MANAGEMENT_ALGS.contains(&alg)
                    || !valid_rsa_jwe_encryption_key(key)
                {
                    anyhow::bail!("jwks 公钥材料与 alg 不匹配");
                }
            }
            _ => anyhow::bail!("jwks 公钥 use 必须为 sig 或 enc"),
        }
    }
    if kidless_signing_key_count > 0 && signing_key_count != 1 {
        anyhow::bail!("省略 kid 时 jwks 必须且只能包含一个签名公钥");
    }
    Ok(())
}

pub(crate) fn validate_client_jwks_with_missing_kid_policy(
    jwks: &Value,
    allow_missing_kid: bool,
) -> anyhow::Result<()> {
    validate_client_jwks_with_policy(jwks, ClientJwksValidationPolicy { allow_missing_kid })
}

fn valid_rsa_jwe_encryption_key(key: &Value) -> bool {
    if key.get("kty").and_then(Value::as_str) != Some("RSA") {
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
    modulus.len() >= 256 && !exponent.is_empty()
}

pub(crate) fn validate_self_signed_mtls_jwks(jwks: &Value) -> bool {
    jwks.get("keys")
        .and_then(Value::as_array)
        .is_some_and(|keys| {
            keys.iter().any(|key| {
                key.get("x5c")
                    .and_then(Value::as_array)
                    .and_then(|x5c| x5c.as_slice().first())
                    .and_then(Value::as_str)
                    .and_then(certificate_x5c_thumbprint)
                    .is_some()
            })
        })
}

#[cfg(test)]
pub(crate) fn authorization_code_key(code: &str) -> String {
    format!("oauth:auth_code:{}", super::security::blake3_hex(code))
}

#[cfg(test)]
#[path = "../../tests/in_source/src/support/tests/oauth_client_jwks.rs"]
mod oauth_client_jwks_tests;

#[cfg(test)]
#[path = "../../tests/in_source/src/support/tests/oauth_redirect_pkce.rs"]
mod oauth_redirect_pkce_tests;
