//! OAuth 作用域、audience 与授权关系工具。
// 只处理 OAuth 语义中的集合判断和授权记录 upsert。

use super::{
    prelude::*,
    security::{
        SUPPORTED_CLIENT_JWT_SIGNING_ALGS, blake3_hex, client_jwt_algorithm_from_name,
        jwt_decoding_key_from_jwk, supported_client_jwt_algorithm_name,
    },
    uri_policy::{oauth_redirect_uri_matches, validate_oauth_redirect_uri},
};

const SUPPORTED_GRANT_TYPES: &[&str] =
    &["authorization_code", "refresh_token", "client_credentials"];
const SUPPORTED_TOKEN_AUTH_METHODS: &[&str] = &[
    "none",
    "client_secret_basic",
    "client_secret_post",
    "private_key_jwt",
];

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum RedirectUriError {
    Missing,
    Invalid,
}

pub(crate) fn json_array_to_strings(value: &Value) -> Vec<String> {
    value
        .as_array()
        .map(|items| {
            items
                .iter()
                .filter_map(|v| v.as_str().map(ToOwned::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

pub(crate) fn parse_scope(raw: &str) -> Vec<String> {
    raw.split_whitespace()
        .map(ToOwned::to_owned)
        .filter(|v| !v.is_empty())
        .collect()
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

pub(crate) fn sorted_scope_string(scopes: &[String]) -> String {
    let mut values = scopes.to_vec();
    values.sort();
    values.dedup();
    values.join(" ")
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

pub(crate) fn validate_client_metadata(
    client_type: &str,
    redirect_uris: &[String],
    scopes: &[String],
    allowed_audiences: &[String],
    grant_types: &[String],
    token_endpoint_auth_method: &str,
    jwks: Option<&Value>,
) -> anyhow::Result<()> {
    if !matches!(client_type, "public" | "confidential") {
        anyhow::bail!("客户端类型无效");
    }
    validate_unique_non_empty("scope", scopes)?;
    validate_unique_non_empty("audience", allowed_audiences)?;
    validate_unique_non_empty("grant_type", grant_types)?;
    for grant in grant_types {
        if !SUPPORTED_GRANT_TYPES.contains(&grant.as_str()) {
            anyhow::bail!("不支持的 grant_type: {grant}");
        }
    }
    if !SUPPORTED_TOKEN_AUTH_METHODS.contains(&token_endpoint_auth_method) {
        anyhow::bail!("客户端认证方式无效");
    }
    if client_type == "public" && token_endpoint_auth_method != "none" {
        anyhow::bail!("public 客户端只能使用 none 认证方式");
    }
    if client_type == "confidential" && token_endpoint_auth_method == "none" {
        anyhow::bail!("confidential 客户端必须使用机密认证方式");
    }
    if let Some(jwks) = jwks {
        validate_client_jwks(jwks)?;
    }
    if token_endpoint_auth_method == "private_key_jwt" {
        if client_type != "confidential" {
            anyhow::bail!("private_key_jwt 只适用于 confidential 客户端");
        }
        if jwks.is_none() {
            anyhow::bail!("private_key_jwt 客户端必须配置 jwks");
        }
    }
    if client_type == "public"
        && grant_types
            .iter()
            .any(|grant| grant == "client_credentials")
    {
        anyhow::bail!("public 客户端不能使用 client_credentials 授权类型");
    }
    if grant_types
        .iter()
        .any(|grant| grant == "client_credentials")
        && scopes.iter().any(|scope| scope == "openid")
    {
        anyhow::bail!("client_credentials 客户端不能申请 openid 作用域");
    }
    if grant_types.iter().any(|grant| grant == "refresh_token")
        && !grant_types
            .iter()
            .any(|grant| grant == "authorization_code")
    {
        anyhow::bail!("refresh_token 授权类型必须与 authorization_code 一起启用");
    }
    if scopes.iter().any(|scope| scope == "offline_access")
        && !grant_types.iter().any(|grant| grant == "refresh_token")
    {
        anyhow::bail!("offline_access 作用域必须与 refresh_token 授权类型一起启用");
    }
    if grant_types
        .iter()
        .any(|grant| grant == "authorization_code")
        && redirect_uris.is_empty()
    {
        anyhow::bail!("authorization_code 客户端必须注册 redirect_uri");
    }
    for redirect_uri in redirect_uris {
        validate_oauth_redirect_uri(client_type, redirect_uri)?;
    }
    Ok(())
}

pub(crate) fn validate_client_jwks(jwks: &Value) -> anyhow::Result<()> {
    let keys = jwks
        .get("keys")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow::anyhow!("jwks 必须包含 keys 数组"))?;
    if keys.is_empty() {
        anyhow::bail!("jwks.keys 不能为空");
    }
    let mut seen_kids = std::collections::HashSet::new();
    for key in keys {
        let kid = key.get("kid").and_then(Value::as_str).unwrap_or_default();
        if kid.trim().is_empty() {
            anyhow::bail!("jwks 公钥必须包含 kid");
        }
        if !seen_kids.insert(kid) {
            anyhow::bail!("jwks kid 不能重复: {kid}");
        }
        if key.get("d").is_some() {
            anyhow::bail!("jwks 不能包含私钥材料");
        }
        if let Some(use_) = key.get("use").and_then(Value::as_str)
            && use_ != "sig"
        {
            anyhow::bail!("jwks 公钥 use 必须为 sig");
        }
        let Some(alg) = key.get("alg").and_then(Value::as_str) else {
            anyhow::bail!("jwks 公钥必须声明 alg");
        };
        let Some(algorithm) = client_jwt_algorithm_from_name(alg) else {
            anyhow::bail!(
                "jwks alg 必须是 {}",
                SUPPORTED_CLIENT_JWT_SIGNING_ALGS.join(", ")
            );
        };
        if supported_client_jwt_algorithm_name(algorithm) != Some(alg)
            || jwt_decoding_key_from_jwk(key, algorithm).is_none()
        {
            anyhow::bail!("jwks 公钥材料与 alg 不匹配");
        }
    }
    Ok(())
}

fn validate_unique_non_empty(name: &str, values: &[String]) -> anyhow::Result<()> {
    let mut seen = std::collections::HashSet::new();
    for value in values {
        let trimmed = value.trim();
        if trimmed.is_empty() || trimmed.split_whitespace().count() != 1 {
            anyhow::bail!("{name} 不能为空或包含空白字符");
        }
        if !seen.insert(trimmed) {
            anyhow::bail!("{name} 不能重复: {trimmed}");
        }
    }
    Ok(())
}

pub(crate) fn authorization_code_key(code: &str) -> String {
    authorization_code_key_from_hash(&blake3_hex(code))
}

pub(crate) fn authorization_code_key_from_hash(code_hash: &str) -> String {
    format!("oauth:auth_code:{code_hash}")
}

pub(crate) async fn upsert_grant(
    state: &AppState,
    user_id: Uuid,
    client_id: &str,
    scopes: &[String],
) -> anyhow::Result<()> {
    let Some(client) = find_client(&state.diesel_db, client_id).await? else {
        return Ok(());
    };
    let now = Utc::now();
    let mut conn = get_conn(&state.diesel_db).await?;
    diesel::insert_into(user_client_grants::table)
        .values((
            user_client_grants::user_id.eq(user_id),
            user_client_grants::client_id.eq(client.id),
            user_client_grants::first_authorized_at.eq(now),
            user_client_grants::last_authorized_at.eq(now),
            user_client_grants::last_scopes.eq(json!(scopes)),
            user_client_grants::authorization_count.eq(1),
        ))
        .on_conflict((user_client_grants::user_id, user_client_grants::client_id))
        .do_update()
        .set((
            user_client_grants::last_authorized_at.eq(now),
            user_client_grants::last_scopes.eq(json!(scopes)),
            user_client_grants::authorization_count.eq(user_client_grants::authorization_count + 1),
        ))
        .execute(&mut conn)
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn client_with_redirects(redirect_uris: &[&str]) -> ClientRow {
        ClientRow {
            id: Uuid::now_v7(),
            client_id: "client-1".to_owned(),
            client_name: "Client".to_owned(),
            client_type: "public".to_owned(),
            client_secret_argon2_hash: None,
            redirect_uris: json!(redirect_uris),
            scopes: json!(["openid"]),
            allowed_audiences: json!(["resource://default"]),
            grant_types: json!(["authorization_code"]),
            token_endpoint_auth_method: "none".to_owned(),
            require_dpop_bound_tokens: false,
            allow_client_assertion_audience_array: false,
            require_par_request_object: false,
            is_active: true,
            jwks: None,
        }
    }

    #[test]
    fn redirect_uri_uses_single_registered_uri_when_omitted() {
        let client = client_with_redirects(&["https://client.example/callback"]);

        assert_eq!(
            registered_redirect_uri(&client, None).unwrap(),
            "https://client.example/callback"
        );
    }

    #[test]
    fn redirect_uri_requires_exact_match() {
        let client = client_with_redirects(&["https://client.example/callback"]);

        assert_eq!(
            registered_redirect_uri(&client, Some("https://client.example/callback/")),
            Err(RedirectUriError::Invalid)
        );
    }

    #[test]
    fn public_loopback_redirect_uri_allows_runtime_port() {
        let client = client_with_redirects(&["http://127.0.0.1:3000/callback"]);

        assert_eq!(
            registered_redirect_uri(&client, Some("http://127.0.0.1:49152/callback")).unwrap(),
            "http://127.0.0.1:49152/callback"
        );
    }

    #[test]
    fn pkce_values_follow_rfc7636_length_and_charset() {
        assert!(is_valid_pkce_value(
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ"
        ));
        assert!(!is_valid_pkce_value("short"));
        assert!(!is_valid_pkce_value(
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNO!"
        ));
    }

    #[test]
    fn client_metadata_rejects_removed_or_unsafe_grants() {
        let result = validate_client_metadata(
            "public",
            &["https://client.example/callback".to_owned()],
            &["openid".to_owned()],
            &["resource://default".to_owned()],
            &["password".to_owned()],
            "none",
            None,
        );

        assert!(result.is_err());
    }

    #[test]
    fn client_metadata_rejects_non_loopback_http_redirect_uri() {
        let result = validate_client_metadata(
            "public",
            &["http://client.example/callback".to_owned()],
            &["openid".to_owned()],
            &["resource://default".to_owned()],
            &["authorization_code".to_owned()],
            "none",
            None,
        );

        assert!(result.is_err());
    }

    #[test]
    fn client_metadata_requires_refresh_grant_for_offline_access() {
        let result = validate_client_metadata(
            "public",
            &["https://client.example/callback".to_owned()],
            &["openid".to_owned(), "offline_access".to_owned()],
            &["resource://default".to_owned()],
            &["authorization_code".to_owned()],
            "none",
            None,
        );

        assert!(result.is_err());

        let result = validate_client_metadata(
            "public",
            &["https://client.example/callback".to_owned()],
            &["openid".to_owned(), "offline_access".to_owned()],
            &["resource://default".to_owned()],
            &["authorization_code".to_owned(), "refresh_token".to_owned()],
            "none",
            None,
        );

        assert!(result.is_ok());
    }

    #[test]
    fn client_metadata_requires_public_jwks_for_private_key_jwt() {
        let jwks = json!({
            "keys": [{
                "kty": "OKP",
                "crv": "Ed25519",
                "x": URL_SAFE_NO_PAD.encode([7u8; 32]),
                "alg": "EdDSA",
                "use": "sig",
                "kid": "key-1"
            }]
        });

        let result = validate_client_metadata(
            "confidential",
            &["https://client.example/callback".to_owned()],
            &["openid".to_owned()],
            &["resource://default".to_owned()],
            &["authorization_code".to_owned()],
            "private_key_jwt",
            None,
        );
        assert!(result.is_err());

        let result = validate_client_metadata(
            "confidential",
            &["https://client.example/callback".to_owned()],
            &["openid".to_owned()],
            &["resource://default".to_owned()],
            &["authorization_code".to_owned()],
            "private_key_jwt",
            Some(&jwks),
        );
        assert!(result.is_ok());
    }

    #[test]
    fn client_metadata_validates_optional_jwks_for_all_auth_methods() {
        let private_jwk = json!({
            "keys": [{
                "kty": "OKP",
                "crv": "Ed25519",
                "x": URL_SAFE_NO_PAD.encode([7u8; 32]),
                "d": URL_SAFE_NO_PAD.encode([8u8; 32]),
                "kid": "key-1"
            }]
        });

        let result = validate_client_metadata(
            "confidential",
            &["https://client.example/callback".to_owned()],
            &["openid".to_owned()],
            &["resource://default".to_owned()],
            &["authorization_code".to_owned()],
            "client_secret_basic",
            Some(&private_jwk),
        );
        assert!(result.is_err());

        let result = validate_client_metadata(
            "confidential",
            &["https://client.example/callback".to_owned()],
            &["openid".to_owned()],
            &["resource://default".to_owned()],
            &["authorization_code".to_owned()],
            "client_secret_basic",
            None,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn client_jwks_requires_non_empty_unique_kids() {
        let missing_kid = json!({
            "keys": [{
                "kty": "OKP",
                "crv": "Ed25519",
                "x": URL_SAFE_NO_PAD.encode([7u8; 32]),
                "alg": "EdDSA",
                "use": "sig"
            }]
        });
        assert!(validate_client_jwks(&missing_kid).is_err());

        let duplicate_kid = json!({
            "keys": [
                {
                    "kty": "OKP",
                    "crv": "Ed25519",
                    "x": URL_SAFE_NO_PAD.encode([7u8; 32]),
                    "alg": "EdDSA",
                    "use": "sig",
                    "kid": "key-1"
                },
                {
                    "kty": "OKP",
                    "crv": "Ed25519",
                    "x": URL_SAFE_NO_PAD.encode([8u8; 32]),
                    "alg": "EdDSA",
                    "use": "sig",
                    "kid": "key-1"
                }
            ]
        });
        assert!(validate_client_jwks(&duplicate_kid).is_err());
    }

    #[test]
    fn client_jwks_rejects_private_key_material() {
        let private_jwk = json!({
            "keys": [{
                "kty": "OKP",
                "crv": "Ed25519",
                "x": URL_SAFE_NO_PAD.encode([7u8; 32]),
                "alg": "EdDSA",
                "d": URL_SAFE_NO_PAD.encode([8u8; 32]),
                "kid": "key-1"
            }]
        });

        assert!(validate_client_jwks(&private_jwk).is_err());
    }

    #[test]
    fn client_jwks_accepts_supported_public_key_algorithms() {
        let jwks = json!({
            "keys": [
                {
                    "kty": "OKP",
                    "crv": "Ed25519",
                    "x": URL_SAFE_NO_PAD.encode([7u8; 32]),
                    "alg": "EdDSA",
                    "use": "sig",
                    "kid": "ed-key"
                },
                {
                    "kty": "RSA",
                    "n": URL_SAFE_NO_PAD.encode([0x91u8; 256]),
                    "e": URL_SAFE_NO_PAD.encode([0x01u8, 0x00, 0x01]),
                    "alg": "RS256",
                    "use": "sig",
                    "kid": "rs-key"
                },
                {
                    "kty": "EC",
                    "crv": "P-256",
                    "x": "w7JAoU_gJbZJvV-zCOvU9yFJq0FNC_edCMRM78P8eQQ",
                    "y": "wQg1EytcsEmGrM70Gb53oluoDbVhCZ3Uq3hHMslHVb4",
                    "alg": "ES256",
                    "use": "sig",
                    "kid": "es-key"
                },
                {
                    "kty": "RSA",
                    "n": URL_SAFE_NO_PAD.encode([0x92u8; 256]),
                    "e": URL_SAFE_NO_PAD.encode([0x01u8, 0x00, 0x01]),
                    "alg": "PS256",
                    "use": "sig",
                    "kid": "ps-key"
                }
            ]
        });

        assert!(validate_client_jwks(&jwks).is_ok());
    }

    #[test]
    fn client_jwks_rejects_algorithm_key_type_mismatch() {
        let jwks = json!({
            "keys": [{
                "kty": "OKP",
                "crv": "Ed25519",
                "x": URL_SAFE_NO_PAD.encode([7u8; 32]),
                "alg": "RS256",
                "use": "sig",
                "kid": "wrong-alg"
            }]
        });

        assert!(validate_client_jwks(&jwks).is_err());
    }
}
