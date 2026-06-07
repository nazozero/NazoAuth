//! OAuth 作用域、audience 与授权关系工具。
// 只处理 OAuth 语义中的集合判断和授权记录 upsert。

use super::{
    mtls::{certificate_x5c_thumbprint, normalize_sha256_thumbprint},
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
    "tls_client_auth",
    "self_signed_tls_client_auth",
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

pub(crate) struct ClientMetadata<'a> {
    pub(crate) client_type: &'a str,
    pub(crate) redirect_uris: &'a [String],
    pub(crate) scopes: &'a [String],
    pub(crate) allowed_audiences: &'a [String],
    pub(crate) grant_types: &'a [String],
    pub(crate) token_endpoint_auth_method: &'a str,
    pub(crate) jwks: Option<&'a Value>,
    pub(crate) mtls_binding: Option<&'a ClientMtlsMetadata>,
}

pub(crate) fn validate_client_metadata(metadata: ClientMetadata<'_>) -> anyhow::Result<()> {
    let ClientMetadata {
        client_type,
        redirect_uris,
        scopes,
        allowed_audiences,
        grant_types,
        token_endpoint_auth_method,
        jwks,
        mtls_binding,
    } = metadata;
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
    if let Some(jwks) = jwks
        && token_endpoint_auth_method != "self_signed_tls_client_auth"
    {
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
    if matches!(
        token_endpoint_auth_method,
        "tls_client_auth" | "self_signed_tls_client_auth"
    ) && client_type != "confidential"
    {
        anyhow::bail!("mTLS 客户端认证只适用于 confidential 客户端");
    }
    if token_endpoint_auth_method == "tls_client_auth"
        && !mtls_binding.is_some_and(ClientMtlsMetadata::has_binding_material)
    {
        anyhow::bail!("tls_client_auth 客户端必须注册 subject DN、SAN 或证书 SHA-256 绑定材料");
    }
    if token_endpoint_auth_method == "self_signed_tls_client_auth"
        && !jwks.is_some_and(validate_self_signed_mtls_jwks)
    {
        anyhow::bail!("self_signed_tls_client_auth 客户端必须注册有效 x5c 证书");
    }
    if let Some(mtls_binding) = mtls_binding {
        validate_mtls_metadata(mtls_binding)?;
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

fn validate_mtls_metadata(mtls_binding: &ClientMtlsMetadata) -> anyhow::Result<()> {
    if let Some(subject_dn) = mtls_binding.tls_client_auth_subject_dn.as_deref()
        && subject_dn.trim().is_empty()
    {
        anyhow::bail!("tls_client_auth_subject_dn 不能为空");
    }
    if let Some(cert_sha256) = mtls_binding.tls_client_auth_cert_sha256.as_deref()
        && normalize_sha256_thumbprint(cert_sha256).is_none()
    {
        anyhow::bail!("tls_client_auth_cert_sha256 必须是 SHA-256 证书指纹");
    }
    validate_unique_non_empty(
        "tls_client_auth_san_dns",
        &mtls_binding.tls_client_auth_san_dns,
    )?;
    validate_unique_non_empty(
        "tls_client_auth_san_uri",
        &mtls_binding.tls_client_auth_san_uri,
    )?;
    validate_unique_non_empty(
        "tls_client_auth_san_ip",
        &mtls_binding.tls_client_auth_san_ip,
    )?;
    validate_unique_non_empty(
        "tls_client_auth_san_email",
        &mtls_binding.tls_client_auth_san_email,
    )?;
    for value in &mtls_binding.tls_client_auth_san_ip {
        value
            .parse::<std::net::IpAddr>()
            .map_err(|_| anyhow::anyhow!("tls_client_auth_san_ip 必须是合法 IP 地址: {value}"))?;
    }
    Ok(())
}

#[derive(Debug, Default)]
pub(crate) struct ClientMtlsMetadata {
    pub(crate) tls_client_auth_subject_dn: Option<String>,
    pub(crate) tls_client_auth_cert_sha256: Option<String>,
    pub(crate) tls_client_auth_san_dns: Vec<String>,
    pub(crate) tls_client_auth_san_uri: Vec<String>,
    pub(crate) tls_client_auth_san_ip: Vec<String>,
    pub(crate) tls_client_auth_san_email: Vec<String>,
}

impl ClientMtlsMetadata {
    pub(crate) fn has_binding_material(&self) -> bool {
        self.tls_client_auth_subject_dn
            .as_deref()
            .is_some_and(|value| !value.trim().is_empty())
            || self.has_cert_thumbprint()
            || !self.tls_client_auth_san_dns.is_empty()
            || !self.tls_client_auth_san_uri.is_empty()
            || !self.tls_client_auth_san_ip.is_empty()
            || !self.tls_client_auth_san_email.is_empty()
    }

    pub(crate) fn has_cert_thumbprint(&self) -> bool {
        self.tls_client_auth_cert_sha256
            .as_deref()
            .and_then(normalize_sha256_thumbprint)
            .is_some()
    }
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
    authorization_details: &Value,
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
            user_client_grants::last_authorization_details.eq(authorization_details.clone()),
            user_client_grants::authorization_count.eq(1),
        ))
        .on_conflict((user_client_grants::user_id, user_client_grants::client_id))
        .do_update()
        .set((
            user_client_grants::last_authorized_at.eq(now),
            user_client_grants::last_scopes.eq(json!(scopes)),
            user_client_grants::last_authorization_details.eq(authorization_details.clone()),
            user_client_grants::authorization_count.eq(user_client_grants::authorization_count + 1),
        ))
        .execute(&mut conn)
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use openssl::asn1::Asn1Time;
    use openssl::hash::MessageDigest;
    use openssl::nid::Nid;
    use openssl::pkey::{PKey, Private};
    use openssl::rsa::Rsa;
    use openssl::x509::{X509Builder, X509Name};

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
            require_mtls_bound_tokens: false,
            tls_client_auth_subject_dn: None,
            tls_client_auth_cert_sha256: None,
            tls_client_auth_san_dns: json!([]),
            tls_client_auth_san_uri: json!([]),
            tls_client_auth_san_ip: json!([]),
            tls_client_auth_san_email: json!([]),
            allow_client_assertion_audience_array: false,
            allow_client_assertion_endpoint_audience: false,
            require_par_request_object: false,
            is_active: true,
            jwks: None,
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn metadata<'a>(
        client_type: &'a str,
        redirect_uris: &'a [String],
        scopes: &'a [String],
        allowed_audiences: &'a [String],
        grant_types: &'a [String],
        token_endpoint_auth_method: &'a str,
        jwks: Option<&'a Value>,
        mtls_binding: Option<&'a ClientMtlsMetadata>,
    ) -> ClientMetadata<'a> {
        ClientMetadata {
            client_type,
            redirect_uris,
            scopes,
            allowed_audiences,
            grant_types,
            token_endpoint_auth_method,
            jwks,
            mtls_binding,
        }
    }

    fn test_x5c(common_name: &str, not_before_offset: i64, not_after_offset: i64) -> String {
        let key: PKey<Private> =
            PKey::from_rsa(Rsa::generate(2048).expect("test rsa key")).expect("test pkey");
        let mut name = X509Name::builder().expect("x509 name builder");
        name.append_entry_by_nid(Nid::COMMONNAME, common_name)
            .expect("test common name");
        let name = name.build();
        let mut builder = X509Builder::new().expect("x509 builder");
        builder.set_version(2).expect("x509 version");
        builder.set_subject_name(&name).expect("x509 subject");
        builder.set_issuer_name(&name).expect("x509 issuer");
        builder.set_pubkey(&key).expect("x509 pubkey");
        let now = Utc::now().timestamp();
        let not_before = Asn1Time::from_unix(now + not_before_offset).expect("x509 not_before");
        let not_after = Asn1Time::from_unix(now + not_after_offset).expect("x509 not_after");
        builder
            .set_not_before(&not_before)
            .expect("set x509 not_before");
        builder
            .set_not_after(&not_after)
            .expect("set x509 not_after");
        builder
            .sign(&key, MessageDigest::sha256())
            .expect("sign test cert");
        STANDARD.encode(builder.build().to_der().expect("cert der"))
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
        let result = validate_client_metadata(metadata(
            "public",
            &["https://client.example/callback".to_owned()],
            &["openid".to_owned()],
            &["resource://default".to_owned()],
            &["password".to_owned()],
            "none",
            None,
            None,
        ));

        assert!(result.is_err());
    }

    #[test]
    fn client_metadata_rejects_non_loopback_http_redirect_uri() {
        let result = validate_client_metadata(metadata(
            "public",
            &["http://client.example/callback".to_owned()],
            &["openid".to_owned()],
            &["resource://default".to_owned()],
            &["authorization_code".to_owned()],
            "none",
            None,
            None,
        ));

        assert!(result.is_err());
    }

    #[test]
    fn client_metadata_requires_refresh_grant_for_offline_access() {
        let result = validate_client_metadata(metadata(
            "public",
            &["https://client.example/callback".to_owned()],
            &["openid".to_owned(), "offline_access".to_owned()],
            &["resource://default".to_owned()],
            &["authorization_code".to_owned()],
            "none",
            None,
            None,
        ));

        assert!(result.is_err());

        let result = validate_client_metadata(metadata(
            "public",
            &["https://client.example/callback".to_owned()],
            &["openid".to_owned(), "offline_access".to_owned()],
            &["resource://default".to_owned()],
            &["authorization_code".to_owned(), "refresh_token".to_owned()],
            "none",
            None,
            None,
        ));

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

        let result = validate_client_metadata(metadata(
            "confidential",
            &["https://client.example/callback".to_owned()],
            &["openid".to_owned()],
            &["resource://default".to_owned()],
            &["authorization_code".to_owned()],
            "private_key_jwt",
            None,
            None,
        ));
        assert!(result.is_err());

        let result = validate_client_metadata(metadata(
            "confidential",
            &["https://client.example/callback".to_owned()],
            &["openid".to_owned()],
            &["resource://default".to_owned()],
            &["authorization_code".to_owned()],
            "private_key_jwt",
            Some(&jwks),
            None,
        ));
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

        let result = validate_client_metadata(metadata(
            "confidential",
            &["https://client.example/callback".to_owned()],
            &["openid".to_owned()],
            &["resource://default".to_owned()],
            &["authorization_code".to_owned()],
            "client_secret_basic",
            Some(&private_jwk),
            None,
        ));
        assert!(result.is_err());

        let result = validate_client_metadata(metadata(
            "confidential",
            &["https://client.example/callback".to_owned()],
            &["openid".to_owned()],
            &["resource://default".to_owned()],
            &["authorization_code".to_owned()],
            "client_secret_basic",
            None,
            None,
        ));
        assert!(result.is_ok());
    }

    #[test]
    fn client_metadata_requires_mtls_binding_material() {
        let empty_mtls = ClientMtlsMetadata::default();
        let result = validate_client_metadata(metadata(
            "confidential",
            &["https://client.example/callback".to_owned()],
            &["accounts".to_owned()],
            &["resource://default".to_owned()],
            &["authorization_code".to_owned()],
            "tls_client_auth",
            None,
            Some(&empty_mtls),
        ));
        assert!(result.is_err());

        let subject_mtls = ClientMtlsMetadata {
            tls_client_auth_subject_dn: Some("CN=client-1,O=Example".to_owned()),
            ..ClientMtlsMetadata::default()
        };
        let result = validate_client_metadata(metadata(
            "confidential",
            &["https://client.example/callback".to_owned()],
            &["accounts".to_owned()],
            &["resource://default".to_owned()],
            &["authorization_code".to_owned()],
            "tls_client_auth",
            None,
            Some(&subject_mtls),
        ));
        assert!(result.is_ok());
    }

    #[test]
    fn client_metadata_requires_self_signed_mtls_x5c_jwks() {
        let subject_only = ClientMtlsMetadata {
            tls_client_auth_subject_dn: Some("CN=client-1,O=Example".to_owned()),
            ..ClientMtlsMetadata::default()
        };
        let result = validate_client_metadata(metadata(
            "confidential",
            &["https://client.example/callback".to_owned()],
            &["accounts".to_owned()],
            &["resource://default".to_owned()],
            &["authorization_code".to_owned()],
            "self_signed_tls_client_auth",
            None,
            Some(&subject_only),
        ));
        assert!(result.is_err());

        let thumbprint = ClientMtlsMetadata {
            tls_client_auth_cert_sha256: Some(
                "00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff"
                    .to_owned(),
            ),
            ..ClientMtlsMetadata::default()
        };
        let result = validate_client_metadata(metadata(
            "confidential",
            &["https://client.example/callback".to_owned()],
            &["accounts".to_owned()],
            &["resource://default".to_owned()],
            &["authorization_code".to_owned()],
            "self_signed_tls_client_auth",
            None,
            Some(&thumbprint),
        ));
        assert!(result.is_err());

        let invalid_jwks = json!({
            "keys": [{
                "kid": "cert-1",
                "x5c": ["invalid-certificate"]
            }]
        });
        assert!(!validate_self_signed_mtls_jwks(&invalid_jwks));

        let result = validate_client_metadata(metadata(
            "confidential",
            &["https://client.example/callback".to_owned()],
            &["accounts".to_owned()],
            &["resource://default".to_owned()],
            &["authorization_code".to_owned()],
            "self_signed_tls_client_auth",
            Some(&invalid_jwks),
            None,
        ));
        assert!(result.is_err());

        let valid_jwks = json!({
            "keys": [{
                "kid": "cert-1",
                "x5c": [test_x5c("client-1", -60, 3600)]
            }]
        });
        assert!(validate_self_signed_mtls_jwks(&valid_jwks));
        let result = validate_client_metadata(metadata(
            "confidential",
            &["https://client.example/callback".to_owned()],
            &["accounts".to_owned()],
            &["resource://default".to_owned()],
            &["authorization_code".to_owned()],
            "self_signed_tls_client_auth",
            Some(&valid_jwks),
            None,
        ));
        assert!(result.is_ok());

        let expired_jwks = json!({
            "keys": [{
                "kid": "expired",
                "x5c": [test_x5c("client-expired", -7200, -3600)]
            }]
        });
        assert!(!validate_self_signed_mtls_jwks(&expired_jwks));
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
