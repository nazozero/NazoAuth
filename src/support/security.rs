//! 密码、哈希、客户端认证和 JWT 工具。
// 安全相关算法集中在这里，调用方只关心验证或签发结果。

use super::prelude::*;

pub(crate) fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right.iter())
        .fold(0u8, |acc, (a, b)| acc | (a ^ b))
        == 0
}

pub(crate) fn hash_password(password: &str) -> password_hash::Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    Ok(Argon2::default()
        .hash_password(password.as_bytes(), &salt)?
        .to_string())
}

pub(crate) fn verify_password(password: &str, password_hash: &str) -> bool {
    let Ok(parsed) = PasswordHash::new(password_hash) else {
        return false;
    };
    Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok()
}

pub(crate) fn blake3_hex(value: &str) -> String {
    blake3::hash(value.as_bytes()).to_hex().to_string()
}

pub(crate) fn random_urlsafe_token() -> String {
    URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>())
}

pub(crate) fn random_numeric_code() -> String {
    const RANGE: u32 = 1_000_000;
    const LIMIT: u32 = u32::MAX - (u32::MAX % RANGE);

    loop {
        let value = u32::from_be_bytes(rand::random::<[u8; 4]>());
        if value < LIMIT {
            return format!("{:06}", value % RANGE);
        }
    }
}

pub(crate) fn pkce_s256(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

pub(crate) fn extract_client_credentials(
    headers: &HeaderMap,
    form_client_id: Option<&str>,
    form_secret: Option<&str>,
) -> (Option<String>, Option<String>, String) {
    if let Some((id, secret)) = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|auth| auth.strip_prefix("Basic "))
        .and_then(|raw| STANDARD.decode(raw).ok())
        .and_then(|decoded| String::from_utf8(decoded).ok())
        .and_then(|text| {
            let (id, secret) = text.split_once(':')?;
            Some((id.to_string(), secret.to_string()))
        })
    {
        return (Some(id), Some(secret), "client_secret_basic".into());
    }
    match form_client_id {
        Some(id) if form_secret.is_some() => (
            Some(id.to_string()),
            form_secret.map(ToOwned::to_owned),
            "client_secret_post".into(),
        ),
        Some(id) => (Some(id.to_string()), None, "none".into()),
        None => (None, None, "none".into()),
    }
}

pub(crate) struct AccessTokenJwtInput<'a> {
    pub(crate) subject: &'a str,
    pub(crate) subject_type: &'a str,
    pub(crate) client_id: &'a str,
    pub(crate) audience: &'a str,
    pub(crate) scopes: &'a [String],
    pub(crate) ttl: i64,
    pub(crate) dpop_jkt: Option<&'a str>,
}

pub(crate) fn make_jwt(
    state: &AppState,
    input: AccessTokenJwtInput<'_>,
) -> jsonwebtoken::errors::Result<String> {
    let now = Utc::now().timestamp();
    let claims = Claims {
        iss: state.settings.issuer.clone(),
        sub: input.subject.to_string(),
        subject_type: input.subject_type.to_string(),
        aud: input.audience.to_string(),
        client_id: input.client_id.to_string(),
        scope: sorted_scope_string(input.scopes),
        token_use: "access".into(),
        jti: Uuid::now_v7().to_string(),
        iat: now,
        nbf: now,
        exp: now + input.ttl,
        cnf: input.dpop_jkt.map(|jkt| ConfirmationClaims {
            jkt: jkt.to_owned(),
        }),
    };
    let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::EdDSA);
    header.typ = Some("at+jwt".to_string());
    header.kid = Some(state.keyset.active_kid.clone());
    jsonwebtoken::encode(
        &header,
        &claims,
        &jsonwebtoken::EncodingKey::from_ed_der(&state.keyset.private_pkcs8_der),
    )
}

pub(crate) fn make_id_token(
    state: &AppState,
    subject: &str,
    client_id: &str,
    nonce: Option<String>,
    ttl: i64,
) -> jsonwebtoken::errors::Result<String> {
    let now = Utc::now().timestamp();
    let claims = json!({
        "iss": state.settings.issuer,
        "sub": subject,
        "aud": client_id,
        "iat": now,
        "nbf": now,
        "exp": now + ttl,
        "jti": Uuid::now_v7().to_string(),
        "nonce": nonce
    });
    let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::EdDSA);
    header.typ = Some("JWT".to_string());
    header.kid = Some(state.keyset.active_kid.clone());
    jsonwebtoken::encode(
        &header,
        &claims,
        &jsonwebtoken::EncodingKey::from_ed_der(&state.keyset.private_pkcs8_der),
    )
}

pub(crate) fn decode_access_claims(state: &AppState, token: &str) -> Option<Claims> {
    let header = jsonwebtoken::decode_header(token).ok()?;
    if header.alg != jsonwebtoken::Algorithm::EdDSA
        || header.typ.as_deref() != Some("at+jwt")
        || header.kid.as_deref() != Some(state.keyset.active_kid.as_str())
    {
        return None;
    }
    let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::EdDSA);
    validation.validate_aud = false;
    validation.set_issuer(&[state.settings.issuer.as_str()]);
    let token_data = jsonwebtoken::decode::<Claims>(
        token,
        &jsonwebtoken::DecodingKey::from_ed_der(&state.keyset.public_key),
        &validation,
    )
    .ok()?;
    if token_data.claims.token_use != "access" {
        return None;
    }
    Some(token_data.claims)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numeric_code_is_six_ascii_digits() {
        let code = random_numeric_code();

        assert_eq!(code.len(), 6);
        assert!(code.chars().all(|value| value.is_ascii_digit()));
    }

    #[test]
    fn random_urlsafe_token_is_256_bit_opaque_value() {
        let token = random_urlsafe_token();

        assert_eq!(token.len(), 43);
        assert!(
            token
                .chars()
                .all(|value| value.is_ascii_alphanumeric() || value == '-' || value == '_')
        );
    }
}
