//! 密码、哈希、客户端认证和 JWT 工具。
// 安全相关算法集中在这里，调用方只关心验证或签发结果。

use super::prelude::*;
use super::{audit_event, audit_fields, signing_algorithm_name, valkey_set_ex_nx};

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

pub(crate) const CLIENT_ASSERTION_TYPE_JWT_BEARER: &str =
    "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
const CLIENT_ASSERTION_MAX_TTL_SECONDS: i64 = 300;
const CLIENT_ASSERTION_CLOCK_SKEW_SECONDS: i64 = 30;
const MAX_CLIENT_ASSERTION_JTI_BYTES: usize = 128;
pub(crate) const SUPPORTED_CLIENT_JWT_SIGNING_ALGS: &[&str] = &["EdDSA", "RS256", "ES256", "PS256"];

pub(crate) struct ClientCredentials {
    pub(crate) client_id: Option<String>,
    pub(crate) client_secret: Option<String>,
    pub(crate) client_assertion: Option<String>,
    pub(crate) method: String,
}

pub(crate) fn has_basic_authorization_scheme(headers: &HeaderMap) -> bool {
    let Some(raw) = headers
        .get(header::AUTHORIZATION)
        .map(HeaderValue::as_bytes)
    else {
        return false;
    };
    let start = raw
        .iter()
        .position(|value| !value.is_ascii_whitespace())
        .unwrap_or(raw.len());
    let end = raw[start..]
        .iter()
        .position(u8::is_ascii_whitespace)
        .map(|offset| start + offset)
        .unwrap_or(raw.len());
    raw[start..end].eq_ignore_ascii_case(b"Basic")
}

pub(crate) fn extract_client_credentials(
    headers: &HeaderMap,
    form_client_id: Option<&str>,
    form_secret: Option<&str>,
    form_assertion_type: Option<&str>,
    form_assertion: Option<&str>,
) -> ClientCredentials {
    if form_assertion_type.is_some() || form_assertion.is_some() {
        let client_id = form_assertion
            .filter(|_| form_assertion_type == Some(CLIENT_ASSERTION_TYPE_JWT_BEARER))
            .and_then(unverified_client_assertion_client_id);
        return ClientCredentials {
            client_id,
            client_secret: None,
            client_assertion: form_assertion.map(ToOwned::to_owned),
            method: "private_key_jwt".to_owned(),
        };
    }
    if let Some((id, secret)) = basic_authorization_credentials(headers)
        .and_then(|raw| STANDARD.decode(raw).ok())
        .and_then(|decoded| String::from_utf8(decoded).ok())
        .and_then(|text| {
            let (id, secret) = text.split_once(':')?;
            Some((id.to_string(), secret.to_string()))
        })
    {
        return ClientCredentials {
            client_id: Some(id),
            client_secret: Some(secret),
            client_assertion: None,
            method: "client_secret_basic".to_owned(),
        };
    }
    match form_client_id {
        Some(id) if form_secret.is_some() => ClientCredentials {
            client_id: Some(id.to_string()),
            client_secret: form_secret.map(ToOwned::to_owned),
            client_assertion: None,
            method: "client_secret_post".to_owned(),
        },
        Some(id) => ClientCredentials {
            client_id: Some(id.to_string()),
            client_secret: None,
            client_assertion: None,
            method: "none".to_owned(),
        },
        None => ClientCredentials {
            client_id: None,
            client_secret: None,
            client_assertion: None,
            method: "none".to_owned(),
        },
    }
}

fn basic_authorization_credentials(headers: &HeaderMap) -> Option<&str> {
    let raw = headers
        .get(header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .trim_start();
    let mut parts = raw.splitn(2, char::is_whitespace);
    let scheme = parts.next()?;
    let credentials = parts.next()?.trim();
    (scheme.eq_ignore_ascii_case("Basic")
        && !credentials.is_empty()
        && credentials.split_whitespace().count() == 1)
        .then_some(credentials)
}

#[derive(serde::Deserialize)]
struct ClientAssertionClaims {
    iss: String,
    sub: String,
    aud: Value,
    exp: i64,
    nbf: Option<i64>,
    iat: Option<i64>,
    jti: String,
}

#[derive(Debug)]
pub(crate) enum ClientAssertionError {
    Invalid,
    ReplayDetected,
    StoreUnavailable,
}

pub(crate) struct ValidatedClientAssertion {
    jti: String,
    exp: i64,
    kid: String,
}

pub(crate) fn verify_private_key_jwt_claims(
    state: &AppState,
    req: &HttpRequest,
    client: &ClientRow,
    assertion: &str,
) -> Result<ValidatedClientAssertion, ClientAssertionError> {
    let header =
        jsonwebtoken::decode_header(assertion).map_err(|_| ClientAssertionError::Invalid)?;
    let kid = header.kid.ok_or(ClientAssertionError::Invalid)?;
    let decoding_key =
        client_jwt_decoding_key(client, &kid, header.alg).ok_or(ClientAssertionError::Invalid)?;

    let mut validation = jsonwebtoken::Validation::new(header.alg);
    validation.validate_aud = false;
    validation.set_issuer(&[client.client_id.as_str()]);
    let token_data =
        jsonwebtoken::decode::<ClientAssertionClaims>(assertion, &decoding_key, &validation)
            .map_err(|_| ClientAssertionError::Invalid)?;
    let claims = token_data.claims;
    let now = Utc::now().timestamp();
    if claims.iss != client.client_id
        || claims.sub != client.client_id
        || !audience_matches(
            &claims.aud,
            &client_assertion_audiences(&state.settings, req),
            client.allow_client_assertion_audience_array,
        )
        || !valid_client_assertion_times(&claims, now)
        || !valid_client_assertion_jti(&claims.jti)
    {
        return Err(ClientAssertionError::Invalid);
    }

    Ok(ValidatedClientAssertion {
        jti: claims.jti,
        exp: claims.exp,
        kid,
    })
}

pub(crate) async fn consume_private_key_jwt(
    state: &AppState,
    client: &ClientRow,
    assertion: &ValidatedClientAssertion,
) -> Result<(), ClientAssertionError> {
    let now = Utc::now().timestamp();
    let ttl_seconds = assertion
        .exp
        .saturating_sub(now)
        .clamp(1, CLIENT_ASSERTION_MAX_TTL_SECONDS) as u64;
    let replay_key = format!(
        "oauth:client_assertion:jti:{}:{}",
        blake3_hex(&client.client_id),
        blake3_hex(&assertion.jti)
    );
    match valkey_set_ex_nx(&state.valkey, replay_key, "1", ttl_seconds).await {
        Ok(true) => Ok(()),
        Ok(false) => {
            audit_event(
                "client_assertion_replay_detected",
                audit_fields(&[
                    ("client_id", json!(client.client_id)),
                    ("jti_hash", json!(blake3_hex(&assertion.jti))),
                    ("kid", json!(assertion.kid)),
                ]),
            );
            Err(ClientAssertionError::ReplayDetected)
        }
        Err(error) => {
            tracing::warn!(%error, "failed to store private_key_jwt jti");
            Err(ClientAssertionError::StoreUnavailable)
        }
    }
}

fn unverified_client_assertion_client_id(assertion: &str) -> Option<String> {
    let claims = jsonwebtoken::dangerous::insecure_decode::<ClientAssertionClaims>(assertion)
        .ok()?
        .claims;
    (claims.iss == claims.sub && !claims.sub.trim().is_empty()).then_some(claims.sub)
}

pub(crate) fn supported_client_jwt_algorithm_name(
    alg: jsonwebtoken::Algorithm,
) -> Option<&'static str> {
    match alg {
        jsonwebtoken::Algorithm::EdDSA => Some("EdDSA"),
        jsonwebtoken::Algorithm::RS256 => Some("RS256"),
        jsonwebtoken::Algorithm::ES256 => Some("ES256"),
        jsonwebtoken::Algorithm::PS256 => Some("PS256"),
        _ => None,
    }
}

pub(crate) fn client_jwt_algorithm_from_name(value: &str) -> Option<jsonwebtoken::Algorithm> {
    match value {
        "EdDSA" => Some(jsonwebtoken::Algorithm::EdDSA),
        "RS256" => Some(jsonwebtoken::Algorithm::RS256),
        "ES256" => Some(jsonwebtoken::Algorithm::ES256),
        "PS256" => Some(jsonwebtoken::Algorithm::PS256),
        _ => None,
    }
}

pub(crate) fn client_jwt_decoding_key(
    client: &ClientRow,
    kid: &str,
    alg: jsonwebtoken::Algorithm,
) -> Option<jsonwebtoken::DecodingKey> {
    let keys = client.jwks.as_ref()?.get("keys")?.as_array()?;
    let key = keys
        .iter()
        .find(|key| key.get("kid").and_then(Value::as_str) == Some(kid))?;
    jwt_decoding_key_from_jwk(key, alg)
}

pub(crate) fn jwt_decoding_key_from_jwk(
    key: &Value,
    alg: jsonwebtoken::Algorithm,
) -> Option<jsonwebtoken::DecodingKey> {
    let expected_alg = supported_client_jwt_algorithm_name(alg)?;
    if let Some(key_alg) = key.get("alg").and_then(Value::as_str)
        && key_alg != expected_alg
    {
        return None;
    }
    if key.get("d").is_some() {
        return None;
    }
    if let Some(use_) = key.get("use").and_then(Value::as_str)
        && use_ != "sig"
    {
        return None;
    }
    match alg {
        jsonwebtoken::Algorithm::EdDSA => {
            if key.get("kty").and_then(Value::as_str) != Some("OKP")
                || key.get("crv").and_then(Value::as_str) != Some("Ed25519")
            {
                return None;
            }
            let x = key.get("x").and_then(Value::as_str)?;
            let bytes = URL_SAFE_NO_PAD.decode(x).ok()?;
            if bytes.len() != 32 {
                return None;
            }
            jsonwebtoken::DecodingKey::from_ed_components(x).ok()
        }
        jsonwebtoken::Algorithm::RS256 | jsonwebtoken::Algorithm::PS256 => {
            if key.get("kty").and_then(Value::as_str) != Some("RSA") {
                return None;
            }
            let n = key.get("n").and_then(Value::as_str)?;
            let e = key.get("e").and_then(Value::as_str)?;
            let modulus = URL_SAFE_NO_PAD.decode(n).ok()?;
            let exponent = URL_SAFE_NO_PAD.decode(e).ok()?;
            if modulus.len() < 256 || exponent.is_empty() {
                return None;
            }
            jsonwebtoken::DecodingKey::from_rsa_components(n, e).ok()
        }
        jsonwebtoken::Algorithm::ES256 => {
            if key.get("kty").and_then(Value::as_str) != Some("EC")
                || key.get("crv").and_then(Value::as_str) != Some("P-256")
            {
                return None;
            }
            let x = key.get("x").and_then(Value::as_str)?;
            let y = key.get("y").and_then(Value::as_str)?;
            let x_bytes = URL_SAFE_NO_PAD.decode(x).ok()?;
            let y_bytes = URL_SAFE_NO_PAD.decode(y).ok()?;
            if x_bytes.len() != 32 || y_bytes.len() != 32 {
                return None;
            }
            jsonwebtoken::DecodingKey::from_ec_components(x, y).ok()
        }
        _ => None,
    }
}

fn client_assertion_audiences(settings: &Settings, req: &HttpRequest) -> Vec<String> {
    client_assertion_audience_candidates(&settings.issuer, req.uri().path())
}

fn client_assertion_audience_candidates(issuer: &str, path: &str) -> Vec<String> {
    if path == "/par" {
        return vec![issuer.to_owned()];
    }
    vec![issuer.to_owned(), format!("{issuer}{path}")]
}

fn audience_matches(aud: &Value, expected: &[String], allow_array: bool) -> bool {
    match aud {
        Value::String(value) => expected.iter().any(|candidate| candidate == value),
        Value::Array(values) if allow_array => values
            .iter()
            .any(|value| audience_matches(value, expected, allow_array)),
        _ => false,
    }
}

fn valid_client_assertion_times(claims: &ClientAssertionClaims, now: i64) -> bool {
    if claims.exp <= now || claims.exp > now.saturating_add(CLIENT_ASSERTION_MAX_TTL_SECONDS) {
        return false;
    }
    if claims
        .nbf
        .is_some_and(|nbf| nbf > now.saturating_add(CLIENT_ASSERTION_CLOCK_SKEW_SECONDS))
    {
        return false;
    }
    if claims.iat.is_some_and(|iat| {
        iat > now.saturating_add(CLIENT_ASSERTION_CLOCK_SKEW_SECONDS)
            || now.saturating_sub(iat) > CLIENT_ASSERTION_MAX_TTL_SECONDS
    }) {
        return false;
    }
    true
}

fn valid_client_assertion_jti(jti: &str) -> bool {
    let trimmed = jti.trim();
    !trimmed.is_empty() && trimmed.len() <= MAX_CLIENT_ASSERTION_JTI_BYTES
}

pub(crate) struct AccessTokenJwtInput<'a> {
    pub(crate) subject: &'a str,
    pub(crate) user_id: Option<Uuid>,
    pub(crate) subject_type: &'a str,
    pub(crate) client_id: &'a str,
    pub(crate) audience: &'a str,
    pub(crate) scopes: &'a [String],
    pub(crate) userinfo_claims: &'a [String],
    pub(crate) ttl: i64,
    pub(crate) dpop_jkt: Option<&'a str>,
}

pub(crate) struct IssuedAccessToken {
    pub(crate) token: String,
    pub(crate) jti: String,
    pub(crate) exp: i64,
}

pub(crate) fn make_jwt(
    state: &AppState,
    input: AccessTokenJwtInput<'_>,
) -> jsonwebtoken::errors::Result<IssuedAccessToken> {
    let now = Utc::now().timestamp();
    let jti = Uuid::now_v7().to_string();
    let exp = now + input.ttl;
    let claims = Claims {
        iss: state.settings.issuer.clone(),
        sub: input.subject.to_string(),
        user_id: input.user_id.map(|id| id.to_string()),
        subject_type: input.subject_type.to_string(),
        aud: input.audience.to_string(),
        client_id: input.client_id.to_string(),
        scope: sorted_scope_string(input.scopes),
        token_use: "access".into(),
        jti: jti.clone(),
        iat: now,
        nbf: now,
        exp,
        cnf: input.dpop_jkt.map(|jkt| ConfirmationClaims {
            jkt: jkt.to_owned(),
        }),
        userinfo_claims: input.userinfo_claims.to_vec(),
    };
    let mut header = jsonwebtoken::Header::new(state.keyset.active_alg);
    header.typ = Some("at+jwt".to_string());
    header.kid = Some(state.keyset.active_kid.clone());
    let token = jsonwebtoken::encode(&header, &claims, &state.keyset.active_encoding_key())?;
    Ok(IssuedAccessToken { token, jti, exp })
}

pub(crate) struct IdTokenInput<'a> {
    pub(crate) subject: &'a str,
    pub(crate) client_id: &'a str,
    pub(crate) nonce: Option<String>,
    pub(crate) auth_time: Option<i64>,
    pub(crate) amr: &'a [String],
    pub(crate) acr: Option<&'a str>,
    pub(crate) extra_claims: Option<&'a Value>,
    pub(crate) ttl: i64,
}

pub(crate) fn make_id_token(
    state: &AppState,
    input: IdTokenInput<'_>,
) -> jsonwebtoken::errors::Result<String> {
    let now = Utc::now().timestamp();
    let mut claims = serde_json::Map::new();
    claims.insert("iss".to_owned(), json!(state.settings.issuer));
    claims.insert("sub".to_owned(), json!(input.subject));
    claims.insert("aud".to_owned(), json!(input.client_id));
    claims.insert("iat".to_owned(), json!(now));
    claims.insert("nbf".to_owned(), json!(now));
    claims.insert("exp".to_owned(), json!(now + input.ttl));
    claims.insert("jti".to_owned(), json!(Uuid::now_v7().to_string()));
    if let Some(nonce) = input.nonce {
        claims.insert("nonce".to_owned(), json!(nonce));
    }
    if let Some(auth_time) = input.auth_time {
        claims.insert("auth_time".to_owned(), json!(auth_time));
    }
    if !input.amr.is_empty() {
        claims.insert("amr".to_owned(), json!(input.amr));
    }
    if let Some(acr) = input.acr {
        claims.insert("acr".to_owned(), json!(acr));
    }
    if let Some(extra_claims) = input.extra_claims.and_then(Value::as_object) {
        for (key, value) in extra_claims {
            if !matches!(
                key.as_str(),
                "iss"
                    | "sub"
                    | "aud"
                    | "iat"
                    | "nbf"
                    | "exp"
                    | "jti"
                    | "nonce"
                    | "auth_time"
                    | "amr"
                    | "acr"
            ) {
                claims.insert(key.clone(), value.clone());
            }
        }
    }
    let mut header = jsonwebtoken::Header::new(state.keyset.active_alg);
    header.typ = Some("JWT".to_string());
    header.kid = Some(state.keyset.active_kid.clone());
    jsonwebtoken::encode(&header, &claims, &state.keyset.active_encoding_key())
}

pub(crate) fn decode_access_claims(state: &AppState, token: &str) -> Option<Claims> {
    let header = jsonwebtoken::decode_header(token).ok()?;
    if header.typ.as_deref() != Some("at+jwt") || signing_algorithm_name(header.alg).is_none() {
        return None;
    }
    let verification_key = state.keyset.verification_key(header.kid.as_deref()?)?;
    let decoding_key = jwt_decoding_key_from_jwk(&verification_key.public_jwk, header.alg)?;
    let mut validation = jsonwebtoken::Validation::new(header.alg);
    validation.validate_aud = false;
    validation.set_issuer(&[state.settings.issuer.as_str()]);
    let token_data = jsonwebtoken::decode::<Claims>(token, &decoding_key, &validation).ok()?;
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

    #[test]
    fn basic_client_credentials_scheme_is_case_insensitive() {
        let mut headers = HeaderMap::new();
        let encoded = STANDARD.encode("client-1:secret-1");
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_str(&format!("basic {encoded}")).unwrap(),
        );

        assert!(has_basic_authorization_scheme(&headers));
        let credentials = extract_client_credentials(&headers, None, None, None, None);

        assert_eq!(credentials.method, "client_secret_basic");
        assert_eq!(credentials.client_id.as_deref(), Some("client-1"));
        assert_eq!(credentials.client_secret.as_deref(), Some("secret-1"));
    }

    #[test]
    fn malformed_basic_authorization_scheme_is_detected() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Basic not-base64 with-space"),
        );

        assert!(has_basic_authorization_scheme(&headers));
    }

    #[test]
    fn malformed_basic_authorization_is_not_decoded_as_basic_credentials() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Basic not-base64 with-space"),
        );

        let credentials = extract_client_credentials(&headers, None, None, None, None);

        assert_eq!(credentials.method, "none");
        assert!(credentials.client_id.is_none());
        assert!(credentials.client_secret.is_none());
    }

    #[test]
    fn par_client_assertion_accepts_only_issuer_audience_by_default() {
        let expected = client_assertion_audience_candidates("https://issuer.example", "/par");

        assert!(audience_matches(
            &json!("https://issuer.example"),
            &expected,
            false
        ));
        assert!(!audience_matches(
            &json!("https://issuer.example/par"),
            &expected,
            false
        ));
        assert!(!audience_matches(
            &json!("https://issuer.example/token"),
            &expected,
            false
        ));
        assert!(!audience_matches(
            &json!(["https://issuer.example", "https://unexpected.example"]),
            &expected,
            false
        ));
        assert!(!audience_matches(
            &json!("https://issuer.example/authorize"),
            &expected,
            false
        ));
        assert!(!audience_matches(
            &json!(["https://unexpected.example"]),
            &expected,
            false
        ));
    }

    #[test]
    fn client_assertion_audience_arrays_require_explicit_client_policy() {
        let expected = client_assertion_audience_candidates("https://issuer.example", "/par");

        assert!(audience_matches(
            &json!(["https://issuer.example", "https://unexpected.example"]),
            &expected,
            true
        ));
        assert!(!audience_matches(
            &json!(["https://issuer.example", "https://unexpected.example"]),
            &expected,
            false
        ));
    }

    #[test]
    fn token_client_assertion_accepts_issuer_and_token_endpoint_audience() {
        let expected = client_assertion_audience_candidates("https://issuer.example", "/token");

        assert!(audience_matches(
            &json!("https://issuer.example"),
            &expected,
            false
        ));
        assert!(audience_matches(
            &json!("https://issuer.example/token"),
            &expected,
            false
        ));
        assert!(!audience_matches(
            &json!("https://issuer.example/par"),
            &expected,
            false
        ));
        assert!(!audience_matches(
            &json!(["https://issuer.example", "https://unexpected.example"]),
            &expected,
            false
        ));
        assert!(audience_matches(
            &json!(["https://issuer.example", "https://unexpected.example"]),
            &expected,
            true
        ));
        assert!(!audience_matches(
            &json!(["https://unexpected.example"]),
            &expected,
            true
        ));
    }

    #[test]
    fn non_utf8_basic_authorization_scheme_is_detected() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_bytes(b"Basic \xff").unwrap(),
        );

        assert!(has_basic_authorization_scheme(&headers));
        let credentials = extract_client_credentials(&headers, None, None, None, None);
        assert_eq!(credentials.method, "none");
    }
}
