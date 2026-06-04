//! JWT-Secured Authorization Request validation.

use super::request::AUTHORIZED_REQUEST_PARAMETERS;
use crate::http::prelude::*;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};

const REQUEST_OBJECT_MAX_TTL_SECONDS: i64 = 300;
const REQUEST_OBJECT_CLOCK_SKEW_SECONDS: i64 = 30;

#[derive(Deserialize)]
struct RequestObjectClaims {
    client_id: String,
    iss: Option<String>,
    sub: Option<String>,
    aud: Option<Value>,
    exp: Option<i64>,
    nbf: Option<i64>,
    iat: Option<i64>,
    jti: Option<String>,
    #[serde(flatten)]
    params: HashMap<String, Value>,
}

#[derive(Deserialize)]
struct RequestObjectHeader {
    alg: String,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum RequestObjectMode {
    BasicOidc,
    SignedJar,
}

pub(crate) async fn apply_request_object(
    state: &AppState,
    outer: &mut HashMap<String, String>,
    client: &ClientRow,
) -> Result<(), HttpResponse> {
    let Some(request_object) = outer.get("request").cloned() else {
        return Ok(());
    };
    let Some((header_part, payload_part, signature_part)) = split_compact_jwt(&request_object)
    else {
        return Err(oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request_object",
            "request object 无效.",
        ));
    };
    let header = decode_request_object_header(header_part)?;
    let (claims, mode) =
        if request_object_uses_none_algorithm(&header, payload_part, signature_part)? {
            (
                decode_request_object_claims(payload_part)?,
                RequestObjectMode::BasicOidc,
            )
        } else {
            let header = jsonwebtoken::decode_header(&request_object).map_err(|_| {
                oauth_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_request_object",
                    "request object 签名算法无效.",
                )
            })?;
            (
                signed_request_object_claims(&request_object, client, header)?,
                RequestObjectMode::SignedJar,
            )
        };
    if !request_object_mode_allowed(client, mode) {
        return Err(oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request_object",
            "request object 签名要求无效.",
        ));
    }
    validate_request_object_claims_and_apply(state, outer, client, claims, mode).await
}

fn signed_request_object_claims(
    request_object: &str,
    client: &ClientRow,
    header: jsonwebtoken::Header,
) -> Result<RequestObjectClaims, HttpResponse> {
    let Some(_algorithm_name) = supported_client_jwt_algorithm_name(header.alg) else {
        return Err(oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request_object",
            "request object 签名算法无效.",
        ));
    };
    let Some(kid) = header.kid.as_deref() else {
        return Err(oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request_object",
            "request object 缺少 kid.",
        ));
    };
    let Some(decoding_key) = client_jwt_decoding_key(client, kid, header.alg) else {
        return Err(oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request_object",
            "request object 签名密钥无效.",
        ));
    };
    let mut validation = jsonwebtoken::Validation::new(header.alg);
    validation.validate_aud = false;
    validation.set_required_spec_claims::<&str>(&[]);
    validation.set_issuer(&[client.client_id.as_str()]);
    let token_data =
        jsonwebtoken::decode::<RequestObjectClaims>(&request_object, &decoding_key, &validation)
            .map_err(|_| {
                oauth_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_request_object",
                    "request object 验签失败.",
                )
            })?;
    Ok(token_data.claims)
}

fn request_object_uses_none_algorithm(
    header: &RequestObjectHeader,
    payload: &str,
    signature: &str,
) -> Result<bool, HttpResponse> {
    if header.alg == "none" {
        if !signature.is_empty() || payload.is_empty() {
            return Err(oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_request_object",
                "unsigned request object 结构无效.",
            ));
        }
        return Ok(true);
    }
    if signature.is_empty() {
        return Err(oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request_object",
            "request object 签名算法无效.",
        ));
    }
    Ok(false)
}

fn request_object_mode_allowed(client: &ClientRow, mode: RequestObjectMode) -> bool {
    !(client.require_dpop_bound_tokens && mode == RequestObjectMode::BasicOidc)
}

fn split_compact_jwt(token: &str) -> Option<(&str, &str, &str)> {
    let mut parts = token.split('.');
    let header = parts.next()?;
    let payload = parts.next()?;
    let signature = parts.next()?;
    parts
        .next()
        .is_none()
        .then_some((header, payload, signature))
}

fn decode_request_object_header(header: &str) -> Result<RequestObjectHeader, HttpResponse> {
    let bytes = URL_SAFE_NO_PAD.decode(header).map_err(|_| {
        oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request_object",
            "request object header 无效.",
        )
    })?;
    serde_json::from_slice(&bytes).map_err(|_| {
        oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request_object",
            "request object header 无效.",
        )
    })
}

fn decode_request_object_claims(payload: &str) -> Result<RequestObjectClaims, HttpResponse> {
    let bytes = URL_SAFE_NO_PAD.decode(payload).map_err(|_| {
        oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request_object",
            "request object claims 无效.",
        )
    })?;
    serde_json::from_slice(&bytes).map_err(|_| {
        oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request_object",
            "request object claims 无效.",
        )
    })
}

async fn validate_request_object_claims_and_apply(
    state: &AppState,
    outer: &mut HashMap<String, String>,
    client: &ClientRow,
    claims: RequestObjectClaims,
    mode: RequestObjectMode,
) -> Result<(), HttpResponse> {
    let now = Utc::now().timestamp();
    if claims.client_id != client.client_id
        || !request_object_party_claims_valid(&claims, client, mode)
        || !request_object_audience_valid(&claims, state, mode)
        || !request_object_times_valid(&claims, now, mode)
        || !request_object_jti_valid(&claims, mode)
    {
        return Err(oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request_object",
            "request object claims 无效.",
        ));
    }
    let mut request_params = request_object_params(&claims)?;
    request_params.insert("client_id".to_owned(), claims.client_id.clone());
    if outer_client_id_conflicts(outer, &claims.client_id) {
        return Err(oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "request object 与外层 client_id 冲突.",
        ));
    }
    if mode == RequestObjectMode::SignedJar && !request_params.contains_key("redirect_uri") {
        return Err(oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request_object",
            "signed request object 缺少 redirect_uri.",
        ));
    }
    if client.require_dpop_bound_tokens
        && mode == RequestObjectMode::SignedJar
        && outer_authorization_params_conflict(outer, &request_params)
    {
        return Err(oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request_object",
            "request object 与外层授权参数冲突.",
        ));
    }
    store_request_object_replay_state(state, client, &claims, now, mode).await?;
    if client.require_dpop_bound_tokens && mode == RequestObjectMode::SignedJar {
        outer.retain(|key, _| matches!(key.as_str(), "request" | "client_id"));
    } else {
        outer.retain(|key, _| key == "request" || !request_params.contains_key(key));
    }
    outer.extend(request_params);
    Ok(())
}

fn request_object_party_claims_valid(
    claims: &RequestObjectClaims,
    client: &ClientRow,
    mode: RequestObjectMode,
) -> bool {
    match mode {
        RequestObjectMode::BasicOidc => {
            claims
                .iss
                .as_deref()
                .is_none_or(|iss| iss == client.client_id)
                && claims
                    .sub
                    .as_deref()
                    .is_none_or(|sub| sub == client.client_id)
        }
        RequestObjectMode::SignedJar => {
            claims.iss.as_deref() == Some(client.client_id.as_str())
                && claims
                    .sub
                    .as_deref()
                    .is_none_or(|sub| sub == client.client_id)
        }
    }
}

fn request_object_audience_valid(
    claims: &RequestObjectClaims,
    state: &AppState,
    mode: RequestObjectMode,
) -> bool {
    match (&claims.aud, mode) {
        (Some(aud), _) => request_object_audience_matches(aud, state),
        (None, RequestObjectMode::BasicOidc) => true,
        (None, RequestObjectMode::SignedJar) => false,
    }
}

fn outer_client_id_conflicts(outer: &HashMap<String, String>, client_id: &str) -> bool {
    outer
        .get("client_id")
        .is_some_and(|outer_value| outer_value != client_id)
}

fn outer_authorization_params_conflict(
    outer: &HashMap<String, String>,
    request_params: &HashMap<String, String>,
) -> bool {
    for key in AUTHORIZED_REQUEST_PARAMETERS {
        if matches!(*key, "request" | "request_uri" | "client_id") {
            continue;
        }
        if let (Some(outer_value), Some(request_value)) =
            (outer.get(*key), request_params.get(*key))
            && outer_value != request_value
        {
            return true;
        }
    }
    false
}

async fn store_request_object_replay_state(
    state: &AppState,
    client: &ClientRow,
    claims: &RequestObjectClaims,
    now: i64,
    mode: RequestObjectMode,
) -> Result<(), HttpResponse> {
    let Some(jti) = claims.jti.as_deref() else {
        return Ok(());
    };
    let ttl_seconds = match claims.exp {
        Some(exp) => exp
            .saturating_sub(now)
            .clamp(1, REQUEST_OBJECT_MAX_TTL_SECONDS) as u64,
        None if mode == RequestObjectMode::BasicOidc => REQUEST_OBJECT_MAX_TTL_SECONDS as u64,
        None => {
            return Err(oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_request_object",
                "request object claims 无效.",
            ));
        }
    };
    let replay_key = format!(
        "oauth:jar:jti:{}:{}",
        blake3_hex(&client.client_id),
        blake3_hex(jti)
    );
    match valkey_set_ex_nx(&state.valkey, replay_key, "1", ttl_seconds).await {
        Ok(true) => Ok(()),
        Ok(false) => Err(oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request_object",
            "request object jti 已使用.",
        )),
        Err(error) => {
            tracing::warn!(%error, "failed to store request object jti");
            Err(oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "request object 防重放状态不可用.",
            ))
        }
    }
}

pub(crate) fn unverified_request_object_client_id(request_object: &str) -> Option<String> {
    let (header, payload, signature) = split_compact_jwt(request_object)?;
    let header = decode_request_object_header(header).ok()?;
    if header.alg == "none" && !signature.is_empty() {
        return None;
    }
    if header.alg != "none" && signature.is_empty() {
        return None;
    }
    let claims = decode_request_object_claims(payload).ok()?;
    let issuer_matches = claims
        .iss
        .as_deref()
        .is_none_or(|iss| iss == claims.client_id);
    let subject_matches = claims
        .sub
        .as_deref()
        .is_none_or(|sub| sub == claims.client_id);
    (issuer_matches && subject_matches && !claims.client_id.trim().is_empty())
        .then_some(claims.client_id)
}

fn request_object_params(
    claims: &RequestObjectClaims,
) -> Result<HashMap<String, String>, HttpResponse> {
    if claims.params.contains_key("request_uri") {
        return Err(oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request_object",
            "request object 不能包含 request_uri.",
        ));
    }

    let mut params = HashMap::new();
    for key in AUTHORIZED_REQUEST_PARAMETERS {
        if matches!(*key, "request" | "request_uri" | "client_id") {
            continue;
        }
        if let Some(value) = claims.params.get(*key) {
            let value = match value {
                Value::String(value) => value.clone(),
                Value::Number(value) => value.to_string(),
                Value::Object(_) if *key == "claims" => value.to_string(),
                _ => {
                    return Err(oauth_error(
                        StatusCode::BAD_REQUEST,
                        "invalid_request_object",
                        "request object 参数类型无效.",
                    ));
                }
            };
            params.insert((*key).to_owned(), value);
        }
    }
    Ok(params)
}

fn request_object_audience_matches(aud: &Value, state: &AppState) -> bool {
    let issuer = state.settings.issuer.as_str();
    let authorize_endpoint = format!("{issuer}/authorize");
    match aud {
        Value::String(value) => value == issuer || value == &authorize_endpoint,
        Value::Array(values) => values.iter().any(|value| {
            value
                .as_str()
                .is_some_and(|value| value == issuer || value == authorize_endpoint)
        }),
        _ => false,
    }
}

fn request_object_times_valid(
    claims: &RequestObjectClaims,
    now: i64,
    mode: RequestObjectMode,
) -> bool {
    let exp = match claims.exp {
        Some(exp) if exp <= now => return false,
        Some(exp) => exp,
        None if mode == RequestObjectMode::SignedJar => return false,
        None => now.saturating_add(REQUEST_OBJECT_MAX_TTL_SECONDS),
    };

    let nbf = match claims.nbf {
        Some(nbf) => nbf,
        None if mode == RequestObjectMode::SignedJar => return false,
        None => now,
    };

    if nbf > now.saturating_add(REQUEST_OBJECT_CLOCK_SKEW_SECONDS) {
        return false;
    }
    if mode == RequestObjectMode::SignedJar {
        if now.saturating_sub(nbf) > REQUEST_OBJECT_MAX_TTL_SECONDS {
            return false;
        }
        if exp <= nbf
            || exp.saturating_sub(nbf)
                > REQUEST_OBJECT_MAX_TTL_SECONDS.saturating_add(REQUEST_OBJECT_CLOCK_SKEW_SECONDS)
        {
            return false;
        }
    } else if exp > now.saturating_add(REQUEST_OBJECT_MAX_TTL_SECONDS) {
        return false;
    }

    if claims.iat.is_some_and(|iat| {
        iat > now.saturating_add(REQUEST_OBJECT_CLOCK_SKEW_SECONDS)
            || now.saturating_sub(iat) > REQUEST_OBJECT_MAX_TTL_SECONDS
    }) {
        return false;
    }
    true
}

fn request_object_jti_valid(claims: &RequestObjectClaims, mode: RequestObjectMode) -> bool {
    match (&claims.jti, mode) {
        (Some(jti), _) => is_valid_request_object_jti(jti),
        (None, _) => true,
    }
}

fn is_valid_request_object_jti(jti: &str) -> bool {
    let trimmed = jti.trim();
    !trimmed.is_empty() && trimmed.len() <= 128
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use serde_json::json;

    fn request_object(payload: Value, alg: &str, signature: &str) -> String {
        let header = if alg == "none" {
            json!({"alg": "none"})
        } else {
            json!({"alg": alg, "kid": "kid-1"})
        };
        format!(
            "{}.{}.{}",
            URL_SAFE_NO_PAD.encode(header.to_string()),
            URL_SAFE_NO_PAD.encode(payload.to_string()),
            signature
        )
    }

    #[test]
    fn unverified_client_id_allows_basic_unsigned_request_object_claims() {
        let token = request_object(
            json!({
                "client_id": "client-a",
                "redirect_uri": "https://client.example/callback",
                "response_type": "code",
                "scope": "openid",
                "state": "state-1",
                "nonce": "nonce-1"
            }),
            "none",
            "",
        );
        assert_eq!(
            unverified_request_object_client_id(&token).as_deref(),
            Some("client-a")
        );
    }

    #[test]
    fn unverified_client_id_rejects_mismatched_party_claims() {
        let token = request_object(
            json!({
                "iss": "client-a",
                "sub": "client-a",
                "client_id": "client-a",
                "aud": "https://issuer.example",
                "exp": 4102444800i64,
                "jti": "jar-1"
            }),
            "EdDSA",
            &URL_SAFE_NO_PAD.encode("signature"),
        );
        assert_eq!(
            unverified_request_object_client_id(&token).as_deref(),
            Some("client-a")
        );

        let mismatched = request_object(
            json!({
                "iss": "client-a",
                "sub": "client-a",
                "client_id": "client-b",
                "aud": "https://issuer.example",
                "exp": 4102444800i64,
                "jti": "jar-2"
            }),
            "EdDSA",
            &URL_SAFE_NO_PAD.encode("signature"),
        );
        assert!(unverified_request_object_client_id(&mismatched).is_none());
    }

    #[test]
    fn unverified_client_id_rejects_invalid_compact_signatures() {
        let payload = json!({"client_id": "client-a"});
        let unsigned_with_signature = request_object(
            payload.clone(),
            "none",
            &URL_SAFE_NO_PAD.encode("signature"),
        );
        assert!(unverified_request_object_client_id(&unsigned_with_signature).is_none());

        let signed_without_signature = request_object(payload, "EdDSA", "");
        assert!(unverified_request_object_client_id(&signed_without_signature).is_none());
    }

    #[test]
    fn request_object_jti_is_optional_but_validated_when_present() {
        assert!(is_valid_request_object_jti("abc"));
        assert!(!is_valid_request_object_jti(""));
        assert!(!is_valid_request_object_jti(&"a".repeat(129)));

        let basic = RequestObjectClaims {
            client_id: "client-a".to_owned(),
            iss: None,
            sub: None,
            aud: None,
            exp: None,
            nbf: None,
            iat: None,
            jti: None,
            params: HashMap::new(),
        };
        assert!(request_object_jti_valid(
            &basic,
            RequestObjectMode::BasicOidc
        ));
        assert!(request_object_jti_valid(
            &basic,
            RequestObjectMode::SignedJar
        ));

        let invalid = RequestObjectClaims {
            jti: Some(String::new()),
            ..basic
        };
        assert!(!request_object_jti_valid(
            &invalid,
            RequestObjectMode::SignedJar
        ));
    }

    #[test]
    fn request_object_params_rejects_request_uri_claim() {
        let mut claims = RequestObjectClaims {
            client_id: "client-a".to_owned(),
            iss: None,
            sub: None,
            aud: None,
            exp: None,
            nbf: None,
            iat: None,
            jti: None,
            params: HashMap::from([
                (
                    "redirect_uri".to_owned(),
                    json!("https://client.example/callback"),
                ),
                ("request_uri".to_owned(), json!("urn:example:bad")),
            ]),
        };
        assert!(request_object_params(&claims).is_err());

        claims.params.remove("request_uri");
        let params = request_object_params(&claims).expect("valid request object params");
        assert_eq!(
            params.get("redirect_uri").map(String::as_str),
            Some("https://client.example/callback")
        );
    }

    fn time_claims(exp: Option<i64>, nbf: Option<i64>, iat: Option<i64>) -> RequestObjectClaims {
        RequestObjectClaims {
            client_id: "client-a".to_owned(),
            iss: None,
            sub: None,
            aud: None,
            exp,
            nbf,
            iat,
            jti: None,
            params: HashMap::new(),
        }
    }

    #[test]
    fn signed_request_object_requires_exp_and_nbf() {
        let now = 1_700_000_000;

        assert!(!request_object_times_valid(
            &time_claims(None, Some(now), None),
            now,
            RequestObjectMode::SignedJar
        ));
        assert!(!request_object_times_valid(
            &time_claims(Some(now + 60), None, None),
            now,
            RequestObjectMode::SignedJar
        ));
        assert!(request_object_times_valid(
            &time_claims(Some(now + 60), Some(now), None),
            now,
            RequestObjectMode::SignedJar
        ));
    }

    #[test]
    fn signed_request_object_rejects_invalid_nbf_window() {
        let now = 1_700_000_000;

        assert!(request_object_times_valid(
            &time_claims(Some(now + 300), Some(now + 8), None),
            now,
            RequestObjectMode::SignedJar
        ));
        assert!(!request_object_times_valid(
            &time_claims(Some(now + 300), Some(now + 31), None),
            now,
            RequestObjectMode::SignedJar
        ));
        assert!(!request_object_times_valid(
            &time_claims(Some(now + 60), Some(now - 301), None),
            now,
            RequestObjectMode::SignedJar
        ));
    }

    #[test]
    fn signed_request_object_rejects_invalid_exp_window() {
        let now = 1_700_000_000;

        assert!(!request_object_times_valid(
            &time_claims(Some(now), Some(now), None),
            now,
            RequestObjectMode::SignedJar
        ));
        assert!(request_object_times_valid(
            &time_claims(Some(now + 301), Some(now), None),
            now,
            RequestObjectMode::SignedJar
        ));
        assert!(!request_object_times_valid(
            &time_claims(Some(now + 331), Some(now), None),
            now,
            RequestObjectMode::SignedJar
        ));
        assert!(!request_object_times_valid(
            &time_claims(Some(now + 60), Some(now + 60), None),
            now,
            RequestObjectMode::SignedJar
        ));
    }

    #[test]
    fn dpop_bound_client_rejects_unsigned_request_objects() {
        let mut client = ClientRow {
            id: Uuid::now_v7(),
            client_id: "client-a".to_owned(),
            client_name: "Client A".to_owned(),
            client_type: "confidential".to_owned(),
            client_secret_argon2_hash: None,
            redirect_uris: json!([]),
            scopes: json!([]),
            allowed_audiences: json!([]),
            grant_types: json!([]),
            token_endpoint_auth_method: "private_key_jwt".to_owned(),
            require_dpop_bound_tokens: false,
            allow_client_assertion_audience_array: false,
            is_active: true,
            jwks: None,
        };

        assert!(request_object_mode_allowed(
            &client,
            RequestObjectMode::BasicOidc
        ));
        assert!(request_object_mode_allowed(
            &client,
            RequestObjectMode::SignedJar
        ));

        client.require_dpop_bound_tokens = true;
        assert!(!request_object_mode_allowed(
            &client,
            RequestObjectMode::BasicOidc
        ));
        assert!(request_object_mode_allowed(
            &client,
            RequestObjectMode::SignedJar
        ));
    }

    #[test]
    fn signed_request_object_sub_is_optional_but_must_match_when_present() {
        let mut claims = RequestObjectClaims {
            client_id: "client-a".to_owned(),
            iss: Some("client-a".to_owned()),
            sub: None,
            aud: None,
            exp: None,
            nbf: None,
            iat: None,
            jti: None,
            params: HashMap::new(),
        };
        let client = ClientRow {
            id: Uuid::now_v7(),
            client_id: "client-a".to_owned(),
            client_name: "Client A".to_owned(),
            client_type: "confidential".to_owned(),
            client_secret_argon2_hash: None,
            redirect_uris: json!([]),
            scopes: json!([]),
            allowed_audiences: json!([]),
            grant_types: json!([]),
            token_endpoint_auth_method: "private_key_jwt".to_owned(),
            require_dpop_bound_tokens: false,
            allow_client_assertion_audience_array: false,
            is_active: true,
            jwks: None,
        };

        assert!(request_object_party_claims_valid(
            &claims,
            &client,
            RequestObjectMode::SignedJar
        ));

        claims.sub = Some("client-a".to_owned());
        assert!(request_object_party_claims_valid(
            &claims,
            &client,
            RequestObjectMode::SignedJar
        ));

        claims.sub = Some("client-b".to_owned());
        assert!(!request_object_party_claims_valid(
            &claims,
            &client,
            RequestObjectMode::SignedJar
        ));
    }
}
