//! JWT-Secured Authorization Request validation.

use super::request::AUTHORIZED_REQUEST_PARAMETERS;
use crate::http::prelude::*;

const REQUEST_OBJECT_MAX_TTL_SECONDS: i64 = 300;
const REQUEST_OBJECT_CLOCK_SKEW_SECONDS: i64 = 30;

#[derive(Deserialize)]
struct RequestObjectClaims {
    iss: String,
    sub: String,
    client_id: String,
    aud: Value,
    exp: i64,
    nbf: Option<i64>,
    iat: Option<i64>,
    jti: String,
    #[serde(flatten)]
    params: HashMap<String, Value>,
}

pub(crate) async fn apply_request_object(
    state: &AppState,
    outer: &mut HashMap<String, String>,
    client: &ClientRow,
) -> Result<(), HttpResponse> {
    let Some(request_object) = outer.get("request").cloned() else {
        return Ok(());
    };
    let header = jsonwebtoken::decode_header(&request_object).map_err(|_| {
        oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request_object",
            "request object 无效.",
        )
    })?;
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
    let claims = token_data.claims;
    let now = Utc::now().timestamp();
    if claims.iss != client.client_id
        || claims.sub != client.client_id
        || claims.client_id != client.client_id
        || !request_object_audience_matches(&claims.aud, state)
        || !request_object_times_valid(&claims, now)
        || !is_valid_request_object_jti(&claims.jti)
    {
        return Err(oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request_object",
            "request object claims 无效.",
        ));
    }
    let mut request_params = request_object_params(&claims)?;
    request_params.insert("client_id".to_owned(), claims.client_id);
    for (key, value) in &request_params {
        if let Some(outer_value) = outer.get(key)
            && outer_value != value
        {
            return Err(oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "request object 与外层参数冲突.",
            ));
        }
    }
    let ttl_seconds = claims
        .exp
        .saturating_sub(now)
        .clamp(1, REQUEST_OBJECT_MAX_TTL_SECONDS) as u64;
    let replay_key = format!(
        "oauth:jar:jti:{}:{}",
        blake3_hex(&client.client_id),
        blake3_hex(&claims.jti)
    );
    match valkey_set_ex_nx(&state.valkey, replay_key, "1", ttl_seconds).await {
        Ok(true) => {}
        Ok(false) => {
            return Err(oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_request_object",
                "request object jti 已使用.",
            ));
        }
        Err(error) => {
            tracing::warn!(%error, "failed to store request object jti");
            return Err(oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "request object 防重放状态不可用.",
            ));
        }
    }
    outer.retain(|key, _| key == "request" || !request_params.contains_key(key));
    outer.extend(request_params);
    Ok(())
}

pub(crate) fn unverified_request_object_client_id(request_object: &str) -> Option<String> {
    let claims = jsonwebtoken::dangerous::insecure_decode::<RequestObjectClaims>(request_object)
        .ok()?
        .claims;
    (claims.iss == claims.sub
        && claims.sub == claims.client_id
        && !claims.client_id.trim().is_empty())
    .then_some(claims.client_id)
}

fn request_object_params(
    claims: &RequestObjectClaims,
) -> Result<HashMap<String, String>, HttpResponse> {
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

fn request_object_times_valid(claims: &RequestObjectClaims, now: i64) -> bool {
    if claims.exp <= now || claims.exp > now.saturating_add(REQUEST_OBJECT_MAX_TTL_SECONDS) {
        return false;
    }
    if claims
        .nbf
        .is_some_and(|nbf| nbf > now.saturating_add(REQUEST_OBJECT_CLOCK_SKEW_SECONDS))
    {
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

fn is_valid_request_object_jti(jti: &str) -> bool {
    let trimmed = jti.trim();
    !trimmed.is_empty() && trimmed.len() <= 128
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use serde_json::json;

    fn unsigned_request_object(payload: Value) -> String {
        let header = json!({"alg": "EdDSA", "kid": "kid-1"});
        format!(
            "{}.{}.{}",
            URL_SAFE_NO_PAD.encode(header.to_string()),
            URL_SAFE_NO_PAD.encode(payload.to_string()),
            URL_SAFE_NO_PAD.encode("signature")
        )
    }

    #[test]
    fn unverified_client_id_requires_matching_registered_party_claims() {
        let token = unsigned_request_object(json!({
            "iss": "client-a",
            "sub": "client-a",
            "client_id": "client-a",
            "aud": "https://issuer.example",
            "exp": 4102444800i64,
            "jti": "jar-1"
        }));
        assert_eq!(
            unverified_request_object_client_id(&token).as_deref(),
            Some("client-a")
        );

        let mismatched = unsigned_request_object(json!({
            "iss": "client-a",
            "sub": "client-a",
            "client_id": "client-b",
            "aud": "https://issuer.example",
            "exp": 4102444800i64,
            "jti": "jar-2"
        }));
        assert!(unverified_request_object_client_id(&mismatched).is_none());
    }

    #[test]
    fn request_object_jti_must_be_non_empty_and_bounded() {
        assert!(is_valid_request_object_jti("abc"));
        assert!(!is_valid_request_object_jti(""));
        assert!(!is_valid_request_object_jti(&"a".repeat(129)));
    }
}
