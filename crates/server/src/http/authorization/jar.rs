//! JWT-Secured Authorization Request validation.
#[cfg(test)]
use nazo_http_actix::OAuthJsonErrorFields;
use nazo_http_actix::oauth_error;

use super::request::AUTHORIZED_REQUEST_PARAMETERS;
#[cfg(test)]
use crate::domain::AppState;
use crate::domain::ClientRow;
use crate::http::authorization::AuthorizationRequestContext;
use crate::settings::RequestObjectJtiPolicy;
#[cfg(test)]
use crate::settings::Settings;
#[cfg(test)]
use crate::support::{DEFAULT_ORGANIZATION_ID, DEFAULT_REALM_ID, DEFAULT_TENANT_ID};
use crate::support::{
    client_jwt_decoding_key, resource_indicators_from_parameter_value,
    supported_client_jwt_algorithm_name,
};
use actix_web::HttpResponse;
use actix_web::http::StatusCode;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::Utc;
use serde::Deserialize;
use serde_json::Value;
use std::collections::HashMap;
#[cfg(test)]
use uuid::Uuid;

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

pub(crate) async fn apply_request_object_with_context(
    context: &AuthorizationRequestContext,
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
    if !request_object_mode_allowed(
        client,
        mode,
        context.config.profile.requires_fapi2_security(),
    ) {
        return Err(oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request_object",
            "request object 签名要求无效.",
        ));
    }
    validate_request_object_claims_and_apply(context, outer, client, claims, mode).await
}

#[cfg(test)]
pub(crate) async fn apply_request_object(
    state: &crate::domain::AppState,
    outer: &mut HashMap<String, String>,
    client: &ClientRow,
) -> Result<(), HttpResponse> {
    let dependencies = super::TestAuthorizationDependencies::new(state);
    apply_request_object_with_context(&dependencies.context(), outer, client).await
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
        if payload.is_empty() || !signature.is_empty() {
            return Err(oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_request_object",
                "request object 签名算法无效.",
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

fn request_object_mode_allowed(
    client: &ClientRow,
    mode: RequestObjectMode,
    profile_disallows_unsigned_request_object: bool,
) -> bool {
    !((client.require_dpop_bound_tokens
        || client.require_par_request_object
        || profile_disallows_unsigned_request_object)
        && mode == RequestObjectMode::BasicOidc)
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
    context: &AuthorizationRequestContext,
    outer: &mut HashMap<String, String>,
    client: &ClientRow,
    claims: RequestObjectClaims,
    mode: RequestObjectMode,
) -> Result<(), HttpResponse> {
    let now = Utc::now().timestamp();
    if claims.client_id != client.client_id
        || !request_object_party_claims_valid(&claims, client, mode)
        || !request_object_audience_valid_with_issuer(&claims, &context.config.issuer, mode)
        || !request_object_times_valid(&claims, now, mode)
        || !request_object_jti_valid(&claims, mode, context.config.request_object_jti_policy)
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
    let require_integrity_protected_parameters =
        signed_request_object_requires_integrity_protected_parameters(context, client, mode);
    if require_integrity_protected_parameters
        && outer_authorization_params_conflict(outer, &request_params)
    {
        return Err(oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request_object",
            "request object 与外层授权参数冲突.",
        ));
    }
    store_request_object_replay_state_with_context(context, client, &claims, now, mode).await?;
    if require_integrity_protected_parameters {
        outer.retain(|key, _| matches!(key.as_str(), "request" | "client_id"));
    } else {
        outer.retain(|key, _| key == "request" || !request_params.contains_key(key));
    }
    outer.extend(request_params);
    Ok(())
}

fn signed_request_object_requires_integrity_protected_parameters(
    context: &AuthorizationRequestContext,
    client: &ClientRow,
    mode: RequestObjectMode,
) -> bool {
    mode == RequestObjectMode::SignedJar
        && (client.require_dpop_bound_tokens
            || client.require_par_request_object
            || context
                .config
                .profile
                .requires_signed_authorization_request())
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

fn request_object_audience_valid_with_issuer(
    claims: &RequestObjectClaims,
    issuer: &str,
    mode: RequestObjectMode,
) -> bool {
    match (&claims.aud, mode) {
        (Some(aud), _) => request_object_audience_matches_with_issuer(aud, issuer),
        (None, RequestObjectMode::BasicOidc) => true,
        (None, RequestObjectMode::SignedJar) => false,
    }
}

#[cfg(test)]
fn request_object_audience_valid(
    claims: &RequestObjectClaims,
    state: &AppState,
    mode: RequestObjectMode,
) -> bool {
    request_object_audience_valid_with_issuer(claims, &state.settings.issuer, mode)
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
        {
            if *key == "resource" {
                if resource_indicators_from_parameter_value(Some(outer_value)).ok()
                    != resource_indicators_from_parameter_value(Some(request_value)).ok()
                {
                    return true;
                }
            } else if outer_value != request_value {
                return true;
            }
        }
    }
    false
}

async fn store_request_object_replay_state_with_context(
    context: &AuthorizationRequestContext,
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
    match context
        .service
        .consume_jar(&client.client_id, jti, ttl_seconds)
        .await
    {
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

#[cfg(test)]
async fn store_request_object_replay_state(
    state: &AppState,
    client: &ClientRow,
    claims: &RequestObjectClaims,
    now: i64,
    mode: RequestObjectMode,
) -> Result<(), HttpResponse> {
    let dependencies = super::TestAuthorizationDependencies::new(state);
    store_request_object_replay_state_with_context(
        &dependencies.context(),
        client,
        claims,
        now,
        mode,
    )
    .await
}

pub(crate) fn request_object_uses_unsigned_algorithm(request_object: &str) -> bool {
    let Some((header, _payload, signature)) = split_compact_jwt(request_object) else {
        return false;
    };
    let Ok(header) = decode_request_object_header(header) else {
        return false;
    };
    header.alg == "none" && signature.is_empty()
}

pub(crate) fn unverified_signed_request_object_client_id(request_object: &str) -> Option<String> {
    let (header, payload, signature) = split_compact_jwt(request_object)?;
    let header = decode_request_object_header(header).ok()?;
    if header.alg == "none" || signature.is_empty() {
        return None;
    }
    unverified_request_object_client_id_from_payload(payload)
}

fn unverified_request_object_client_id_from_payload(payload: &str) -> Option<String> {
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
                Value::Array(_) if matches!(*key, "authorization_details" | "resource") => {
                    value.to_string()
                }
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

fn request_object_audience_matches_with_issuer(aud: &Value, issuer: &str) -> bool {
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

#[cfg(test)]
fn request_object_audience_matches(aud: &Value, state: &AppState) -> bool {
    request_object_audience_matches_with_issuer(aud, &state.settings.issuer)
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

fn request_object_jti_valid(
    claims: &RequestObjectClaims,
    mode: RequestObjectMode,
    policy: RequestObjectJtiPolicy,
) -> bool {
    match (&claims.jti, mode) {
        (Some(jti), _) => is_valid_request_object_jti(jti),
        (None, RequestObjectMode::SignedJar)
            if policy == RequestObjectJtiPolicy::RequiredForSignedJar =>
        {
            false
        }
        (None, _) => true,
    }
}

fn is_valid_request_object_jti(jti: &str) -> bool {
    let trimmed = jti.trim();
    !trimmed.is_empty() && trimmed.len() <= 128
}

#[cfg(test)]
#[path = "../../../tests/in_source/src/http/authorization/tests/jar.rs"]
mod tests;
