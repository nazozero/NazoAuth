use crate::domain::AppState;
#[cfg(test)]
use crate::settings::Settings;
use actix_web::http::StatusCode;
use actix_web::http::header;
#[cfg(test)]
use actix_web::http::header::HeaderMap;
use actix_web::http::header::HeaderValue;
use actix_web::{HttpRequest, HttpResponse};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::Utc;
pub(crate) use nazo_http_actix::AccessTokenAuthScheme;
use nazo_http_actix::oauth_error;
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::Digest;
use sha2::Sha256;

#[cfg(test)]
use nazo_auth::is_valid_dpop_jkt;

use super::{
    audit_event, audit_fields, blake3_hex, client_jwt_algorithm_from_name,
    jwt_decoding_key_from_jwk, random_urlsafe_token,
};
use crate::settings::DpopNoncePolicy;

const DPOP_TTL_SECONDS: i64 = 300;
const DPOP_CLOCK_SKEW_SECONDS: i64 = 30;
const MAX_DPOP_JTI_BYTES: usize = 128;

#[derive(Debug)]
pub(crate) enum DpopError {
    MissingProof,
    MalformedProof,
    InvalidProof,
    ReplayDetected,
    BindingMismatch,
    TokenNotBound,
    UseNonce(String),
    NonceStoreUnavailable,
}

pub(crate) enum DpopErrorContext {
    TokenEndpoint,
    ProtectedResource,
}

#[derive(Deserialize)]
struct DpopHeader {
    alg: String,
    typ: Option<String>,
    jwk: Value,
}

#[derive(Deserialize)]
struct DpopClaims {
    htm: String,
    htu: String,
    iat: i64,
    jti: String,
    ath: Option<String>,
    nonce: Option<String>,
}

pub(crate) fn dpop_error_response(error: DpopError, context: DpopErrorContext) -> HttpResponse {
    let description = match &error {
        DpopError::MissingProof => "DPoP proof is required.",
        DpopError::MalformedProof => "DPoP proof is malformed.",
        DpopError::InvalidProof => "DPoP proof validation failed.",
        DpopError::ReplayDetected => "DPoP proof jti has already been used.",
        DpopError::BindingMismatch => "DPoP binding mismatch.",
        DpopError::TokenNotBound => "Token is not DPoP-bound.",
        DpopError::UseNonce(_) => "Authorization server requires nonce in DPoP proof.",
        DpopError::NonceStoreUnavailable => "DPoP nonce validation is unavailable.",
    };
    let status = match &error {
        DpopError::MissingProof if matches!(context, DpopErrorContext::TokenEndpoint) => {
            StatusCode::BAD_REQUEST
        }
        DpopError::MissingProof => StatusCode::UNAUTHORIZED,
        DpopError::UseNonce(_) if matches!(context, DpopErrorContext::ProtectedResource) => {
            StatusCode::UNAUTHORIZED
        }
        DpopError::NonceStoreUnavailable => StatusCode::SERVICE_UNAVAILABLE,
        _ => StatusCode::BAD_REQUEST,
    };
    let error_code = match &error {
        DpopError::UseNonce(_) => "use_dpop_nonce",
        DpopError::NonceStoreUnavailable => "server_error",
        _ => "invalid_dpop_proof",
    };
    let mut response = oauth_error(status, error_code, description);
    if matches!(context, DpopErrorContext::TokenEndpoint) {
        response
            .headers_mut()
            .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        response
            .headers_mut()
            .insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    }
    if let DpopError::UseNonce(nonce) = error
        && let Ok(value) = HeaderValue::from_str(&nonce)
    {
        response
            .headers_mut()
            .insert(header::HeaderName::from_static("dpop-nonce"), value);
    }
    response.headers_mut().insert(
        header::WWW_AUTHENTICATE,
        HeaderValue::from_str(&format!("DPoP error=\"{error_code}\""))
            .unwrap_or_else(|_| HeaderValue::from_static("DPoP")),
    );
    response
}

pub(crate) fn dpop_proof_present(req: &HttpRequest) -> bool {
    req.headers()
        .contains_key(header::HeaderName::from_static("dpop"))
}

pub(crate) async fn validate_dpop_proof(
    state: &AppState,
    req: &HttpRequest,
    token_for_ath: Option<&str>,
    expected_jkt: Option<&str>,
) -> Result<Option<String>, DpopError> {
    validate_dpop_proof_with_store(
        &nazo_valkey::ReplayStore::new(&state.valkey_connection()),
        &state.settings.endpoint.issuer,
        &state.settings.endpoint.mtls_endpoint_base_url,
        state.settings.protocol.dpop_nonce_policy,
        req,
        token_for_ath,
        expected_jkt,
    )
    .await
}

pub(crate) async fn validate_dpop_proof_with_store(
    replay_store: &nazo_valkey::ReplayStore,
    issuer: &str,
    mtls_endpoint_base_url: &str,
    nonce_policy: DpopNoncePolicy,
    req: &HttpRequest,
    token_for_ath: Option<&str>,
    expected_jkt: Option<&str>,
) -> Result<Option<String>, DpopError> {
    validate_dpop_proof_with_replay(
        DpopReplay::Store(replay_store),
        issuer,
        mtls_endpoint_base_url,
        nonce_policy,
        req,
        token_for_ath,
        expected_jkt,
    )
    .await
}

pub(crate) async fn validate_dpop_proof_with_authorization_service(
    service: &crate::http::authorization::ServerAuthorizationService,
    issuer: &str,
    mtls_endpoint_base_url: &str,
    nonce_policy: DpopNoncePolicy,
    req: &HttpRequest,
    token_for_ath: Option<&str>,
    expected_jkt: Option<&str>,
) -> Result<Option<String>, DpopError> {
    validate_dpop_proof_with_replay(
        DpopReplay::Authorization(service),
        issuer,
        mtls_endpoint_base_url,
        nonce_policy,
        req,
        token_for_ath,
        expected_jkt,
    )
    .await
}

enum DpopReplay<'a> {
    Store(&'a nazo_valkey::ReplayStore),
    Authorization(&'a crate::http::authorization::ServerAuthorizationService),
}

impl DpopReplay<'_> {
    async fn consume_dpop(&self, jkt: &str, jti: &str, ttl: u64) -> Result<bool, ()> {
        match self {
            Self::Store(store) => store.consume_dpop(jkt, jti, ttl).await.map_err(|_| ()),
            Self::Authorization(service) => {
                service.consume_dpop(jkt, jti, ttl).await.map_err(|_| ())
            }
        }
    }

    async fn consume_nonce(&self, nonce: &str) -> Result<bool, ()> {
        match self {
            Self::Store(store) => store.consume_dpop_nonce(nonce).await.map_err(|_| ()),
            Self::Authorization(service) => service.consume_dpop_nonce(nonce).await.map_err(|_| ()),
        }
    }

    async fn issue_nonce(&self, nonce: &str, ttl: u64) -> Result<(), ()> {
        match self {
            Self::Store(store) => store.issue_dpop_nonce(nonce, ttl).await.map_err(|_| ()),
            Self::Authorization(service) => {
                service.issue_dpop_nonce(nonce, ttl).await.map_err(|_| ())
            }
        }
    }
}

async fn validate_dpop_proof_with_replay(
    replay: DpopReplay<'_>,
    issuer: &str,
    mtls_endpoint_base_url: &str,
    nonce_policy: DpopNoncePolicy,
    req: &HttpRequest,
    token_for_ath: Option<&str>,
    expected_jkt: Option<&str>,
) -> Result<Option<String>, DpopError> {
    let Some(raw) = dpop_proof_header(req)? else {
        return if expected_jkt.is_some() {
            Err(DpopError::MissingProof)
        } else {
            Ok(None)
        };
    };

    let (header, claims, signing_input, signature) = decode_proof(raw)?;
    let algorithm = client_jwt_algorithm_from_name(&header.alg).ok_or(DpopError::InvalidProof)?;
    if !header
        .typ
        .as_deref()
        .is_some_and(|value| value.eq_ignore_ascii_case("dpop+jwt"))
    {
        return Err(DpopError::InvalidProof);
    }
    if !dpop_algorithm_allowed(algorithm) {
        return Err(DpopError::InvalidProof);
    }
    let jkt = jwk_thumbprint(&header.jwk)?;
    if expected_jkt.is_some_and(|expected| expected != jkt.as_str()) {
        return Err(DpopError::BindingMismatch);
    }
    verify_signature(&header.jwk, algorithm, signing_input.as_bytes(), &signature)?;
    validate_dpop_claims(
        &[issuer, mtls_endpoint_base_url],
        req.method().as_str(),
        req.uri().path(),
        &claims,
        token_for_ath,
    )?;
    validate_dpop_nonce_with_replay(&replay, nonce_policy, claims.nonce.as_deref()).await?;

    if !replay
        .consume_dpop(&jkt, &claims.jti, DPOP_TTL_SECONDS as u64)
        .await
        .map_err(|_| DpopError::InvalidProof)?
    {
        audit_event(
            "dpop_replay_detected",
            audit_fields(&[
                ("jti_hash", json!(blake3_hex(&claims.jti))),
                ("kid", json!(header.jwk.get("kid").and_then(Value::as_str))),
            ]),
        );
        return Err(DpopError::ReplayDetected);
    }
    Ok(Some(jkt))
}

#[cfg(test)]
async fn validate_dpop_nonce(state: &AppState, nonce: Option<&str>) -> Result<(), DpopError> {
    validate_dpop_nonce_with_store(
        &nazo_valkey::ReplayStore::new(&state.valkey_connection()),
        state.settings.protocol.dpop_nonce_policy,
        nonce,
    )
    .await
}

#[cfg(test)]
async fn validate_dpop_nonce_with_store(
    replay_store: &nazo_valkey::ReplayStore,
    nonce_policy: DpopNoncePolicy,
    nonce: Option<&str>,
) -> Result<(), DpopError> {
    validate_dpop_nonce_with_replay(&DpopReplay::Store(replay_store), nonce_policy, nonce).await
}

async fn validate_dpop_nonce_with_replay(
    replay: &DpopReplay<'_>,
    nonce_policy: DpopNoncePolicy,
    nonce: Option<&str>,
) -> Result<(), DpopError> {
    let Some(nonce) = nonce else {
        if !dpop_nonce_required(nonce_policy) {
            return Ok(());
        }
        return Err(DpopError::UseNonce(
            issue_dpop_nonce_with_replay(replay).await?,
        ));
    };
    match replay.consume_nonce(nonce).await {
        Ok(true) => Ok(()),
        Ok(false) => Err(DpopError::UseNonce(
            issue_dpop_nonce_with_replay(replay).await?,
        )),
        Err(()) => {
            tracing::warn!("failed to consume dpop nonce");
            Err(DpopError::NonceStoreUnavailable)
        }
    }
}

fn dpop_nonce_required(policy: DpopNoncePolicy) -> bool {
    policy == DpopNoncePolicy::Required
}

pub(crate) async fn issue_dpop_nonce(state: &AppState) -> Result<String, DpopError> {
    issue_dpop_nonce_with_store(&nazo_valkey::ReplayStore::new(&state.valkey_connection())).await
}

pub(crate) async fn issue_dpop_nonce_with_store(
    replay_store: &nazo_valkey::ReplayStore,
) -> Result<String, DpopError> {
    issue_dpop_nonce_with_replay(&DpopReplay::Store(replay_store)).await
}

async fn issue_dpop_nonce_with_replay(replay: &DpopReplay<'_>) -> Result<String, DpopError> {
    let nonce = random_urlsafe_token();
    replay
        .issue_nonce(&nonce, DPOP_TTL_SECONDS as u64)
        .await
        .map_err(|()| {
            tracing::warn!("failed to issue dpop nonce");
            DpopError::NonceStoreUnavailable
        })?;
    Ok(nonce)
}

#[cfg(test)]
fn dpop_replay_key(jkt: &str, jti: &str) -> String {
    format!("oauth:dpop:jti:{jkt}:{}", blake3_hex(jti))
}

fn dpop_proof_header(req: &HttpRequest) -> Result<Option<&str>, DpopError> {
    let name = header::HeaderName::from_static("dpop");
    let mut values = req.headers().get_all(name);
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(DpopError::MalformedProof);
    }
    let value = value
        .to_str()
        .map_err(|_| DpopError::MalformedProof)?
        .trim();
    Ok((!value.is_empty()).then_some(value))
}

fn dpop_iat_within_window(iat: i64, now: i64) -> bool {
    if iat > now.saturating_add(DPOP_CLOCK_SKEW_SECONDS) {
        return false;
    }
    if iat > now {
        return true;
    }
    now.checked_sub(iat)
        .is_some_and(|age| age <= DPOP_TTL_SECONDS)
}

fn validate_dpop_claims(
    endpoint_bases: &[&str],
    method: &str,
    path: &str,
    claims: &DpopClaims,
    token_for_ath: Option<&str>,
) -> Result<(), DpopError> {
    let actual_htu = normalize_htu(&claims.htu)?;
    let mut htu_matches = false;
    for base in endpoint_bases {
        let expected_htu = format!("{}{}", base.trim_end_matches('/'), path);
        if actual_htu == expected_htu {
            htu_matches = true;
            break;
        }
    }
    if !htu_matches || !claims.htm.eq_ignore_ascii_case(method) {
        return Err(DpopError::InvalidProof);
    }
    if !dpop_iat_within_window(claims.iat, Utc::now().timestamp()) || !valid_jti(&claims.jti) {
        return Err(DpopError::InvalidProof);
    }
    if let Some(value) = token_for_ath {
        let expected_ath = URL_SAFE_NO_PAD.encode(Sha256::digest(value.as_bytes()));
        if claims.ath.as_deref() != Some(expected_ath.as_str()) {
            return Err(DpopError::InvalidProof);
        }
    }
    Ok(())
}

fn valid_jti(jti: &str) -> bool {
    let trimmed = jti.trim();
    !trimmed.is_empty() && trimmed.len() <= MAX_DPOP_JTI_BYTES
}

fn dpop_algorithm_allowed(algorithm: jsonwebtoken::Algorithm) -> bool {
    matches!(
        algorithm,
        jsonwebtoken::Algorithm::EdDSA | jsonwebtoken::Algorithm::ES256
    )
}

fn decode_proof(raw: &str) -> Result<(DpopHeader, DpopClaims, String, String), DpopError> {
    let mut parts = raw.split('.');
    let encoded_header = parts.next().ok_or(DpopError::MalformedProof)?;
    let encoded_payload = parts.next().ok_or(DpopError::MalformedProof)?;
    let encoded_signature = parts.next().ok_or(DpopError::MalformedProof)?;
    if parts.next().is_some() {
        return Err(DpopError::MalformedProof);
    }
    let header_bytes = URL_SAFE_NO_PAD
        .decode(encoded_header)
        .map_err(|_| DpopError::MalformedProof)?;
    let payload_bytes = URL_SAFE_NO_PAD
        .decode(encoded_payload)
        .map_err(|_| DpopError::MalformedProof)?;
    URL_SAFE_NO_PAD
        .decode(encoded_signature)
        .map_err(|_| DpopError::MalformedProof)?;
    let header = serde_json::from_slice::<DpopHeader>(&header_bytes)
        .map_err(|_| DpopError::MalformedProof)?;
    let claims = serde_json::from_slice::<DpopClaims>(&payload_bytes)
        .map_err(|_| DpopError::MalformedProof)?;
    Ok((
        header,
        claims,
        format!("{encoded_header}.{encoded_payload}"),
        encoded_signature.to_owned(),
    ))
}

fn jwk_thumbprint(jwk: &Value) -> Result<String, DpopError> {
    let kty = jwk
        .get("kty")
        .and_then(Value::as_str)
        .ok_or(DpopError::MalformedProof)?;
    let canonical = match kty {
        "OKP" => {
            let crv = jwk
                .get("crv")
                .and_then(Value::as_str)
                .ok_or(DpopError::MalformedProof)?;
            let x = jwk
                .get("x")
                .and_then(Value::as_str)
                .ok_or(DpopError::MalformedProof)?;
            if crv != "Ed25519" {
                return Err(DpopError::InvalidProof);
            }
            format!(r#"{{"crv":"{crv}","kty":"OKP","x":"{x}"}}"#)
        }
        "EC" => {
            let crv = jwk
                .get("crv")
                .and_then(Value::as_str)
                .ok_or(DpopError::MalformedProof)?;
            let x = jwk
                .get("x")
                .and_then(Value::as_str)
                .ok_or(DpopError::MalformedProof)?;
            let y = jwk
                .get("y")
                .and_then(Value::as_str)
                .ok_or(DpopError::MalformedProof)?;
            if crv != "P-256" {
                return Err(DpopError::InvalidProof);
            }
            format!(r#"{{"crv":"{crv}","kty":"EC","x":"{x}","y":"{y}"}}"#)
        }
        "RSA" => {
            let e = jwk
                .get("e")
                .and_then(Value::as_str)
                .ok_or(DpopError::MalformedProof)?;
            let n = jwk
                .get("n")
                .and_then(Value::as_str)
                .ok_or(DpopError::MalformedProof)?;
            format!(r#"{{"e":"{e}","kty":"RSA","n":"{n}"}}"#)
        }
        _ => return Err(DpopError::InvalidProof),
    };
    Ok(URL_SAFE_NO_PAD.encode(Sha256::digest(canonical.as_bytes())))
}

fn verify_signature(
    jwk: &Value,
    algorithm: jsonwebtoken::Algorithm,
    signing_input: &[u8],
    signature: &str,
) -> Result<(), DpopError> {
    let decoding_key =
        jwt_decoding_key_from_jwk(jwk, algorithm).ok_or(DpopError::MalformedProof)?;
    if jsonwebtoken::crypto::verify(signature, signing_input, &decoding_key, algorithm)
        .map_err(|_| DpopError::MalformedProof)?
    {
        Ok(())
    } else {
        Err(DpopError::InvalidProof)
    }
}

fn normalize_htu(value: &str) -> Result<String, DpopError> {
    let mut url = url::Url::parse(value).map_err(|_| DpopError::MalformedProof)?;
    url.set_query(None);
    url.set_fragment(None);
    Ok(url.to_string())
}

#[cfg(test)]
#[path = "../../tests/in_source/src/support/tests/dpop.rs"]
mod tests;
