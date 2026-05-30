//! DPoP proof verification and access-token binding helpers.
// Implements the server-side pieces of RFC 9449 needed by the OAuth endpoints.

use std::convert::TryInto;

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::Deserialize;

use super::prelude::*;
use super::{oauth_error, valkey_set_ex};

const DPOP_PROOF_MAX_AGE_SECONDS: i64 = 300;

#[derive(Clone, Copy, Debug)]
pub(crate) enum AccessTokenAuthScheme {
    Bearer,
    DPoP,
}

#[derive(Debug)]
pub(crate) enum DpopError {
    MissingProof,
    MalformedProof,
    UnsupportedAlgorithm,
    InvalidProof,
    ReplayDetected,
    BindingMismatch,
}

#[derive(Deserialize)]
struct DpopJwtHeader {
    alg: String,
    typ: Option<String>,
    jwk: Value,
}

#[derive(Deserialize)]
struct DpopProofClaims {
    htm: String,
    htu: String,
    iat: i64,
    jti: String,
    ath: Option<String>,
}

impl DpopError {
    fn description(&self) -> &'static str {
        match self {
            Self::MissingProof => "DPoP-bound token requires a DPoP proof.",
            Self::MalformedProof => "DPoP proof is malformed.",
            Self::UnsupportedAlgorithm => "DPoP proof algorithm is not supported.",
            Self::InvalidProof => "DPoP proof validation failed.",
            Self::ReplayDetected => "DPoP proof jti has already been used.",
            Self::BindingMismatch => "DPoP proof key does not match the token binding.",
        }
    }
}

pub(crate) fn dpop_error_response(error: DpopError) -> HttpResponse {
    let mut response = oauth_error(
        match error {
            DpopError::MissingProof => StatusCode::UNAUTHORIZED,
            _ => StatusCode::BAD_REQUEST,
        },
        "invalid_dpop_proof",
        error.description(),
    );
    response.headers_mut().insert(
        header::WWW_AUTHENTICATE,
        HeaderValue::from_static("DPoP error=\"invalid_dpop_proof\""),
    );
    response
}

pub(crate) fn authorization_access_token(
    headers: &HeaderMap,
) -> Option<(AccessTokenAuthScheme, String)> {
    let raw = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    if let Some(token) = raw.strip_prefix("DPoP ") {
        return Some((AccessTokenAuthScheme::DPoP, token.to_owned()));
    }
    raw.strip_prefix("Bearer ")
        .map(|token| (AccessTokenAuthScheme::Bearer, token.to_owned()))
}

pub(crate) async fn validate_dpop_proof(
    state: &AppState,
    req: &HttpRequest,
    access_token: Option<&str>,
    expected_jkt: Option<&str>,
) -> Result<Option<String>, DpopError> {
    let Some(proof) = req
        .headers()
        .get(header::HeaderName::from_static("dpop"))
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return if expected_jkt.is_some() {
            Err(DpopError::MissingProof)
        } else {
            Ok(None)
        };
    };

    let (header, claims, signing_input, signature) = decode_dpop_proof(proof)?;
    if !header
        .typ
        .as_deref()
        .is_some_and(|typ| typ.eq_ignore_ascii_case("dpop+jwt"))
    {
        return Err(DpopError::MalformedProof);
    }
    if header.alg != "EdDSA" {
        return Err(DpopError::UnsupportedAlgorithm);
    }

    let jkt = jwk_thumbprint(&header.jwk)?;
    if expected_jkt.is_some_and(|expected| expected != jkt.as_str()) {
        return Err(DpopError::BindingMismatch);
    }
    verify_eddsa_dpop_signature(&header.jwk, signing_input.as_bytes(), &signature)?;
    validate_dpop_claims(state, req, access_token, &jkt, &claims).await?;
    Ok(Some(jkt))
}

fn decode_dpop_proof(
    proof: &str,
) -> Result<(DpopJwtHeader, DpopProofClaims, String, Vec<u8>), DpopError> {
    let mut parts = proof.split('.');
    let header = parts.next().ok_or(DpopError::MalformedProof)?;
    let payload = parts.next().ok_or(DpopError::MalformedProof)?;
    let signature = parts.next().ok_or(DpopError::MalformedProof)?;
    if parts.next().is_some() {
        return Err(DpopError::MalformedProof);
    }
    let header_json = URL_SAFE_NO_PAD
        .decode(header)
        .map_err(|_| DpopError::MalformedProof)?;
    let payload_json = URL_SAFE_NO_PAD
        .decode(payload)
        .map_err(|_| DpopError::MalformedProof)?;
    let signature = URL_SAFE_NO_PAD
        .decode(signature)
        .map_err(|_| DpopError::MalformedProof)?;
    let header = serde_json::from_slice::<DpopJwtHeader>(&header_json)
        .map_err(|_| DpopError::MalformedProof)?;
    let claims = serde_json::from_slice::<DpopProofClaims>(&payload_json)
        .map_err(|_| DpopError::MalformedProof)?;
    Ok((header, claims, format!("{header}.{payload}"), signature))
}

fn jwk_thumbprint(jwk: &Value) -> Result<String, DpopError> {
    let kty = jwk
        .get("kty")
        .and_then(Value::as_str)
        .ok_or(DpopError::MalformedProof)?;
    let crv = jwk
        .get("crv")
        .and_then(Value::as_str)
        .ok_or(DpopError::MalformedProof)?;
    let x = jwk
        .get("x")
        .and_then(Value::as_str)
        .ok_or(DpopError::MalformedProof)?;
    if kty != "OKP" || crv != "Ed25519" {
        return Err(DpopError::UnsupportedAlgorithm);
    }
    let canonical = format!(r#"{{"crv":"{crv}","kty":"OKP","x":"{x}"}}"#);
    Ok(URL_SAFE_NO_PAD.encode(Sha256::digest(canonical.as_bytes())))
}

fn verify_eddsa_dpop_signature(
    jwk: &Value,
    signing_input: &[u8],
    signature: &[u8],
) -> Result<(), DpopError> {
    let x = jwk
        .get("x")
        .and_then(Value::as_str)
        .ok_or(DpopError::MalformedProof)?;
    let key_bytes = URL_SAFE_NO_PAD
        .decode(x)
        .map_err(|_| DpopError::MalformedProof)?;
    let key_bytes: [u8; 32] = key_bytes
        .try_into()
        .map_err(|_| DpopError::MalformedProof)?;
    let signature = Signature::from_slice(signature).map_err(|_| DpopError::MalformedProof)?;
    let verifying_key =
        VerifyingKey::from_bytes(&key_bytes).map_err(|_| DpopError::MalformedProof)?;
    verifying_key
        .verify(signing_input, &signature)
        .map_err(|_| DpopError::InvalidProof)
}

async fn validate_dpop_claims(
    state: &AppState,
    req: &HttpRequest,
    access_token: Option<&str>,
    jkt: &str,
    claims: &DpopProofClaims,
) -> Result<(), DpopError> {
    if !claims.htm.eq_ignore_ascii_case(req.method().as_str()) {
        return Err(DpopError::InvalidProof);
    }
    let expected_htu = format!(
        "{}{}",
        state.settings.issuer.trim_end_matches('/'),
        req.uri().path()
    );
    let actual_htu = normalize_htu(&claims.htu)?;
    if actual_htu != expected_htu {
        return Err(DpopError::InvalidProof);
    }
    let now = Utc::now().timestamp();
    if claims.iat > now + 30 || now - claims.iat > DPOP_PROOF_MAX_AGE_SECONDS {
        return Err(DpopError::InvalidProof);
    }
    if claims.jti.trim().is_empty() {
        return Err(DpopError::MalformedProof);
    }
    let replay_key = format!("oauth:dpop:jti:{jkt}:{}", claims.jti);
    if valkey_get(&state.valkey, replay_key.clone())
        .await
        .map_err(|_| DpopError::InvalidProof)?
        .is_some()
    {
        return Err(DpopError::ReplayDetected);
    }
    valkey_set_ex(
        &state.valkey,
        replay_key,
        "1",
        DPOP_PROOF_MAX_AGE_SECONDS as u64,
    )
    .await
    .map_err(|_| DpopError::InvalidProof)?;

    if let Some(access_token) = access_token {
        let expected_ath = URL_SAFE_NO_PAD.encode(Sha256::digest(access_token.as_bytes()));
        if claims.ath.as_deref() != Some(expected_ath.as_str()) {
            return Err(DpopError::InvalidProof);
        }
    }
    Ok(())
}

fn normalize_htu(value: &str) -> Result<String, DpopError> {
    let mut url = url::Url::parse(value).map_err(|_| DpopError::MalformedProof)?;
    url.set_query(None);
    url.set_fragment(None);
    Ok(url.to_string())
}
