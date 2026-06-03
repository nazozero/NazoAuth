use serde::Deserialize;

use super::prelude::*;
use super::{
    audit_event, audit_fields, blake3_hex, client_jwt_algorithm_from_name,
    jwt_decoding_key_from_jwk, oauth_error, random_urlsafe_token, valkey_getdel, valkey_set_ex,
    valkey_set_ex_nx,
};

const DPOP_TTL_SECONDS: i64 = 300;
const DPOP_CLOCK_SKEW_SECONDS: i64 = 30;
const MAX_DPOP_JTI_BYTES: usize = 128;

#[derive(Clone, Copy, Debug)]
pub(crate) enum AccessTokenAuthScheme {
    Bearer,
    DPoP,
}

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

pub(crate) fn authorization_access_token(
    headers: &HeaderMap,
) -> Option<(AccessTokenAuthScheme, String)> {
    let raw = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let mut parts = raw.splitn(2, char::is_whitespace);
    let scheme = parts.next()?.trim();
    let token = parts.next()?.trim();
    if token.is_empty() || token.split_whitespace().count() != 1 {
        return None;
    }
    if scheme.eq_ignore_ascii_case("DPoP") {
        return Some((AccessTokenAuthScheme::DPoP, token.to_owned()));
    }
    if scheme.eq_ignore_ascii_case("Bearer") {
        return Some((AccessTokenAuthScheme::Bearer, token.to_owned()));
    }
    None
}

pub(crate) fn dpop_proof_present(req: &HttpRequest) -> bool {
    req.headers()
        .contains_key(header::HeaderName::from_static("dpop"))
}

pub(crate) fn is_valid_dpop_jkt(value: &str) -> bool {
    value.len() == 43
        && URL_SAFE_NO_PAD
            .decode(value)
            .is_ok_and(|bytes| bytes.len() == 32)
}

pub(crate) async fn validate_dpop_proof(
    state: &AppState,
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
    let jkt = jwk_thumbprint(&header.jwk)?;
    if expected_jkt.is_some_and(|expected| expected != jkt.as_str()) {
        return Err(DpopError::BindingMismatch);
    }
    verify_signature(&header.jwk, algorithm, signing_input.as_bytes(), &signature)?;
    validate_dpop_claims(
        &state.settings.issuer,
        req.method().as_str(),
        req.uri().path(),
        &claims,
        token_for_ath,
    )?;
    validate_dpop_nonce(state, claims.nonce.as_deref()).await?;

    let replay_key = format!("oauth:dpop:jti:{jkt}:{}", blake3_hex(&claims.jti));
    if !valkey_set_ex_nx(&state.valkey, replay_key, "1", DPOP_TTL_SECONDS as u64)
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

async fn validate_dpop_nonce(state: &AppState, nonce: Option<&str>) -> Result<(), DpopError> {
    let Some(nonce) = nonce else {
        return Err(DpopError::UseNonce(issue_dpop_nonce(state).await?));
    };
    let key = dpop_nonce_key(nonce);
    match valkey_getdel(&state.valkey, key).await {
        Ok(Some(_)) => Ok(()),
        Ok(None) => Err(DpopError::UseNonce(issue_dpop_nonce(state).await?)),
        Err(error) => {
            tracing::warn!(%error, "failed to consume dpop nonce");
            Err(DpopError::NonceStoreUnavailable)
        }
    }
}

pub(crate) async fn issue_dpop_nonce(state: &AppState) -> Result<String, DpopError> {
    let nonce = random_urlsafe_token();
    valkey_set_ex(
        &state.valkey,
        dpop_nonce_key(&nonce),
        "1",
        DPOP_TTL_SECONDS as u64,
    )
    .await
    .map_err(|error| {
        tracing::warn!(%error, "failed to issue dpop nonce");
        DpopError::NonceStoreUnavailable
    })?;
    Ok(nonce)
}

fn dpop_nonce_key(nonce: &str) -> String {
    format!("oauth:dpop:nonce:{}", blake3_hex(nonce))
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
    issuer: &str,
    method: &str,
    path: &str,
    claims: &DpopClaims,
    token_for_ath: Option<&str>,
) -> Result<(), DpopError> {
    let expected_htu = format!("{issuer}{path}");
    let actual_htu = normalize_htu(&claims.htu)?;
    if actual_htu != expected_htu || !claims.htm.eq_ignore_ascii_case(method) {
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
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    #[test]
    fn authorization_scheme_is_case_insensitive() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("dpop abc.def"),
        );

        let Some((scheme, token)) = authorization_access_token(&headers) else {
            panic!("authorization header should parse");
        };

        assert!(matches!(scheme, AccessTokenAuthScheme::DPoP));
        assert_eq!(token, "abc.def");
    }

    #[test]
    fn bearer_scheme_is_case_insensitive() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("bearer token"),
        );

        let Some((scheme, token)) = authorization_access_token(&headers) else {
            panic!("authorization header should parse");
        };

        assert!(matches!(scheme, AccessTokenAuthScheme::Bearer));
        assert_eq!(token, "token");
    }

    #[test]
    fn token_endpoint_nonce_challenge_uses_bad_request() {
        let response = dpop_error_response(
            DpopError::UseNonce("nonce-1".to_owned()),
            DpopErrorContext::TokenEndpoint,
        );

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            response.headers().get("dpop-nonce").unwrap(),
            HeaderValue::from_static("nonce-1")
        );
    }

    #[test]
    fn protected_resource_nonce_challenge_uses_unauthorized() {
        let response = dpop_error_response(
            DpopError::UseNonce("nonce-1".to_owned()),
            DpopErrorContext::ProtectedResource,
        );

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            response.headers().get(header::WWW_AUTHENTICATE).unwrap(),
            HeaderValue::from_static(r#"DPoP error="use_dpop_nonce""#)
        );
    }

    #[test]
    fn token_endpoint_missing_proof_uses_bad_request() {
        let response =
            dpop_error_response(DpopError::MissingProof, DpopErrorContext::TokenEndpoint);

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            response.headers().get(header::WWW_AUTHENTICATE).unwrap(),
            HeaderValue::from_static(r#"DPoP error="invalid_dpop_proof""#)
        );
    }

    #[test]
    fn dpop_iat_rejects_extreme_past_without_overflow() {
        assert!(!dpop_iat_within_window(i64::MIN, 1_000));
    }

    #[test]
    fn dpop_iat_allows_clock_skew_but_not_far_future() {
        let now = 1_000;

        assert!(dpop_iat_within_window(now + DPOP_CLOCK_SKEW_SECONDS, now));
        assert!(!dpop_iat_within_window(
            now + DPOP_CLOCK_SKEW_SECONDS + 1,
            now
        ));
    }

    #[test]
    fn dpop_jkt_uses_base64url_sha256_thumbprint_shape() {
        assert!(is_valid_dpop_jkt(
            "w7JAoU_gJbZJvV-zCOvU9yFJq0FNC_edCMRM78P8eQQ"
        ));
        assert!(!is_valid_dpop_jkt("short"));
        assert!(!is_valid_dpop_jkt(
            "w7JAoU/gJbZJvV+zCOvU9yFJq0FNC+edCMRM78P8eQQ"
        ));
    }

    #[test]
    fn dpop_header_rejects_multiple_proofs() {
        let req = actix_web::test::TestRequest::get()
            .insert_header(("DPoP", "proof-1"))
            .append_header(("DPoP", "proof-2"))
            .to_http_request();

        assert!(matches!(
            dpop_proof_header(&req),
            Err(DpopError::MalformedProof)
        ));
    }

    #[test]
    fn signed_dpop_proof_verifies_signature_thumbprint_and_claims() {
        let signing_key = SigningKey::from_bytes(&[7u8; 32]);
        let access_token = "access.token.value";
        let proof = signed_test_proof(
            &signing_key,
            "POST",
            "https://issuer.example/token?ignored=true",
            Utc::now().timestamp(),
            "proof-1",
            Some(access_token),
            Some("nonce-1"),
        );

        let (header, claims, signing_input, signature) = decode_proof(&proof).unwrap();
        let algorithm = client_jwt_algorithm_from_name(&header.alg).unwrap();
        verify_signature(&header.jwk, algorithm, signing_input.as_bytes(), &signature).unwrap();
        assert!(!jwk_thumbprint(&header.jwk).unwrap().is_empty());
        validate_dpop_claims(
            "https://issuer.example",
            "POST",
            "/token",
            &claims,
            Some(access_token),
        )
        .unwrap();
    }

    #[test]
    fn dpop_claim_validation_rejects_wrong_method_htu_and_ath() {
        let signing_key = SigningKey::from_bytes(&[9u8; 32]);
        let proof = signed_test_proof(
            &signing_key,
            "POST",
            "https://issuer.example/token",
            Utc::now().timestamp(),
            "proof-2",
            Some("bound-token"),
            Some("nonce-2"),
        );
        let (_, claims, _, _) = decode_proof(&proof).unwrap();

        assert!(matches!(
            validate_dpop_claims("https://issuer.example", "GET", "/token", &claims, None),
            Err(DpopError::InvalidProof)
        ));
        assert!(matches!(
            validate_dpop_claims("https://issuer.example", "POST", "/userinfo", &claims, None),
            Err(DpopError::InvalidProof)
        ));
        assert!(matches!(
            validate_dpop_claims(
                "https://issuer.example",
                "POST",
                "/token",
                &claims,
                Some("other-token")
            ),
            Err(DpopError::InvalidProof)
        ));
    }

    fn signed_test_proof(
        signing_key: &SigningKey,
        method: &str,
        htu: &str,
        iat: i64,
        jti: &str,
        token_for_ath: Option<&str>,
        nonce: Option<&str>,
    ) -> String {
        let public_key = URL_SAFE_NO_PAD.encode(signing_key.verifying_key().to_bytes());
        let header = json!({
            "typ": "dpop+jwt",
            "alg": "EdDSA",
            "jwk": {
                "kty": "OKP",
                "crv": "Ed25519",
                "x": public_key
            }
        });
        let mut claims = json!({
            "htm": method,
            "htu": htu,
            "iat": iat,
            "jti": jti
        });
        if let Some(token) = token_for_ath {
            claims["ath"] = json!(URL_SAFE_NO_PAD.encode(Sha256::digest(token.as_bytes())));
        }
        if let Some(nonce) = nonce {
            claims["nonce"] = json!(nonce);
        }

        let encoded_header = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
        let encoded_claims = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap());
        let signing_input = format!("{encoded_header}.{encoded_claims}");
        let signature = signing_key.sign(signing_input.as_bytes());

        format!(
            "{}.{}",
            signing_input,
            URL_SAFE_NO_PAD.encode(signature.to_bytes())
        )
    }
}
