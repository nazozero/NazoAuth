//! Resource-server JWT access-token verifier.
//!
//! This module is intentionally independent from the authorization server
//! runtime state. Resource servers should validate issuer, audience, token
//! type, algorithm, key id, expiry, scopes, and sender constraints locally
//! before falling back to introspection or application policy hooks.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::Utc;
use futures_util::future::{Ready, ready};
use http::{HeaderMap, header};
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, HashMap},
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
};
use tower::{Layer, Service};

const DEFAULT_CLOCK_SKEW_SECONDS: i64 = 60;
const DEFAULT_DPOP_MAX_AGE_SECONDS: i64 = 300;

#[derive(Clone, Debug)]
pub struct ResourceServerVerifier {
    config: ResourceServerVerifierConfig,
}

#[derive(Clone, Debug)]
pub struct ResourceServerVerifierConfig {
    pub issuer: String,
    pub audiences: Vec<String>,
    pub jwks: Value,
    pub required_scopes: Vec<String>,
    pub confirmation: ConfirmationPolicy,
    pub allowed_algs: Vec<Algorithm>,
    pub clock_skew_seconds: i64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum ConfirmationPolicy {
    #[default]
    Optional,
    RequireDpop,
    RequireDpopJkt(String),
    RequireMtls,
    RequireMtlsThumbprint(String),
    RequireAnySenderConstraint,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedAccessToken {
    pub issuer: String,
    pub subject: String,
    pub client_id: String,
    pub audiences: Vec<String>,
    pub scopes: Vec<String>,
    pub jti: String,
    pub exp: i64,
    pub cnf: Option<ConfirmationClaims>,
    pub authorization_details: Value,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct ConfirmationClaims {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jkt: Option<String>,
    #[serde(rename = "x5t#S256", default, skip_serializing_if = "Option::is_none")]
    pub x5t_s256: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResourceServerVerifierError {
    MissingIssuer,
    MissingAudience,
    MissingJwks,
    UnsupportedAlgorithm,
    MissingKeyId,
    UnknownKeyId,
    InvalidKey,
    InvalidToken,
    WrongTokenType,
    IssuerMismatch,
    AudienceMismatch,
    Expired,
    NotYetValid,
    MissingScope(String),
    MissingSenderConstraint,
    DpopBindingMismatch,
    MtlsBindingMismatch,
}

/// Sender-constraint material that has already been verified by the resource
/// server's DPoP proof verifier or mTLS certificate boundary.
///
/// This type intentionally does not represent a raw DPoP proof JWT. A caller
/// must validate DPoP `typ`, proof signature, `htu`, `htm`, `ath`, `jti`, and
/// nonce policy before filling `dpop_jkt`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct VerifiedSenderConstraintProof {
    pub dpop_jkt: Option<String>,
    pub mtls_x5t_s256: Option<String>,
}

pub type SenderConstraintProof = VerifiedSenderConstraintProof;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ResourceServerRequestError {
    MissingToken,
    InvalidRequest,
    InvalidToken(ResourceServerVerifierError),
    InvalidDpopProof(DpopProofVerifierError),
    MissingSenderConstraint,
    DpopBindingMismatch,
    MtlsBindingMismatch,
}

#[derive(Clone, Debug)]
pub struct DpopProofVerifier {
    config: DpopProofVerifierConfig,
    replay_cache: Arc<Mutex<HashMap<String, i64>>>,
}

#[derive(Clone, Debug)]
pub struct DpopProofVerifierConfig {
    pub allowed_algs: Vec<Algorithm>,
    pub clock_skew_seconds: i64,
    pub max_age_seconds: i64,
    pub required_nonce: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DpopProofVerifierError {
    MalformedProof,
    UnsupportedAlgorithm,
    MissingPublicJwk,
    InvalidPublicJwk,
    InvalidSignature,
    WrongType,
    MethodMismatch,
    UriMismatch,
    AccessTokenHashMismatch,
    MissingJti,
    ReplayDetected,
    Expired,
    NotYetValid,
    NonceMismatch,
    ReplayStoreUnavailable,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PresentedAccessTokenScheme {
    Bearer,
    Dpop,
}

#[derive(Debug, Deserialize)]
struct AccessTokenClaims {
    iss: String,
    sub: String,
    aud: Value,
    client_id: String,
    #[serde(default)]
    scope: String,
    #[serde(default)]
    authorization_details: Value,
    token_use: String,
    jti: String,
    #[serde(default)]
    nbf: Option<i64>,
    exp: i64,
    #[serde(default)]
    cnf: Option<ConfirmationClaims>,
}

#[derive(Debug, Deserialize)]
struct DpopProofClaims {
    htm: String,
    htu: String,
    iat: i64,
    jti: String,
    #[serde(default)]
    ath: Option<String>,
    #[serde(default)]
    nonce: Option<String>,
}

impl DpopProofVerifier {
    pub fn new(config: DpopProofVerifierConfig) -> Self {
        Self {
            config,
            replay_cache: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn verify(
        &self,
        proof_jwt: &str,
        method: &str,
        htu: &str,
        access_token: &str,
    ) -> Result<VerifiedSenderConstraintProof, DpopProofVerifierError> {
        let header = jsonwebtoken::decode_header(proof_jwt)
            .map_err(|_| DpopProofVerifierError::MalformedProof)?;
        if header.typ.as_deref() != Some("dpop+jwt") {
            return Err(DpopProofVerifierError::WrongType);
        }
        if !self.config.allowed_algs.contains(&header.alg) {
            return Err(DpopProofVerifierError::UnsupportedAlgorithm);
        }
        let jwk = header
            .jwk
            .as_ref()
            .ok_or(DpopProofVerifierError::MissingPublicJwk)?;
        let public_jwk =
            serde_json::to_value(jwk).map_err(|_| DpopProofVerifierError::InvalidPublicJwk)?;
        let decoding_key = dpop_jwk_decoding_key(&public_jwk, header.alg)
            .ok_or(DpopProofVerifierError::InvalidPublicJwk)?;
        let claims = decode_and_verify_dpop_proof(proof_jwt, &decoding_key, header.alg)?;
        self.validate_claims(&claims, method, htu, access_token)?;
        let jkt =
            dpop_jwk_thumbprint(&public_jwk).ok_or(DpopProofVerifierError::InvalidPublicJwk)?;
        self.check_replay(&jkt, &claims.jti)?;
        Ok(VerifiedSenderConstraintProof {
            dpop_jkt: Some(jkt),
            mtls_x5t_s256: None,
        })
    }

    fn validate_claims(
        &self,
        claims: &DpopProofClaims,
        method: &str,
        htu: &str,
        access_token: &str,
    ) -> Result<(), DpopProofVerifierError> {
        if claims.htm != method.to_ascii_uppercase() {
            return Err(DpopProofVerifierError::MethodMismatch);
        }
        if claims.htu != htu {
            return Err(DpopProofVerifierError::UriMismatch);
        }
        if claims.ath.as_deref() != Some(access_token_hash(access_token).as_str()) {
            return Err(DpopProofVerifierError::AccessTokenHashMismatch);
        }
        if claims.jti.trim().is_empty() {
            return Err(DpopProofVerifierError::MissingJti);
        }
        let now = Utc::now().timestamp();
        let skew = self.config.clock_skew_seconds.max(0);
        let max_age = self.config.max_age_seconds.max(1);
        if claims.iat < now.saturating_sub(max_age.saturating_add(skew)) {
            return Err(DpopProofVerifierError::Expired);
        }
        if claims.iat > now.saturating_add(skew) {
            return Err(DpopProofVerifierError::NotYetValid);
        }
        if let Some(expected) = self.config.required_nonce.as_deref()
            && claims.nonce.as_deref() != Some(expected)
        {
            return Err(DpopProofVerifierError::NonceMismatch);
        }
        Ok(())
    }

    fn check_replay(&self, jkt: &str, jti: &str) -> Result<(), DpopProofVerifierError> {
        let now = Utc::now().timestamp();
        let ttl = self
            .config
            .max_age_seconds
            .max(1)
            .saturating_add(self.config.clock_skew_seconds.max(0));
        let mut cache = self
            .replay_cache
            .lock()
            .map_err(|_| DpopProofVerifierError::ReplayStoreUnavailable)?;
        cache.retain(|_, expires_at| *expires_at > now);
        let replay_key = format!("{jkt}:{jti}");
        if cache.contains_key(&replay_key) {
            return Err(DpopProofVerifierError::ReplayDetected);
        }
        cache.insert(replay_key, now.saturating_add(ttl));
        Ok(())
    }
}

impl Default for DpopProofVerifierConfig {
    fn default() -> Self {
        Self {
            allowed_algs: vec![
                Algorithm::EdDSA,
                Algorithm::RS256,
                Algorithm::ES256,
                Algorithm::PS256,
            ],
            clock_skew_seconds: DEFAULT_CLOCK_SKEW_SECONDS,
            max_age_seconds: DEFAULT_DPOP_MAX_AGE_SECONDS,
            required_nonce: None,
        }
    }
}

impl ResourceServerVerifier {
    pub fn new(config: ResourceServerVerifierConfig) -> Result<Self, ResourceServerVerifierError> {
        if config.issuer.trim().is_empty() {
            return Err(ResourceServerVerifierError::MissingIssuer);
        }
        if config.audiences.is_empty() {
            return Err(ResourceServerVerifierError::MissingAudience);
        }
        if config.jwks.get("keys").and_then(Value::as_array).is_none() {
            return Err(ResourceServerVerifierError::MissingJwks);
        }
        Ok(Self { config })
    }

    pub fn verify(&self, token: &str) -> Result<VerifiedAccessToken, ResourceServerVerifierError> {
        let header = jsonwebtoken::decode_header(token)
            .map_err(|_| ResourceServerVerifierError::InvalidToken)?;
        if header.typ.as_deref() != Some("at+jwt") {
            return Err(ResourceServerVerifierError::WrongTokenType);
        }
        if !self.config.allowed_algs.contains(&header.alg) {
            return Err(ResourceServerVerifierError::UnsupportedAlgorithm);
        }
        let kid = header
            .kid
            .as_deref()
            .ok_or(ResourceServerVerifierError::MissingKeyId)?;
        let key = self
            .jwk_for_kid(kid)
            .ok_or(ResourceServerVerifierError::UnknownKeyId)?;
        let decoding_key =
            jwk_decoding_key(key, header.alg).ok_or(ResourceServerVerifierError::InvalidKey)?;
        let mut validation = Validation::new(header.alg);
        validation.validate_aud = false;
        validation.validate_exp = false;
        validation.validate_nbf = false;
        let decoded = jsonwebtoken::decode::<AccessTokenClaims>(token, &decoding_key, &validation)
            .map_err(|_| ResourceServerVerifierError::InvalidToken)?;
        self.validate_claims(decoded.claims)
    }

    fn validate_claims(
        &self,
        claims: AccessTokenClaims,
    ) -> Result<VerifiedAccessToken, ResourceServerVerifierError> {
        if claims.token_use != "access" {
            return Err(ResourceServerVerifierError::WrongTokenType);
        }
        if claims.iss != self.config.issuer {
            return Err(ResourceServerVerifierError::IssuerMismatch);
        }
        let audiences = audience_values(&claims.aud);
        if !audiences
            .iter()
            .any(|aud| self.config.audiences.iter().any(|expected| expected == aud))
        {
            return Err(ResourceServerVerifierError::AudienceMismatch);
        }
        let now = Utc::now().timestamp();
        let skew = self.config.clock_skew_seconds.max(0);
        if claims.exp <= now.saturating_sub(skew) {
            return Err(ResourceServerVerifierError::Expired);
        }
        if claims.nbf.is_some_and(|nbf| nbf > now.saturating_add(skew)) {
            return Err(ResourceServerVerifierError::NotYetValid);
        }
        let scopes = scope_values(&claims.scope);
        for required in &self.config.required_scopes {
            if !scopes.iter().any(|scope| scope == required) {
                return Err(ResourceServerVerifierError::MissingScope(required.clone()));
            }
        }
        validate_confirmation_policy(&self.config.confirmation, claims.cnf.as_ref())?;
        Ok(VerifiedAccessToken {
            issuer: claims.iss,
            subject: claims.sub,
            client_id: claims.client_id,
            audiences,
            scopes,
            jti: claims.jti,
            exp: claims.exp,
            cnf: claims.cnf,
            authorization_details: claims.authorization_details,
        })
    }

    fn jwk_for_kid(&self, kid: &str) -> Option<&Value> {
        self.config
            .jwks
            .get("keys")?
            .as_array()?
            .iter()
            .find(|key| key.get("kid").and_then(Value::as_str) == Some(kid))
    }
}

impl ResourceServerVerifierConfig {
    pub fn new(issuer: impl Into<String>, audience: impl Into<String>, jwks: Value) -> Self {
        Self {
            issuer: issuer.into(),
            audiences: vec![audience.into()],
            jwks,
            required_scopes: Vec::new(),
            confirmation: ConfirmationPolicy::Optional,
            allowed_algs: vec![
                Algorithm::EdDSA,
                Algorithm::RS256,
                Algorithm::ES256,
                Algorithm::PS256,
            ],
            clock_skew_seconds: DEFAULT_CLOCK_SKEW_SECONDS,
        }
    }
}

pub fn authorize_resource_request(
    verifier: &ResourceServerVerifier,
    authorization_headers: &[&str],
    query: Option<&str>,
    proof: &VerifiedSenderConstraintProof,
) -> Result<VerifiedAccessToken, ResourceServerRequestError> {
    if query_has_access_token(query) {
        return Err(ResourceServerRequestError::InvalidRequest);
    }
    let (scheme, token) = presented_authorization_token(authorization_headers)?;
    let verified = verifier
        .verify(token)
        .map_err(ResourceServerRequestError::InvalidToken)?;
    validate_presented_sender_constraint(scheme, &verified, proof)?;
    Ok(verified)
}

pub fn authorize_dpop_resource_request(
    verifier: &ResourceServerVerifier,
    dpop_verifier: &DpopProofVerifier,
    authorization_headers: &[&str],
    dpop_proof_jwt: &str,
    query: Option<&str>,
    method: &str,
    htu: &str,
) -> Result<(VerifiedAccessToken, VerifiedSenderConstraintProof), ResourceServerRequestError> {
    if query_has_access_token(query) {
        return Err(ResourceServerRequestError::InvalidRequest);
    }
    let (scheme, access_token) = presented_authorization_token(authorization_headers)?;
    if scheme != PresentedAccessTokenScheme::Dpop {
        return Err(ResourceServerRequestError::MissingSenderConstraint);
    }
    let proof = dpop_verifier
        .verify(dpop_proof_jwt, method, htu, access_token)
        .map_err(ResourceServerRequestError::InvalidDpopProof)?;
    let verified = verifier
        .verify(access_token)
        .map_err(ResourceServerRequestError::InvalidToken)?;
    validate_presented_sender_constraint(scheme, &verified, &proof)?;
    Ok((verified, proof))
}

pub fn authorize_http_request<B>(
    verifier: &ResourceServerVerifier,
    request: &mut http::Request<B>,
) -> Result<VerifiedAccessToken, ResourceServerRequestError> {
    let headers = http_authorization_headers(request.headers())?;
    let proof = request
        .extensions()
        .get::<VerifiedSenderConstraintProof>()
        .cloned()
        .unwrap_or_default();
    let verified = authorize_resource_request(verifier, &headers, request.uri().query(), &proof)?;
    request.extensions_mut().insert(verified.clone());
    Ok(verified)
}

pub fn authorize_dpop_http_request<B>(
    verifier: &ResourceServerVerifier,
    dpop_verifier: &DpopProofVerifier,
    request: &mut http::Request<B>,
    htu: &str,
) -> Result<VerifiedAccessToken, ResourceServerRequestError> {
    let authorization_headers = http_authorization_headers(request.headers())?;
    let dpop_headers = http_dpop_headers(request.headers())?;
    let dpop_proof_jwt = single_dpop_header(&dpop_headers)?;
    let (verified, proof) = authorize_dpop_resource_request(
        verifier,
        dpop_verifier,
        &authorization_headers,
        dpop_proof_jwt,
        request.uri().query(),
        request.method().as_str(),
        htu,
    )?;
    request.extensions_mut().insert(proof);
    request.extensions_mut().insert(verified.clone());
    Ok(verified)
}

pub fn authorize_actix_request(
    verifier: &ResourceServerVerifier,
    request: &actix_web::HttpRequest,
) -> Result<VerifiedAccessToken, ResourceServerRequestError> {
    use actix_web::HttpMessage;

    let headers: Result<Vec<_>, _> = request
        .headers()
        .get_all(actix_web::http::header::AUTHORIZATION)
        .map(|value| {
            value
                .to_str()
                .map_err(|_| ResourceServerRequestError::InvalidRequest)
        })
        .collect();
    let headers = headers?;
    let proof = request
        .extensions()
        .get::<VerifiedSenderConstraintProof>()
        .cloned()
        .unwrap_or_default();
    let query = if request.query_string().is_empty() {
        None
    } else {
        Some(request.query_string())
    };
    let verified = authorize_resource_request(verifier, &headers, query, &proof)?;
    request.extensions_mut().insert(verified.clone());
    Ok(verified)
}

#[derive(Clone, Debug)]
pub struct ActixVerifiedAccessToken(pub VerifiedAccessToken);

impl actix_web::FromRequest for ActixVerifiedAccessToken {
    type Error = actix_web::Error;
    type Future = Ready<Result<Self, Self::Error>>;

    fn from_request(
        req: &actix_web::HttpRequest,
        _payload: &mut actix_web::dev::Payload,
    ) -> Self::Future {
        let Some(verifier) = req.app_data::<actix_web::web::Data<ResourceServerVerifier>>() else {
            return ready(Err(actix_web::error::InternalError::from_response(
                "resource server verifier is not configured",
                actix_bearer_error_response(ResourceServerRequestError::InvalidRequest),
            )
            .into()));
        };
        ready(
            authorize_actix_request(verifier, req)
                .map(ActixVerifiedAccessToken)
                .map_err(|error| {
                    actix_web::error::InternalError::from_response(
                        format!("{error:?}"),
                        actix_bearer_error_response(error),
                    )
                    .into()
                }),
        )
    }
}

pub fn actix_bearer_error_response(error: ResourceServerRequestError) -> actix_web::HttpResponse {
    let status = http_status_for_request_error(&error);
    let (code, description) = bearer_error_fields(&error);
    let challenge = bearer_challenge_value(code, description);
    actix_web::HttpResponse::build(
        actix_web::http::StatusCode::from_u16(status.as_u16())
            .unwrap_or(actix_web::http::StatusCode::UNAUTHORIZED),
    )
    .insert_header((actix_web::http::header::WWW_AUTHENTICATE, challenge))
    .json(serde_json::json!({
        "error": code,
        "error_description": description
    }))
}

#[derive(Clone, Debug)]
pub struct TowerResourceServerLayer {
    verifier: ResourceServerVerifier,
}

impl TowerResourceServerLayer {
    pub fn new(verifier: ResourceServerVerifier) -> Self {
        Self { verifier }
    }
}

impl<S> Layer<S> for TowerResourceServerLayer {
    type Service = TowerResourceServerService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        TowerResourceServerService {
            inner,
            verifier: self.verifier.clone(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct TowerResourceServerService<S> {
    inner: S,
    verifier: ResourceServerVerifier,
}

#[derive(Debug)]
pub enum TowerResourceServerError<E> {
    Unauthorized(ResourceServerRequestError),
    Inner(E),
}

impl<S, B> Service<http::Request<B>> for TowerResourceServerService<S>
where
    S: Service<http::Request<B>> + Send + 'static,
    S::Future: Send + 'static,
    S::Response: Send + 'static,
    S::Error: Send + 'static,
    B: Send + 'static,
{
    type Response = S::Response;
    type Error = TowerResourceServerError<S::Error>;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner
            .poll_ready(cx)
            .map_err(TowerResourceServerError::Inner)
    }

    fn call(&mut self, mut request: http::Request<B>) -> Self::Future {
        if let Err(error) = authorize_http_request(&self.verifier, &mut request) {
            return Box::pin(async move { Err(TowerResourceServerError::Unauthorized(error)) });
        }
        let future = self.inner.call(request);
        Box::pin(async move { future.await.map_err(TowerResourceServerError::Inner) })
    }
}

pub fn authorize_tonic_request<T>(
    verifier: &ResourceServerVerifier,
    request: &mut tonic::Request<T>,
) -> Result<VerifiedAccessToken, tonic::Status> {
    let headers = request
        .metadata()
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .into_iter()
        .collect::<Vec<_>>();
    let proof = request
        .extensions()
        .get::<VerifiedSenderConstraintProof>()
        .cloned()
        .unwrap_or_default();
    match authorize_resource_request(verifier, &headers, None, &proof) {
        Ok(verified) => {
            request.extensions_mut().insert(verified.clone());
            Ok(verified)
        }
        Err(error) => Err(tonic_status_for_request_error(error)),
    }
}

pub fn http_bearer_error_response(error: &ResourceServerRequestError) -> http::Response<String> {
    let status = http_status_for_request_error(error);
    let (code, description) = bearer_error_fields(error);
    http::Response::builder()
        .status(status)
        .header(
            header::WWW_AUTHENTICATE,
            bearer_challenge_value(code, description),
        )
        .header(header::CONTENT_TYPE, "application/json")
        .body(format!(
            r#"{{"error":"{code}","error_description":"{description}"}}"#
        ))
        .expect("static bearer error response must be valid")
}

fn http_authorization_headers(
    headers: &HeaderMap,
) -> Result<Vec<&str>, ResourceServerRequestError> {
    headers
        .get_all(header::AUTHORIZATION)
        .iter()
        .map(|value| {
            value
                .to_str()
                .map_err(|_| ResourceServerRequestError::InvalidRequest)
        })
        .collect()
}

fn http_dpop_headers(headers: &HeaderMap) -> Result<Vec<&str>, ResourceServerRequestError> {
    headers
        .get_all("dpop")
        .iter()
        .map(|value| {
            value
                .to_str()
                .map_err(|_| ResourceServerRequestError::InvalidRequest)
        })
        .collect()
}

fn single_dpop_header<'a>(values: &'a [&'a str]) -> Result<&'a str, ResourceServerRequestError> {
    if values.is_empty() {
        return Err(ResourceServerRequestError::MissingSenderConstraint);
    }
    if values.len() != 1 {
        return Err(ResourceServerRequestError::InvalidRequest);
    }
    if values[0].trim().is_empty() {
        return Err(ResourceServerRequestError::InvalidRequest);
    }
    Ok(values[0])
}

fn query_has_access_token(query: Option<&str>) -> bool {
    query.is_some_and(|query| {
        url::form_urlencoded::parse(query.as_bytes()).any(|(key, _)| key == "access_token")
    })
}

fn presented_authorization_token<'a>(
    values: &'a [&'a str],
) -> Result<(PresentedAccessTokenScheme, &'a str), ResourceServerRequestError> {
    if values.is_empty() {
        return Err(ResourceServerRequestError::MissingToken);
    }
    if values.len() != 1 {
        return Err(ResourceServerRequestError::InvalidRequest);
    }
    let mut parts = values[0].split_whitespace();
    let Some(scheme) = parts.next() else {
        return Err(ResourceServerRequestError::MissingToken);
    };
    let Some(token) = parts.next().filter(|token| !token.trim().is_empty()) else {
        return Err(ResourceServerRequestError::MissingToken);
    };
    if parts.next().is_some() {
        return Err(ResourceServerRequestError::InvalidRequest);
    }
    let scheme = if scheme.eq_ignore_ascii_case("bearer") {
        PresentedAccessTokenScheme::Bearer
    } else if scheme.eq_ignore_ascii_case("dpop") {
        PresentedAccessTokenScheme::Dpop
    } else {
        return Err(ResourceServerRequestError::MissingToken);
    };
    Ok((scheme, token))
}

fn validate_presented_sender_constraint(
    scheme: PresentedAccessTokenScheme,
    verified: &VerifiedAccessToken,
    proof: &VerifiedSenderConstraintProof,
) -> Result<(), ResourceServerRequestError> {
    let Some(cnf) = verified.cnf.as_ref() else {
        return if scheme == PresentedAccessTokenScheme::Dpop {
            Err(ResourceServerRequestError::MissingSenderConstraint)
        } else {
            Ok(())
        };
    };
    if let Some(expected) = cnf.jkt.as_ref() {
        if scheme != PresentedAccessTokenScheme::Dpop {
            return Err(ResourceServerRequestError::MissingSenderConstraint);
        }
        return match proof.dpop_jkt.as_ref() {
            Some(actual) if actual == expected => Ok(()),
            Some(_) => Err(ResourceServerRequestError::DpopBindingMismatch),
            None => Err(ResourceServerRequestError::MissingSenderConstraint),
        };
    }
    if let Some(expected) = cnf.x5t_s256.as_ref() {
        return match proof.mtls_x5t_s256.as_ref() {
            Some(actual) if actual == expected => Ok(()),
            Some(_) => Err(ResourceServerRequestError::MtlsBindingMismatch),
            None => Err(ResourceServerRequestError::MissingSenderConstraint),
        };
    }
    Err(ResourceServerRequestError::MissingSenderConstraint)
}

fn http_status_for_request_error(error: &ResourceServerRequestError) -> http::StatusCode {
    match error {
        ResourceServerRequestError::InvalidRequest => http::StatusCode::BAD_REQUEST,
        _ => http::StatusCode::UNAUTHORIZED,
    }
}

fn bearer_error_fields(error: &ResourceServerRequestError) -> (&'static str, &'static str) {
    match error {
        ResourceServerRequestError::InvalidRequest => (
            "invalid_request",
            "The request used an invalid access token transport.",
        ),
        ResourceServerRequestError::MissingToken => {
            ("invalid_token", "Missing bearer access token.")
        }
        ResourceServerRequestError::MissingSenderConstraint => (
            "invalid_token",
            "Sender-constrained access token requires verified proof.",
        ),
        ResourceServerRequestError::DpopBindingMismatch => {
            ("invalid_token", "DPoP proof does not match access token.")
        }
        ResourceServerRequestError::MtlsBindingMismatch => (
            "invalid_token",
            "Client certificate does not match access token.",
        ),
        ResourceServerRequestError::InvalidToken(_) => {
            ("invalid_token", "Access token is invalid.")
        }
        ResourceServerRequestError::InvalidDpopProof(_) => {
            ("invalid_token", "DPoP proof is invalid.")
        }
    }
}

fn bearer_challenge_value(error: &str, description: &str) -> String {
    format!(r#"Bearer error="{error}", error_description="{description}""#)
}

fn tonic_status_for_request_error(error: ResourceServerRequestError) -> tonic::Status {
    match error {
        ResourceServerRequestError::InvalidRequest => {
            tonic::Status::invalid_argument("invalid_request")
        }
        _ => tonic::Status::unauthenticated("invalid_token"),
    }
}

fn validate_confirmation_policy(
    policy: &ConfirmationPolicy,
    cnf: Option<&ConfirmationClaims>,
) -> Result<(), ResourceServerVerifierError> {
    match policy {
        ConfirmationPolicy::Optional => Ok(()),
        ConfirmationPolicy::RequireAnySenderConstraint => {
            let Some(cnf) = cnf else {
                return Err(ResourceServerVerifierError::MissingSenderConstraint);
            };
            if cnf.jkt.is_some() || cnf.x5t_s256.is_some() {
                Ok(())
            } else {
                Err(ResourceServerVerifierError::MissingSenderConstraint)
            }
        }
        ConfirmationPolicy::RequireDpop => {
            if cnf.and_then(|claims| claims.jkt.as_ref()).is_some() {
                Ok(())
            } else {
                Err(ResourceServerVerifierError::MissingSenderConstraint)
            }
        }
        ConfirmationPolicy::RequireDpopJkt(expected) => {
            match cnf.and_then(|claims| claims.jkt.as_ref()) {
                Some(actual) if actual == expected => Ok(()),
                Some(_) => Err(ResourceServerVerifierError::DpopBindingMismatch),
                None => Err(ResourceServerVerifierError::MissingSenderConstraint),
            }
        }
        ConfirmationPolicy::RequireMtls => {
            if cnf.and_then(|claims| claims.x5t_s256.as_ref()).is_some() {
                Ok(())
            } else {
                Err(ResourceServerVerifierError::MissingSenderConstraint)
            }
        }
        ConfirmationPolicy::RequireMtlsThumbprint(expected) => {
            match cnf.and_then(|claims| claims.x5t_s256.as_ref()) {
                Some(actual) if actual == expected => Ok(()),
                Some(_) => Err(ResourceServerVerifierError::MtlsBindingMismatch),
                None => Err(ResourceServerVerifierError::MissingSenderConstraint),
            }
        }
    }
}

fn audience_values(value: &Value) -> Vec<String> {
    match value {
        Value::String(value) => vec![value.clone()],
        Value::Array(values) => values
            .iter()
            .filter_map(|value| value.as_str().map(ToOwned::to_owned))
            .collect(),
        _ => Vec::new(),
    }
}

fn scope_values(value: &str) -> Vec<String> {
    value
        .split_whitespace()
        .map(ToOwned::to_owned)
        .filter(|scope| !scope.is_empty())
        .collect()
}

fn decode_and_verify_dpop_proof(
    proof_jwt: &str,
    decoding_key: &DecodingKey,
    alg: Algorithm,
) -> Result<DpopProofClaims, DpopProofVerifierError> {
    let mut parts = proof_jwt.split('.');
    let Some(header) = parts.next().filter(|part| !part.is_empty()) else {
        return Err(DpopProofVerifierError::MalformedProof);
    };
    let Some(payload) = parts.next().filter(|part| !part.is_empty()) else {
        return Err(DpopProofVerifierError::MalformedProof);
    };
    let Some(signature) = parts.next().filter(|part| !part.is_empty()) else {
        return Err(DpopProofVerifierError::MalformedProof);
    };
    if parts.next().is_some() {
        return Err(DpopProofVerifierError::MalformedProof);
    }
    let signing_input = format!("{header}.{payload}");
    if !jsonwebtoken::crypto::verify(signature, signing_input.as_bytes(), decoding_key, alg)
        .map_err(|_| DpopProofVerifierError::InvalidSignature)?
    {
        return Err(DpopProofVerifierError::InvalidSignature);
    }
    let payload = URL_SAFE_NO_PAD
        .decode(payload)
        .map_err(|_| DpopProofVerifierError::MalformedProof)?;
    let claims = serde_json::from_slice::<DpopProofClaims>(&payload)
        .map_err(|_| DpopProofVerifierError::MalformedProof)?;
    Ok(claims)
}

fn dpop_jwk_decoding_key(key: &Value, alg: Algorithm) -> Option<DecodingKey> {
    let expected_alg = algorithm_name(alg)?;
    if let Some(key_alg) = key.get("alg").and_then(Value::as_str)
        && key_alg != expected_alg
    {
        return None;
    }
    if key.get("d").is_some() {
        return None;
    }
    if key
        .get("use")
        .and_then(Value::as_str)
        .is_some_and(|use_| use_ != "sig")
    {
        return None;
    }
    match alg {
        Algorithm::EdDSA => {
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
            DecodingKey::from_ed_components(x).ok()
        }
        Algorithm::RS256 | Algorithm::PS256 => {
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
            DecodingKey::from_rsa_components(n, e).ok()
        }
        Algorithm::ES256 => {
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
            DecodingKey::from_ec_components(x, y).ok()
        }
        _ => None,
    }
}

fn dpop_jwk_thumbprint(key: &Value) -> Option<String> {
    let mut members = BTreeMap::new();
    match key.get("kty").and_then(Value::as_str)? {
        "EC" => {
            members.insert("crv", key.get("crv")?.as_str()?);
            members.insert("kty", "EC");
            members.insert("x", key.get("x")?.as_str()?);
            members.insert("y", key.get("y")?.as_str()?);
        }
        "OKP" => {
            members.insert("crv", key.get("crv")?.as_str()?);
            members.insert("kty", "OKP");
            members.insert("x", key.get("x")?.as_str()?);
        }
        "RSA" => {
            members.insert("e", key.get("e")?.as_str()?);
            members.insert("kty", "RSA");
            members.insert("n", key.get("n")?.as_str()?);
        }
        _ => return None,
    }
    let canonical = serde_json::to_string(&members).ok()?;
    Some(URL_SAFE_NO_PAD.encode(Sha256::digest(canonical.as_bytes())))
}

fn access_token_hash(access_token: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(access_token.as_bytes()))
}

fn jwk_decoding_key(key: &Value, alg: Algorithm) -> Option<DecodingKey> {
    let expected_alg = algorithm_name(alg)?;
    if key.get("alg").and_then(Value::as_str) != Some(expected_alg) {
        return None;
    }
    if key.get("d").is_some() {
        return None;
    }
    if key
        .get("use")
        .and_then(Value::as_str)
        .is_some_and(|use_| use_ != "sig")
    {
        return None;
    }
    match alg {
        Algorithm::EdDSA => {
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
            DecodingKey::from_ed_components(x).ok()
        }
        Algorithm::RS256 | Algorithm::PS256 => {
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
            DecodingKey::from_rsa_components(n, e).ok()
        }
        Algorithm::ES256 => {
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
            DecodingKey::from_ec_components(x, y).ok()
        }
        _ => None,
    }
}

fn algorithm_name(alg: Algorithm) -> Option<&'static str> {
    match alg {
        Algorithm::EdDSA => Some("EdDSA"),
        Algorithm::RS256 => Some("RS256"),
        Algorithm::ES256 => Some("ES256"),
        Algorithm::PS256 => Some("PS256"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{
        EncodingKey, Header,
        jwk::{Jwk, PublicKeyUse},
    };
    use openssl::rsa::Rsa;
    use serde_json::json;

    struct Fixture {
        verifier: ResourceServerVerifier,
        jwks: Value,
        encoding_key: EncodingKey,
    }

    struct DpopFixture {
        encoding_key: EncodingKey,
        public_jwk: Jwk,
        jkt: String,
    }

    fn fixture() -> Fixture {
        let der = Rsa::generate(2048).unwrap().private_key_to_der().unwrap();
        let encoding_key = EncodingKey::from_rsa_der(&der);
        let mut jwk = Jwk::from_encoding_key(&encoding_key, Algorithm::RS256).unwrap();
        jwk.common.key_id = Some("test-rs256".to_owned());
        jwk.common.public_key_use = Some(PublicKeyUse::Signature);
        let jwks = json!({"keys": [serde_json::to_value(jwk).unwrap()]});
        let mut config = ResourceServerVerifierConfig::new(
            "https://issuer.example",
            "resource://default",
            jwks.clone(),
        );
        config.required_scopes = vec!["read".to_owned()];
        Fixture {
            verifier: ResourceServerVerifier::new(config).unwrap(),
            jwks,
            encoding_key,
        }
    }

    fn dpop_fixture() -> DpopFixture {
        let der = Rsa::generate(2048).unwrap().private_key_to_der().unwrap();
        let encoding_key = EncodingKey::from_rsa_der(&der);
        let mut public_jwk = Jwk::from_encoding_key(&encoding_key, Algorithm::RS256).unwrap();
        public_jwk.common.key_id = Some("dpop-rs256".to_owned());
        public_jwk.common.public_key_use = Some(PublicKeyUse::Signature);
        let public_jwk_value = serde_json::to_value(&public_jwk).unwrap();
        let jkt = dpop_jwk_thumbprint(&public_jwk_value).unwrap();
        DpopFixture {
            encoding_key,
            public_jwk,
            jkt,
        }
    }

    fn token(
        fixture: &Fixture,
        claim_overrides: Value,
        header_overrides: Option<Header>,
    ) -> String {
        let now = Utc::now().timestamp();
        let mut claims = json!({
            "iss": "https://issuer.example",
            "sub": "subject-1",
            "aud": "resource://default",
            "client_id": "client-1",
            "scope": "read write",
            "authorization_details": [],
            "token_use": "access",
            "jti": "jti-1",
            "iat": now,
            "nbf": now,
            "exp": now + 300
        });
        merge_object(&mut claims, claim_overrides);
        let mut header = header_overrides.unwrap_or_else(|| {
            let mut header = Header::new(Algorithm::RS256);
            header.typ = Some("at+jwt".to_owned());
            header.kid = Some("test-rs256".to_owned());
            header
        });
        if header.kid.is_none() {
            header.kid = Some("test-rs256".to_owned());
        }
        jsonwebtoken::encode(&header, &claims, &fixture.encoding_key).unwrap()
    }

    fn dpop_proof(
        fixture: &DpopFixture,
        access_token: &str,
        method: &str,
        htu: &str,
        jti: &str,
        nonce: Option<&str>,
        ath_override: Option<&str>,
    ) -> String {
        let mut claims = json!({
            "htu": htu,
            "htm": method,
            "iat": Utc::now().timestamp(),
            "jti": jti,
            "ath": ath_override
                .map(ToOwned::to_owned)
                .unwrap_or_else(|| access_token_hash(access_token)),
        });
        if let Some(nonce) = nonce {
            claims["nonce"] = json!(nonce);
        }
        let mut header = Header::new(Algorithm::RS256);
        header.typ = Some("dpop+jwt".to_owned());
        header.jwk = Some(fixture.public_jwk.clone());
        jsonwebtoken::encode(&header, &claims, &fixture.encoding_key).unwrap()
    }

    fn merge_object(target: &mut Value, overrides: Value) {
        let target = target.as_object_mut().unwrap();
        for (key, value) in overrides.as_object().unwrap() {
            target.insert(key.clone(), value.clone());
        }
    }

    fn bearer(token: &str) -> String {
        format!("Bearer {token}")
    }

    fn dpop(token: &str) -> String {
        format!("DPoP {token}")
    }

    #[test]
    fn verifies_jwt_access_token_with_required_scope() {
        let fixture = fixture();
        let verified = fixture
            .verifier
            .verify(&token(&fixture, json!({}), None))
            .unwrap();

        assert_eq!(verified.issuer, "https://issuer.example");
        assert_eq!(verified.subject, "subject-1");
        assert_eq!(verified.audiences, vec!["resource://default"]);
        assert_eq!(verified.scopes, vec!["read", "write"]);
    }

    #[test]
    fn rejects_wrong_audience() {
        let fixture = fixture();
        let error = fixture
            .verifier
            .verify(&token(&fixture, json!({"aud": "resource://other"}), None))
            .unwrap_err();

        assert_eq!(error, ResourceServerVerifierError::AudienceMismatch);
    }

    #[test]
    fn rejects_missing_required_scope() {
        let fixture = fixture();
        let error = fixture
            .verifier
            .verify(&token(&fixture, json!({"scope": "write"}), None))
            .unwrap_err();

        assert_eq!(
            error,
            ResourceServerVerifierError::MissingScope("read".to_owned())
        );
    }

    #[test]
    fn rejects_id_token_typ() {
        let fixture = fixture();
        let mut header = Header::new(Algorithm::RS256);
        header.typ = Some("JWT".to_owned());
        header.kid = Some("test-rs256".to_owned());
        let error = fixture
            .verifier
            .verify(&token(&fixture, json!({}), Some(header)))
            .unwrap_err();

        assert_eq!(error, ResourceServerVerifierError::WrongTokenType);
    }

    #[test]
    fn enforces_dpop_jkt_binding() {
        let fixture = fixture();
        let mut config = ResourceServerVerifierConfig::new(
            "https://issuer.example",
            "resource://default",
            fixture.jwks.clone(),
        );
        config.confirmation = ConfirmationPolicy::RequireDpopJkt("jkt-1".to_owned());
        let verifier = ResourceServerVerifier::new(config).unwrap();

        let verified = verifier
            .verify(&token(&fixture, json!({"cnf": {"jkt": "jkt-1"}}), None))
            .unwrap();
        assert_eq!(verified.cnf.unwrap().jkt, Some("jkt-1".to_owned()));
    }

    #[test]
    fn rejects_dpop_jkt_mismatch() {
        let fixture = fixture();
        let mut config = ResourceServerVerifierConfig::new(
            "https://issuer.example",
            "resource://default",
            fixture.jwks.clone(),
        );
        config.confirmation = ConfirmationPolicy::RequireDpopJkt("jkt-1".to_owned());
        let verifier = ResourceServerVerifier::new(config).unwrap();

        let error = verifier
            .verify(&token(&fixture, json!({"cnf": {"jkt": "jkt-2"}}), None))
            .unwrap_err();

        assert_eq!(error, ResourceServerVerifierError::DpopBindingMismatch);
    }

    #[test]
    fn request_authorizer_rejects_query_access_tokens() {
        let fixture = fixture();
        let token = bearer(&token(&fixture, json!({}), None));
        let error = authorize_resource_request(
            &fixture.verifier,
            &[token.as_str()],
            Some("access_token=query-token"),
            &SenderConstraintProof::default(),
        )
        .unwrap_err();

        assert_eq!(error, ResourceServerRequestError::InvalidRequest);
    }

    #[test]
    fn request_authorizer_rejects_duplicate_authorization_headers() {
        let fixture = fixture();
        let token = bearer(&token(&fixture, json!({}), None));
        let error = authorize_resource_request(
            &fixture.verifier,
            &[token.as_str(), token.as_str()],
            None,
            &SenderConstraintProof::default(),
        )
        .unwrap_err();

        assert_eq!(error, ResourceServerRequestError::InvalidRequest);
    }

    #[test]
    fn request_authorizer_requires_verified_dpop_binding_context() {
        let fixture = fixture();
        let token = token(&fixture, json!({"cnf": {"jkt": "jkt-1"}}), None);
        let header = dpop(&token);
        let error = authorize_resource_request(
            &fixture.verifier,
            &[header.as_str()],
            None,
            &SenderConstraintProof::default(),
        )
        .unwrap_err();

        assert_eq!(error, ResourceServerRequestError::MissingSenderConstraint);

        let verified = authorize_resource_request(
            &fixture.verifier,
            &[header.as_str()],
            None,
            &SenderConstraintProof {
                dpop_jkt: Some("jkt-1".to_owned()),
                mtls_x5t_s256: None,
            },
        )
        .unwrap();

        assert_eq!(verified.cnf.unwrap().jkt, Some("jkt-1".to_owned()));
    }

    #[test]
    fn dpop_proof_verifier_produces_verified_sender_context() {
        let fixture = fixture();
        let dpop_fixture = dpop_fixture();
        let access_token = token(&fixture, json!({"cnf": {"jkt": dpop_fixture.jkt}}), None);
        let proof_jwt = dpop_proof(
            &dpop_fixture,
            &access_token,
            "GET",
            "https://api.example/orders",
            "proof-jti-1",
            None,
            None,
        );
        let verifier = DpopProofVerifier::new(DpopProofVerifierConfig::default());

        let proof = verifier
            .verify(
                &proof_jwt,
                "GET",
                "https://api.example/orders",
                &access_token,
            )
            .unwrap();
        let header = dpop(&access_token);
        let verified =
            authorize_resource_request(&fixture.verifier, &[header.as_str()], None, &proof)
                .unwrap();

        assert_eq!(verified.cnf.unwrap().jkt, Some(dpop_fixture.jkt));
    }

    #[test]
    fn dpop_http_authorizer_verifies_proof_and_inserts_extensions() {
        let fixture = fixture();
        let dpop_fixture = dpop_fixture();
        let access_token = token(&fixture, json!({"cnf": {"jkt": dpop_fixture.jkt}}), None);
        let proof_jwt = dpop_proof(
            &dpop_fixture,
            &access_token,
            "GET",
            "https://api.example/orders",
            "proof-jti-http",
            None,
            None,
        );
        let dpop_verifier = DpopProofVerifier::new(DpopProofVerifierConfig::default());
        let mut request = http::Request::builder()
            .method("GET")
            .uri("/orders")
            .header(header::AUTHORIZATION, dpop(&access_token))
            .header("DPoP", proof_jwt)
            .body(())
            .unwrap();

        let verified = authorize_dpop_http_request(
            &fixture.verifier,
            &dpop_verifier,
            &mut request,
            "https://api.example/orders",
        )
        .unwrap();

        assert_eq!(verified.cnf.unwrap().jkt, Some(dpop_fixture.jkt.clone()));
        assert_eq!(
            request
                .extensions()
                .get::<VerifiedSenderConstraintProof>()
                .unwrap()
                .dpop_jkt,
            Some(dpop_fixture.jkt)
        );
        assert!(request.extensions().get::<VerifiedAccessToken>().is_some());
    }

    #[test]
    fn dpop_authorizer_rejects_invalid_proof_before_token_binding() {
        let fixture = fixture();
        let dpop_fixture = dpop_fixture();
        let access_token = token(&fixture, json!({"cnf": {"jkt": dpop_fixture.jkt}}), None);
        let proof_jwt = dpop_proof(
            &dpop_fixture,
            &access_token,
            "GET",
            "https://api.example/orders",
            "proof-jti-invalid",
            None,
            Some("wrong-ath"),
        );
        let dpop_verifier = DpopProofVerifier::new(DpopProofVerifierConfig::default());
        let authorization = dpop(&access_token);

        let error = authorize_dpop_resource_request(
            &fixture.verifier,
            &dpop_verifier,
            &[authorization.as_str()],
            &proof_jwt,
            None,
            "GET",
            "https://api.example/orders",
        )
        .unwrap_err();

        assert_eq!(
            error,
            ResourceServerRequestError::InvalidDpopProof(
                DpopProofVerifierError::AccessTokenHashMismatch
            )
        );
    }

    #[test]
    fn dpop_proof_verifier_rejects_replayed_jti() {
        let dpop = dpop_fixture();
        let access_token = "access-token";
        let proof_jwt = dpop_proof(
            &dpop,
            access_token,
            "GET",
            "https://api.example/orders",
            "proof-jti-replay",
            None,
            None,
        );
        let verifier = DpopProofVerifier::new(DpopProofVerifierConfig::default());

        verifier
            .verify(
                &proof_jwt,
                "GET",
                "https://api.example/orders",
                access_token,
            )
            .unwrap();
        let error = verifier
            .verify(
                &proof_jwt,
                "GET",
                "https://api.example/orders",
                access_token,
            )
            .unwrap_err();

        assert_eq!(error, DpopProofVerifierError::ReplayDetected);
    }

    #[test]
    fn dpop_proof_verifier_rejects_wrong_ath() {
        let dpop = dpop_fixture();
        let proof_jwt = dpop_proof(
            &dpop,
            "access-token",
            "GET",
            "https://api.example/orders",
            "proof-jti-ath",
            None,
            Some("wrong-ath"),
        );
        let verifier = DpopProofVerifier::new(DpopProofVerifierConfig::default());

        let error = verifier
            .verify(
                &proof_jwt,
                "GET",
                "https://api.example/orders",
                "access-token",
            )
            .unwrap_err();

        assert_eq!(error, DpopProofVerifierError::AccessTokenHashMismatch);
    }

    #[test]
    fn dpop_proof_verifier_enforces_required_nonce() {
        let dpop = dpop_fixture();
        let access_token = "access-token";
        let proof_jwt = dpop_proof(
            &dpop,
            access_token,
            "GET",
            "https://api.example/orders",
            "proof-jti-nonce",
            Some("nonce-1"),
            None,
        );
        let verifier = DpopProofVerifier::new(DpopProofVerifierConfig {
            required_nonce: Some("nonce-1".to_owned()),
            ..DpopProofVerifierConfig::default()
        });

        verifier
            .verify(
                &proof_jwt,
                "GET",
                "https://api.example/orders",
                access_token,
            )
            .unwrap();

        let verifier = DpopProofVerifier::new(DpopProofVerifierConfig {
            required_nonce: Some("nonce-2".to_owned()),
            ..DpopProofVerifierConfig::default()
        });
        let error = verifier
            .verify(
                &proof_jwt,
                "GET",
                "https://api.example/orders",
                access_token,
            )
            .unwrap_err();

        assert_eq!(error, DpopProofVerifierError::NonceMismatch);
    }

    #[test]
    fn request_authorizer_requires_verified_mtls_binding_context() {
        let fixture = fixture();
        let token = token(&fixture, json!({"cnf": {"x5t#S256": "thumb-1"}}), None);
        let header = bearer(&token);
        let error = authorize_resource_request(
            &fixture.verifier,
            &[header.as_str()],
            None,
            &SenderConstraintProof::default(),
        )
        .unwrap_err();

        assert_eq!(error, ResourceServerRequestError::MissingSenderConstraint);

        let verified = authorize_resource_request(
            &fixture.verifier,
            &[header.as_str()],
            None,
            &SenderConstraintProof {
                dpop_jkt: None,
                mtls_x5t_s256: Some("thumb-1".to_owned()),
            },
        )
        .unwrap();

        assert_eq!(verified.cnf.unwrap().x5t_s256, Some("thumb-1".to_owned()));
    }

    #[test]
    fn http_request_authorizer_inserts_verified_claims_for_tower_and_axum() {
        let fixture = fixture();
        let token = bearer(&token(&fixture, json!({}), None));
        let mut request = http::Request::builder()
            .uri("https://api.example/orders")
            .header(header::AUTHORIZATION, token)
            .body(())
            .unwrap();

        let verified = authorize_http_request(&fixture.verifier, &mut request).unwrap();

        assert_eq!(verified.subject, "subject-1");
        assert_eq!(
            request
                .extensions()
                .get::<VerifiedAccessToken>()
                .unwrap()
                .client_id,
            "client-1"
        );
    }

    #[actix_web::test]
    async fn actix_request_authorizer_inserts_verified_claims() {
        use actix_web::HttpMessage;

        let fixture = fixture();
        let token = bearer(&token(&fixture, json!({}), None));
        let request = actix_web::test::TestRequest::get()
            .uri("/orders")
            .insert_header((actix_web::http::header::AUTHORIZATION, token))
            .to_http_request();

        let verified = authorize_actix_request(&fixture.verifier, &request).unwrap();

        assert_eq!(verified.subject, "subject-1");
        assert_eq!(
            request
                .extensions()
                .get::<VerifiedAccessToken>()
                .unwrap()
                .client_id,
            "client-1"
        );
    }

    #[tokio::test]
    async fn tower_layer_inserts_verified_claims_before_inner_service() {
        #[derive(Clone)]
        struct ExtensionCheckService;

        impl Service<http::Request<()>> for ExtensionCheckService {
            type Response = bool;
            type Error = ();
            type Future = Ready<Result<bool, ()>>;

            fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
                Poll::Ready(Ok(()))
            }

            fn call(&mut self, request: http::Request<()>) -> Self::Future {
                ready(Ok(request
                    .extensions()
                    .get::<VerifiedAccessToken>()
                    .is_some()))
            }
        }

        let fixture = fixture();
        let token = bearer(&token(&fixture, json!({}), None));
        let request = http::Request::builder()
            .uri("https://api.example/orders")
            .header(header::AUTHORIZATION, token)
            .body(())
            .unwrap();
        let mut service =
            TowerResourceServerLayer::new(fixture.verifier).layer(ExtensionCheckService);

        let saw_claims = service.call(request).await.unwrap();

        assert!(saw_claims);
    }

    #[test]
    fn tonic_request_authorizer_inserts_verified_claims() {
        let fixture = fixture();
        let token = bearer(&token(&fixture, json!({}), None));
        let mut request = tonic::Request::new(());
        request
            .metadata_mut()
            .insert("authorization", token.parse().unwrap());

        let verified = authorize_tonic_request(&fixture.verifier, &mut request).unwrap();

        assert_eq!(verified.subject, "subject-1");
        assert_eq!(
            request
                .extensions()
                .get::<VerifiedAccessToken>()
                .unwrap()
                .client_id,
            "client-1"
        );
    }
}
