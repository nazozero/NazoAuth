//! Resource-server JWT access-token verifier.
//!
//! This module is intentionally independent from the authorization server
//! runtime state. Resource servers should validate issuer, audience, token
//! type, algorithm, key id, expiry, scopes, and sender constraints locally
//! before falling back to introspection or application policy hooks.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::Utc;
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use serde_json::Value;

const DEFAULT_CLOCK_SKEW_SECONDS: i64 = 60;

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

#[derive(Debug, PartialEq, Eq)]
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

    fn merge_object(target: &mut Value, overrides: Value) {
        let target = target.as_object_mut().unwrap();
        for (key, value) in overrides.as_object().unwrap() {
            target.insert(key.clone(), value.clone());
        }
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
}
