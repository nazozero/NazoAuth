//! OIDC relying-party request, ID Token and upstream identity semantics.

use jiff::Timestamp;
use nazo_crypto::{
    jwk::{jwt_decoding_key_from_jwk, jwt_decoding_key_from_jwks},
    jwt,
};
use serde::Deserialize;
use serde_json::Value;

use super::{OidcFederationStart, VerifiedExternalIdentity};
use crate::email::normalize_email_address;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OidcError {
    InvalidIdToken,
    InvalidLogoutToken,
    InvalidUserInfo,
    InvalidTokenResponse,
}

impl std::fmt::Display for OidcError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::InvalidIdToken => "OIDC ID Token validation failed",
            Self::InvalidLogoutToken => "OIDC Logout Token validation failed",
            Self::InvalidUserInfo => "OIDC UserInfo subject does not match the ID Token",
            Self::InvalidTokenResponse => "OIDC Token Response validation failed",
        })
    }
}

impl std::error::Error for OidcError {}

/// The endpoints from one validated issuer configuration document.
#[derive(Clone, Deserialize, serde::Serialize)]
pub struct OidcProviderMetadata {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    #[serde(rename = "jwks_uri")]
    pub jwks_url: String,
    pub userinfo_endpoint: Option<String>,
    pub end_session_endpoint: Option<String>,
    pub response_types_supported: Vec<String>,
    pub subject_types_supported: Vec<String>,
    pub id_token_signing_alg_values_supported: Vec<String>,
    pub token_endpoint_auth_methods_supported: Option<Vec<String>>,
}

pub fn https_endpoint(value: &str) -> Option<url::Url> {
    let (scheme, authority) = value.split_once("://")?;
    let authority = authority.split(['/', '?', '#']).next()?;
    if !scheme.eq_ignore_ascii_case("https")
        || authority.is_empty()
        || authority.contains('@')
        || value.contains('\\')
        || value.chars().any(|c| c.is_whitespace() || c.is_control())
    {
        return None;
    }
    let url = url::Url::parse(value).ok()?;
    (url.scheme() == "https"
        && url.host().is_some()
        && url.username().is_empty()
        && url.password().is_none()
        && url.fragment().is_none())
    .then_some(url)
}

pub fn discovery_url(issuer: &str) -> Option<String> {
    https_endpoint(issuer)?.query().is_none().then(|| {
        format!(
            "{}/.well-known/openid-configuration",
            issuer.strip_suffix('/').unwrap_or(issuer)
        )
    })
}

impl OidcProviderMetadata {
    pub fn validate(&self, issuer: &str) -> bool {
        self.issuer == issuer
            && self
                .response_types_supported
                .iter()
                .any(|response| response == "code")
            && self
                .subject_types_supported
                .iter()
                .any(|kind| matches!(kind.as_str(), "public" | "pairwise"))
            && self.supports_signing_algorithm(jwt::Algorithm::RS256)
            && self
                .token_endpoint_auth_methods_supported
                .as_ref()
                .is_none_or(|methods| methods.iter().any(|method| method == "client_secret_basic"))
            && https_endpoint(&self.authorization_endpoint).is_some()
            && https_endpoint(&self.token_endpoint).is_some()
            && https_endpoint(&self.jwks_url).is_some()
            && self
                .userinfo_endpoint
                .as_deref()
                .is_none_or(|url| https_endpoint(url).is_some())
    }

    pub fn supports_signing_algorithm(&self, algorithm: jwt::Algorithm) -> bool {
        let name = match algorithm {
            jwt::Algorithm::RS256 => "RS256",
            jwt::Algorithm::PS256 => "PS256",
            jwt::Algorithm::ES256 => "ES256",
            jwt::Algorithm::EdDSA => "EdDSA",
            _ => return false,
        };
        self.id_token_signing_alg_values_supported
            .iter()
            .any(|supported| supported == name)
    }
}

impl OidcUpstreamLogin {
    pub fn subject_key(&self) -> &str {
        &self.subject_key
    }
}

// The token endpoint response is validated exactly once during JSON decoding.
// Later UserInfo requests only borrow the accepted Bearer token.
#[derive(Deserialize)]
#[serde(try_from = "OidcTokenResponseWire")]
pub struct OidcTokenResponse {
    pub id_token: String,
    access_token: String,
}

#[derive(Deserialize)]
struct OidcTokenResponseWire {
    id_token: String,
    access_token: String,
    token_type: String,
}

impl TryFrom<OidcTokenResponseWire> for OidcTokenResponse {
    type Error = OidcError;

    fn try_from(wire: OidcTokenResponseWire) -> Result<Self, Self::Error> {
        if wire.access_token.is_empty() || !wire.token_type.eq_ignore_ascii_case("Bearer") {
            return Err(OidcError::InvalidTokenResponse);
        }
        Ok(Self {
            id_token: wire.id_token,
            access_token: wire.access_token,
        })
    }
}

impl OidcTokenResponse {
    pub fn userinfo_access_token(&self) -> &str {
        &self.access_token
    }
}

#[derive(Deserialize)]
pub struct OidcIdTokenClaims {
    iss: String,
    sub: String,
    aud: Value,
    iat: i64,
    nonce: Option<String>,
    sid: Option<String>,
    email: Option<String>,
    email_verified: Option<bool>,
    name: Option<String>,
    given_name: Option<String>,
    family_name: Option<String>,
}

#[derive(Deserialize)]
pub struct OidcUserInfo {
    sub: String,
    email: Option<String>,
    email_verified: Option<bool>,
    name: Option<String>,
    given_name: Option<String>,
    family_name: Option<String>,
}

pub struct OidcUpstreamLogin {
    pub(super) subject_key: String,
    pub(super) sid_key: Option<String>,
    pub(super) started_at: i64,
    pub encrypted_logout: Option<String>,
}

pub struct OidcLogout {
    pub(super) key: String,
    pub(super) cutoff: i64,
}

fn scope_key(
    tenant_id: crate::TenantId,
    provider: &str,
    issuer: &str,
    client_id: &str,
    kind: &str,
    value: &str,
) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"NazoAuth/oidc-logout/v1\0");
    hasher.update(tenant_id.as_uuid().as_bytes());
    for component in [provider, issuer, client_id, kind, value] {
        hasher.update(&(component.len() as u64).to_be_bytes());
        hasher.update(component.as_bytes());
    }
    hasher.finalize().to_hex().to_string()
}

fn valid_oidc_subject(subject: &str) -> bool {
    !subject.is_empty() && subject.len() <= 255 && subject.is_ascii()
}

fn valid_session_id(value: &str) -> bool {
    !value.is_empty() && value.bytes().all(|byte| (0x20..=0x7e).contains(&byte))
}

impl OidcIdTokenClaims {
    pub fn upstream_login(
        &self,
        tenant_id: crate::TenantId,
        provider: &str,
        client_id: &str,
        started_at: i64,
    ) -> Result<OidcUpstreamLogin, OidcError> {
        if self.iat < started_at.saturating_sub(60)
            || self
                .sid
                .as_deref()
                .is_some_and(|sid| !valid_session_id(sid))
        {
            return Err(OidcError::InvalidIdToken);
        }
        Ok(OidcUpstreamLogin {
            subject_key: scope_key(tenant_id, provider, &self.iss, client_id, "sub", &self.sub),
            sid_key: self
                .sid
                .as_deref()
                .map(|sid| scope_key(tenant_id, provider, &self.iss, client_id, "sid", sid)),
            started_at,
            encrypted_logout: None,
        })
    }

    pub fn into_identity(
        self,
        provider_id: &str,
        userinfo: Option<OidcUserInfo>,
    ) -> Result<VerifiedExternalIdentity, OidcError> {
        let profile = match userinfo {
            Some(userinfo) => {
                if userinfo.sub != self.sub {
                    return Err(OidcError::InvalidUserInfo);
                }
                userinfo
            }
            None => OidcUserInfo {
                sub: self.sub,
                email: self.email,
                email_verified: self.email_verified,
                name: self.name,
                given_name: self.given_name,
                family_name: self.family_name,
            },
        };
        // Subject identifies an existing link. Only a verified, valid email may
        // be offered to the identity service for provisioning a new account.
        let email = profile
            .email
            .as_deref()
            .filter(|_| profile.email_verified == Some(true))
            .and_then(|value| normalize_email_address(value).ok());
        // Only fields used both by account resolution and by the persisted
        // profile need a second owned value.
        let mut claims = serde_json::Map::new();
        for (name, value) in [
            ("iss", Value::String(self.iss)),
            ("sub", Value::String(profile.sub.clone())),
            ("email", email.clone().map_or(Value::Null, Value::String)),
            (
                "name",
                profile.name.clone().map_or(Value::Null, Value::String),
            ),
            (
                "given_name",
                profile.given_name.map_or(Value::Null, Value::String),
            ),
            (
                "family_name",
                profile.family_name.map_or(Value::Null, Value::String),
            ),
        ] {
            claims.insert(name.to_owned(), value);
        }
        Ok(VerifiedExternalIdentity {
            provider_type: "oidc".to_owned(),
            provider_id: provider_id.to_owned(),
            subject: profile.sub,
            email,
            display_name: profile.name,
            claims: Value::Object(claims),
        })
    }
}

pub fn authorization_url(
    endpoint: &str,
    client_id: &str,
    redirect_uri: &str,
    scopes: &str,
    start: &OidcFederationStart,
) -> String {
    let mut url = url::Url::parse(endpoint).expect("validated federation endpoint");
    url.query_pairs_mut()
        .append_pair("response_type", "code")
        .append_pair("client_id", client_id)
        .append_pair("redirect_uri", redirect_uri)
        .append_pair("scope", scopes)
        .append_pair("state", &start.state)
        .append_pair("nonce", &start.nonce)
        .append_pair("code_challenge_method", "S256")
        .append_pair(
            "code_challenge",
            &nazo_crypto::pkce_s256(&start.pkce_verifier),
        );
    url.into()
}

pub fn verify_id_token(
    issuer: &str,
    client_id: &str,
    jwks: &Value,
    token: &str,
    expected_nonce: &str,
) -> Result<OidcIdTokenClaims, OidcError> {
    verify_id_token_with_algorithm(issuer, client_id, jwks, token, expected_nonce, None)
}

pub fn verify_id_token_with_algorithm(
    issuer: &str,
    client_id: &str,
    jwks: &Value,
    token: &str,
    expected_nonce: &str,
    expected_algorithm: Option<jwt::Algorithm>,
) -> Result<OidcIdTokenClaims, OidcError> {
    let (header, key) = signing_key(jwks, token, expected_algorithm, OidcError::InvalidIdToken)?;
    let mut validation = jwt::Validation::new(header.alg);
    validation.set_issuer(&[issuer]);
    validation.set_audience(&[client_id]);
    validation.set_required_spec_claims(&["exp", "aud"]);
    validation.leeway = 0;
    validation.reject_tokens_expiring_in_less_than = 1;
    let claims = jwt::decode::<OidcIdTokenClaims>(token, &key, &validation)
        .map_err(|_| OidcError::InvalidIdToken)?
        .claims;
    if !valid_oidc_subject(&claims.sub)
        || claims.nonce.as_deref() != Some(expected_nonce)
        || has_untrusted_audience(&claims.aud, client_id)
        || claims.iat > Timestamp::now().as_second() + 60
    {
        return Err(OidcError::InvalidIdToken);
    }
    Ok(claims)
}

fn has_untrusted_audience(audience: &Value, client_id: &str) -> bool {
    // JWT validation requires this client to be present. No other client is
    // configured as trusted by this RP; azp cannot grant that trust.
    audience
        .as_array()
        .is_some_and(|values| values.iter().any(|value| value.as_str() != Some(client_id)))
}

fn nonce_present<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<bool, D::Error> {
    serde::de::IgnoredAny::deserialize(deserializer)?;
    Ok(true)
}

fn signing_key(
    jwks: &Value,
    token: &str,
    expected_algorithm: Option<jwt::Algorithm>,
    error: OidcError,
) -> Result<(jwt::Header, jwt::VerificationKey), OidcError> {
    let header = jwt::decode_header(token).map_err(|_| error)?;
    if expected_algorithm.is_some_and(|algorithm| header.alg != algorithm)
        || !matches!(
            header.alg,
            jwt::Algorithm::RS256
                | jwt::Algorithm::PS256
                | jwt::Algorithm::ES256
                | jwt::Algorithm::EdDSA
        )
    {
        return Err(error);
    }
    let key = if let Some(kid) = header.kid.as_deref() {
        jwt_decoding_key_from_jwks(jwks, kid, header.alg).ok_or(error)?
    } else {
        let keys = jwks.get("keys").and_then(Value::as_array).ok_or(error)?;
        let mut matching = keys
            .iter()
            .filter_map(|key| jwt_decoding_key_from_jwk(key, header.alg));
        let key = matching.next().ok_or(error)?;
        if matching.next().is_some() {
            return Err(error);
        }
        key
    };
    Ok((header, key))
}

pub fn verify_logout_token(
    tenant_id: crate::TenantId,
    provider: &str,
    issuer: &str,
    client_id: &str,
    jwks: &Value,
    token: &str,
    now: Timestamp,
) -> Result<OidcLogout, OidcError> {
    verify_logout_token_with_algorithm(
        tenant_id, provider, issuer, client_id, jwks, token, now, None,
    )
}

pub fn verify_logout_token_with_algorithm(
    tenant_id: crate::TenantId,
    provider: &str,
    issuer: &str,
    client_id: &str,
    jwks: &Value,
    token: &str,
    now: Timestamp,
    expected_algorithm: Option<jwt::Algorithm>,
) -> Result<OidcLogout, OidcError> {
    #[derive(Deserialize)]
    struct Claims {
        iss: String,
        sub: Option<String>,
        sid: Option<String>,
        aud: Value,
        iat: i64,
        jti: String,
        events: Value,
        #[serde(default, deserialize_with = "nonce_present")]
        nonce: bool,
    }
    let error = OidcError::InvalidLogoutToken;
    let (header, key) = signing_key(jwks, token, expected_algorithm, error)?;
    if header.typ.as_deref().is_some_and(|typ| {
        ![
            "logout+jwt",
            "application/logout+jwt",
            "jwt",
            "application/jwt",
        ]
        .iter()
        .any(|known| typ.eq_ignore_ascii_case(known))
    }) {
        return Err(error);
    }
    let mut validation = jwt::Validation::new(header.alg);
    validation.set_issuer(&[issuer]);
    validation.set_audience(&[client_id]);
    validation.set_required_spec_claims(&["exp", "aud"]);
    validation.leeway = 0;
    validation.reject_tokens_expiring_in_less_than = 1;
    let claims = jwt::decode::<Claims>(token, &key, &validation)
        .map_err(|_| error)?
        .claims;
    let time = now.as_second();
    if has_untrusted_audience(&claims.aud, client_id)
        || claims.iat > time.saturating_add(60)
        || claims.iat < time.saturating_sub(300)
        || claims.jti.is_empty()
        || claims.nonce
        || !claims
            .events
            .get("http://schemas.openid.net/event/backchannel-logout")
            .is_some_and(Value::is_object)
        || claims
            .sub
            .as_deref()
            .is_some_and(|sub| !valid_oidc_subject(sub))
        || claims
            .sid
            .as_deref()
            .is_some_and(|sid| !valid_session_id(sid))
    {
        return Err(error);
    }
    let (kind, value) = claims
        .sid
        .as_deref()
        .map(|sid| ("sid", sid))
        .or_else(|| claims.sub.as_deref().map(|sub| ("sub", sub)))
        .ok_or(error)?;
    Ok(OidcLogout {
        key: scope_key(tenant_id, provider, &claims.iss, client_id, kind, value),
        // A sid identifies one upstream session. Subject logout covers every
        // login started by local receipt time, independently of the OP's clock.
        cutoff: if kind == "sid" { i64::MAX } else { time },
    })
}
