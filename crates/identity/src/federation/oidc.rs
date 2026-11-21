//! OIDC relying-party request, ID Token and upstream identity semantics.

use jiff::Timestamp;
use nazo_crypto::{
    jwk::{jwt_decoding_key_from_jwk, jwt_decoding_key_from_jwks},
    jwt,
};
use serde::Deserialize;
use serde_json::{Value, json};

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
            Self::InvalidTokenResponse => "OIDC UserInfo requires a Bearer access token",
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
    pub response_types_supported: Vec<String>,
    pub token_endpoint_auth_methods_supported: Option<Vec<String>>,
}

fn https_endpoint(value: &str) -> Option<url::Url> {
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
}

#[derive(Deserialize)]
pub struct OidcTokenResponse {
    pub id_token: String,
    access_token: Option<String>,
    token_type: Option<String>,
}

impl OidcTokenResponse {
    pub fn userinfo_access_token(&self) -> Result<&str, OidcError> {
        if !self
            .token_type
            .as_deref()
            .is_some_and(|kind| kind.eq_ignore_ascii_case("Bearer"))
        {
            return Err(OidcError::InvalidTokenResponse);
        }
        self.access_token
            .as_deref()
            .filter(|token| !token.is_empty())
            .ok_or(OidcError::InvalidTokenResponse)
    }
}

#[derive(Deserialize)]
pub struct OidcIdTokenClaims {
    iss: String,
    sub: String,
    aud: Value,
    azp: Option<String>,
    iat: i64,
    nonce: Option<String>,
    sid: Option<String>,
    #[serde(flatten)]
    profile: OidcProfile,
}

#[derive(Deserialize)]
pub struct OidcUserInfo {
    sub: String,
    #[serde(flatten)]
    profile: OidcProfile,
}

#[derive(Deserialize)]
struct OidcProfile {
    email: Option<String>,
    email_verified: Option<bool>,
    name: Option<String>,
    given_name: Option<String>,
    family_name: Option<String>,
}

pub struct OidcUpstreamLogin {
    pub(super) subject_key: String,
    pub(super) sid_key: Option<String>,
    pub(super) issued_at: i64,
}

pub struct OidcLogout {
    pub(super) key: String,
    pub(super) issued_at: i64,
}

fn scope_key(provider: &str, issuer: &str, client_id: &str, kind: &str, value: &str) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"NazoAuth/oidc-logout/v1\0");
    for component in [provider, issuer, client_id, kind, value] {
        hasher.update(&(component.len() as u64).to_be_bytes());
        hasher.update(component.as_bytes());
    }
    hasher.finalize().to_hex().to_string()
}

fn valid_oidc_subject(subject: &str) -> bool {
    !subject.is_empty() && subject.len() <= 255 && subject.is_ascii()
}

fn valid_opaque_id(value: &str) -> bool {
    !value.is_empty() && value.len() <= 1024 && !value.chars().any(char::is_control)
}

impl OidcIdTokenClaims {
    pub fn upstream_login(
        &self,
        provider: &str,
        client_id: &str,
        started_at: i64,
    ) -> Result<OidcUpstreamLogin, OidcError> {
        if self.iat < started_at.saturating_sub(60)
            || self.sid.as_deref().is_some_and(|sid| !valid_opaque_id(sid))
        {
            return Err(OidcError::InvalidIdToken);
        }
        Ok(OidcUpstreamLogin {
            subject_key: scope_key(provider, &self.iss, client_id, "sub", &self.sub),
            sid_key: self
                .sid
                .as_deref()
                .map(|sid| scope_key(provider, &self.iss, client_id, "sid", sid)),
            issued_at: self.iat,
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
                userinfo.profile
            }
            None => self.profile,
        };
        // Subject identifies an existing link. Only a verified, valid email may
        // be offered to the identity service for provisioning a new account.
        let email = profile
            .email
            .as_deref()
            .filter(|_| profile.email_verified == Some(true))
            .and_then(|value| normalize_email_address(value).ok());
        Ok(VerifiedExternalIdentity {
            provider_type: "oidc".to_owned(),
            provider_id: provider_id.to_owned(),
            subject: self.sub.clone(),
            email: email.clone(),
            display_name: profile.name.clone(),
            claims: json!({
                "iss": self.iss,
                "sub": self.sub,
                "email": email,
                "name": profile.name,
                "given_name": profile.given_name,
                "family_name": profile.family_name,
            }),
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
    let (header, key) = signing_key(jwks, token, OidcError::InvalidIdToken)?;
    let mut validation = jwt::Validation::new(header.alg);
    validation.set_issuer(&[issuer]);
    validation.set_audience(&[client_id]);
    validation.set_required_spec_claims(&["exp", "aud"]);
    validation.leeway = 0;
    validation.reject_tokens_expiring_in_less_than = 1;
    let claims = jwt::decode::<OidcIdTokenClaims>(token, &key, &validation)
        .map_err(|_| OidcError::InvalidIdToken)?
        .claims;
    let audience_count = claims.aud.as_array().map_or(1, Vec::len);
    if !valid_oidc_subject(&claims.sub)
        || claims.nonce.as_deref() != Some(expected_nonce)
        || (audience_count > 1 && claims.azp.as_deref() != Some(client_id))
        || claims.iat > Timestamp::now().as_second() + 60
    {
        return Err(OidcError::InvalidIdToken);
    }
    Ok(claims)
}

fn signing_key(
    jwks: &Value,
    token: &str,
    error: OidcError,
) -> Result<(jwt::Header, jwt::VerificationKey), OidcError> {
    let header = jwt::decode_header(token).map_err(|_| error)?;
    if !matches!(
        header.alg,
        jwt::Algorithm::RS256
            | jwt::Algorithm::PS256
            | jwt::Algorithm::ES256
            | jwt::Algorithm::EdDSA
    ) {
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
    provider: &str,
    issuer: &str,
    client_id: &str,
    jwks: &Value,
    token: &str,
    now: Timestamp,
) -> Result<OidcLogout, OidcError> {
    #[derive(Deserialize)]
    struct Claims {
        sub: Option<String>,
        sid: Option<String>,
        aud: Value,
        azp: Option<String>,
        iat: i64,
        jti: String,
        events: Value,
        #[serde(flatten)]
        extra: serde_json::Map<String, Value>,
    }
    let error = OidcError::InvalidLogoutToken;
    let (header, key) = signing_key(jwks, token, error)?;
    if header.typ.as_deref().is_some_and(|typ| {
        !typ.eq_ignore_ascii_case("logout+jwt") && !typ.eq_ignore_ascii_case("jwt")
    }) {
        return Err(error);
    }
    let mut validation = jwt::Validation::new(header.alg);
    validation.set_issuer(&[issuer]);
    validation.set_audience(&[client_id]);
    validation.set_required_spec_claims(&["exp", "aud", "iss"]);
    validation.leeway = 0;
    let claims = jwt::decode::<Claims>(token, &key, &validation)
        .map_err(|_| error)?
        .claims;
    let time = now.as_second();
    let audience_count = claims.aud.as_array().map_or(1, Vec::len);
    if (audience_count > 1 && claims.azp.as_deref() != Some(client_id))
        || claims.iat > time.saturating_add(60)
        || claims.iat < time.saturating_sub(300)
        || !valid_opaque_id(&claims.jti)
        || claims.extra.contains_key("nonce")
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
            .is_some_and(|sid| !valid_opaque_id(sid))
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
        key: scope_key(provider, issuer, client_id, kind, value),
        issued_at: claims.iat,
    })
}
