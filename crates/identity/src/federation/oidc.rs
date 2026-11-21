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
    InvalidUserInfo,
    InvalidTokenResponse,
}

impl std::fmt::Display for OidcError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::InvalidIdToken => "OIDC ID Token validation failed",
            Self::InvalidUserInfo => "OIDC UserInfo subject does not match the ID Token",
            Self::InvalidTokenResponse => "OIDC UserInfo requires a Bearer access token",
        })
    }
}

impl std::error::Error for OidcError {}

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

impl OidcIdTokenClaims {
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
    let header = jwt::decode_header(token).map_err(|_| OidcError::InvalidIdToken)?;
    if !matches!(
        header.alg,
        jwt::Algorithm::RS256
            | jwt::Algorithm::PS256
            | jwt::Algorithm::ES256
            | jwt::Algorithm::EdDSA
    ) {
        return Err(OidcError::InvalidIdToken);
    }
    let key = if let Some(kid) = header.kid.as_deref() {
        jwt_decoding_key_from_jwks(jwks, kid, header.alg).ok_or(OidcError::InvalidIdToken)?
    } else {
        let keys = jwks
            .get("keys")
            .and_then(Value::as_array)
            .ok_or(OidcError::InvalidIdToken)?;
        let mut matching = keys
            .iter()
            .filter_map(|key| jwt_decoding_key_from_jwk(key, header.alg));
        let key = matching.next().ok_or(OidcError::InvalidIdToken)?;
        if matching.next().is_some() {
            return Err(OidcError::InvalidIdToken);
        }
        key
    };
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
    if claims.sub.is_empty()
        || claims.sub.len() > 255
        || !claims.sub.is_ascii()
        || claims.nonce.as_deref() != Some(expected_nonce)
        || (audience_count > 1 && claims.azp.as_deref() != Some(client_id))
        || claims.iat > Timestamp::now().as_second() + 60
    {
        return Err(OidcError::InvalidIdToken);
    }
    Ok(claims)
}
