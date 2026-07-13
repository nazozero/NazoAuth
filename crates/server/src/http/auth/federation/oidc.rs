use serde::Serialize;

use crate::http::prelude::*;
use crate::settings::OidcFederationSettings;

pub(super) const FEDERATION_STATE_TTL_SECONDS: u64 = 300;

#[derive(Serialize, Deserialize)]
pub(super) struct OidcFederationState {
    pub(super) nonce: String,
    pub(super) pkce_verifier: String,
    pub(super) created_at: i64,
}

#[derive(Deserialize)]
pub(crate) struct OidcCallbackQuery {
    pub(super) code: Option<String>,
    pub(super) state: Option<String>,
    pub(super) error: Option<String>,
}

#[derive(Deserialize)]
pub(super) struct OidcTokenResponse {
    pub(super) id_token: String,
}

#[derive(Deserialize)]
pub(super) struct OidcIdTokenClaims {
    pub(super) iss: String,
    pub(super) sub: String,
    pub(super) aud: Value,
    pub(super) exp: i64,
    pub(super) iat: Option<i64>,
    pub(super) nonce: Option<String>,
    pub(super) email: Option<String>,
    pub(super) email_verified: Option<bool>,
    pub(super) name: Option<String>,
    pub(super) given_name: Option<String>,
    pub(super) family_name: Option<String>,
}

pub(super) fn oidc_authorization_url(
    provider: &OidcFederationSettings,
    state: &str,
    nonce: &str,
    verifier: &str,
) -> String {
    let mut serializer = url::form_urlencoded::Serializer::new(String::new());
    serializer
        .append_pair("response_type", "code")
        .append_pair("client_id", &provider.client_id)
        .append_pair("redirect_uri", &provider.redirect_uri)
        .append_pair("scope", &provider.scopes)
        .append_pair("state", state)
        .append_pair("nonce", nonce)
        .append_pair("code_challenge_method", "S256")
        .append_pair("code_challenge", &pkce_s256(verifier));
    format!(
        "{}?{}",
        provider.authorization_endpoint,
        serializer.finish()
    )
}

#[cfg(test)]
pub(super) fn oidc_state_key(state: &str) -> String {
    format!("oauth:federation:oidc:state:{}", blake3_hex(state))
}

pub(super) async fn exchange_oidc_code(
    provider: &OidcFederationSettings,
    code: &str,
    verifier: &str,
) -> anyhow::Result<OidcTokenResponse> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()?;
    let body = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("grant_type", "authorization_code")
        .append_pair("code", code)
        .append_pair("redirect_uri", &provider.redirect_uri)
        .append_pair("code_verifier", verifier)
        .finish();
    let response = client
        .post(&provider.token_endpoint)
        .basic_auth(&provider.client_id, Some(&provider.client_secret))
        .header(
            reqwest::header::CONTENT_TYPE,
            "application/x-www-form-urlencoded",
        )
        .body(body)
        .send()
        .await?
        .error_for_status()?;
    Ok(response.json::<OidcTokenResponse>().await?)
}

pub(super) async fn fetch_oidc_jwks(provider: &OidcFederationSettings) -> anyhow::Result<Value> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()?;
    let value = client
        .get(&provider.jwks_url)
        .send()
        .await?
        .error_for_status()?
        .json::<Value>()
        .await?;
    if value.get("keys").and_then(Value::as_array).is_none() {
        anyhow::bail!("OIDC JWKS does not contain keys array");
    }
    Ok(value)
}

pub(super) fn verify_oidc_id_token(
    provider: &OidcFederationSettings,
    jwks: &Value,
    token: &str,
    expected_nonce: &str,
) -> anyhow::Result<OidcIdTokenClaims> {
    let header = jsonwebtoken::decode_header(token)?;
    let kid = header
        .kid
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("missing kid"))?;
    let keys = jwks
        .get("keys")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow::anyhow!("missing keys"))?;
    let key = keys
        .iter()
        .find(|key| key.get("kid").and_then(Value::as_str) == Some(kid))
        .ok_or_else(|| anyhow::anyhow!("kid not found"))?;
    let decoding_key = jwt_decoding_key_from_jwk(key, header.alg)
        .ok_or_else(|| anyhow::anyhow!("unsupported OIDC JWK"))?;
    let mut validation = jsonwebtoken::Validation::new(header.alg);
    validation.set_issuer(&[provider.issuer.as_str()]);
    validation.set_audience(&[provider.client_id.as_str()]);
    let token = jsonwebtoken::decode::<OidcIdTokenClaims>(token, &decoding_key, &validation)?;
    let claims = token.claims;
    if claims.nonce.as_deref() != Some(expected_nonce)
        || !audience_contains(&claims.aud, &provider.client_id)
        || claims.exp <= Utc::now().timestamp()
        || claims
            .iat
            .is_some_and(|iat| iat > Utc::now().timestamp().saturating_add(60))
    {
        anyhow::bail!("OIDC ID Token claims failed policy");
    }
    Ok(claims)
}

fn audience_contains(aud: &Value, client_id: &str) -> bool {
    match aud {
        Value::String(value) => value == client_id,
        Value::Array(values) => values.iter().any(|value| value.as_str() == Some(client_id)),
        _ => false,
    }
}

#[cfg(test)]
#[path = "../../../../tests/in_source/src/http/auth/tests/federation_oidc.rs"]
mod tests;
