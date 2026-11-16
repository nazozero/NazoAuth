use chrono::Utc;
use nazo_auth::jwt_decoding_key_from_jwks;
use nazo_oauth_server::crypto::pkce_s256;
use serde::Deserialize;
use serde_json::Value;

use crate::config::OidcFederationSettings;

#[derive(Deserialize)]
pub struct OidcCallbackQuery {
    pub code: Option<String>,
    pub state: Option<String>,
    pub error: Option<String>,
}

#[derive(Deserialize)]
pub struct OidcTokenResponse {
    pub id_token: String,
}

#[derive(Deserialize)]
pub struct OidcIdTokenClaims {
    pub iss: String,
    pub sub: String,
    pub aud: Value,
    pub azp: Option<String>,
    pub iat: i64,
    pub nonce: Option<String>,
    pub email: Option<String>,
    pub email_verified: Option<bool>,
    pub name: Option<String>,
    pub given_name: Option<String>,
    pub family_name: Option<String>,
}

pub fn oidc_authorization_url(
    provider: &OidcFederationSettings,
    state: &str,
    nonce: &str,
    verifier: &str,
) -> String {
    let mut url =
        url::Url::parse(&provider.authorization_endpoint).expect("validated federation endpoint");
    url.query_pairs_mut()
        .append_pair("response_type", "code")
        .append_pair("client_id", &provider.client_id)
        .append_pair("redirect_uri", &provider.redirect_uri)
        .append_pair("scope", &provider.scopes)
        .append_pair("state", state)
        .append_pair("nonce", nonce)
        .append_pair("code_challenge_method", "S256")
        .append_pair("code_challenge", &pkce_s256(verifier));
    url.into()
}

pub async fn exchange_oidc_code(
    client: &dyn super::FederationHttpClient,
    provider: &OidcFederationSettings,
    code: &str,
    verifier: &str,
) -> anyhow::Result<OidcTokenResponse> {
    let body = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("grant_type", "authorization_code")
        .append_pair("code", code)
        .append_pair("redirect_uri", &provider.redirect_uri)
        .append_pair("code_verifier", verifier)
        .finish();
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    let credentials = format!(
        "{}:{}",
        url::form_urlencoded::byte_serialize(provider.client_id.as_bytes()).collect::<String>(),
        url::form_urlencoded::byte_serialize(provider.client_secret.as_bytes()).collect::<String>()
    );
    let request = http::Request::post(&provider.token_endpoint)
        .header(
            http::header::AUTHORIZATION,
            format!("Basic {}", STANDARD.encode(credentials)),
        )
        .header(
            http::header::CONTENT_TYPE,
            "application/x-www-form-urlencoded",
        )
        .body(bytes::Bytes::from(body))?;
    super::federation_json_response(super::send(client, request).await?)
}

pub async fn fetch_oidc_jwks(
    client: &dyn super::FederationHttpClient,
    provider: &OidcFederationSettings,
) -> anyhow::Result<Value> {
    let response = super::send(
        client,
        http::Request::get(&provider.jwks_url).body(bytes::Bytes::new())?,
    )
    .await?;
    let value = super::federation_json_response::<Value>(response)?;
    if value.get("keys").and_then(Value::as_array).is_none() {
        anyhow::bail!("OIDC JWKS does not contain keys array");
    }
    Ok(value)
}

pub fn verify_oidc_id_token(
    provider: &OidcFederationSettings,
    jwks: &Value,
    token: &str,
    expected_nonce: &str,
) -> anyhow::Result<OidcIdTokenClaims> {
    let header = nazo_crypto::jwt::decode_header(token)?;
    if !matches!(
        header.alg,
        nazo_crypto::jwt::Algorithm::RS256
            | nazo_crypto::jwt::Algorithm::PS256
            | nazo_crypto::jwt::Algorithm::ES256
            | nazo_crypto::jwt::Algorithm::EdDSA
    ) {
        anyhow::bail!("OIDC ID Token algorithm is not allowed");
    }
    let kid = header
        .kid
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("missing kid"))?;
    let decoding_key = jwt_decoding_key_from_jwks(jwks, kid, header.alg)
        .ok_or_else(|| anyhow::anyhow!("no unique usable OIDC verification key for kid"))?;
    let mut validation = nazo_crypto::jwt::Validation::new(header.alg);
    validation.set_issuer(&[provider.issuer.as_str()]);
    validation.set_audience(&[provider.client_id.as_str()]);
    validation.set_required_spec_claims(&["exp", "aud"]);
    validation.leeway = 0;
    // Keep the existing strict expiry policy: exp must be later than now.
    validation.reject_tokens_expiring_in_less_than = 1;
    let token = nazo_crypto::jwt::decode::<OidcIdTokenClaims>(token, &decoding_key, &validation)?;
    let claims = token.claims;
    let audience_count = claims.aud.as_array().map_or(1, Vec::len);
    if claims.nonce.as_deref() != Some(expected_nonce)
        || (audience_count > 1 && claims.azp.as_deref() != Some(&provider.client_id))
        || claims.iat > Utc::now().timestamp() + 60
    {
        anyhow::bail!("OIDC ID Token claims failed policy");
    }
    Ok(claims)
}
