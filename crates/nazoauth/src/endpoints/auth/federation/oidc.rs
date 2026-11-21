use nazo_identity::federation::oidc::{OidcTokenResponse, OidcUserInfo};
use serde::Deserialize;
use serde_json::Value;

use crate::config::OidcFederationSettings;

#[derive(Deserialize)]
pub struct OidcCallbackQuery {
    pub code: Option<String>,
    pub state: Option<String>,
    pub error: Option<String>,
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

pub async fn fetch_oidc_userinfo(
    client: &dyn super::FederationHttpClient,
    endpoint: &str,
    token: &OidcTokenResponse,
) -> anyhow::Result<OidcUserInfo> {
    let request = http::Request::get(endpoint)
        .header(
            http::header::AUTHORIZATION,
            format!("Bearer {}", token.userinfo_access_token()?),
        )
        .header(http::header::ACCEPT, "application/json")
        .body(bytes::Bytes::new())?;
    super::federation_json_response(super::send(client, request).await?)
}
