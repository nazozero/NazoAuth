use nazo_identity::federation::oidc::{
    OidcProviderMetadata, OidcTokenResponse, OidcUserInfo, discovery_url,
};
use serde::Deserialize;
use serde_json::Value;

use crate::config::OidcFederationSettings;

#[derive(Deserialize)]
pub struct OidcCallbackQuery {
    pub code: Option<String>,
    pub state: Option<String>,
    pub error: Option<String>,
}

pub async fn discover_oidc(
    client: &dyn super::FederationHttpClient,
    issuer: &str,
) -> anyhow::Result<OidcProviderMetadata> {
    let url = discovery_url(issuer).ok_or_else(|| anyhow::anyhow!("invalid discovery issuer"))?;
    let response = client
        .send_discovered(
            http::Request::get(url).body(bytes::Bytes::new())?,
            super::MAX_FEDERATION_PROVIDER_RESPONSE_BYTES,
        )
        .await?;
    let metadata = super::federation_json_response::<OidcProviderMetadata>(response)?;
    anyhow::ensure!(metadata.validate(issuer), "invalid OIDC discovery metadata");
    Ok(metadata)
}

pub fn resolved_provider(
    provider: &OidcFederationSettings,
    metadata: OidcProviderMetadata,
) -> OidcFederationSettings {
    OidcFederationSettings {
        authorization_endpoint: metadata.authorization_endpoint,
        token_endpoint: metadata.token_endpoint,
        jwks_url: metadata.jwks_url,
        userinfo_endpoint: metadata.userinfo_endpoint,
        ..provider.clone()
    }
}

async fn send(
    client: &dyn super::FederationHttpClient,
    request: http::Request<bytes::Bytes>,
    discovered: bool,
) -> anyhow::Result<http::Response<bytes::Bytes>> {
    if discovered {
        client
            .send_discovered(request, super::MAX_FEDERATION_PROVIDER_RESPONSE_BYTES)
            .await
    } else {
        super::send(client, request).await
    }
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
    super::federation_json_response(send(client, request, provider.discovery).await?)
}

pub async fn fetch_oidc_jwks(
    client: &dyn super::FederationHttpClient,
    provider: &OidcFederationSettings,
) -> anyhow::Result<Value> {
    let response = send(
        client,
        http::Request::get(&provider.jwks_url).body(bytes::Bytes::new())?,
        provider.discovery,
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
    discovered: bool,
) -> anyhow::Result<OidcUserInfo> {
    let request = http::Request::get(endpoint)
        .header(
            http::header::AUTHORIZATION,
            format!("Bearer {}", token.userinfo_access_token()?),
        )
        .header(http::header::ACCEPT, "application/json")
        .body(bytes::Bytes::new())?;
    super::federation_json_response(send(client, request, discovered).await?)
}
