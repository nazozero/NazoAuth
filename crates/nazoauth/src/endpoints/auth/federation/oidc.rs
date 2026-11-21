use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use nazo_identity::federation::oidc::{
    OidcProviderMetadata, OidcTokenResponse, OidcUserInfo, discovery_url,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::config::OidcFederationSettings;

#[derive(Deserialize)]
pub struct OidcCallbackQuery {
    pub code: Option<String>,
    pub state: Option<String>,
    pub error: Option<String>,
}

#[derive(Deserialize, Serialize)]
pub(super) struct UpstreamLogoutRequest {
    pub endpoint: String,
    pub id_token_hint: String,
}

impl UpstreamLogoutRequest {
    pub fn seal(&self, provider: &OidcFederationSettings, subject_key: &str) -> Option<String> {
        let key = logout_key(provider);
        let nonce = rand::random::<[u8; 12]>();
        let encoded = serde_json::to_vec(self).ok()?;
        let sealed = nazo_crypto::aead::encrypt_prefixed(
            &key,
            &nonce,
            subject_key.as_bytes(),
            &encoded,
            &nonce,
        )
        .ok()?;
        Some(URL_SAFE_NO_PAD.encode(sealed))
    }

    pub fn open(
        ciphertext: &str,
        provider: &OidcFederationSettings,
        subject_key: &str,
    ) -> Option<Self> {
        let key = logout_key(provider);
        let mut sealed = URL_SAFE_NO_PAD.decode(ciphertext).ok()?;
        let decoded =
            nazo_crypto::aead::decrypt_nonce_prefixed(&key, subject_key.as_bytes(), &mut sealed)
                .ok()?;
        serde_json::from_slice(decoded).ok()
    }
}

fn logout_key(provider: &OidcFederationSettings) -> [u8; 32] {
    let mut hasher =
        blake3::Hasher::new_derive_key("NazoAuth upstream OIDC logout hint encryption v1");
    for field in [
        &provider.provider_id,
        &provider.issuer,
        &provider.client_id,
        &provider.client_secret,
    ] {
        hasher.update(&(field.len() as u64).to_be_bytes());
        hasher.update(field.as_bytes());
    }
    *hasher.finalize().as_bytes()
}

pub async fn discover_oidc(
    client: &dyn super::FederationHttpClient,
    provider: &OidcFederationSettings,
) -> anyhow::Result<OidcProviderMetadata> {
    let url = discovery_url(&provider.issuer)
        .ok_or_else(|| anyhow::anyhow!("invalid discovery issuer"))?;
    let response = client
        .send_discovered(
            http::Request::get(url).body(bytes::Bytes::new())?,
            super::MAX_FEDERATION_PROVIDER_RESPONSE_BYTES,
        )
        .await?;
    let metadata = super::federation_json_response::<OidcProviderMetadata>(response)?;
    anyhow::ensure!(
        metadata.validate(&provider.issuer)
            && metadata.supports_signing_algorithm(provider.signing_algorithm()),
        "invalid OIDC discovery metadata"
    );
    Ok(metadata)
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
    token_endpoint: &str,
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
    let request = http::Request::post(token_endpoint)
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
    endpoint: &str,
    discovered: bool,
) -> anyhow::Result<Value> {
    let response = send(
        client,
        http::Request::get(endpoint).body(bytes::Bytes::new())?,
        discovered,
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
