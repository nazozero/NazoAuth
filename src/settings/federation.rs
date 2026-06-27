use anyhow::bail;

use crate::{config::ConfigSource, support::validate_issuer_url};

#[derive(Clone)]
pub(crate) struct FederationSettings {
    pub(crate) oidc: Option<OidcFederationSettings>,
    pub(crate) saml_gateway: Option<SamlGatewaySettings>,
}

#[derive(Clone)]
pub(crate) struct OidcFederationSettings {
    pub(crate) provider_id: String,
    pub(crate) issuer: String,
    pub(crate) authorization_endpoint: String,
    pub(crate) token_endpoint: String,
    pub(crate) jwks_url: String,
    pub(crate) client_id: String,
    pub(crate) client_secret: String,
    pub(crate) redirect_uri: String,
    pub(crate) scopes: String,
}

#[derive(Clone)]
pub(crate) struct SamlGatewaySettings {
    pub(crate) issuer: String,
    pub(crate) audience: String,
    pub(crate) secret: String,
}

impl FederationSettings {
    pub(super) fn from_config(config: &ConfigSource) -> anyhow::Result<Self> {
        let oidc = OidcFederationSettings::from_config(config)?;
        let saml_gateway = SamlGatewaySettings::from_config(config)?;
        Ok(Self { oidc, saml_gateway })
    }
}

impl OidcFederationSettings {
    fn from_config(config: &ConfigSource) -> anyhow::Result<Option<Self>> {
        let provider_id = config.optional_string("FEDERATION_OIDC_PROVIDER_ID");
        let issuer = config.optional_string("FEDERATION_OIDC_ISSUER");
        let authorization_endpoint =
            config.optional_string("FEDERATION_OIDC_AUTHORIZATION_ENDPOINT");
        let token_endpoint = config.optional_string("FEDERATION_OIDC_TOKEN_ENDPOINT");
        let jwks_url = config.optional_string("FEDERATION_OIDC_JWKS_URL");
        let client_id = config.optional_string("FEDERATION_OIDC_CLIENT_ID");
        let client_secret = config.optional_string("FEDERATION_OIDC_CLIENT_SECRET");
        let redirect_uri = config.optional_string("FEDERATION_OIDC_REDIRECT_URI");
        let any = [
            &provider_id,
            &issuer,
            &authorization_endpoint,
            &token_endpoint,
            &jwks_url,
            &client_id,
            &client_secret,
            &redirect_uri,
        ]
        .iter()
        .any(|value| {
            value
                .as_deref()
                .is_some_and(|value| !value.trim().is_empty())
        });
        if !any {
            return Ok(None);
        }
        let settings = Self {
            provider_id: required_optional(provider_id, "FEDERATION_OIDC_PROVIDER_ID")?,
            issuer: required_optional(issuer, "FEDERATION_OIDC_ISSUER")?,
            authorization_endpoint: required_optional(
                authorization_endpoint,
                "FEDERATION_OIDC_AUTHORIZATION_ENDPOINT",
            )?,
            token_endpoint: required_optional(token_endpoint, "FEDERATION_OIDC_TOKEN_ENDPOINT")?,
            jwks_url: required_optional(jwks_url, "FEDERATION_OIDC_JWKS_URL")?,
            client_id: required_optional(client_id, "FEDERATION_OIDC_CLIENT_ID")?,
            client_secret: required_optional(client_secret, "FEDERATION_OIDC_CLIENT_SECRET")?,
            redirect_uri: required_optional(redirect_uri, "FEDERATION_OIDC_REDIRECT_URI")?,
            scopes: config.string("FEDERATION_OIDC_SCOPES", "openid email profile"),
        };
        validate_issuer_url(&settings.issuer)?;
        validate_issuer_url(&settings.authorization_endpoint)?;
        validate_issuer_url(&settings.token_endpoint)?;
        validate_issuer_url(&settings.jwks_url)?;
        validate_issuer_url(&settings.redirect_uri)?;
        if !settings
            .scopes
            .split_whitespace()
            .any(|scope| scope == "openid")
        {
            bail!("FEDERATION_OIDC_SCOPES must include openid");
        }
        Ok(Some(settings))
    }
}

impl SamlGatewaySettings {
    fn from_config(config: &ConfigSource) -> anyhow::Result<Option<Self>> {
        if !config.bool("FEDERATION_SAML_GATEWAY_ENABLED", false)? {
            return Ok(None);
        }
        let settings = Self {
            issuer: config.required_string("FEDERATION_SAML_GATEWAY_ISSUER")?,
            audience: config.required_string("FEDERATION_SAML_GATEWAY_AUDIENCE")?,
            secret: config.required_string("FEDERATION_SAML_GATEWAY_SECRET")?,
        };
        if settings.secret.len() < 32 {
            bail!("FEDERATION_SAML_GATEWAY_SECRET must be at least 32 bytes");
        }
        Ok(Some(settings))
    }
}

fn required_optional(value: Option<String>, key: &str) -> anyhow::Result<String> {
    value
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
        .ok_or_else(|| anyhow::anyhow!("{} is required when OIDC federation is configured", key))
}
