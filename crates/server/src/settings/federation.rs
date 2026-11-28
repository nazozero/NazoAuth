use crate::config::ConfigSource;
use nazoauth::config::federation::{
    ExternalLoginProviderAdapter, FederationProviderRegistry, FederationSettings,
    SamlGatewaySettings,
};

pub(super) fn from_config(
    config: &ConfigSource,
    tenant: Option<(&str, &str)>,
) -> anyhow::Result<FederationSettings> {
    let mut providers = config
        .get("FEDERATION_PROVIDER_CONFIGS")
        .map(str::trim)
        .filter(|raw| !raw.is_empty())
        .map(FederationProviderRegistry::from_json)
        .transpose()?
        .unwrap_or_default();
    if let Some((issuer, origin)) = tenant {
        let mut entries = providers.into_providers();
        for provider in &mut entries {
            let redirect_uri = match &mut provider.adapter {
                ExternalLoginProviderAdapter::Oidc(settings) => {
                    if let Some(post_logout) = &mut settings.post_logout_redirect_uri {
                        *post_logout =
                            super::config_loader::tenant_endpoint_origin(post_logout, origin);
                    }
                    &mut settings.redirect_uri
                }
                ExternalLoginProviderAdapter::Social(settings) => &mut settings.redirect_uri,
            };
            // The directory owns the host and mount prefix. Preserve configured
            // query bytes: upstream authorization and token requests must use
            // exactly the same registered callback.
            let query = redirect_uri
                .find('?')
                .map_or("", |offset| &redirect_uri[offset..]);
            *redirect_uri = format!(
                "{issuer}/auth/federation/{}/callback{query}",
                provider.provider_id
            );
        }
        providers = FederationProviderRegistry::new(entries)?;
    }
    let saml_gateway = if config.bool("FEDERATION_SAML_GATEWAY_ENABLED", false)? {
        let settings = SamlGatewaySettings {
            issuer: config.required_string("FEDERATION_SAML_GATEWAY_ISSUER")?,
            audience: config.required_string("FEDERATION_SAML_GATEWAY_AUDIENCE")?,
            secret: config.required_string("FEDERATION_SAML_GATEWAY_SECRET")?,
        };
        Some(settings)
    } else {
        None
    };
    Ok(FederationSettings {
        providers,
        saml_gateway,
    })
}
