use crate::config::ConfigSource;
use nazoauth::config::federation::{
    FederationProviderRegistry, FederationSettings, SamlGatewaySettings,
};

pub(super) fn from_config(config: &ConfigSource) -> anyhow::Result<FederationSettings> {
    let providers = config
        .get("FEDERATION_PROVIDER_CONFIGS")
        .map(str::trim)
        .filter(|raw| !raw.is_empty())
        .map(FederationProviderRegistry::from_json)
        .transpose()?
        .unwrap_or_default();
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
