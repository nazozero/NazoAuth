mod providers;
pub use providers::{
    ExternalLoginProvider, ExternalLoginProviderAdapter, FederationProviderRegistry,
    SocialProviderKind, SocialProviderSettings,
};

#[derive(Clone)]
pub struct FederationSettings {
    pub providers: FederationProviderRegistry,
    pub saml_gateway: Option<SamlGatewaySettings>,
}

#[derive(Clone)]
pub struct OidcFederationSettings {
    pub provider_id: String,
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub jwks_url: String,
    pub userinfo_endpoint: Option<String>,
    pub client_id: String,
    pub client_secret: String,
    pub redirect_uri: String,
    pub scopes: String,
}

#[derive(Clone)]
pub struct SamlGatewaySettings {
    pub issuer: String,
    pub audience: String,
    pub secret: String,
}
