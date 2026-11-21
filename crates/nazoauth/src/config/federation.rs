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
    pub discovery: bool,
    pub backchannel_logout: bool,
    pub id_token_signed_response_alg: Option<nazo_crypto::jwt::Algorithm>,
    pub post_logout_redirect_uri: Option<String>,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub jwks_url: String,
    pub userinfo_endpoint: Option<String>,
    pub client_id: String,
    pub client_secret: String,
    pub redirect_uri: String,
    pub scopes: String,
}

impl OidcFederationSettings {
    pub fn signing_algorithm(&self) -> nazo_crypto::jwt::Algorithm {
        self.id_token_signed_response_alg
            .unwrap_or(nazo_crypto::jwt::Algorithm::RS256)
    }
}

#[derive(Clone)]
pub struct SamlGatewaySettings {
    pub issuer: String,
    pub audience: String,
    pub secret: String,
}
