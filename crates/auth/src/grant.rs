#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GrantType {
    AuthorizationCode,
    RefreshToken,
    ClientCredentials,
    DeviceCode,
    TokenExchange,
    JwtBearer,
    Ciba,
}

impl GrantType {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AuthorizationCode => "authorization_code",
            Self::RefreshToken => "refresh_token",
            Self::ClientCredentials => "client_credentials",
            Self::DeviceCode => "urn:ietf:params:oauth:grant-type:device_code",
            Self::TokenExchange => "urn:ietf:params:oauth:grant-type:token-exchange",
            Self::JwtBearer => "urn:ietf:params:oauth:grant-type:jwt-bearer",
            Self::Ciba => "urn:openid:params:grant-type:ciba",
        }
    }
}
