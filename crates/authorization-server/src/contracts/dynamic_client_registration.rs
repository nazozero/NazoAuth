use std::{future::Future, pin::Pin, sync::Arc};

use nazo_auth::{
    AdminClientCryptoPort, ClientSecretDigesterPort, DynamicRegistrationSecretPort, OAuthClient,
};
use serde_json::Value;

pub type RemoteJwksFuture<'a> = Pin<Box<dyn Future<Output = Result<Value, String>> + Send + 'a>>;

/// Resolves a remote JWKS under the embedding server's outbound-document policy.
pub trait RemoteJwksResolverPort: Send + Sync {
    fn resolve<'a>(&'a self, uri: &'a str, expected_kid: Option<&'a str>) -> RemoteJwksFuture<'a>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DynamicRegistrationRateLimitError {
    Limited { retry_after_seconds: u64 },
    Unavailable,
}

pub trait DynamicRegistrationRequestGuard: Send + Sync {
    fn accepts_new_requests(&self) -> bool;

    fn enforce_rate_limit<'a>(
        &'a self,
        source_ip: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<(), DynamicRegistrationRateLimitError>> + Send + 'a>>;

    fn audit(&self, event: &'static str, client: &OAuthClient, source_ip: &str);
}

#[derive(Clone)]
pub struct DynamicRegistrationSecurityServices {
    pub(crate) remote_jwks: Arc<dyn RemoteJwksResolverPort>,
    pub(crate) crypto: Arc<dyn AdminClientCryptoPort>,
    pub(crate) secret_digester: Arc<dyn ClientSecretDigesterPort>,
    pub(crate) registration_tokens: Arc<dyn DynamicRegistrationSecretPort>,
}

impl DynamicRegistrationSecurityServices {
    pub fn new(
        remote_jwks: Arc<dyn RemoteJwksResolverPort>,
        crypto: Arc<dyn AdminClientCryptoPort>,
        secret_digester: Arc<dyn ClientSecretDigesterPort>,
        registration_tokens: Arc<dyn DynamicRegistrationSecretPort>,
    ) -> Self {
        Self {
            remote_jwks,
            crypto,
            secret_digester,
            registration_tokens,
        }
    }
}
