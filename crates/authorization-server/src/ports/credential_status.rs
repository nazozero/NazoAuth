use nazo_digital_credentials::{CredentialFormat, CredentialFuture, CredentialTrustError};

/// Fetch the complete signed list, without sending the credential or its index.
/// Implementations enforce HTTPS, network admission, deadlines and size limits.
pub trait CredentialStatusResolver: Send + Sync {
    fn fetch<'a>(
        &'a self,
        uri: &'a str,
        format: CredentialFormat,
    ) -> CredentialFuture<'a, Result<Vec<u8>, CredentialTrustError>>;
}
