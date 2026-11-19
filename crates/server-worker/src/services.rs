use nazo_identity::{PasswordHash, ports::*};
use zeroize::Zeroizing;

/// Memory-hard password work runs synchronously on the isolate. There is no
/// await while Argon2 owns its 19 MiB buffer, so requests cannot accumulate
/// concurrently allocated password workspaces inside one isolate.
pub(crate) struct Passwords;

impl SecretVerifyPort for Passwords {
    fn verify_secret(&self, secret: String, hash: PasswordHash) -> SecretVerifyFuture<'_> {
        Box::pin(async move { Ok(hash.verify_password(&Zeroizing::new(secret))) })
    }
}

impl SecretHashPort for Passwords {
    fn hash_secret(&self, secret: String) -> RepositoryFuture<'_, PasswordHashInput> {
        Box::pin(async move {
            let secret = Zeroizing::new(secret);
            let hash = nazo_crypto::password::hash_argon2id(secret.as_bytes(), 19_456, 2, 1)
                .map_err(|_| RepositoryError::Unavailable)?;
            PasswordHashInput::new(hash).map_err(|_| RepositoryError::Unavailable)
        })
    }

    fn verify_secret(&self, secret: String, hash: PasswordHash) -> RepositoryFuture<'_, bool> {
        Box::pin(async move { Ok(hash.verify_password(&Zeroizing::new(secret))) })
    }
}

/// Optional capabilities absent from this deployment profile fail explicitly.
pub(crate) struct Unavailable;

impl MfaSecretHashPort for Unavailable {
    fn hash_secrets(&self, _: Vec<String>) -> MfaHashFuture<'_, Vec<EncodedSecretHash>> {
        Box::pin(async { Err(MfaHashError::Failed) })
    }

    fn find_matching_secret(
        &self,
        _: String,
        _: Vec<EncodedSecretHash>,
    ) -> MfaHashFuture<'_, Option<usize>> {
        Box::pin(async { Err(MfaHashError::Failed) })
    }
}

impl VerificationEmailDeliveryPort for Unavailable {
    fn deliver<'a>(&'a self, _: &'a str, _: &'a str, _: u64) -> RepositoryFuture<'a, ()> {
        Box::pin(async { Err(RepositoryError::Unavailable) })
    }
}

impl nazo_auth::SectorIdentifierResolverPort for Unavailable {
    fn resolve<'a>(&'a self, _: &'a str) -> nazo_auth::SectorIdentifierFuture<'a> {
        Box::pin(async {
            Err("remote sector documents are unavailable in this deployment profile".into())
        })
    }
}

impl nazo_oauth_server::contracts::dynamic_client_registration::RemoteJwksResolverPort
    for Unavailable
{
    fn resolve<'a>(
        &'a self,
        _: &'a str,
        _: Option<&'a str>,
    ) -> nazo_oauth_server::contracts::dynamic_client_registration::RemoteJwksFuture<'a> {
        Box::pin(async { Err("remote JWKS are unavailable; provision inline client keys".into()) })
    }
}

impl nazo_oauth_server::ports::remote_request_object::RemoteRequestObjectResolverPort
    for Unavailable
{
    fn resolve_request_object<'a>(
        &'a self,
        _: &'a str,
    ) -> nazo_oauth_server::ports::remote_request_object::RequestObjectFuture<'a> {
        Box::pin(async {
            Err("remote request objects are unavailable; submit inline or use PAR".into())
        })
    }
}

impl nazo_oauth_server::ports::credential_status::CredentialStatusResolver for Unavailable {
    fn fetch<'a>(
        &'a self,
        _: &'a str,
        _: nazo_digital_credentials::CredentialFormat,
    ) -> nazo_digital_credentials::CredentialFuture<
        'a,
        Result<Vec<u8>, nazo_digital_credentials::CredentialTrustError>,
    > {
        Box::pin(async { Err(nazo_digital_credentials::CredentialTrustError::Unavailable) })
    }
}

impl nazoauth::capabilities::FederationHttpClient for Unavailable {
    fn send(
        &self,
        _: http::Request<bytes::Bytes>,
        _: usize,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = anyhow::Result<http::Response<bytes::Bytes>>>
                + Send
                + '_,
        >,
    > {
        Box::pin(async {
            anyhow::bail!("federation HTTP is unavailable in this deployment profile")
        })
    }
}

impl nazo_scim_events::EventPollerPort for Unavailable {
    fn poll<'a>(
        &'a self,
        _: &'a nazo_scim_events::EventReceiver,
        _: &'a nazo_scim_events::ValidatedPollRequest,
    ) -> nazo_scim_events::EventFuture<
        'a,
        Result<nazo_scim_events::PollResponse, nazo_scim_events::PollError>,
    > {
        Box::pin(async { Err(nazo_scim_events::EventStoreError::Unavailable.into()) })
    }
}

impl nazo_runtime_modules::ModuleLifecycle for Unavailable {
    fn drain_stored_transactions(
        &self,
        _: nazo_runtime_modules::ModuleId,
        _: nazo_runtime_modules::ModuleRevision,
        _: std::time::Duration,
    ) -> nazo_runtime_modules::LifecycleFuture<
        '_,
        Result<bool, nazo_runtime_modules::LifecycleFailure>,
    > {
        Box::pin(async {
            Err(nazo_runtime_modules::LifecycleFailure {
                code: "deployment_managed_modules",
            })
        })
    }
}
