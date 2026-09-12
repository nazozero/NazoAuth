use nazo_oauth_server::crypto::random_urlsafe_token;
// Native password execution and client credential extraction.

use crate::http::mtls::request_mtls_client_certificate;

use actix_web::HttpRequest;
use actix_web::http::header;
use actix_web::http::header::{HeaderMap, HeaderValue};
use anyhow::{anyhow, bail};
use argon2::Argon2;
use argon2::PasswordHash;
use argon2::PasswordHasher;
use argon2::PasswordVerifier;
use nazo_auth::unverified_client_assertion_client_id;
use std::sync::{
    Arc, OnceLock,
    atomic::{AtomicU64, AtomicUsize, Ordering},
};
use tokio::sync::Semaphore;
use tokio::time::{Duration, timeout};

#[cfg(test)]
#[path = "../../tests/support/adapters/security/tokens.rs"]
pub(crate) mod tokens;

#[derive(Clone, Copy)]
pub(crate) struct ServerScimBootstrapPasswordProvider;

impl nazo_oauth_server::contracts::scim::ScimBootstrapPasswordProvider
    for ServerScimBootstrapPasswordProvider
{
    fn password_hash(
        &self,
    ) -> nazo_oauth_server::contracts::scim::ScimFuture<
        '_,
        Result<
            nazo_identity::ports::PasswordHashInput,
            nazo_oauth_server::contracts::scim::ScimDependencyError,
        >,
    > {
        use nazo_oauth_server::contracts::scim::ScimDependencyError;
        Box::pin(async {
            let hash = hash_password_blocking_limited(random_urlsafe_token())
                .await
                .map_err(|_| ScimDependencyError::Unavailable)?;
            nazo_identity::ports::PasswordHashInput::new(hash)
                .map_err(|_| ScimDependencyError::Unavailable)
        })
    }
}

const ARGON2_MEMORY_COST_KIB: u32 = 19_456;
const ARGON2_TIME_COST: u32 = 2;
const ARGON2_PARALLELISM: u32 = 1;
const DEFAULT_PASSWORD_HASH_MAX_CONCURRENCY: usize = 8;
const DEFAULT_PASSWORD_HASH_QUEUE_TIMEOUT_MS: u64 = 100;

pub(crate) const LOCAL_DEVELOPMENT_CLIENT_SECRET_PEPPER: &str =
    "local-development-client-secret-pepper-00000001";

static PASSWORD_HASH_MAX_CONCURRENCY: AtomicUsize =
    AtomicUsize::new(DEFAULT_PASSWORD_HASH_MAX_CONCURRENCY);
static PASSWORD_HASH_QUEUE_TIMEOUT_MS: AtomicU64 =
    AtomicU64::new(DEFAULT_PASSWORD_HASH_QUEUE_TIMEOUT_MS);
static PASSWORD_HASH_CONCURRENCY_LIMIT: OnceLock<Arc<Semaphore>> = OnceLock::new();
static DUMMY_PASSWORD_HASH: OnceLock<Result<String, String>> = OnceLock::new();

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PasswordVerificationError {
    Saturated,
    WorkerFailed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PasswordHashingError {
    Saturated,
    WorkerFailed,
    HashFailed,
}

pub(crate) fn hash_password(password: &str) -> argon2::password_hash::Result<String> {
    Ok(password_hasher()
        .hash_password(password.as_bytes())?
        .to_string())
}

pub(crate) fn initialize_dummy_password_hash() -> anyhow::Result<()> {
    dummy_password_hash().map(drop)
}

pub(crate) fn dummy_password_hash() -> anyhow::Result<String> {
    match DUMMY_PASSWORD_HASH
        .get_or_init(|| hash_password(&random_urlsafe_token()).map_err(|error| error.to_string()))
    {
        Ok(hash) => Ok(hash.clone()),
        Err(error) => Err(anyhow!("failed to initialize dummy password hash: {error}")),
    }
}

pub(crate) fn default_password_hash_max_concurrency() -> usize {
    DEFAULT_PASSWORD_HASH_MAX_CONCURRENCY
}

pub(crate) fn default_password_hash_queue_timeout_ms() -> u64 {
    DEFAULT_PASSWORD_HASH_QUEUE_TIMEOUT_MS
}

pub(crate) fn configure_password_hash_limits(
    max_concurrency: usize,
    queue_timeout_ms: u64,
) -> anyhow::Result<()> {
    if max_concurrency == 0 {
        bail!("PASSWORD_HASH_MAX_CONCURRENCY must be positive");
    }
    if queue_timeout_ms == 0 {
        bail!("PASSWORD_HASH_QUEUE_TIMEOUT_MS must be positive");
    }
    if PASSWORD_HASH_CONCURRENCY_LIMIT.get().is_some() {
        bail!("password hash limits must be configured before password verification");
    }
    AtomicUsize::store(
        &PASSWORD_HASH_MAX_CONCURRENCY,
        max_concurrency,
        Ordering::Relaxed,
    );
    AtomicU64::store(
        &PASSWORD_HASH_QUEUE_TIMEOUT_MS,
        queue_timeout_ms,
        Ordering::Relaxed,
    );
    Ok(())
}

pub(crate) async fn verify_password_blocking_limited(
    password: String,
    password_hash: nazo_identity::PasswordHash,
) -> Result<bool, PasswordVerificationError> {
    let acquire = password_hash_concurrency_limit().clone().acquire_owned();
    let Ok(Ok(permit)) = timeout(password_hash_queue_timeout(), acquire).await else {
        return Err(PasswordVerificationError::Saturated);
    };

    tokio::task::spawn_blocking(move || {
        // A cancelled caller cannot stop an already queued or running worker.
        let _permit = permit;
        password_hash.verify_password(&password)
    })
    .await
    .map_err(|_| PasswordVerificationError::WorkerFailed)
}

pub(crate) async fn hash_password_blocking_limited(
    password: String,
) -> Result<String, PasswordHashingError> {
    let acquire = password_hash_concurrency_limit().clone().acquire_owned();
    let Ok(Ok(permit)) = timeout(password_hash_queue_timeout(), acquire).await else {
        return Err(PasswordHashingError::Saturated);
    };

    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        hash_password(&password)
    })
    .await
    .map_err(|_| PasswordHashingError::WorkerFailed)?
    .map_err(|_| PasswordHashingError::HashFailed)
}

pub(crate) async fn verify_encoded_hashes_blocking_limited(
    secret: String,
    candidates: Vec<nazo_identity::ports::EncodedSecretHash>,
) -> Result<Option<usize>, PasswordVerificationError> {
    let acquire = password_hash_concurrency_limit().clone().acquire_owned();
    let Ok(Ok(permit)) = timeout(password_hash_queue_timeout(), acquire).await else {
        return Err(PasswordVerificationError::Saturated);
    };

    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        candidates.into_iter().position(|candidate| {
            let Ok(parsed) = PasswordHash::new(candidate.as_str()) else {
                return false;
            };
            password_hasher()
                .verify_password(secret.as_bytes(), &parsed)
                .is_ok()
        })
    })
    .await
    .map_err(|_| PasswordVerificationError::WorkerFailed)
}

fn password_hasher() -> Argon2<'static> {
    let params = argon2::Params::new(
        ARGON2_MEMORY_COST_KIB,
        ARGON2_TIME_COST,
        ARGON2_PARALLELISM,
        None,
    )
    .expect("Argon2 password hash policy must be valid");
    Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params)
}

fn password_hash_concurrency_limit() -> &'static Arc<Semaphore> {
    PASSWORD_HASH_CONCURRENCY_LIMIT.get_or_init(|| {
        Arc::new(Semaphore::new(AtomicUsize::load(
            &PASSWORD_HASH_MAX_CONCURRENCY,
            Ordering::Relaxed,
        )))
    })
}

fn password_hash_queue_timeout() -> Duration {
    Duration::from_millis(AtomicU64::load(
        &PASSWORD_HASH_QUEUE_TIMEOUT_MS,
        Ordering::Relaxed,
    ))
}

use nazo_auth::CLIENT_ASSERTION_TYPE_JWT_BEARER;

pub(crate) use nazo_auth::PresentedClientCredentials as ClientCredentials;

pub(crate) fn has_basic_authorization_scheme(headers: &HeaderMap) -> bool {
    let Some(raw) = headers
        .get(header::AUTHORIZATION)
        .map(HeaderValue::as_bytes)
    else {
        return false;
    };
    let start = raw
        .iter()
        .position(|value| !value.is_ascii_whitespace())
        .unwrap_or(raw.len());
    let end = raw[start..]
        .iter()
        .position(u8::is_ascii_whitespace)
        .map(|offset| start + offset)
        .unwrap_or(raw.len());
    raw[start..end].eq_ignore_ascii_case(b"Basic")
}

pub(crate) fn extract_client_credentials_with_trusted_proxies(
    req: &HttpRequest,
    trusted_proxy_cidrs: &[nazo_http_actix::IpCidr],
    form_client_id: Option<&str>,
    form_secret: Option<&str>,
    form_assertion_type: Option<&str>,
    form_assertion: Option<&str>,
) -> ClientCredentials {
    let facts = nazo_http_actix::token_client_auth_transport_facts(
        req,
        nazo_http_actix::TokenClientAuthForm {
            client_id: form_client_id,
            client_secret: form_secret,
            client_assertion_type: form_assertion_type,
            client_assertion: form_assertion,
        },
    );
    let assertion_client_id = facts
        .client_assertion()
        .filter(|_| facts.client_assertion_type() == Some(CLIENT_ASSERTION_TYPE_JWT_BEARER))
        .and_then(unverified_client_assertion_client_id);
    let presentation = facts.presentation();
    let mtls_client_id = if !presentation.http_basic
        && !presentation.client_assertion_type
        && !presentation.client_assertion
        && form_secret.is_none()
    {
        form_client_id
            .filter(|_| request_mtls_client_certificate(req, trusted_proxy_cidrs).is_some())
            .map(str::to_owned)
    } else {
        None
    };
    facts.presented_credentials(assertion_client_id, mtls_client_id)
}

#[cfg(test)]
#[path = "../../tests/unit/adapters/security.rs"]
mod tests;

use nazo_identity::ports::{EncodedSecretHash, MfaHashError, MfaHashFuture, MfaSecretHashPort};

#[derive(Clone, Copy)]
pub(crate) struct ServerMfaSecretHasher;

impl MfaSecretHashPort for ServerMfaSecretHasher {
    fn hash_secrets(&self, secrets: Vec<String>) -> MfaHashFuture<'_, Vec<EncodedSecretHash>> {
        Box::pin(async move {
            let mut hashes = Vec::with_capacity(secrets.len());
            for secret in secrets {
                let hash =
                    hash_password_blocking_limited(secret)
                        .await
                        .map_err(|error| match error {
                            PasswordHashingError::Saturated => MfaHashError::Busy,
                            PasswordHashingError::WorkerFailed
                            | PasswordHashingError::HashFailed => MfaHashError::Failed,
                        })?;
                hashes.push(EncodedSecretHash::new(hash).map_err(|_| MfaHashError::Failed)?);
            }
            Ok(hashes)
        })
    }

    fn find_matching_secret(
        &self,
        secret: String,
        candidates: Vec<EncodedSecretHash>,
    ) -> MfaHashFuture<'_, Option<usize>> {
        Box::pin(async move {
            verify_encoded_hashes_blocking_limited(secret, candidates)
                .await
                .map_err(|error| match error {
                    PasswordVerificationError::Saturated => MfaHashError::Busy,
                    PasswordVerificationError::WorkerFailed => MfaHashError::Failed,
                })
        })
    }
}
