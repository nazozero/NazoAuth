use nazo_oauth_server::crypto::random_urlsafe_token;
// Native bounded execution of memory-hard password work.

use anyhow::{anyhow, bail};
use std::sync::{
    Arc, OnceLock,
    atomic::{AtomicU64, AtomicUsize, Ordering},
};
use tokio::sync::Semaphore;
use tokio::time::{Duration, timeout};

#[cfg(test)]
#[path = "../../tests/support/adapters/security/tokens.rs"]
pub(crate) mod tokens;

const ARGON2_MEMORY_COST_KIB: u32 = 19_456;
const ARGON2_TIME_COST: u32 = 2;
const ARGON2_PARALLELISM: u32 = 1;
const DEFAULT_PASSWORD_HASH_MAX_CONCURRENCY: usize = 8;
const DEFAULT_PASSWORD_HASH_QUEUE_TIMEOUT_MS: u64 = 100;

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

pub(crate) fn hash_password(password: &str) -> nazo_crypto::Result<String> {
    nazo_crypto::password::hash_argon2id(
        password.as_bytes(),
        ARGON2_MEMORY_COST_KIB,
        ARGON2_TIME_COST,
        ARGON2_PARALLELISM,
    )
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
            nazo_crypto::password::verify_argon2_phc(candidate.as_str(), secret.as_bytes())
        })
    })
    .await
    .map_err(|_| PasswordVerificationError::WorkerFailed)
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
