use nazo_identity::{PasswordHash, ports::*};
use zeroize::Zeroizing;

pub(crate) struct EmailRelay {
    pub(crate) client: crate::outbound::Outbound,
    pub(crate) configuration: crate::config::EmailRelay,
    pub(crate) token: Zeroizing<String>,
}

impl VerificationEmailDeliveryPort for EmailRelay {
    fn deliver<'a>(&'a self, email: &'a str, code: &'a str, ttl: u64) -> RepositoryFuture<'a, ()> {
        Box::pin(async move {
            let body = serde_json::json!({
                "from": self.configuration.from,
                "to": [email],
                "subject": "NazoAuth email verification",
                "text": format!("Your NazoAuth verification code is {code}. It expires in {ttl} seconds. If you did not request this code, you can ignore this email."),
            });
            let request = http::Request::builder()
                .method("POST")
                .uri(&self.configuration.endpoint)
                .header(http::header::CONTENT_TYPE, "application/json")
                .header(
                    http::header::AUTHORIZATION,
                    format!("Bearer {}", self.token.as_str()),
                )
                .body(bytes::Bytes::from(
                    serde_json::to_vec(&body).map_err(|_| RepositoryError::Unavailable)?,
                ))
                .map_err(|_| RepositoryError::Unavailable)?;
            let response = self
                .client
                .send(request, 0, std::time::Duration::from_secs(10))
                .await
                .map_err(|_| RepositoryError::Unavailable)?;
            if !response.status().is_success() {
                return Err(RepositoryError::Unavailable);
            }
            Ok(())
        })
    }
}

pub(crate) struct ScimPoll<P>(pub(crate) P);

impl<P: nazo_scim_events::EventPollerPort> nazo_scim_events::EventPollerPort for ScimPoll<P> {
    fn poll<'a>(
        &'a self,
        receiver: &'a nazo_scim_events::EventReceiver,
        request: &'a nazo_scim_events::ValidatedPollRequest,
    ) -> nazo_scim_events::EventFuture<
        'a,
        Result<nazo_scim_events::PollResponse, nazo_scim_events::PollError>,
    > {
        Box::pin(async move {
            let response = self.0.poll(receiver, request).await?;
            if request.return_immediately || !response.sets.is_empty() || response.more_available {
                return Ok(response);
            }
            #[cfg(target_arch = "wasm32")]
            {
                let deadline = jiff::Timestamp::now() + jiff::SignedDuration::from_secs(30);
                let mut response = response;
                // ACKs/errors are consumed once, before the long-poll loop.
                let next = nazo_scim_events::ValidatedPollRequest {
                    max_events: request.max_events,
                    return_immediately: false,
                    ack: Vec::new(),
                    set_errors: Default::default(),
                };
                while response.sets.is_empty()
                    && !response.more_available
                    && jiff::Timestamp::now() < deadline
                {
                    worker::send::SendFuture::new(worker::Delay::from(
                        std::time::Duration::from_secs(1),
                    ))
                    .await;
                    response = self.0.poll(receiver, &next).await?;
                }
                Ok(response)
            }
            #[cfg(not(target_arch = "wasm32"))]
            Err(nazo_scim_events::EventStoreError::Unavailable.into())
        })
    }
}

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

impl MfaSecretHashPort for Passwords {
    fn hash_secrets(&self, secrets: Vec<String>) -> MfaHashFuture<'_, Vec<EncodedSecretHash>> {
        Box::pin(async move {
            let secrets = Zeroizing::new(secrets);
            let mut hashes = Vec::with_capacity(secrets.len());
            for secret in secrets.iter() {
                let hash = nazo_crypto::password::hash_argon2id(secret.as_bytes(), 19_456, 2, 1)
                    .map_err(|_| MfaHashError::Failed)?;
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
            let secret = Zeroizing::new(secret);
            Ok(candidates.iter().position(|candidate| {
                nazo_crypto::password::verify_argon2_phc(candidate.as_str(), secret.as_bytes())
            }))
        })
    }
}

#[cfg(test)]
#[path = "../tests/unit/mfa_hashing.rs"]
mod mfa_hashing_tests;

impl VerificationEmailDeliveryPort for Unavailable {
    fn deliver<'a>(&'a self, _: &'a str, _: &'a str, _: u64) -> RepositoryFuture<'a, ()> {
        Box::pin(async { Err(RepositoryError::Unavailable) })
    }
}

#[cfg(all(feature = "provisioning", not(target_arch = "wasm32")))]
impl nazo_auth::SectorIdentifierResolverPort for Unavailable {
    fn resolve<'a>(&'a self, _: &'a str) -> nazo_auth::SectorIdentifierFuture<'a> {
        Box::pin(async {
            Err("remote sector documents are unavailable in this deployment profile".into())
        })
    }
}

pub(crate) struct RuntimeLifecycle {
    pub(crate) provider: std::sync::Arc<nazo_oauth_server_d1::D1Provider>,
    pub(crate) tenant: uuid::Uuid,
}

impl nazo_runtime_modules::ModuleLifecycle for RuntimeLifecycle {
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
                code: "bounded_module_reconcile_required",
            })
        })
    }

    fn poll_stored_transactions(
        &self,
        module_id: nazo_runtime_modules::ModuleId,
        revision: nazo_runtime_modules::ModuleRevision,
        remaining_duration: std::time::Duration,
    ) -> nazo_runtime_modules::LifecycleFuture<
        '_,
        Result<nazo_runtime_modules::DrainProgress, nazo_runtime_modules::LifecycleFailure>,
    > {
        use nazo_oauth_server::ports::persistence::ServerPersistenceProvider;
        Box::pin(async move {
            // The shared registry derives the same persistent deadline for all
            // isolates. As with the native host, retain stored admission for
            // that full window, checking its authoritative revision each step.
            // No invocation sleeps for the lifetime of a session or grant.
            let current = self
                .provider
                .runtime_modules(self.tenant)
                .validate_revision(module_id, revision)
                .await
                .map_err(|_| nazo_runtime_modules::LifecycleFailure {
                    code: "drain_revision_lookup_failed",
                })?;
            if !current {
                return Err(nazo_runtime_modules::LifecycleFailure {
                    code: "revision_changed",
                });
            }
            Ok(if remaining_duration.is_zero() {
                nazo_runtime_modules::DrainProgress::Complete
            } else {
                nazo_runtime_modules::DrainProgress::Pending
            })
        })
    }
}
