use kevy_store::SetCondition;
use nazo_identity::{
    TenantId,
    ports::{
        EmailVerificationConsume, EmailVerificationRecord, EmailVerificationStorePort,
        FederationStatePort, PasskeyCeremonyPort, PasswordHashInput, RepositoryError,
        RepositoryFuture,
    },
};
use serde::{Deserialize, Serialize};

use crate::{
    Error, TenantState,
    storage::{deadline, decode, encode, now_ms, set_until, ttl},
};

#[derive(Serialize, Deserialize)]
struct EmailCode<S> {
    owner: S,
    password_hash: S,
    attempts: u64,
    expires_at_ms: u64,
}

impl TenantState {
    fn email_key(&self, tenant: TenantId, kind: &str, value: &str) -> Result<Vec<u8>, Error> {
        if tenant != self.tenant_id {
            return Err(Error::Unexpected);
        }
        Ok(self.key(kind, &[value.as_bytes()]))
    }

    fn reserve_send(
        &self,
        tenant: TenantId,
        kind: &str,
        value: &str,
        owner: &str,
        seconds: u64,
    ) -> Result<bool, Error> {
        let key = self.email_key(tenant, kind, value)?;
        let duration = ttl(seconds)?;
        Ok(self.volatile.with_key(&key, |db| {
            db.set_slice(
                &key,
                owner.as_bytes(),
                Some(duration),
                SetCondition::IfAbsent,
            )
        }))
    }

    fn release_send(
        &self,
        tenant: TenantId,
        kind: &str,
        value: &str,
        owner: &str,
    ) -> Result<(), Error> {
        let key = self.email_key(tenant, kind, value)?;
        self.volatile.with_key(&key, |db| {
            if db.get(&key)?.as_deref() == Some(owner.as_bytes()) {
                db.del(&[&key]);
            }
            Ok(())
        })
    }

    fn take_bound<T: serde::de::DeserializeOwned>(
        &self,
        key: &[u8],
        binding: &str,
    ) -> Result<Option<T>, Error> {
        #[derive(Deserialize)]
        struct BrowserBinding<'a> {
            browser_binding_hash: &'a str,
        }
        self.volatile.with_key(key, |db| {
            let Some(raw) = db.get(key)? else {
                return Ok(None);
            };
            // A different browser must neither consume nor refresh this state.
            let Ok(owner) = serde_json::from_slice::<BrowserBinding<'_>>(&raw) else {
                return Ok(None);
            };
            if owner.browser_binding_hash != binding {
                return Ok(None);
            }
            let value = decode(&raw);
            db.del(&[key]);
            value.map(Some)
        })
    }
}

impl EmailVerificationStorePort for TenantState {
    fn reserve_peer_send<'a>(
        &'a self,
        tenant: TenantId,
        subject: &'a str,
        owner: &'a str,
        seconds: u64,
    ) -> RepositoryFuture<'a, bool> {
        Box::pin(async move {
            self.reserve_send(tenant, "email-peer", subject, owner, seconds)
                .map_err(Into::into)
        })
    }

    fn reserve_email_send<'a>(
        &'a self,
        tenant: TenantId,
        email: &'a str,
        owner: &'a str,
        seconds: u64,
    ) -> RepositoryFuture<'a, bool> {
        Box::pin(async move {
            self.reserve_send(tenant, "email-send", email, owner, seconds)
                .map_err(Into::into)
        })
    }

    fn store_code<'a>(
        &'a self,
        tenant: TenantId,
        email: &'a str,
        owner: &'a str,
        password_hash: PasswordHashInput,
        seconds: u64,
    ) -> RepositoryFuture<'a, ()> {
        Box::pin(async move {
            let key = self.email_key(tenant, "email-code", email)?;
            let reservation = self.email_key(tenant, "email-send", email)?;
            let expires_at_ms = deadline(seconds)?;
            let raw = encode(&EmailCode {
                owner,
                password_hash: password_hash.into_persistence_value().as_str(),
                attempts: 0,
                expires_at_ms,
            })?;
            let stored = self.volatile.with_key(&key, |db| -> Result<bool, Error> {
                if db.get(&reservation)?.as_deref() != Some(owner.as_bytes()) {
                    return Ok(false);
                }
                set_until(db, &key, raw, expires_at_ms);
                Ok(true)
            })?;
            stored.then_some(()).ok_or(RepositoryError::Conflict)
        })
    }

    fn reserve_code_attempt<'a>(
        &'a self,
        tenant: TenantId,
        email: &'a str,
        max_attempts: u64,
    ) -> RepositoryFuture<'a, Option<EmailVerificationRecord>> {
        Box::pin(async move {
            let key = self.email_key(tenant, "email-code", email)?;
            self.volatile
                .with_key(&key, |db| -> Result<_, Error> {
                    let Some(raw) = db.get(&key)? else {
                        return Ok(None);
                    };
                    let mut code: EmailCode<String> = decode(&raw)?;
                    if code.expires_at_ms <= now_ms() || code.attempts >= max_attempts {
                        return Ok(None);
                    }
                    code.attempts += 1;
                    let opaque_version =
                        serde_json::to_string(&(&code.owner, &code.password_hash))?;
                    let replacement = encode(&code)?;
                    let password_hash = nazo_identity::PasswordHash::new(code.password_hash)
                        .map_err(|_| Error::CorruptData)?;
                    set_until(db, &key, replacement, code.expires_at_ms);
                    Ok(Some(EmailVerificationRecord {
                        password_hash,
                        opaque_version,
                    }))
                })
                .map_err(Into::into)
        })
    }

    fn consume_code<'a>(
        &'a self,
        tenant: TenantId,
        email: &'a str,
        expected: &'a str,
    ) -> RepositoryFuture<'a, EmailVerificationConsume> {
        Box::pin(async move {
            let key = self.email_key(tenant, "email-code", email)?;
            self.volatile
                .with_key(&key, |db| -> Result<_, Error> {
                    let Some(raw) = db.get(&key)? else {
                        return Ok(EmailVerificationConsume::MissingOrChanged);
                    };
                    let code: EmailCode<String> = decode(&raw)?;
                    let (owner, hash): (&str, &str) = serde_json::from_str(expected)?;
                    if code.expires_at_ms <= now_ms()
                        || code.owner != owner
                        || code.password_hash != hash
                    {
                        return Ok(EmailVerificationConsume::MissingOrChanged);
                    }
                    db.del(&[&key]);
                    Ok(EmailVerificationConsume::Consumed)
                })
                .map_err(Into::into)
        })
    }

    fn delete_code<'a>(
        &'a self,
        tenant: TenantId,
        email: &'a str,
        owner: &'a str,
    ) -> RepositoryFuture<'a, ()> {
        Box::pin(async move {
            let key = self.email_key(tenant, "email-code", email)?;
            self.volatile
                .with_key(&key, |db| -> Result<_, Error> {
                    if let Some(raw) = db.get(&key)? {
                        let code: EmailCode<String> = decode(&raw)?;
                        if code.owner == owner {
                            db.del(&[&key]);
                        }
                    }
                    Ok(())
                })
                .map_err(Into::into)
        })
    }

    fn release_email_send<'a>(
        &'a self,
        tenant: TenantId,
        email: &'a str,
        owner: &'a str,
    ) -> RepositoryFuture<'a, ()> {
        Box::pin(async move {
            self.release_send(tenant, "email-send", email, owner)
                .map_err(Into::into)
        })
    }

    fn release_peer_send<'a>(
        &'a self,
        tenant: TenantId,
        subject: &'a str,
        owner: &'a str,
    ) -> RepositoryFuture<'a, ()> {
        Box::pin(async move {
            self.release_send(tenant, "email-peer", subject, owner)
                .map_err(Into::into)
        })
    }
}

impl PasskeyCeremonyPort for TenantState {
    fn store_registration<'a>(
        &'a self,
        id: &'a str,
        value: &'a nazo_identity::StoredPasskeyRegistration,
        seconds: u64,
    ) -> RepositoryFuture<'a, ()> {
        Box::pin(async move {
            self.put_json(
                &self.key("passkey-registration", &[id.as_bytes()]),
                value,
                seconds,
            )
            .map_err(Into::into)
        })
    }
    fn take_registration<'a>(
        &'a self,
        id: &'a str,
    ) -> RepositoryFuture<'a, Option<nazo_identity::StoredPasskeyRegistration>> {
        Box::pin(async move {
            self.take_json(&self.key("passkey-registration", &[id.as_bytes()]))
                .map_err(Into::into)
        })
    }
    fn store_authentication<'a>(
        &'a self,
        id: &'a str,
        value: &'a nazo_identity::StoredPasskeyAuthentication,
        seconds: u64,
    ) -> RepositoryFuture<'a, ()> {
        Box::pin(async move {
            self.put_json(
                &self.key("passkey-authentication", &[id.as_bytes()]),
                value,
                seconds,
            )
            .map_err(Into::into)
        })
    }
    fn take_authentication<'a>(
        &'a self,
        id: &'a str,
    ) -> RepositoryFuture<'a, Option<nazo_identity::StoredPasskeyAuthentication>> {
        Box::pin(async move {
            self.take_json(&self.key("passkey-authentication", &[id.as_bytes()]))
                .map_err(Into::into)
        })
    }
}

impl FederationStatePort for TenantState {
    fn store_oidc<'a>(
        &'a self,
        state: &'a str,
        value: &'a nazo_identity::OidcFederationState,
        seconds: u64,
    ) -> RepositoryFuture<'a, ()> {
        Box::pin(async move {
            self.put_json(
                &self.key("oidc-federation", &[state.as_bytes()]),
                value,
                seconds,
            )
            .map_err(Into::into)
        })
    }
    fn take_oidc<'a>(
        &'a self,
        state: &'a str,
        binding: &'a str,
    ) -> RepositoryFuture<'a, Option<nazo_identity::OidcFederationState>> {
        Box::pin(async move {
            self.take_bound(&self.key("oidc-federation", &[state.as_bytes()]), binding)
                .map_err(Into::into)
        })
    }
    fn store_social<'a>(
        &'a self,
        state: &'a str,
        value: &'a nazo_identity::SocialFederationState,
        seconds: u64,
    ) -> RepositoryFuture<'a, ()> {
        Box::pin(async move {
            self.put_json(
                &self.key("social-federation", &[state.as_bytes()]),
                value,
                seconds,
            )
            .map_err(Into::into)
        })
    }
    fn take_social<'a>(
        &'a self,
        state: &'a str,
        binding: &'a str,
    ) -> RepositoryFuture<'a, Option<nazo_identity::SocialFederationState>> {
        Box::pin(async move {
            self.take_bound(&self.key("social-federation", &[state.as_bytes()]), binding)
                .map_err(Into::into)
        })
    }
    fn reserve_saml_replay<'a>(
        &'a self,
        signature: &'a str,
        seconds: u64,
    ) -> RepositoryFuture<'a, bool> {
        Box::pin(async move {
            self.consume_replay("saml", &[signature.as_bytes()], seconds)
                .await
                .map_err(Into::into)
        })
    }
}

#[cfg(test)]
#[path = "../tests/unit/identity.rs"]
mod tests;
