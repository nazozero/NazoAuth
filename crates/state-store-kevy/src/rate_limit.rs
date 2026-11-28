use nazo_identity::ports::{
    LoginThrottlePort, MfaAttemptThrottleDecision, MfaAttemptThrottlePort, RepositoryFuture,
};

use crate::{Error, TenantState, ttl};

impl TenantState {
    pub(crate) fn increment_counter(&self, key: &[u8], seconds: u64) -> Result<u64, Error> {
        let duration = ttl(seconds)?;
        self.volatile.with(|store| {
            let count = store.incr_by(key, 1)?;
            if count == 1 {
                store.expire(key, duration);
            }
            u64::try_from(count).map_err(|_| Error::CorruptData)
        })
    }

    pub(crate) fn increment_rate(
        &self,
        dimension: &str,
        subject: &str,
        seconds: u64,
    ) -> Result<u64, Error> {
        self.increment_counter(&self.key(dimension, &[subject.as_bytes()]), seconds)
    }
}

impl nazo_auth::RequestRateLimitPort for TenantState {
    fn increment<'a>(
        &'a self,
        bucket: nazo_auth::RequestRateLimitBucket,
        subject: &'a str,
        window_seconds: u64,
    ) -> nazo_auth::RequestRateLimitFuture<'a> {
        Box::pin(async move {
            let namespace = match bucket {
                nazo_auth::RequestRateLimitBucket::Authentication => "rate-auth",
                nazo_auth::RequestRateLimitBucket::Token => "rate-token",
                nazo_auth::RequestRateLimitBucket::TokenManagement => "rate-token-management",
            };
            self.increment_rate(namespace, subject, window_seconds)
                .map_err(|_| nazo_auth::RequestRateLimitError)
        })
    }
}

impl LoginThrottlePort for TenantState {
    fn failure_count<'a>(
        &'a self,
        email: &'a str,
        source_ip: &'a str,
    ) -> RepositoryFuture<'a, u64> {
        Box::pin(async move {
            let key = self.key("login-failure", &[source_ip.as_bytes(), email.as_bytes()]);
            self.volatile
                .get_with(&key, |raw| {
                    raw.map(|raw| {
                        std::str::from_utf8(raw)
                            .ok()
                            .and_then(|raw| raw.parse::<u64>().ok())
                            .ok_or(Error::CorruptData)
                    })
                    .transpose()
                    .map(|count| count.unwrap_or(0))
                })
                .map_err(|_| Error::Unavailable)?
                .map_err(Into::into)
        })
    }

    fn record_failure<'a>(
        &'a self,
        email: &'a str,
        source_ip: &'a str,
        window_seconds: u64,
    ) -> RepositoryFuture<'a, ()> {
        Box::pin(async move {
            self.increment_counter(
                &self.key("login-failure", &[source_ip.as_bytes(), email.as_bytes()]),
                window_seconds,
            )
            .map(|_| ())
            .map_err(Into::into)
        })
    }

    fn clear_failure<'a>(&'a self, email: &'a str, source_ip: &'a str) -> RepositoryFuture<'a, ()> {
        Box::pin(async move {
            self.delete(&self.key("login-failure", &[source_ip.as_bytes(), email.as_bytes()]));
            Ok(())
        })
    }
}

impl MfaAttemptThrottlePort for TenantState {
    fn reserve_attempt<'a>(
        &'a self,
        tenant_id: nazo_identity::TenantId,
        user_id: nazo_identity::UserId,
        window_seconds: u64,
        max_attempts: u64,
    ) -> RepositoryFuture<'a, MfaAttemptThrottleDecision> {
        Box::pin(async move {
            if tenant_id != self.tenant_id {
                return Err(Error::Unexpected.into());
            }
            let key = self.key("mfa-failure", &[user_id.as_uuid().as_bytes()]);
            let count = self.increment_counter(&key, window_seconds)?;
            Ok(if count > max_attempts {
                MfaAttemptThrottleDecision::Limited {
                    retry_after_seconds: window_seconds,
                }
            } else {
                MfaAttemptThrottleDecision::Allowed
            })
        })
    }

    fn clear_attempts<'a>(
        &'a self,
        tenant_id: nazo_identity::TenantId,
        user_id: nazo_identity::UserId,
    ) -> RepositoryFuture<'a, ()> {
        Box::pin(async move {
            if tenant_id != self.tenant_id {
                return Err(Error::Unexpected.into());
            }
            self.delete(&self.key("mfa-failure", &[user_id.as_uuid().as_bytes()]));
            Ok(())
        })
    }
}

#[cfg(test)]
#[path = "../tests/unit/rate_limit.rs"]
mod tests;
