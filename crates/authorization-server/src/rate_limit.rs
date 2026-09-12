//! Fixed-window request limits over the canonical semantic state port.
use std::sync::Arc;

use http::StatusCode;
use nazo_auth::{RequestRateLimitBucket, RequestRateLimitPort};

use crate::contracts::oauth_error::OAuthEndpointError;

#[derive(Clone)]
pub struct AuthRequestLimiter {
    store: Arc<dyn RequestRateLimitPort>,
    window_seconds: u64,
    max_requests: u64,
}

#[derive(Clone)]
pub struct TokenManagementRequestLimiter {
    store: Arc<dyn RequestRateLimitPort>,
    window_seconds: u64,
    max_requests: u64,
}

impl AuthRequestLimiter {
    pub fn new(
        store: Arc<dyn RequestRateLimitPort>,
        window_seconds: u64,
        max_requests: u64,
    ) -> Self {
        Self {
            store,
            window_seconds,
            max_requests,
        }
    }

    pub async fn enforce(&self, source_ip: &str) -> Result<(), OAuthEndpointError> {
        enforce_rate_limit(
            self.store.as_ref(),
            RequestRateLimitBucket::Authentication,
            source_ip,
            self.window_seconds,
            self.max_requests,
        )
        .await
    }
}

impl TokenManagementRequestLimiter {
    pub fn new(
        store: Arc<dyn RequestRateLimitPort>,
        window_seconds: u64,
        max_requests: u64,
    ) -> Self {
        Self {
            store,
            window_seconds,
            max_requests,
        }
    }

    pub async fn enforce(&self, source_ip: &str) -> Result<(), OAuthEndpointError> {
        enforce_rate_limit(
            self.store.as_ref(),
            RequestRateLimitBucket::TokenManagement,
            source_ip,
            self.window_seconds,
            self.max_requests,
        )
        .await
    }
}

async fn enforce_rate_limit(
    store: &dyn RequestRateLimitPort,
    bucket: RequestRateLimitBucket,
    source_ip: &str,
    window_seconds: u64,
    max_requests: u64,
) -> Result<(), OAuthEndpointError> {
    let count = store
        .increment(bucket, source_ip, window_seconds)
        .await
        .map_err(|error| {
            tracing::warn!(%error, "rate limit increment failed");
            OAuthEndpointError::json(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "请求频率校验失败.",
            )
        })?;
    if count > max_requests {
        return Err(OAuthEndpointError::RateLimited {
            retry_after_seconds: window_seconds,
        });
    }
    Ok(())
}
