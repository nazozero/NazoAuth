#![forbid(unsafe_code)]

//! Native, single-process transient state. Workflow state is volatile; accepted
//! proof fingerprints are retained in an exclusively owned synchronous AOF.

mod authorization;
mod avatar;
mod ciba;
mod delivery;
mod device;
mod identity;
mod rate_limit;
mod replay;
mod session;
mod storage;

#[cfg(test)]
#[path = "../tests/support/mod.rs"]
mod test_support;

use std::sync::Arc;

use nazo_oauth_server::ports::transient_state::{
    ServerStateBackendBindings, ServerTransientStateBindings, ServerTransientStateProvider,
    TenantDirectoryCachePort, TenantTransientStateFactory, TransientStateError,
    TransientStateFuture, TransientStateHealthPort,
};

pub use storage::{KevyBackend, TenantState};
pub(crate) use storage::{decode, encode, ttl};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Unavailable,
    CorruptData,
    Unexpected,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Unavailable => "embedded state is unavailable",
            Self::CorruptData => "embedded state is corrupt",
            Self::Unexpected => "invalid embedded state operation",
        })
    }
}

impl std::error::Error for Error {}

impl From<kevy_store::StoreError> for Error {
    fn from(_: kevy_store::StoreError) -> Self {
        Self::CorruptData
    }
}

impl From<serde_json::Error> for Error {
    fn from(_: serde_json::Error) -> Self {
        Self::CorruptData
    }
}

impl From<Error> for nazo_identity::ports::RepositoryError {
    fn from(value: Error) -> Self {
        match value {
            Error::Unavailable => Self::Unavailable,
            Error::CorruptData => Self::Consistency(value.to_string()),
            Error::Unexpected => Self::Unexpected(value.to_string()),
        }
    }
}

impl From<Error> for nazo_auth::AuthorizationPortError {
    fn from(value: Error) -> Self {
        match value {
            Error::Unavailable => Self::Unavailable,
            Error::CorruptData => Self::CorruptData,
            Error::Unexpected => Self::Unexpected,
        }
    }
}

impl From<Error> for nazo_auth::TokenPortError {
    fn from(value: Error) -> Self {
        match value {
            Error::Unavailable => Self::Unavailable,
            Error::CorruptData => Self::CorruptData,
            Error::Unexpected => Self::Unexpected,
        }
    }
}

impl From<Error> for TransientStateError {
    fn from(value: Error) -> Self {
        match value {
            Error::Unavailable => Self::Unavailable,
            Error::CorruptData => Self::CorruptData,
            Error::Unexpected => Self::Unexpected,
        }
    }
}

impl TenantTransientStateFactory for KevyBackend {
    fn for_tenant(
        &self,
        tenant_id: nazo_identity::TenantId,
    ) -> Result<ServerTransientStateBindings, TransientStateError> {
        Ok(ServerTransientStateBindings::new(Arc::new(
            KevyBackend::for_tenant(self, tenant_id),
        )))
    }
}

impl TenantDirectoryCachePort for KevyBackend {
    fn load(
        &self,
    ) -> TransientStateFuture<'_, Option<Arc<nazo_identity::TenantDirectorySnapshot>>> {
        Box::pin(async move {
            self.directory
                .lock()
                .map(|current| current.clone())
                .map_err(|_| TransientStateError::Unavailable)
        })
    }

    fn publish_authoritative<'a>(
        &'a self,
        snapshot: &'a nazo_identity::TenantDirectorySnapshot,
    ) -> TransientStateFuture<'a, bool> {
        Box::pin(async move {
            let mut current = self
                .directory
                .lock()
                .map_err(|_| TransientStateError::Unavailable)?;
            if current.as_ref().is_some_and(|value| {
                value.revision > snapshot.revision || value.as_ref() == snapshot
            }) {
                return Ok(false);
            }
            *current = Some(Arc::new(snapshot.clone()));
            Ok(true)
        })
    }
}

impl TransientStateHealthPort for TenantState {
    fn check(&self) -> TransientStateFuture<'_, ()> {
        Box::pin(async move { self.replay_check().await.map_err(Into::into) })
    }
}

macro_rules! capability {
    ($method:ident, $port:path) => {
        fn $method(&self) -> Arc<dyn $port> {
            Arc::new(self.clone())
        }
    };
}

impl ServerTransientStateProvider for TenantState {
    capability!(health, TransientStateHealthPort);
    capability!(authorization_state, nazo_auth::AuthorizationStateStorePort);
    capability!(token_state, nazo_auth::TokenStateStorePort);
    fn ciba_state(
        &self,
    ) -> Arc<dyn nazo_auth::CibaStateStorePort<Version = nazo_auth::CibaStateVersion>> {
        Arc::new(self.clone())
    }
    capability!(
        ciba_ping_deliveries,
        nazo_oauth_server::ports::transient_state::CibaPingDeliveryPort
    );
    fn device_state(
        &self,
    ) -> Arc<dyn nazo_auth::DeviceStateStorePort<Version = nazo_auth::DeviceStateVersion>> {
        Arc::new(self.clone())
    }
    capability!(dpop_state, nazo_auth::DpopStateStorePort);
    capability!(
        protected_resource_dpop_state,
        nazo_resource_server::ProtectedResourceDpopStateStore
    );
    capability!(
        fapi_http_signature_replay,
        nazo_oauth_server::ports::fapi_replay::FapiHttpSignatureReplayStore
    );
    capability!(request_rate_limits, nazo_auth::RequestRateLimitPort);
    capability!(
        email_verification,
        nazo_identity::ports::EmailVerificationStorePort
    );
    capability!(
        passkey_ceremonies,
        nazo_identity::ports::PasskeyCeremonyPort
    );
    capability!(federation_state, nazo_identity::ports::FederationStatePort);
    capability!(login_sessions, nazo_identity::ports::LoginSessionPort);
    capability!(sessions, nazo_identity::ports::SessionStorePort);
    capability!(login_throttle, nazo_identity::ports::LoginThrottlePort);
    capability!(
        mfa_attempt_throttle,
        nazo_identity::ports::MfaAttemptThrottlePort
    );
    capability!(delivery, nazo_identity::ports::DeliveryStorePort);
    capability!(
        avatar_upload_state,
        nazo_identity::ports::AvatarUploadStatePort
    );
}

#[must_use]
pub fn server_state_bindings(backend: KevyBackend) -> ServerStateBackendBindings {
    let backend = Arc::new(backend);
    ServerStateBackendBindings::new(backend.clone(), backend)
}
