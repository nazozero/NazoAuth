//! Override the authentication budget port while retaining the real state provider.
use nazo_oauth_server::ports::transient_state::{
    CibaPingDeliveryPort, ServerTransientStateBindings, ServerTransientStateProvider,
    TransientStateHealthPort,
};
use std::sync::Arc;

use nazo_auth::{
    AuthorizationStateStorePort, CibaStateStorePort, CibaStateVersion, DeviceStateStorePort,
    DeviceStateVersion, DpopStateStorePort, TokenStateStorePort,
};
use nazo_identity::ports::{
    AvatarUploadStatePort, DeliveryStorePort, EmailVerificationStorePort, FederationStatePort,
    LoginSessionPort, LoginThrottlePort, MfaAttemptThrottlePort, PasskeyCeremonyPort,
    SessionStorePort,
};

pub(crate) fn with_rate_limits(
    state: &ServerTransientStateBindings,
    rate_limits: Arc<dyn nazo_auth::RequestRateLimitPort>,
) -> ServerTransientStateBindings {
    ServerTransientStateBindings::new(Arc::new(RateLimitOverride {
        base: state.provider().clone(),
        rate_limits,
    }))
}

struct RateLimitOverride {
    base: Arc<dyn ServerTransientStateProvider>,
    rate_limits: Arc<dyn nazo_auth::RequestRateLimitPort>,
}

impl ServerTransientStateProvider for RateLimitOverride {
    fn health(&self) -> Arc<dyn TransientStateHealthPort> {
        self.base.health()
    }
    fn authorization_state(&self) -> Arc<dyn AuthorizationStateStorePort> {
        self.base.authorization_state()
    }
    fn token_state(&self) -> Arc<dyn TokenStateStorePort> {
        self.base.token_state()
    }
    fn ciba_state(&self) -> Arc<dyn CibaStateStorePort<Version = CibaStateVersion>> {
        self.base.ciba_state()
    }
    fn ciba_ping_deliveries(&self) -> Arc<dyn CibaPingDeliveryPort> {
        self.base.ciba_ping_deliveries()
    }
    fn device_state(&self) -> Arc<dyn DeviceStateStorePort<Version = DeviceStateVersion>> {
        self.base.device_state()
    }
    fn dpop_state(&self) -> Arc<dyn DpopStateStorePort> {
        self.base.dpop_state()
    }
    fn protected_resource_dpop_state(
        &self,
    ) -> Arc<dyn nazo_resource_server::ProtectedResourceDpopStateStore> {
        self.base.protected_resource_dpop_state()
    }
    fn fapi_http_signature_replay(
        &self,
    ) -> Arc<dyn nazo_oauth_server::ports::fapi_replay::FapiHttpSignatureReplayStore> {
        self.base.fapi_http_signature_replay()
    }
    fn request_rate_limits(&self) -> Arc<dyn nazo_auth::RequestRateLimitPort> {
        self.rate_limits.clone()
    }
    fn email_verification(&self) -> Arc<dyn EmailVerificationStorePort> {
        self.base.email_verification()
    }
    fn passkey_ceremonies(&self) -> Arc<dyn PasskeyCeremonyPort> {
        self.base.passkey_ceremonies()
    }
    fn federation_state(&self) -> Arc<dyn FederationStatePort> {
        self.base.federation_state()
    }
    fn login_sessions(&self) -> Arc<dyn LoginSessionPort> {
        self.base.login_sessions()
    }
    fn sessions(&self) -> Arc<dyn SessionStorePort> {
        self.base.sessions()
    }
    fn login_throttle(&self) -> Arc<dyn LoginThrottlePort> {
        self.base.login_throttle()
    }
    fn mfa_attempt_throttle(&self) -> Arc<dyn MfaAttemptThrottlePort> {
        self.base.mfa_attempt_throttle()
    }
    fn delivery(&self) -> Arc<dyn DeliveryStorePort> {
        self.base.delivery()
    }
    fn avatar_upload_state(&self) -> Arc<dyn AvatarUploadStatePort> {
        self.base.avatar_upload_state()
    }
}
