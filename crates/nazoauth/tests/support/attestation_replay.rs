//! One-shot lost-ACK injector for the real authorization state adapter.
//! All effects and policy stay in production; only the first successful PoP
//! acknowledgement is hidden from the application.

use nazo_auth::*;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

pub(crate) struct UnknownAttestationAck {
    inner: Arc<dyn AuthorizationStateStorePort>,
    lose_ack: AtomicBool,
}

impl UnknownAttestationAck {
    pub(crate) fn new(inner: Arc<dyn AuthorizationStateStorePort>) -> Self {
        Self {
            inner,
            lose_ack: AtomicBool::new(true),
        }
    }
}

impl AuthorizationStateStorePort for UnknownAttestationAck {
    fn load_par<'a>(
        &'a self,
        request_uri: &'a str,
    ) -> AuthorizationFuture<'a, Option<AuthorizationStateSnapshot<PushedAuthorizationRequest>>>
    {
        self.inner.as_ref().load_par(request_uri)
    }

    fn compare_and_delete_par<'a>(
        &'a self,
        request_uri: &'a str,
        expected: &'a str,
    ) -> AuthorizationFuture<'a, bool> {
        self.inner
            .as_ref()
            .compare_and_delete_par(request_uri, expected)
    }

    fn store_par<'a>(
        &'a self,
        request_uri: &'a str,
        payload: &'a PushedAuthorizationRequest,
        ttl_seconds: u64,
    ) -> AuthorizationFuture<'a, ()> {
        self.inner
            .as_ref()
            .store_par(request_uri, payload, ttl_seconds)
    }

    fn load_consent<'a>(
        &'a self,
        request_id: &'a str,
    ) -> AuthorizationFuture<'a, Option<AuthorizationStateSnapshot<ConsentPayload>>> {
        self.inner.as_ref().load_consent(request_id)
    }

    fn take_consent<'a>(
        &'a self,
        request_id: &'a str,
    ) -> AuthorizationFuture<'a, Option<ConsentPayload>> {
        self.inner.as_ref().take_consent(request_id)
    }

    fn compare_and_delete_consent<'a>(
        &'a self,
        request_id: &'a str,
        expected: &'a str,
    ) -> AuthorizationFuture<'a, bool> {
        self.inner
            .as_ref()
            .compare_and_delete_consent(request_id, expected)
    }

    fn discard_decision_material<'a>(
        &'a self,
        request_id: &'a str,
        expected_consent: &'a str,
        pushed_request: Option<(&'a str, &'a str)>,
    ) -> DecisionMaterialDiscardFuture<'a> {
        self.inner
            .as_ref()
            .discard_decision_material(request_id, expected_consent, pushed_request)
    }

    fn store_consent<'a>(
        &'a self,
        request_id: &'a str,
        payload: &'a ConsentPayload,
        ttl_seconds: u64,
    ) -> AuthorizationFuture<'a, ()> {
        self.inner
            .as_ref()
            .store_consent(request_id, payload, ttl_seconds)
    }

    fn store_authorization_code<'a>(
        &'a self,
        code_hash: &'a str,
        state: &'a AuthorizationCodeState,
        ttl_seconds: u64,
    ) -> AuthorizationFuture<'a, ()> {
        self.inner
            .as_ref()
            .store_authorization_code(code_hash, state, ttl_seconds)
    }

    fn delete_authorization_code<'a>(&'a self, code_hash: &'a str) -> AuthorizationFuture<'a, ()> {
        self.inner.as_ref().delete_authorization_code(code_hash)
    }

    fn take_reauth_nonce<'a>(&'a self, nonce: &'a str) -> AuthorizationFuture<'a, Option<i64>> {
        self.inner.as_ref().take_reauth_nonce(nonce)
    }

    fn store_reauth_nonce<'a>(
        &'a self,
        nonce: &'a str,
        started_at: i64,
        ttl_seconds: u64,
    ) -> AuthorizationFuture<'a, ()> {
        self.inner
            .as_ref()
            .store_reauth_nonce(nonce, started_at, ttl_seconds)
    }

    fn consume_jar<'a>(
        &'a self,
        client_id: &'a str,
        jti: &'a str,
        expires_at: i64,
    ) -> AuthorizationFuture<'a, bool> {
        self.inner.as_ref().consume_jar(client_id, jti, expires_at)
    }

    fn consume_client_attestation_proof<'a>(
        &'a self,
        client_id: &'a str,
        jti: &'a str,
        window: nazo_auth::ClientAttestationProofWindow,
    ) -> AuthorizationFuture<'a, bool> {
        Box::pin(async move {
            let accepted = self
                .inner
                .consume_client_attestation_proof(client_id, jti, window)
                .await?;
            if accepted && self.lose_ack.swap(false, Ordering::SeqCst) {
                Err(AuthorizationPortError::Unavailable)
            } else {
                Ok(accepted)
            }
        })
    }

    fn consume_private_key_jwt<'a>(
        &'a self,
        client_id: &'a str,
        jti: &'a str,
        ttl_seconds: u64,
    ) -> AuthorizationFuture<'a, bool> {
        self.inner
            .as_ref()
            .consume_private_key_jwt(client_id, jti, ttl_seconds)
    }

    fn consume_jwt_bearer<'a>(
        &'a self,
        client_id: &'a str,
        jti: &'a str,
        ttl_seconds: u64,
    ) -> AuthorizationFuture<'a, bool> {
        self.inner
            .as_ref()
            .consume_jwt_bearer(client_id, jti, ttl_seconds)
    }

    fn consume_ciba_request_object<'a>(
        &'a self,
        client_id: &'a str,
        jti: &'a str,
        expires_at: i64,
    ) -> AuthorizationFuture<'a, bool> {
        self.inner
            .as_ref()
            .consume_ciba_request_object(client_id, jti, expires_at)
    }

    fn consume_dpop<'a>(
        &'a self,
        thumbprint: &'a str,
        jti: &'a str,
        ttl_seconds: u64,
    ) -> AuthorizationFuture<'a, bool> {
        self.inner
            .as_ref()
            .consume_dpop(thumbprint, jti, ttl_seconds)
    }

    fn issue_dpop_nonce<'a>(
        &'a self,
        nonce: &'a str,
        ttl_seconds: u64,
    ) -> AuthorizationFuture<'a, ()> {
        self.inner.as_ref().issue_dpop_nonce(nonce, ttl_seconds)
    }

    fn validate_dpop_nonce<'a>(&'a self, nonce: &'a str) -> AuthorizationFuture<'a, bool> {
        self.inner.as_ref().validate_dpop_nonce(nonce)
    }

    fn increment_rate<'a>(
        &'a self,
        dimension: AuthorizationRateDimension,
        subject: &'a str,
        window_seconds: u64,
    ) -> AuthorizationFuture<'a, u64> {
        self.inner
            .as_ref()
            .increment_rate(dimension, subject, window_seconds)
    }
}
