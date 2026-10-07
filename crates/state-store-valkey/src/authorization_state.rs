use nazo_auth::{
    AuthorizationCodeState, AuthorizationFuture, AuthorizationPortError,
    AuthorizationRateDimension, AuthorizationStateSnapshot, AuthorizationStateStorePort,
    ConsentPayload, DecisionMaterialDiscardError, DecisionMaterialDiscardFuture,
    PushedAuthorizationRequest,
};

use crate::{
    AuthorizationPreparationWrite, AuthorizationStore, Error, ErrorKind, RateDimension,
    RateLimitStore, ReplayStore, ValkeyConnection,
};

/// Valkey mechanisms required by an authorization flow, grouped at the
/// infrastructure boundary rather than in the HTTP layer.
#[derive(Clone, Debug)]
pub struct AuthorizationStateAdapter {
    authorization: AuthorizationStore,
    replay: ReplayStore,
    rate_limits: RateLimitStore,
}

impl AuthorizationStateAdapter {
    #[must_use]
    pub fn new(connection: &ValkeyConnection) -> Self {
        Self {
            authorization: AuthorizationStore::new(connection),
            replay: ReplayStore::new(connection),
            rate_limits: RateLimitStore::new(connection),
        }
    }
}

impl AuthorizationStateStorePort for AuthorizationStateAdapter {
    fn load_par<'a>(
        &'a self,
        request_uri: &'a str,
    ) -> AuthorizationFuture<'a, Option<AuthorizationStateSnapshot<PushedAuthorizationRequest>>>
    {
        Box::pin(async move {
            self.authorization
                .load_par(request_uri)
                .await
                .map_err(map_error)
        })
    }

    fn compare_and_delete_par<'a>(
        &'a self,
        request_uri: &'a str,
        expected: &'a str,
    ) -> AuthorizationFuture<'a, bool> {
        Box::pin(async move {
            self.authorization
                .compare_and_delete_par(request_uri, expected)
                .await
                .map_err(map_error)
        })
    }

    fn store_par<'a>(
        &'a self,
        request_uri: &'a str,
        payload: &'a PushedAuthorizationRequest,
        ttl_seconds: u64,
    ) -> AuthorizationFuture<'a, ()> {
        Box::pin(async move {
            self.authorization
                .store_par(request_uri, payload, ttl_seconds)
                .await
                .map_err(map_error)
                .and_then(map_preparation_write)
        })
    }

    fn load_consent<'a>(
        &'a self,
        request_id: &'a str,
    ) -> AuthorizationFuture<'a, Option<AuthorizationStateSnapshot<ConsentPayload>>> {
        Box::pin(async move {
            self.authorization
                .load_consent_snapshot(request_id)
                .await
                .map_err(map_error)
        })
    }

    fn take_consent<'a>(
        &'a self,
        request_id: &'a str,
    ) -> AuthorizationFuture<'a, Option<ConsentPayload>> {
        Box::pin(async move {
            self.authorization
                .take_consent(request_id)
                .await
                .map_err(map_error)
        })
    }

    fn compare_and_delete_consent<'a>(
        &'a self,
        request_id: &'a str,
        expected: &'a str,
    ) -> AuthorizationFuture<'a, bool> {
        Box::pin(async move {
            self.authorization
                .compare_and_delete_consent(request_id, expected)
                .await
                .map_err(map_error)
        })
    }

    fn discard_decision_material<'a>(
        &'a self,
        request_id: &'a str,
        expected_consent: &'a str,
        pushed_request: Option<(&'a str, &'a str)>,
    ) -> DecisionMaterialDiscardFuture<'a> {
        Box::pin(async move {
            self.authorization
                .discard_decision_material(request_id, expected_consent, pushed_request)
                .await
                .map_err(map_discard_error)
        })
    }

    fn store_consent<'a>(
        &'a self,
        request_id: &'a str,
        payload: &'a ConsentPayload,
        ttl_seconds: u64,
    ) -> AuthorizationFuture<'a, ()> {
        Box::pin(async move {
            self.authorization
                .store_consent(request_id, payload, ttl_seconds)
                .await
                .map_err(map_error)
                .and_then(map_preparation_write)
        })
    }

    fn store_authorization_code<'a>(
        &'a self,
        code_hash: &'a str,
        state: &'a AuthorizationCodeState,
        ttl_seconds: u64,
    ) -> AuthorizationFuture<'a, ()> {
        Box::pin(async move {
            self.authorization
                .store_authorization_code_hash(code_hash, state, ttl_seconds)
                .await
                .map_err(map_error)
        })
    }

    fn delete_authorization_code<'a>(&'a self, code_hash: &'a str) -> AuthorizationFuture<'a, ()> {
        Box::pin(async move {
            self.authorization
                .delete_authorization_code_hash(code_hash)
                .await
                .map(|_| ())
                .map_err(map_error)
        })
    }

    fn take_reauth_nonce<'a>(&'a self, nonce: &'a str) -> AuthorizationFuture<'a, Option<i64>> {
        Box::pin(async move {
            self.authorization
                .take_reauth_nonce(nonce)
                .await
                .map_err(map_error)
        })
    }

    fn store_reauth_nonce<'a>(
        &'a self,
        nonce: &'a str,
        started_at: i64,
        ttl_seconds: u64,
    ) -> AuthorizationFuture<'a, ()> {
        Box::pin(async move {
            self.authorization
                .store_reauth_nonce(nonce, started_at, ttl_seconds)
                .await
                .map_err(map_error)
        })
    }

    fn consume_jar<'a>(
        &'a self,
        client_id: &'a str,
        jti: &'a str,
        expires_at: i64,
    ) -> AuthorizationFuture<'a, bool> {
        Box::pin(async move {
            self.replay
                .consume_jar(client_id, jti, expires_at)
                .await
                .map_err(map_error)
        })
    }

    fn consume_client_attestation_proof<'a>(
        &'a self,
        client_id: &'a str,
        jti: &'a str,
        window: nazo_auth::ClientAttestationProofWindow,
    ) -> AuthorizationFuture<'a, bool> {
        Box::pin(async move {
            self.replay
                .consume_client_attestation_proof(client_id, jti, window)
                .await
                .map_err(map_error)
        })
    }

    fn consume_private_key_jwt<'a>(
        &'a self,
        client_id: &'a str,
        jti: &'a str,
        ttl_seconds: u64,
    ) -> AuthorizationFuture<'a, bool> {
        Box::pin(async move {
            self.replay
                .consume_private_key_jwt(client_id, jti, ttl_seconds)
                .await
                .map_err(map_error)
        })
    }

    fn consume_jwt_bearer<'a>(
        &'a self,
        client_id: &'a str,
        jti: &'a str,
        ttl_seconds: u64,
    ) -> AuthorizationFuture<'a, bool> {
        Box::pin(async move {
            self.replay
                .consume_jwt_bearer(client_id, jti, ttl_seconds)
                .await
                .map_err(map_error)
        })
    }

    fn consume_ciba_request_object<'a>(
        &'a self,
        client_id: &'a str,
        jti: &'a str,
        expires_at: i64,
    ) -> AuthorizationFuture<'a, bool> {
        Box::pin(async move {
            self.replay
                .consume_ciba_request_object(client_id, jti, expires_at)
                .await
                .map_err(map_error)
        })
    }

    fn consume_dpop<'a>(
        &'a self,
        thumbprint: &'a str,
        jti: &'a str,
        ttl_seconds: u64,
    ) -> AuthorizationFuture<'a, bool> {
        Box::pin(async move {
            self.replay
                .consume_dpop(thumbprint, jti, ttl_seconds)
                .await
                .map_err(map_error)
        })
    }

    fn issue_dpop_nonce<'a>(
        &'a self,
        nonce: &'a str,
        ttl_seconds: u64,
    ) -> AuthorizationFuture<'a, ()> {
        Box::pin(async move {
            self.replay
                .issue_dpop_nonce(nonce, ttl_seconds)
                .await
                .map_err(map_error)
        })
    }

    fn validate_dpop_nonce<'a>(&'a self, nonce: &'a str) -> AuthorizationFuture<'a, bool> {
        Box::pin(async move {
            self.replay
                .validate_dpop_nonce(nonce)
                .await
                .map_err(map_error)
        })
    }

    fn increment_rate<'a>(
        &'a self,
        dimension: AuthorizationRateDimension,
        subject: &'a str,
        window_seconds: u64,
    ) -> AuthorizationFuture<'a, u64> {
        Box::pin(async move {
            let dimension = match dimension {
                AuthorizationRateDimension::Token => RateDimension::Token,
                AuthorizationRateDimension::TokenManagement => RateDimension::TokenManagement,
            };
            self.rate_limits
                .increment(dimension, subject, window_seconds)
                .await
                .map_err(map_error)
        })
    }
}

fn map_preparation_write(
    outcome: AuthorizationPreparationWrite,
) -> Result<(), AuthorizationPortError> {
    match outcome {
        AuthorizationPreparationWrite::Stored => Ok(()),
        AuthorizationPreparationWrite::Conflict => Err(AuthorizationPortError::Conflict),
    }
}

fn map_discard_error(error: DecisionMaterialDiscardError<Error>) -> DecisionMaterialDiscardError {
    match error {
        DecisionMaterialDiscardError::ConsentOrUnknown(source) => {
            DecisionMaterialDiscardError::ConsentOrUnknown(map_error(source))
        }
        DecisionMaterialDiscardError::PushedRequest(source) => {
            DecisionMaterialDiscardError::PushedRequest(map_error(source))
        }
    }
}

fn map_error(error: Error) -> AuthorizationPortError {
    match error.kind() {
        ErrorKind::Timeout | ErrorKind::Unavailable => AuthorizationPortError::Unavailable,
        ErrorKind::CorruptData => AuthorizationPortError::CorruptData,
        ErrorKind::Protocol | ErrorKind::UnexpectedResult => AuthorizationPortError::Unexpected,
    }
}

#[cfg(test)]
#[path = "../tests/unit/authorization_state.rs"]
mod tests;
