use nazo_auth::*;
pub(super) struct AllowParRateState(pub std::sync::Arc<dyn AuthorizationStateStorePort>);
impl AuthorizationStateStorePort for AllowParRateState {
    fn load_par<'a>(
        &'a self,
        request_uri: &'a str,
    ) -> AuthorizationFuture<'a, Option<PushedAuthorizationRequest>> {
        self.0.as_ref().load_par(request_uri)
    }

    fn take_par<'a>(
        &'a self,
        request_uri: &'a str,
    ) -> AuthorizationFuture<'a, Option<PushedAuthorizationRequest>> {
        self.0.as_ref().take_par(request_uri)
    }

    fn compare_and_delete_par<'a>(
        &'a self,
        request_uri: &'a str,
        expected: &'a PushedAuthorizationRequest,
    ) -> AuthorizationFuture<'a, bool> {
        self.0
            .as_ref()
            .compare_and_delete_par(request_uri, expected)
    }

    fn store_par<'a>(
        &'a self,
        request_uri: &'a str,
        payload: &'a PushedAuthorizationRequest,
        ttl_seconds: u64,
    ) -> AuthorizationFuture<'a, ()> {
        self.0.as_ref().store_par(request_uri, payload, ttl_seconds)
    }

    fn load_consent<'a>(
        &'a self,
        request_id: &'a str,
    ) -> AuthorizationFuture<'a, Option<ConsentPayload>> {
        self.0.as_ref().load_consent(request_id)
    }

    fn take_consent<'a>(
        &'a self,
        request_id: &'a str,
    ) -> AuthorizationFuture<'a, Option<ConsentPayload>> {
        self.0.as_ref().take_consent(request_id)
    }

    fn compare_and_delete_consent<'a>(
        &'a self,
        request_id: &'a str,
        expected: &'a ConsentPayload,
    ) -> AuthorizationFuture<'a, bool> {
        self.0
            .as_ref()
            .compare_and_delete_consent(request_id, expected)
    }

    fn store_consent<'a>(
        &'a self,
        request_id: &'a str,
        payload: &'a ConsentPayload,
        ttl_seconds: u64,
    ) -> AuthorizationFuture<'a, ()> {
        self.0
            .as_ref()
            .store_consent(request_id, payload, ttl_seconds)
    }

    fn store_authorization_code<'a>(
        &'a self,
        code_hash: &'a str,
        state: &'a AuthorizationCodeState,
        ttl_seconds: u64,
    ) -> AuthorizationFuture<'a, ()> {
        self.0
            .as_ref()
            .store_authorization_code(code_hash, state, ttl_seconds)
    }

    fn delete_authorization_code<'a>(&'a self, code_hash: &'a str) -> AuthorizationFuture<'a, ()> {
        self.0.as_ref().delete_authorization_code(code_hash)
    }

    fn take_reauth_nonce<'a>(&'a self, nonce: &'a str) -> AuthorizationFuture<'a, Option<i64>> {
        self.0.as_ref().take_reauth_nonce(nonce)
    }

    fn store_reauth_nonce<'a>(
        &'a self,
        nonce: &'a str,
        started_at: i64,
        ttl_seconds: u64,
    ) -> AuthorizationFuture<'a, ()> {
        self.0
            .as_ref()
            .store_reauth_nonce(nonce, started_at, ttl_seconds)
    }

    fn consume_jar<'a>(
        &'a self,
        client_id: &'a str,
        jti: &'a str,
        ttl_seconds: u64,
    ) -> AuthorizationFuture<'a, bool> {
        self.0.as_ref().consume_jar(client_id, jti, ttl_seconds)
    }

    fn consume_private_key_jwt<'a>(
        &'a self,
        client_id: &'a str,
        jti: &'a str,
        ttl_seconds: u64,
    ) -> AuthorizationFuture<'a, bool> {
        self.0
            .as_ref()
            .consume_private_key_jwt(client_id, jti, ttl_seconds)
    }

    fn consume_jwt_bearer<'a>(
        &'a self,
        client_id: &'a str,
        jti: &'a str,
        ttl_seconds: u64,
    ) -> AuthorizationFuture<'a, bool> {
        self.0
            .as_ref()
            .consume_jwt_bearer(client_id, jti, ttl_seconds)
    }

    fn consume_ciba_request_object<'a>(
        &'a self,
        client_id: &'a str,
        jti: &'a str,
        ttl_seconds: u64,
    ) -> AuthorizationFuture<'a, bool> {
        self.0
            .as_ref()
            .consume_ciba_request_object(client_id, jti, ttl_seconds)
    }

    fn consume_dpop<'a>(
        &'a self,
        thumbprint: &'a str,
        jti: &'a str,
        ttl_seconds: u64,
    ) -> AuthorizationFuture<'a, bool> {
        self.0.as_ref().consume_dpop(thumbprint, jti, ttl_seconds)
    }

    fn issue_dpop_nonce<'a>(
        &'a self,
        nonce: &'a str,
        ttl_seconds: u64,
    ) -> AuthorizationFuture<'a, ()> {
        self.0.as_ref().issue_dpop_nonce(nonce, ttl_seconds)
    }

    fn validate_dpop_nonce<'a>(&'a self, nonce: &'a str) -> AuthorizationFuture<'a, bool> {
        self.0.as_ref().validate_dpop_nonce(nonce)
    }

    fn increment_rate<'a>(
        &'a self,
        _: AuthorizationRateDimension,
        _: &'a str,
        _: u64,
    ) -> AuthorizationFuture<'a, u64> {
        Box::pin(async { Ok(1) })
    }
}
