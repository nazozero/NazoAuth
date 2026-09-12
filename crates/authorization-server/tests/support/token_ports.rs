use crate::services::{ServerAuthorizationService, ServerTokenService};
use chrono::{DateTime, Utc};
use nazo_auth::*;
use nazo_identity::SubjectClaims;
use serde_json::Value;
use std::sync::Arc;
use uuid::Uuid;

#[derive(Clone)]
struct HolderFixture {
    code: Result<Option<AuthorizationCodeState>, TokenPortError>,
    client: Result<Option<OAuthClient>, AuthorizationPortError>,
}

#[allow(unused_variables)]
impl TokenRepositoryPort for HolderFixture {
    fn validate_response_key_ring(&self) -> TokenFuture<'_, ()> {
        panic!("unexpected TokenRepositoryPort::validate_response_key_ring call")
    }
    fn commit_token_issuance<'a>(
        &'a self,
        input: CommitTokenIssuance,
    ) -> TokenFuture<'a, CommitTokenIssuanceResult> {
        panic!("unexpected TokenRepositoryPort::commit_token_issuance call")
    }
    fn token_issuance_by_grant<'a>(
        &'a self,
        tenant_id: Uuid,
        client_id: Uuid,
        grant_key: &'a str,
    ) -> TokenFuture<'a, Option<TokenIssuanceRecord>> {
        panic!("unexpected TokenRepositoryPort::token_issuance_by_grant call")
    }
    fn client_by_protocol_id<'a>(
        &'a self,
        tenant_id: Uuid,
        client_id: &'a str,
    ) -> TokenFuture<'a, Option<OAuthClient>> {
        panic!("unexpected TokenRepositoryPort::client_by_protocol_id call")
    }
    fn refresh_token<'a>(
        &'a self,
        tenant_id: Uuid,
        raw_token: &'a str,
    ) -> TokenFuture<'a, Option<RefreshToken>> {
        panic!("unexpected TokenRepositoryPort::refresh_token call")
    }
    fn inspect_lost_response_successor<'a>(
        &'a self,
        token: &'a RefreshToken,
        client_id: Uuid,
        retry_started_at: DateTime<Utc>,
    ) -> TokenFuture<'a, Option<RefreshToken>> {
        panic!("unexpected TokenRepositoryPort::inspect_lost_response_successor call")
    }
    fn active_subject_claims(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
    ) -> TokenFuture<'_, Option<SubjectClaims>> {
        panic!("unexpected TokenRepositoryPort::active_subject_claims call")
    }
    fn revoke_issued_tokens<'a>(
        &'a self,
        tenant_id: Uuid,
        client_id: Uuid,
        access_token_jti: &'a str,
        access_token_expires_at: Option<DateTime<Utc>>,
        refresh_token_family_id: Option<Uuid>,
    ) -> TokenFuture<'a, ()> {
        panic!("unexpected TokenRepositoryPort::revoke_issued_tokens call")
    }
    fn access_token_revoked<'a>(&'a self, tenant_id: Uuid, jti: &'a str) -> TokenFuture<'a, bool> {
        panic!("unexpected TokenRepositoryPort::access_token_revoked call")
    }
    fn refresh_family_active(
        &self,
        tenant_id: Uuid,
        family_id: Uuid,
        user_id: Uuid,
    ) -> TokenFuture<'_, bool> {
        panic!("unexpected TokenRepositoryPort::refresh_family_active call")
    }
    fn revoke_token<'a>(&'a self, input: TokenRevocation<'a>) -> TokenFuture<'a, usize> {
        panic!("unexpected TokenRepositoryPort::revoke_token call")
    }
}

#[allow(unused_variables)]
impl TokenStateStorePort for HolderFixture {
    fn load_authorization_code<'a>(
        &'a self,
        code_hash: &'a str,
    ) -> TokenFuture<'a, Option<AuthorizationCodeState>> {
        Box::pin(async move { self.code.clone() })
    }
    fn begin_authorization_code<'a>(
        &'a self,
        code_hash: &'a str,
        consuming_at: DateTime<Utc>,
    ) -> TokenFuture<'a, AuthorizationCodeBeginResult> {
        panic!("unexpected TokenStateStorePort::begin_authorization_code call")
    }
    fn mark_authorization_code<'a>(
        &'a self,
        code_hash: &'a str,
        replacement: &'a AuthorizationCodeState,
        ttl_seconds: u64,
    ) -> TokenFuture<'a, AuthorizationCodeTransitionResult> {
        panic!("unexpected TokenStateStorePort::mark_authorization_code call")
    }
    fn store_access_token_subject<'a>(
        &'a self,
        tenant_id: Uuid,
        jti: &'a str,
        user_id: Uuid,
        ttl_seconds: u64,
    ) -> TokenFuture<'a, ()> {
        panic!("unexpected TokenStateStorePort::store_access_token_subject call")
    }
    fn load_access_token_subject<'a>(
        &'a self,
        tenant_id: Uuid,
        jti: &'a str,
    ) -> TokenFuture<'a, Option<Uuid>> {
        panic!("unexpected TokenStateStorePort::load_access_token_subject call")
    }
    fn increment_token_management_rate<'a>(
        &'a self,
        subject: &'a str,
        window_seconds: u64,
    ) -> TokenFuture<'a, u64> {
        panic!("unexpected TokenStateStorePort::increment_token_management_rate call")
    }
    fn store_native_sso<'a>(
        &'a self,
        secret: &'a str,
        value: &'a Value,
        ttl_seconds: u64,
    ) -> TokenFuture<'a, ()> {
        panic!("unexpected TokenStateStorePort::store_native_sso call")
    }
    fn load_native_sso<'a>(&'a self, secret: &'a str) -> TokenFuture<'a, Option<Value>> {
        panic!("unexpected TokenStateStorePort::load_native_sso call")
    }
}

#[allow(unused_variables)]
impl AuthorizationRepositoryPort for HolderFixture {
    fn client_by_id<'a>(
        &'a self,
        client_id: &'a str,
    ) -> AuthorizationFuture<'a, Option<OAuthClient>> {
        Box::pin(async move { self.client.clone() })
    }
    fn mtls_trust_anchor_bundle(&self, client_id: Uuid) -> AuthorizationFuture<'_, String> {
        panic!("unexpected AuthorizationRepositoryPort::mtls_trust_anchor_bundle call")
    }
    fn grant<'a>(
        &'a self,
        user_id: Uuid,
        client_id: Uuid,
    ) -> AuthorizationFuture<'a, Option<StoredAuthorizationGrant>> {
        panic!("unexpected AuthorizationRepositoryPort::grant call")
    }
    fn upsert_grant<'a>(&'a self, write: GrantWrite<'a>) -> AuthorizationFuture<'a, ()> {
        panic!("unexpected AuthorizationRepositoryPort::upsert_grant call")
    }
    fn client_secret_salt<'a>(
        &'a self,
        client_id: Uuid,
    ) -> AuthorizationFuture<'a, Option<String>> {
        panic!("unexpected AuthorizationRepositoryPort::client_secret_salt call")
    }
    fn client_secret_digest_matches<'a>(
        &'a self,
        client_id: Uuid,
        candidate_digest: &'a str,
    ) -> AuthorizationFuture<'a, bool> {
        panic!("unexpected AuthorizationRepositoryPort::client_secret_digest_matches call")
    }
}

#[allow(unused_variables)]
impl AuthorizationStateStorePort for HolderFixture {
    fn load_par<'a>(
        &'a self,
        request_uri: &'a str,
    ) -> AuthorizationFuture<'a, Option<PushedAuthorizationRequest>> {
        panic!("unexpected AuthorizationStateStorePort::load_par call")
    }
    fn take_par<'a>(
        &'a self,
        request_uri: &'a str,
    ) -> AuthorizationFuture<'a, Option<PushedAuthorizationRequest>> {
        panic!("unexpected AuthorizationStateStorePort::take_par call")
    }
    fn compare_and_delete_par<'a>(
        &'a self,
        request_uri: &'a str,
        expected: &'a PushedAuthorizationRequest,
    ) -> AuthorizationFuture<'a, bool> {
        panic!("unexpected AuthorizationStateStorePort::compare_and_delete_par call")
    }
    fn store_par<'a>(
        &'a self,
        request_uri: &'a str,
        payload: &'a PushedAuthorizationRequest,
        ttl_seconds: u64,
    ) -> AuthorizationFuture<'a, ()> {
        panic!("unexpected AuthorizationStateStorePort::store_par call")
    }
    fn load_consent<'a>(
        &'a self,
        request_id: &'a str,
    ) -> AuthorizationFuture<'a, Option<ConsentPayload>> {
        panic!("unexpected AuthorizationStateStorePort::load_consent call")
    }
    fn take_consent<'a>(
        &'a self,
        request_id: &'a str,
    ) -> AuthorizationFuture<'a, Option<ConsentPayload>> {
        panic!("unexpected AuthorizationStateStorePort::take_consent call")
    }
    fn compare_and_delete_consent<'a>(
        &'a self,
        request_id: &'a str,
        expected: &'a ConsentPayload,
    ) -> AuthorizationFuture<'a, bool> {
        panic!("unexpected AuthorizationStateStorePort::compare_and_delete_consent call")
    }
    fn store_consent<'a>(
        &'a self,
        request_id: &'a str,
        payload: &'a ConsentPayload,
        ttl_seconds: u64,
    ) -> AuthorizationFuture<'a, ()> {
        panic!("unexpected AuthorizationStateStorePort::store_consent call")
    }
    fn store_authorization_code<'a>(
        &'a self,
        code_hash: &'a str,
        state: &'a AuthorizationCodeState,
        ttl_seconds: u64,
    ) -> AuthorizationFuture<'a, ()> {
        panic!("unexpected AuthorizationStateStorePort::store_authorization_code call")
    }
    fn delete_authorization_code<'a>(&'a self, code_hash: &'a str) -> AuthorizationFuture<'a, ()> {
        panic!("unexpected AuthorizationStateStorePort::delete_authorization_code call")
    }
    fn take_reauth_nonce<'a>(&'a self, nonce: &'a str) -> AuthorizationFuture<'a, Option<i64>> {
        panic!("unexpected AuthorizationStateStorePort::take_reauth_nonce call")
    }
    fn store_reauth_nonce<'a>(
        &'a self,
        nonce: &'a str,
        started_at: i64,
        ttl_seconds: u64,
    ) -> AuthorizationFuture<'a, ()> {
        panic!("unexpected AuthorizationStateStorePort::store_reauth_nonce call")
    }
    fn consume_jar<'a>(
        &'a self,
        client_id: &'a str,
        jti: &'a str,
        ttl_seconds: u64,
    ) -> AuthorizationFuture<'a, bool> {
        panic!("unexpected AuthorizationStateStorePort::consume_jar call")
    }
    fn consume_private_key_jwt<'a>(
        &'a self,
        client_id: &'a str,
        jti: &'a str,
        ttl_seconds: u64,
    ) -> AuthorizationFuture<'a, bool> {
        panic!("unexpected AuthorizationStateStorePort::consume_private_key_jwt call")
    }
    fn consume_jwt_bearer<'a>(
        &'a self,
        client_id: &'a str,
        jti: &'a str,
        ttl_seconds: u64,
    ) -> AuthorizationFuture<'a, bool> {
        panic!("unexpected AuthorizationStateStorePort::consume_jwt_bearer call")
    }
    fn consume_ciba_request_object<'a>(
        &'a self,
        client_id: &'a str,
        jti: &'a str,
        ttl_seconds: u64,
    ) -> AuthorizationFuture<'a, bool> {
        panic!("unexpected AuthorizationStateStorePort::consume_ciba_request_object call")
    }
    fn consume_dpop<'a>(
        &'a self,
        thumbprint: &'a str,
        jti: &'a str,
        ttl_seconds: u64,
    ) -> AuthorizationFuture<'a, bool> {
        panic!("unexpected AuthorizationStateStorePort::consume_dpop call")
    }
    fn issue_dpop_nonce<'a>(
        &'a self,
        nonce: &'a str,
        ttl_seconds: u64,
    ) -> AuthorizationFuture<'a, ()> {
        panic!("unexpected AuthorizationStateStorePort::issue_dpop_nonce call")
    }
    fn validate_dpop_nonce<'a>(&'a self, nonce: &'a str) -> AuthorizationFuture<'a, bool> {
        panic!("unexpected AuthorizationStateStorePort::validate_dpop_nonce call")
    }
    fn increment_rate<'a>(
        &'a self,
        dimension: AuthorizationRateDimension,
        subject: &'a str,
        window_seconds: u64,
    ) -> AuthorizationFuture<'a, u64> {
        panic!("unexpected AuthorizationStateStorePort::increment_rate call")
    }
}

pub(crate) fn services(
    code: Result<Option<AuthorizationCodeState>, TokenPortError>,
    client: Result<Option<OAuthClient>, AuthorizationPortError>,
) -> (ServerTokenService, ServerAuthorizationService) {
    let fixture = HolderFixture { code, client };
    let key = nazo_key_management::KeyManager::for_test(jsonwebtoken::Algorithm::EdDSA);
    (
        ServerTokenService::new(
            fixture.clone(),
            Arc::new(fixture.clone()) as Arc<dyn TokenStateStorePort>,
            key.clone(),
        ),
        ServerAuthorizationService::new(
            fixture.clone(),
            Arc::new(fixture) as Arc<dyn AuthorizationStateStorePort>,
            key,
        ),
    )
}
