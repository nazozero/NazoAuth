#![allow(dead_code)]

use super::app::services::{ServerAuthorizationService, ServerTokenService};
use jiff::Timestamp;
use nazo_auth::*;
use serde_json::Value;
use std::sync::Arc;
use uuid::Uuid;

#[derive(Clone)]
struct HolderFixture {
    code: Result<Option<AuthorizationCodeState>, TokenPortError>,
    client: Result<Option<OAuthClient>, AuthorizationPortError>,
    userinfo: Option<(nazo_identity::SubjectClaims, bool)>,
}

#[allow(unused_variables)]
impl TokenRepositoryPort for HolderFixture {
    fn machine_client_active(
        &self,
        _tenant_id: Uuid,
        _client_id: Uuid,
        _epoch: i64,
    ) -> TokenFuture<'_, bool> {
        panic!("unexpected machine-client check")
    }

    fn token_principal_state<'a>(
        &'a self,
        _tenant_id: Uuid,
        _client_epoch: i64,
        _user_id: Option<Uuid>,
        _subject: &'a str,
    ) -> TokenFuture<'a, nazo_auth::TokenPrincipalState> {
        panic!("unexpected issuance principal lookup")
    }

    fn commit_token_issuance<'a>(
        &'a self,
        input: CommitTokenIssuance,
    ) -> TokenFuture<'a, CommitTokenIssuanceResult> {
        panic!("unexpected TokenRepositoryPort::commit_token_issuance call")
    }
    fn single_use_redemption<'a>(
        &'a self,
        tenant_id: Uuid,
        client_id: Uuid,
        grant_key: &'a str,
    ) -> TokenFuture<'a, Option<SingleUseRedemption>> {
        panic!("unexpected TokenRepositoryPort::single_use_redemption call")
    }
    fn userinfo_snapshot<'a>(
        &'a self,
        tenant_id: Uuid,
        subject: UserinfoSubjectRef<'a>,
        client_id: &'a str,
    ) -> TokenFuture<'a, Option<UserinfoSnapshot>> {
        let (claims, _) = self
            .userinfo
            .as_ref()
            .expect("UserInfo read must be configured");
        let client = self.client.as_ref().unwrap().as_ref().unwrap();
        assert_eq!(tenant_id, client.tenant_id);
        assert_eq!(client_id, client.client_id);
        assert!(
            matches!(subject, UserinfoSubjectRef::UserId(id) if id == claims.subject.as_uuid())
        );
        Box::pin(async move {
            Ok(Some(UserinfoSnapshot {
                subject: claims.clone(),
                client: Some(client.clone()),
            }))
        })
    }
    fn refresh_token<'a>(
        &'a self,
        tenant_id: Uuid,
        raw_token: &'a str,
    ) -> TokenFuture<'a, Option<RefreshToken>> {
        panic!("unexpected TokenRepositoryPort::refresh_token call")
    }
    fn refresh_token_snapshot<'a>(
        &'a self,
        _tenant_id: Uuid,
        _raw_token: &'a str,
        _client_id: Uuid,
        _retry_started_at: jiff::Timestamp,
        _prepare_oidc_subject: bool,
    ) -> nazo_auth::TokenFuture<'a, Option<nazo_auth::RefreshTokenSnapshot>> {
        panic!("unexpected refresh snapshot lookup")
    }
    fn active_subject_claims<'a>(
        &'a self,
        tenant_id: Uuid,
        user_id: Uuid,
        token_subject: &'a str,
    ) -> TokenFuture<'a, Option<PreparedTokenSubject>> {
        panic!("unexpected TokenRepositoryPort::active_subject_claims call")
    }
    fn active_subject_id(&self, tenant_id: Uuid, user_id: Uuid) -> TokenFuture<'_, Option<Uuid>> {
        panic!("unexpected TokenRepositoryPort::active_subject_id call")
    }
    fn active_subject_id_by_access_token<'a>(
        &'a self,
        tenant_id: Uuid,
        jti: &'a str,
        subject: &'a str,
    ) -> TokenFuture<'a, Option<Uuid>> {
        panic!("unexpected TokenRepositoryPort::active_subject_id_by_access_token call")
    }
    fn revoke_issued_tokens<'a>(
        &'a self,
        tenant_id: Uuid,
        client_id: Uuid,
        access_token_jti: &'a str,
        access_token_expires_at: Option<Timestamp>,
        refresh_token_family_id: Option<Uuid>,
    ) -> TokenFuture<'a, ()> {
        panic!("unexpected TokenRepositoryPort::revoke_issued_tokens call")
    }
    fn access_token_revoked<'a>(
        &'a self,
        tenant_id: Uuid,
        claims: &'a nazo_auth::Claims,
    ) -> TokenFuture<'a, bool> {
        let (_, revoked) = self
            .userinfo
            .as_ref()
            .expect("revocation read must be configured");
        assert_eq!(tenant_id.to_string(), claims.tenant_id);
        Box::pin(async move { Ok(*revoked) })
    }
    fn refresh_family_active(
        &self,
        tenant_id: Uuid,
        family_id: Uuid,
        user_id: Uuid,
    ) -> TokenFuture<'_, bool> {
        panic!("unexpected TokenRepositoryPort::refresh_family_active call")
    }
    fn revoke_token_with_audit<'a>(
        &'a self,
        input: TokenRevocation<'a>,
        _client_public_id: &'a str,
        _source_ip_hash: &'a str,
    ) -> TokenFuture<'a, usize> {
        panic!("unexpected TokenRepositoryPort::revoke_token_with_audit call")
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
        consuming_at: Timestamp,
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
    fn delete_authorization_code<'a>(&'a self, code_hash: &'a str) -> TokenFuture<'a, ()> {
        panic!("unexpected TokenStateStorePort::delete_authorization_code call")
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
    fn active_client_presentation<'a>(
        &'a self,
        _client_id: &'a str,
    ) -> AuthorizationFuture<'a, Option<nazo_auth::ClientPresentation>> {
        panic!("unexpected AuthorizationRepositoryPort::active_client_presentation call")
    }

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
    fn commit_decision(
        &self,
        input: nazo_auth::AuthorizationDecisionCommit,
    ) -> AuthorizationFuture<'_, nazo_auth::AuthorizationDecisionCommitResult> {
        panic!("unexpected AuthorizationRepositoryPort::commit_decision call")
    }

    fn client_authentication_snapshot<'a>(
        &'a self,
        client_id: &'a str,
    ) -> AuthorizationFuture<'a, Option<nazo_auth::ClientAuthenticationSnapshot>> {
        let client = self.client.clone();
        Box::pin(async move {
            client.map(|client| {
                client.map(|client| nazo_auth::ClientAuthenticationSnapshot {
                    client_epoch: 0,
                    client,
                    secret_digest: None,
                })
            })
        })
    }
}

#[allow(unused_variables)]
impl AuthorizationStateStorePort for HolderFixture {
    fn load_par<'a>(
        &'a self,
        request_uri: &'a str,
    ) -> AuthorizationFuture<'a, Option<AuthorizationStateSnapshot<PushedAuthorizationRequest>>>
    {
        panic!("unexpected AuthorizationStateStorePort::load_par call")
    }
    fn compare_and_delete_par<'a>(
        &'a self,
        request_uri: &'a str,
        expected: &'a str,
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
    ) -> AuthorizationFuture<'a, Option<AuthorizationStateSnapshot<ConsentPayload>>> {
        panic!("unexpected AuthorizationStateStorePort::load_consent call")
    }
    fn compare_and_delete_consent<'a>(
        &'a self,
        request_id: &'a str,
        expected: &'a str,
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
        expires_at: i64,
    ) -> AuthorizationFuture<'a, bool> {
        panic!("unexpected AuthorizationStateStorePort::consume_jar call")
    }
    fn consume_client_attestation_proof<'a>(
        &'a self,
        _client_id: &'a str,
        _jti: &'a str,
        _window: nazo_auth::ClientAttestationProofWindow,
    ) -> AuthorizationFuture<'a, bool> {
        panic!("unexpected AuthorizationStateStorePort::consume_client_attestation_proof call")
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
        expires_at: i64,
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
    let fixture = HolderFixture {
        code,
        client,
        userinfo: None,
    };
    let key = nazo_key_management::KeyManager::for_test(nazo_crypto::jwt::Algorithm::EdDSA);
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

pub(crate) fn userinfo_service(
    keys: nazo_key_management::KeyManager,
    client: OAuthClient,
    subject: nazo_identity::SubjectClaims,
    revoked: bool,
) -> ServerTokenService {
    let ports = HolderFixture {
        code: Ok(None),
        client: Ok(Some(client)),
        userinfo: Some((subject, revoked)),
    };
    ServerTokenService::new(
        ports.clone(),
        Arc::new(ports) as Arc<dyn TokenStateStorePort>,
        keys,
    )
}
