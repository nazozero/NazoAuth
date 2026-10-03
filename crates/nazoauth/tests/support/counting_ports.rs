//! Protocol-layer call spies that delegate every port method to the real
//! PostgreSQL-backed implementation while counting selected reads. They exist
//! so HTTP/application tests can prove how many times a port method runs per
//! request — a separate evidence category from the SQL-level counters in
//! `persistence-postgres`'s `query_counter` support.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use nazo_auth::{
    AuthorizationFuture, AuthorizationRepositoryPort, ClientAuthenticationSnapshot,
    CommitTokenIssuance, CommitTokenIssuanceResult, OAuthClient, RefreshToken, SingleUseRedemption,
    StoredAuthorizationGrant, TokenFuture, TokenRepositoryPort, TokenRevocation,
};
use uuid::Uuid;

/// Delegating `TokenRepositoryPort` that counts the two subject-read methods
/// changed by the remediation: `active_subject_claims` (CIBA snapshot read)
/// and `active_subject_id_by_access_token` (exchange owner resolution).
#[derive(Clone)]
pub(crate) struct CountingTokenRepository {
    inner: Arc<dyn TokenRepositoryPort>,
    pub(crate) active_subject_claims_calls: Arc<AtomicUsize>,
    pub(crate) owner_lookup_calls: Arc<AtomicUsize>,
    pub(crate) userinfo_snapshot_calls: Arc<AtomicUsize>,
    pub(crate) principal_snapshot_calls: Arc<AtomicUsize>,
    fail_owner_lookups: bool,
    lose_next_commit_ack: Arc<AtomicBool>,
    code_commit_keys: Arc<Mutex<Vec<String>>>,
}

impl CountingTokenRepository {
    pub(crate) fn new(inner: Arc<dyn TokenRepositoryPort>) -> Self {
        Self {
            inner,
            active_subject_claims_calls: Arc::new(AtomicUsize::new(0)),
            owner_lookup_calls: Arc::new(AtomicUsize::new(0)),
            userinfo_snapshot_calls: Arc::new(AtomicUsize::new(0)),
            principal_snapshot_calls: Arc::new(AtomicUsize::new(0)),
            fail_owner_lookups: false,
            lose_next_commit_ack: Arc::new(AtomicBool::new(false)),
            code_commit_keys: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Variant whose owner lookup reports a backend outage, used to prove the
    /// caller maps repository failures to server_error rather than
    /// invalid_grant.
    pub(crate) fn with_failing_owner_lookup(inner: Arc<dyn TokenRepositoryPort>) -> Self {
        Self {
            fail_owner_lookups: true,
            ..Self::new(inner)
        }
    }

    /// Let the real adapter commit its effect, then hide exactly one ACK.
    pub(crate) fn with_lost_commit_ack(inner: Arc<dyn TokenRepositoryPort>) -> Self {
        Self {
            lose_next_commit_ack: Arc::new(AtomicBool::new(true)),
            ..Self::new(inner)
        }
    }

    pub(crate) fn code_commit_keys(&self) -> Vec<String> {
        self.code_commit_keys.lock().unwrap().clone()
    }

    pub(crate) fn active_subject_claims_count(&self) -> usize {
        self.active_subject_claims_calls.load(Ordering::SeqCst)
    }

    pub(crate) fn owner_lookup_count(&self) -> usize {
        self.owner_lookup_calls.load(Ordering::SeqCst)
    }

    pub(crate) fn principal_snapshot_count(&self) -> usize {
        self.principal_snapshot_calls.load(Ordering::SeqCst)
    }

    pub(crate) fn userinfo_snapshot_count(&self) -> usize {
        self.userinfo_snapshot_calls.load(Ordering::SeqCst)
    }

    /// Total subject-data reads (`active_subject_claims` + `userinfo_snapshot`)
    /// — matches the probe counter the issue tests assert stays at zero for
    /// non-OIDC issuance.
    pub(crate) fn subject_data_reads(&self) -> usize {
        self.active_subject_claims_count() + self.userinfo_snapshot_count()
    }
}

impl TokenRepositoryPort for CountingTokenRepository {
    fn token_principal_state<'a>(
        &'a self,
        tenant_id: Uuid,
        client_epoch: i64,
        user_id: Option<Uuid>,
        subject: &'a str,
    ) -> TokenFuture<'a, nazo_auth::TokenPrincipalState> {
        self.principal_snapshot_calls.fetch_add(1, Ordering::SeqCst);
        self.inner
            .token_principal_state(tenant_id, client_epoch, user_id, subject)
    }

    fn commit_token_issuance<'a>(
        &'a self,
        input: CommitTokenIssuance,
    ) -> TokenFuture<'a, CommitTokenIssuanceResult> {
        if let nazo_auth::TokenIssuanceMode::AuthorizationCode { code_identity, .. } = &input.mode {
            self.code_commit_keys
                .lock()
                .unwrap()
                .push(code_identity.clone());
        }
        Box::pin(async move {
            let result = self.inner.commit_token_issuance(input).await?;
            if result == CommitTokenIssuanceResult::Committed
                && self.lose_next_commit_ack.swap(false, Ordering::SeqCst)
            {
                Err(nazo_auth::TokenPortError::Unavailable)
            } else {
                Ok(result)
            }
        })
    }

    fn single_use_redemption<'a>(
        &'a self,
        tenant_id: Uuid,
        client_id: Uuid,
        grant_key: &'a str,
    ) -> TokenFuture<'a, Option<SingleUseRedemption>> {
        self.inner
            .single_use_redemption(tenant_id, client_id, grant_key)
    }
    fn userinfo_snapshot<'a>(
        &'a self,
        tenant_id: Uuid,
        subject: nazo_auth::UserinfoSubjectRef<'a>,
        client_id: &'a str,
    ) -> TokenFuture<'a, Option<nazo_auth::UserinfoSnapshot>> {
        self.userinfo_snapshot_calls.fetch_add(1, Ordering::SeqCst);
        self.inner.userinfo_snapshot(tenant_id, subject, client_id)
    }

    fn refresh_token<'a>(
        &'a self,
        tenant_id: Uuid,
        raw_token: &'a str,
    ) -> TokenFuture<'a, Option<RefreshToken>> {
        self.inner.refresh_token(tenant_id, raw_token)
    }

    fn inspect_lost_response_successor<'a>(
        &'a self,
        token: &'a RefreshToken,
        client_id: Uuid,
        retry_started_at: chrono::DateTime<chrono::Utc>,
    ) -> TokenFuture<'a, Option<RefreshToken>> {
        self.inner
            .inspect_lost_response_successor(token, client_id, retry_started_at)
    }

    fn active_subject_claims<'a>(
        &'a self,
        tenant_id: Uuid,
        user_id: Uuid,
        token_subject: &'a str,
    ) -> TokenFuture<'a, Option<nazo_auth::PreparedTokenSubject>> {
        self.active_subject_claims_calls
            .fetch_add(1, Ordering::SeqCst);
        self.inner
            .active_subject_claims(tenant_id, user_id, token_subject)
    }

    fn active_subject_id<'a>(
        &'a self,
        tenant_id: Uuid,
        user_id: Uuid,
    ) -> TokenFuture<'a, Option<Uuid>> {
        self.inner.active_subject_id(tenant_id, user_id)
    }

    fn active_subject_id_by_access_token<'a>(
        &'a self,
        tenant_id: Uuid,
        jti: &'a str,
        subject: &'a str,
    ) -> TokenFuture<'a, Option<Uuid>> {
        self.owner_lookup_calls.fetch_add(1, Ordering::SeqCst);
        if self.fail_owner_lookups {
            return Box::pin(async { Err(nazo_auth::TokenPortError::Unavailable) });
        }
        self.inner
            .active_subject_id_by_access_token(tenant_id, jti, subject)
    }

    fn revoke_issued_tokens<'a>(
        &'a self,
        tenant_id: Uuid,
        client_id: Uuid,
        access_token_jti: &'a str,
        access_token_expires_at: Option<chrono::DateTime<chrono::Utc>>,
        refresh_token_family_id: Option<Uuid>,
    ) -> TokenFuture<'a, ()> {
        self.inner.revoke_issued_tokens(
            tenant_id,
            client_id,
            access_token_jti,
            access_token_expires_at,
            refresh_token_family_id,
        )
    }

    fn access_token_revoked<'a>(
        &'a self,
        tenant_id: Uuid,
        claims: &'a nazo_auth::Claims,
    ) -> TokenFuture<'a, bool> {
        self.inner.access_token_revoked(tenant_id, claims)
    }

    fn refresh_family_active<'a>(
        &'a self,
        tenant_id: Uuid,
        family_id: Uuid,
        user_id: Uuid,
    ) -> TokenFuture<'a, bool> {
        self.inner
            .refresh_family_active(tenant_id, family_id, user_id)
    }

    fn revoke_token<'a>(&'a self, input: TokenRevocation<'a>) -> TokenFuture<'a, usize> {
        self.inner.revoke_token(input)
    }

    fn revoke_token_with_audit<'a>(
        &'a self,
        input: nazo_auth::TokenRevocation<'a>,
        client_public_id: &'a str,
        source_ip_hash: &'a str,
    ) -> nazo_auth::TokenFuture<'a, usize> {
        self.inner
            .revoke_token_with_audit(input, client_public_id, source_ip_hash)
    }
}

/// Delegating `AuthorizationRepositoryPort` that counts the client-data reads
/// on the secret-authentication path: the combined
/// `client_authentication_snapshot` (client + salt in one query) and the
/// retained `client_secret_digest_matches` check.
#[derive(Clone)]
pub(crate) struct CountingAuthorizationRepository {
    inner: Arc<dyn AuthorizationRepositoryPort>,
    pub(crate) snapshot_calls: Arc<AtomicUsize>,
    pub(crate) digest_calls: Arc<AtomicUsize>,
    pub(crate) client_by_id_calls: Arc<AtomicUsize>,
}

impl CountingAuthorizationRepository {
    pub(crate) fn new(inner: Arc<dyn AuthorizationRepositoryPort>) -> Self {
        Self {
            inner,
            snapshot_calls: Arc::new(AtomicUsize::new(0)),
            digest_calls: Arc::new(AtomicUsize::new(0)),
            client_by_id_calls: Arc::new(AtomicUsize::new(0)),
        }
    }

    pub(crate) fn snapshot_count(&self) -> usize {
        self.snapshot_calls.load(Ordering::SeqCst)
    }

    pub(crate) fn digest_count(&self) -> usize {
        self.digest_calls.load(Ordering::SeqCst)
    }

    pub(crate) fn client_by_id_count(&self) -> usize {
        self.client_by_id_calls.load(Ordering::SeqCst)
    }
}

impl AuthorizationRepositoryPort for CountingAuthorizationRepository {
    fn client_by_id<'a>(
        &'a self,
        client_id: &'a str,
    ) -> AuthorizationFuture<'a, Option<OAuthClient>> {
        self.client_by_id_calls.fetch_add(1, Ordering::SeqCst);
        self.inner.client_by_id(client_id)
    }

    fn client_authentication_snapshot<'a>(
        &'a self,
        client_id: &'a str,
    ) -> AuthorizationFuture<'a, Option<ClientAuthenticationSnapshot>> {
        self.snapshot_calls.fetch_add(1, Ordering::SeqCst);
        self.inner.client_authentication_snapshot(client_id)
    }

    fn mtls_trust_anchor_bundle(&self, client_id: Uuid) -> AuthorizationFuture<'_, String> {
        self.inner.mtls_trust_anchor_bundle(client_id)
    }

    fn grant<'a>(
        &'a self,
        user_id: Uuid,
        client_id: Uuid,
    ) -> AuthorizationFuture<'a, Option<StoredAuthorizationGrant>> {
        self.inner.grant(user_id, client_id)
    }

    fn commit_decision(
        &self,
        input: nazo_auth::AuthorizationDecisionCommit,
    ) -> AuthorizationFuture<'_, nazo_auth::AuthorizationDecisionCommitResult> {
        self.inner.commit_decision(input)
    }

    fn client_secret_digest_matches<'a>(
        &'a self,
        client_id: Uuid,
        candidate_digest: &'a str,
    ) -> AuthorizationFuture<'a, bool> {
        self.digest_calls.fetch_add(1, Ordering::SeqCst);
        self.inner
            .client_secret_digest_matches(client_id, candidate_digest)
    }
}
