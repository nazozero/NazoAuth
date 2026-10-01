use std::{future::Future, pin::Pin};

use chrono::{DateTime, Duration, Utc};
use serde_json::Value;
use uuid::Uuid;

use crate::{
    AuthorizationCodeState, AuthorizationRequestError, AuthorizationResponsePolicyError,
    ConsentPayload, JarmAuthorizationResponse, JwtBearerGrantError, NormalizedRequestObject,
    OAuthClient, PushedAuthorizationRequest, PushedAuthorizationRequestConsumeError,
    RequestObjectClaims, RequestObjectPolicy, SignedJarmAuthorizationResponse,
    ValidatedJwtBearerAssertion, authorization_details_empty,
    authorization_request::{apply_request_object_plan, prepare_request_object},
    canonical_authorization_details, high_risk_authorization_details,
};

pub type AuthorizationFuture<'a, T> =
    Pin<Box<dyn Future<Output = Result<T, AuthorizationPortError>> + Send + 'a>>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthorizationPortError {
    Unavailable,
    Conflict,
    CorruptData,
    Unexpected,
}

impl std::fmt::Display for AuthorizationPortError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Unavailable => "authorization dependency unavailable",
            Self::Conflict => "authorization state conflict",
            Self::CorruptData => "authorization state contains corrupt data",
            Self::Unexpected => "unexpected authorization dependency failure",
        })
    }
}

impl std::error::Error for AuthorizationPortError {}

#[derive(Clone, Debug, PartialEq)]
pub struct StoredAuthorizationGrant {
    pub scopes: Value,
    pub resource_indicators: Value,
    pub authorization_details: Value,
}

/// A committed decision, not an acknowledgement that its response was delivered.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthorizationDecisionKind {
    Approve,
    Deny,
    PromptNone,
}

impl AuthorizationDecisionKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Approve => "approve",
            Self::Deny => "deny",
            Self::PromptNone => "prompt_none",
        }
    }
}

/// One owned durable action: consume request/PAR identities, apply the grant
/// change when appropriate, and retain the immutable decision fact together.
/// Implementations must not emulate atomicity across independent adapters.
#[derive(Clone, Debug)]
pub struct AuthorizationDecisionCommit {
    pub tenant_id: Uuid,
    pub user_id: Uuid,
    pub client_id: String,
    pub request_id: String,
    pub pushed_request_uri: Option<String>,
    pub valid_until: DateTime<Utc>,
    pub retain_until: DateTime<Utc>,
    pub decision: AuthorizationDecisionKind,
    pub event_id: Uuid,
    pub occurred_at: DateTime<Utc>,
    pub audit_fields: Value,
    pub scopes: Vec<String>,
    pub resource_indicators: Vec<String>,
    pub authorization_details: Value,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthorizationDecisionCommitResult {
    Committed,
    Conflict,
    Expired,
    ClientUnavailable,
    GrantUnavailable,
}

/// Prepared in memory; this is not a usable authorization code until the
/// decision commit succeeds and the state adapter accepts its Pending state.
pub struct PreparedAuthorizationCode {
    pub tenant_id: Uuid,
    pub hash: String,
    pub payload: crate::CodePayload,
    pub ttl_seconds: u64,
}

/// A parsed authorization state and the opaque storage version read with it.
/// The adapter must compare this version without reserializing the payload.
#[derive(Clone, Debug)]
pub struct AuthorizationStateSnapshot<T> {
    pub payload: T,
    pub version: String,
}

/// Best-effort disposal of the exact preparation versions already observed.
/// A PAR mismatch leaves that PAR intact after the consent has been removed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[must_use]
pub enum DecisionMaterialDiscardOutcome {
    Discarded,
    ConsentMissingOrChanged,
    ParMissingOrChanged,
}

/// Failure of preparation cleanup, never a rollback of the durable decision.
/// `ConsentOrUnknown` also covers a lost response from a combined operation:
/// neither the completed phase nor whether anything was removed is then known.
#[derive(Debug, Eq, PartialEq)]
pub enum DecisionMaterialDiscardError<E = AuthorizationPortError> {
    ConsentOrUnknown(E),
    PushedRequest(E),
}

pub type DecisionMaterialDiscardFuture<'a> = Pin<
    Box<
        dyn Future<Output = Result<DecisionMaterialDiscardOutcome, DecisionMaterialDiscardError>>
            + Send
            + 'a,
    >,
>;

/// Immutable preparation and original expiry observed during validation.
/// The durable decision commit owns consumption; versions only protect later
/// best-effort disposal of the preparation objects.
#[derive(Clone, Debug)]
pub struct ConsentAdmissionPreview {
    consent: ConsentPayload,
    consent_version: String,
    pushed_request_version: Option<String>,
    valid_until: DateTime<Utc>,
    retain_until: DateTime<Utc>,
}

impl ConsentAdmissionPreview {
    pub fn consent(&self) -> &ConsentPayload {
        &self.consent
    }

    pub fn valid_until(&self) -> DateTime<Utc> {
        self.valid_until
    }

    pub fn retain_until(&self) -> DateTime<Utc> {
        self.retain_until
    }

    pub fn into_consent(self) -> ConsentPayload {
        self.consent
    }
}

#[derive(Clone, Debug)]
pub enum AuthorizationDecisionAdmissionError {
    ConsentMissing,
    ConsentMalformed,
    ConsentReadFailed(AuthorizationPortError),
    UserMismatch,
    PushedRequestMissing(Box<ConsentPayload>),
    PushedRequestMalformed(Box<ConsentPayload>),
    PushedRequestReadFailed {
        consent: Box<ConsentPayload>,
        source: AuthorizationPortError,
    },
}

impl std::fmt::Display for AuthorizationDecisionAdmissionError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::ConsentMissing => "authorization consent is missing or expired",
            Self::ConsentMalformed => "authorization consent is malformed",
            Self::ConsentReadFailed(_) => "authorization consent store is unavailable",
            Self::UserMismatch => "authorization consent belongs to another user",
            Self::PushedRequestMissing(_) => "pushed authorization request is missing or expired",
            Self::PushedRequestMalformed(_) => "pushed authorization request is malformed",
            Self::PushedRequestReadFailed { .. } => {
                "pushed authorization request store is unavailable"
            }
        })
    }
}

impl std::error::Error for AuthorizationDecisionAdmissionError {}

pub struct AuthorizationApprovalInput<'a> {
    pub consent: &'a ConsentPayload,
    pub code_hash: &'a str,
    pub code_id: &'a str,
    pub issued_at: DateTime<Utc>,
    pub code_ttl_seconds: u64,
    pub tenant_id: Uuid,
}

pub fn prepare_authorization_code(
    input: AuthorizationApprovalInput<'_>,
) -> PreparedAuthorizationCode {
    let consent = input.consent;
    let code_payload = crate::CodePayload {
        code_id: input.code_id.to_owned(),
        user_id: consent.user_id,
        client_id: consent.client_id.clone(),
        redirect_uri: consent.redirect_uri.clone(),
        redirect_uri_was_supplied: consent.redirect_uri_was_supplied,
        scopes: consent.scopes.clone(),
        resource_indicators: consent.resource_indicators.clone(),
        authorization_details: consent.authorization_details.clone(),
        nonce: consent.nonce.clone(),
        auth_time: consent.auth_time,
        amr: consent.amr.clone(),
        oidc_sid: consent.oidc_sid.clone(),
        acr: consent.acr.clone(),
        userinfo_claims: consent.userinfo_claims.clone(),
        userinfo_claim_requests: consent.userinfo_claim_requests.clone(),
        id_token_claims: consent.id_token_claims.clone(),
        id_token_claim_requests: consent.id_token_claim_requests.clone(),
        code_challenge: consent.code_challenge.clone(),
        code_challenge_method: consent.code_challenge_method.clone(),
        dpop_jkt: consent.dpop_jkt.clone(),
        mtls_x5t_s256: consent.mtls_x5t_s256.clone(),
        issued_at: input.issued_at,
        expires_at: input.issued_at
            + Duration::seconds(input.code_ttl_seconds.try_into().unwrap_or(i64::MAX)),
    };
    PreparedAuthorizationCode {
        tenant_id: input.tenant_id,
        hash: input.code_hash.to_owned(),
        payload: code_payload,
        ttl_seconds: input.code_ttl_seconds,
    }
}

pub fn pushed_authorization_request_digest(
    request: &PushedAuthorizationRequest,
) -> Result<String, AuthorizationPortError> {
    #[derive(serde::Serialize)]
    struct CanonicalPushedAuthorizationRequest<'a> {
        client_id: &'a str,
        params: std::collections::BTreeMap<&'a str, &'a str>,
        dpop_jkt: Option<&'a str>,
        mtls_x5t_s256: Option<&'a str>,
        issued_at: &'a DateTime<Utc>,
        expires_at: &'a DateTime<Utc>,
    }

    let canonical = CanonicalPushedAuthorizationRequest {
        client_id: &request.client_id,
        params: request
            .params
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_str()))
            .collect(),
        dpop_jkt: request.dpop_jkt.as_deref(),
        mtls_x5t_s256: request.mtls_x5t_s256.as_deref(),
        issued_at: &request.issued_at,
        expires_at: &request.expires_at,
    };
    serde_json::to_vec(&canonical)
        .map(|encoded| blake3::hash(&encoded).to_hex().to_string())
        .map_err(|_| AuthorizationPortError::Unexpected)
}

#[derive(Clone, Copy)]
pub struct AuthorizationResponseSignInput<'a> {
    pub issuer: &'a str,
    pub client_id: &'a str,
    pub code: Option<&'a str>,
    pub error: Option<&'a str>,
    pub state: Option<&'a str>,
    pub ttl: i64,
    pub signing_algorithm: Option<&'a str>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthorizationRateDimension {
    Token,
    TokenManagement,
}

/// Client metadata together with the salt derived from its stored secret
/// verifier. Authentication loads both in one read; `secret_salt` is absent
/// when the client has no usable secret verifier or is inactive.
#[derive(Clone, Debug)]
pub struct ClientAuthenticationSnapshot {
    /// Version observed with the authenticated client; issuance rechecks it under lock.
    pub client_epoch: i64,
    pub client: OAuthClient,
    pub secret_salt: Option<String>,
}

pub trait AuthorizationRepositoryPort: Send + Sync {
    /// Only Committed permits code publication. Unavailable may mean an
    /// unknown commit outcome; callers must not release or replace its fence.
    fn commit_decision<'a>(
        &'a self,
        input: AuthorizationDecisionCommit,
    ) -> AuthorizationFuture<'a, AuthorizationDecisionCommitResult>;

    fn client_by_id<'a>(
        &'a self,
        client_id: &'a str,
    ) -> AuthorizationFuture<'a, Option<OAuthClient>>;
    fn client_authentication_snapshot<'a>(
        &'a self,
        client_id: &'a str,
    ) -> AuthorizationFuture<'a, Option<ClientAuthenticationSnapshot>>;
    fn mtls_trust_anchor_bundle(&self, client_id: Uuid) -> AuthorizationFuture<'_, String>;
    fn grant<'a>(
        &'a self,
        user_id: Uuid,
        client_id: Uuid,
    ) -> AuthorizationFuture<'a, Option<StoredAuthorizationGrant>>;
    fn client_secret_digest_matches<'a>(
        &'a self,
        client_id: Uuid,
        candidate_digest: &'a str,
    ) -> AuthorizationFuture<'a, bool>;
}

pub trait AuthorizationStateStorePort: Send + Sync {
    fn load_par<'a>(
        &'a self,
        request_uri: &'a str,
    ) -> AuthorizationFuture<'a, Option<AuthorizationStateSnapshot<PushedAuthorizationRequest>>>;
    /// Consume only the exact storage version returned by `load_par`.
    fn compare_and_delete_par<'a>(
        &'a self,
        request_uri: &'a str,
        expected: &'a str,
    ) -> AuthorizationFuture<'a, bool>;
    fn store_par<'a>(
        &'a self,
        request_uri: &'a str,
        payload: &'a PushedAuthorizationRequest,
        ttl_seconds: u64,
    ) -> AuthorizationFuture<'a, ()>;
    fn load_consent<'a>(
        &'a self,
        request_id: &'a str,
    ) -> AuthorizationFuture<'a, Option<AuthorizationStateSnapshot<ConsentPayload>>>;
    fn take_consent<'a>(
        &'a self,
        request_id: &'a str,
    ) -> AuthorizationFuture<'a, Option<ConsentPayload>>;
    /// Consume only the exact storage version returned by `load_consent`.
    fn compare_and_delete_consent<'a>(
        &'a self,
        request_id: &'a str,
        expected: &'a str,
    ) -> AuthorizationFuture<'a, bool>;
    /// Discard consent first, then its optional PAR, using opaque raw versions.
    /// A confirmed consent mismatch/error leaves PAR untouched; a later PAR
    /// failure does not restore consent. A lost response can leave either
    /// cleanup outcome unknown. This is not consumption authority.
    fn discard_decision_material<'a>(
        &'a self,
        request_id: &'a str,
        expected_consent: &'a str,
        pushed_request: Option<(&'a str, &'a str)>,
    ) -> DecisionMaterialDiscardFuture<'a> {
        Box::pin(async move {
            if !self
                .compare_and_delete_consent(request_id, expected_consent)
                .await
                .map_err(DecisionMaterialDiscardError::ConsentOrUnknown)?
            {
                return Ok(DecisionMaterialDiscardOutcome::ConsentMissingOrChanged);
            }
            if let Some((request_uri, expected)) = pushed_request
                && !self
                    .compare_and_delete_par(request_uri, expected)
                    .await
                    .map_err(DecisionMaterialDiscardError::PushedRequest)?
            {
                return Ok(DecisionMaterialDiscardOutcome::ParMissingOrChanged);
            }
            Ok(DecisionMaterialDiscardOutcome::Discarded)
        })
    }
    fn store_consent<'a>(
        &'a self,
        request_id: &'a str,
        payload: &'a ConsentPayload,
        ttl_seconds: u64,
    ) -> AuthorizationFuture<'a, ()>;
    fn store_authorization_code<'a>(
        &'a self,
        code_hash: &'a str,
        state: &'a AuthorizationCodeState,
        ttl_seconds: u64,
    ) -> AuthorizationFuture<'a, ()>;
    fn delete_authorization_code<'a>(&'a self, code_hash: &'a str) -> AuthorizationFuture<'a, ()>;
    fn take_reauth_nonce<'a>(&'a self, nonce: &'a str) -> AuthorizationFuture<'a, Option<i64>>;
    fn store_reauth_nonce<'a>(
        &'a self,
        nonce: &'a str,
        started_at: i64,
        ttl_seconds: u64,
    ) -> AuthorizationFuture<'a, ()>;
    fn consume_jar<'a>(
        &'a self,
        client_id: &'a str,
        jti: &'a str,
        ttl_seconds: u64,
    ) -> AuthorizationFuture<'a, bool>;
    fn consume_private_key_jwt<'a>(
        &'a self,
        client_id: &'a str,
        jti: &'a str,
        ttl_seconds: u64,
    ) -> AuthorizationFuture<'a, bool>;
    fn consume_jwt_bearer<'a>(
        &'a self,
        client_id: &'a str,
        jti: &'a str,
        ttl_seconds: u64,
    ) -> AuthorizationFuture<'a, bool>;
    fn consume_ciba_request_object<'a>(
        &'a self,
        client_id: &'a str,
        jti: &'a str,
        ttl_seconds: u64,
    ) -> AuthorizationFuture<'a, bool>;
    fn consume_dpop<'a>(
        &'a self,
        thumbprint: &'a str,
        jti: &'a str,
        ttl_seconds: u64,
    ) -> AuthorizationFuture<'a, bool>;
    fn issue_dpop_nonce<'a>(
        &'a self,
        nonce: &'a str,
        ttl_seconds: u64,
    ) -> AuthorizationFuture<'a, ()>;
    fn validate_dpop_nonce<'a>(&'a self, nonce: &'a str) -> AuthorizationFuture<'a, bool>;
    fn increment_rate<'a>(
        &'a self,
        dimension: AuthorizationRateDimension,
        subject: &'a str,
        window_seconds: u64,
    ) -> AuthorizationFuture<'a, u64>;
}

impl<T> AuthorizationStateStorePort for std::sync::Arc<T>
where
    T: AuthorizationStateStorePort + ?Sized,
{
    fn load_par<'a>(
        &'a self,
        request_uri: &'a str,
    ) -> AuthorizationFuture<'a, Option<AuthorizationStateSnapshot<PushedAuthorizationRequest>>>
    {
        self.as_ref().load_par(request_uri)
    }

    fn compare_and_delete_par<'a>(
        &'a self,
        request_uri: &'a str,
        expected: &'a str,
    ) -> AuthorizationFuture<'a, bool> {
        self.as_ref().compare_and_delete_par(request_uri, expected)
    }

    fn store_par<'a>(
        &'a self,
        request_uri: &'a str,
        payload: &'a PushedAuthorizationRequest,
        ttl_seconds: u64,
    ) -> AuthorizationFuture<'a, ()> {
        self.as_ref().store_par(request_uri, payload, ttl_seconds)
    }

    fn load_consent<'a>(
        &'a self,
        request_id: &'a str,
    ) -> AuthorizationFuture<'a, Option<AuthorizationStateSnapshot<ConsentPayload>>> {
        self.as_ref().load_consent(request_id)
    }

    fn take_consent<'a>(
        &'a self,
        request_id: &'a str,
    ) -> AuthorizationFuture<'a, Option<ConsentPayload>> {
        self.as_ref().take_consent(request_id)
    }

    fn compare_and_delete_consent<'a>(
        &'a self,
        request_id: &'a str,
        expected: &'a str,
    ) -> AuthorizationFuture<'a, bool> {
        self.as_ref()
            .compare_and_delete_consent(request_id, expected)
    }

    fn discard_decision_material<'a>(
        &'a self,
        request_id: &'a str,
        expected_consent: &'a str,
        pushed_request: Option<(&'a str, &'a str)>,
    ) -> DecisionMaterialDiscardFuture<'a> {
        self.as_ref()
            .discard_decision_material(request_id, expected_consent, pushed_request)
    }

    fn store_consent<'a>(
        &'a self,
        request_id: &'a str,
        payload: &'a ConsentPayload,
        ttl_seconds: u64,
    ) -> AuthorizationFuture<'a, ()> {
        self.as_ref()
            .store_consent(request_id, payload, ttl_seconds)
    }

    fn store_authorization_code<'a>(
        &'a self,
        code_hash: &'a str,
        state: &'a AuthorizationCodeState,
        ttl_seconds: u64,
    ) -> AuthorizationFuture<'a, ()> {
        self.as_ref()
            .store_authorization_code(code_hash, state, ttl_seconds)
    }

    fn delete_authorization_code<'a>(&'a self, code_hash: &'a str) -> AuthorizationFuture<'a, ()> {
        self.as_ref().delete_authorization_code(code_hash)
    }

    fn take_reauth_nonce<'a>(&'a self, nonce: &'a str) -> AuthorizationFuture<'a, Option<i64>> {
        self.as_ref().take_reauth_nonce(nonce)
    }

    fn store_reauth_nonce<'a>(
        &'a self,
        nonce: &'a str,
        started_at: i64,
        ttl_seconds: u64,
    ) -> AuthorizationFuture<'a, ()> {
        self.as_ref()
            .store_reauth_nonce(nonce, started_at, ttl_seconds)
    }

    fn consume_jar<'a>(
        &'a self,
        client_id: &'a str,
        jti: &'a str,
        ttl_seconds: u64,
    ) -> AuthorizationFuture<'a, bool> {
        self.as_ref().consume_jar(client_id, jti, ttl_seconds)
    }

    fn consume_private_key_jwt<'a>(
        &'a self,
        client_id: &'a str,
        jti: &'a str,
        ttl_seconds: u64,
    ) -> AuthorizationFuture<'a, bool> {
        self.as_ref()
            .consume_private_key_jwt(client_id, jti, ttl_seconds)
    }

    fn consume_jwt_bearer<'a>(
        &'a self,
        client_id: &'a str,
        jti: &'a str,
        ttl_seconds: u64,
    ) -> AuthorizationFuture<'a, bool> {
        self.as_ref()
            .consume_jwt_bearer(client_id, jti, ttl_seconds)
    }

    fn consume_ciba_request_object<'a>(
        &'a self,
        client_id: &'a str,
        jti: &'a str,
        ttl_seconds: u64,
    ) -> AuthorizationFuture<'a, bool> {
        self.as_ref()
            .consume_ciba_request_object(client_id, jti, ttl_seconds)
    }

    fn consume_dpop<'a>(
        &'a self,
        thumbprint: &'a str,
        jti: &'a str,
        ttl_seconds: u64,
    ) -> AuthorizationFuture<'a, bool> {
        self.as_ref().consume_dpop(thumbprint, jti, ttl_seconds)
    }

    fn issue_dpop_nonce<'a>(
        &'a self,
        nonce: &'a str,
        ttl_seconds: u64,
    ) -> AuthorizationFuture<'a, ()> {
        self.as_ref().issue_dpop_nonce(nonce, ttl_seconds)
    }

    fn validate_dpop_nonce<'a>(&'a self, nonce: &'a str) -> AuthorizationFuture<'a, bool> {
        self.as_ref().validate_dpop_nonce(nonce)
    }

    fn increment_rate<'a>(
        &'a self,
        dimension: AuthorizationRateDimension,
        subject: &'a str,
        window_seconds: u64,
    ) -> AuthorizationFuture<'a, u64> {
        self.as_ref()
            .increment_rate(dimension, subject, window_seconds)
    }
}

pub trait AuthorizationResponseSignerPort: Send + Sync {
    fn sign_authorization_response<'a>(
        &'a self,
        input: AuthorizationResponseSignInput<'a>,
    ) -> AuthorizationFuture<'a, String>;
}

pub struct AuthorizationService<S, K> {
    repository: std::sync::Arc<dyn AuthorizationRepositoryPort>,
    state: S,
    signer: K,
}

impl<S, K> AuthorizationService<S, K>
where
    S: AuthorizationStateStorePort,
    K: AuthorizationResponseSignerPort,
{
    pub fn new<R>(repository: R, state: S, signer: K) -> Self
    where
        R: AuthorizationRepositoryPort + 'static,
    {
        Self {
            repository: std::sync::Arc::new(repository),
            state,
            signer,
        }
    }

    pub fn from_port(
        repository: std::sync::Arc<dyn AuthorizationRepositoryPort>,
        state: S,
        signer: K,
    ) -> Self {
        Self {
            repository,
            state,
            signer,
        }
    }

    pub async fn client_by_id(
        &self,
        client_id: &str,
    ) -> Result<Option<OAuthClient>, AuthorizationPortError> {
        self.repository.client_by_id(client_id).await
    }

    pub async fn client_authentication_snapshot(
        &self,
        client_id: &str,
    ) -> Result<Option<ClientAuthenticationSnapshot>, AuthorizationPortError> {
        self.repository
            .client_authentication_snapshot(client_id)
            .await
    }

    pub async fn mtls_trust_anchor_bundle(
        &self,
        client_id: Uuid,
    ) -> Result<String, AuthorizationPortError> {
        self.repository.mtls_trust_anchor_bundle(client_id).await
    }

    pub async fn client_secret_digest_matches(
        &self,
        client_id: Uuid,
        candidate: &str,
    ) -> Result<bool, AuthorizationPortError> {
        self.repository
            .client_secret_digest_matches(client_id, candidate)
            .await
    }

    pub async fn grant_covers(
        &self,
        user_id: Uuid,
        client_id: Uuid,
        scopes: &[String],
        resources: &[String],
        details: &Value,
    ) -> Result<bool, AuthorizationPortError> {
        Ok(self
            .repository
            .grant(user_id, client_id)
            .await?
            .as_ref()
            .is_some_and(|stored| {
                stored_grant_covers_requested_authorization(stored, scopes, resources, details)
            }))
    }

    /// Commit the effective decision and its fact before publishing a code.
    /// A later code-store failure is approved-but-undelivered: never compensate
    /// the durable grant or free the consumption fence.
    pub async fn commit_decision(
        &self,
        mut input: AuthorizationDecisionCommit,
        code: Option<PreparedAuthorizationCode>,
    ) -> Result<AuthorizationDecisionCommitResult, AuthorizationPortError> {
        if (input.decision == AuthorizationDecisionKind::Deny) != code.is_none() {
            return Err(AuthorizationPortError::CorruptData);
        }
        if let Some(code) = code.as_ref() {
            if input.tenant_id != code.tenant_id
                || input.user_id != code.payload.user_id
                || input.client_id != code.payload.client_id
                || input.scopes != code.payload.scopes
                || input.resource_indicators != code.payload.resource_indicators
                || input.authorization_details != code.payload.authorization_details
            {
                return Err(AuthorizationPortError::CorruptData);
            }
            let encoded = serde_json::to_vec(&code.payload)
                .map_err(|_| AuthorizationPortError::CorruptData)?;
            let fields = input
                .audit_fields
                .as_object_mut()
                .ok_or(AuthorizationPortError::CorruptData)?;
            fields.insert(
                "code_id".to_owned(),
                Value::String(code.payload.code_id.clone()),
            );
            fields.insert("code_hash".to_owned(), Value::String(code.hash.clone()));
            fields.insert(
                "code_payload_digest".to_owned(),
                Value::String(blake3::hash(&encoded).to_hex().to_string()),
            );
            input.retain_until = input.retain_until.max(code.payload.expires_at);
        }
        let result = self.repository.commit_decision(input).await?;
        if result == AuthorizationDecisionCommitResult::Committed
            && let Some(code) = code
        {
            self.state
                .store_authorization_code(
                    &code.hash,
                    &AuthorizationCodeState::Pending {
                        payload: code.payload,
                    },
                    code.ttl_seconds,
                )
                .await?;
        }
        Ok(result)
    }

    /// Loads and validates a consent transaction for the authenticated user
    /// without deleting any state. The returned snapshot is the exact state a
    /// later `discard_decision_material` must still observe: the compare-and-delete
    /// claims only that snapshot, so a replaced consent or pushed request fails
    /// instead of consuming replacement data.
    ///
    /// Preview is non-destructive. The decision repository, not this state
    /// adapter, owns the final tenant-scoped once-only consumption fence.
    pub async fn preview_user_decision(
        &self,
        request_id: &str,
        user_id: Uuid,
    ) -> Result<ConsentAdmissionPreview, AuthorizationDecisionAdmissionError> {
        let AuthorizationStateSnapshot {
            payload: consent,
            version: consent_version,
        } = match self.state.load_consent(request_id).await {
            Ok(Some(consent)) => consent,
            Ok(None) => return Err(AuthorizationDecisionAdmissionError::ConsentMissing),
            Err(AuthorizationPortError::CorruptData) => {
                return Err(AuthorizationDecisionAdmissionError::ConsentMalformed);
            }
            Err(error) => {
                return Err(AuthorizationDecisionAdmissionError::ConsentReadFailed(
                    error,
                ));
            }
        };
        if consent.user_id != user_id {
            return Err(AuthorizationDecisionAdmissionError::UserMismatch);
        }

        let mut pushed_request_version = None;
        let mut valid_until = consent.expires_at;
        let mut retain_until = consent.expires_at;
        if let Some(request_uri) = consent.pushed_request_uri.as_deref() {
            let AuthorizationStateSnapshot {
                payload: pushed,
                version,
            } = match self.state.load_par(request_uri).await {
                Ok(Some(pushed)) => pushed,
                Ok(None) => {
                    return Err(AuthorizationDecisionAdmissionError::PushedRequestMissing(
                        Box::new(consent),
                    ));
                }
                Err(AuthorizationPortError::CorruptData) => {
                    return Err(AuthorizationDecisionAdmissionError::PushedRequestMalformed(
                        Box::new(consent),
                    ));
                }
                Err(source) => {
                    return Err(
                        AuthorizationDecisionAdmissionError::PushedRequestReadFailed {
                            consent: Box::new(consent),
                            source,
                        },
                    );
                }
            };
            if let Some(expected_digest) = consent.pushed_request_digest.as_deref() {
                let actual_digest =
                    pushed_authorization_request_digest(&pushed).map_err(|source| {
                        AuthorizationDecisionAdmissionError::PushedRequestReadFailed {
                            consent: Box::new(consent.clone()),
                            source,
                        }
                    })?;
                if expected_digest != actual_digest {
                    return Err(AuthorizationDecisionAdmissionError::PushedRequestMissing(
                        Box::new(consent),
                    ));
                }
            }
            valid_until = valid_until.min(pushed.expires_at);
            retain_until = retain_until.max(pushed.expires_at);
            pushed_request_version = Some(version);
        }
        Ok(ConsentAdmissionPreview {
            consent,
            consent_version,
            pushed_request_version,
            valid_until,
            retain_until,
        })
    }

    /// Discards preparation after a committed decision. This is not authority.
    /// Each compare-and-delete fails when the stored row no longer matches the
    /// previewed snapshot, so a concurrently replaced consent or pushed request
    /// is never consumed.
    pub async fn discard_decision_material(
        &self,
        request_id: &str,
        preview: &ConsentAdmissionPreview,
    ) -> Result<(), AuthorizationDecisionAdmissionError> {
        let consent = &preview.consent;
        let pushed_request = preview.pushed_request_version.as_deref().map(|version| {
            let request_uri = consent
                .pushed_request_uri
                .as_deref()
                .expect("a previewed pushed request implies its consent uri");
            (request_uri, version)
        });
        match self
            .state
            .discard_decision_material(request_id, &preview.consent_version, pushed_request)
            .await
        {
            Ok(DecisionMaterialDiscardOutcome::Discarded) => Ok(()),
            Ok(DecisionMaterialDiscardOutcome::ConsentMissingOrChanged) => {
                Err(AuthorizationDecisionAdmissionError::ConsentMissing)
            }
            Ok(DecisionMaterialDiscardOutcome::ParMissingOrChanged) => Err(
                AuthorizationDecisionAdmissionError::PushedRequestMissing(Box::new(
                    consent.clone(),
                )),
            ),
            // Keep the existing protocol mapping for an unconfirmed cleanup.
            // A combined call may have removed either object before its reply
            // was lost; this error does not establish a rollback or its phase.
            Err(DecisionMaterialDiscardError::ConsentOrUnknown(error)) => {
                Err(AuthorizationDecisionAdmissionError::ConsentReadFailed(error))
            }
            Err(DecisionMaterialDiscardError::PushedRequest(source)) => {
                Err(AuthorizationDecisionAdmissionError::PushedRequestReadFailed {
                    consent: Box::new(consent.clone()),
                    source,
                })
            }
        }
    }

    pub async fn load_par(
        &self,
        uri: &str,
    ) -> Result<
        Option<AuthorizationStateSnapshot<PushedAuthorizationRequest>>,
        AuthorizationPortError,
    > {
        self.state.load_par(uri).await
    }
    pub async fn store_par(
        &self,
        uri: &str,
        payload: &PushedAuthorizationRequest,
        ttl: u64,
    ) -> Result<(), AuthorizationPortError> {
        self.state.store_par(uri, payload, ttl).await
    }
    pub async fn load_consent(
        &self,
        id: &str,
    ) -> Result<Option<ConsentPayload>, AuthorizationPortError> {
        Ok(self
            .state
            .load_consent(id)
            .await?
            .map(|snapshot| snapshot.payload))
    }
    pub async fn take_consent(
        &self,
        id: &str,
    ) -> Result<Option<ConsentPayload>, AuthorizationPortError> {
        self.state.take_consent(id).await
    }
    pub async fn store_consent(
        &self,
        id: &str,
        payload: &ConsentPayload,
        ttl: u64,
    ) -> Result<(), AuthorizationPortError> {
        self.state.store_consent(id, payload, ttl).await
    }
    pub async fn take_reauth_nonce(
        &self,
        nonce: &str,
    ) -> Result<Option<i64>, AuthorizationPortError> {
        self.state.take_reauth_nonce(nonce).await
    }
    pub async fn store_reauth_nonce(
        &self,
        nonce: &str,
        started_at: i64,
        ttl: u64,
    ) -> Result<(), AuthorizationPortError> {
        self.state.store_reauth_nonce(nonce, started_at, ttl).await
    }
    pub async fn consume_jar(
        &self,
        client_id: &str,
        jti: &str,
        ttl: u64,
    ) -> Result<bool, AuthorizationPortError> {
        self.state.consume_jar(client_id, jti, ttl).await
    }

    /// Validates a verified request object and commits its replay marker only
    /// after all pure claim and outer-parameter policy has succeeded.
    pub async fn admit_request_object(
        &self,
        outer: &std::collections::HashMap<String, String>,
        claims: &RequestObjectClaims,
        policy: RequestObjectPolicy<'_>,
    ) -> Result<NormalizedRequestObject, AuthorizationRequestError> {
        let mut outer = outer.clone();
        self.admit_request_object_owned(&mut outer, claims, policy)
            .await
    }

    /// Validates a verified request object while reusing the caller's outer
    /// parameter map. Policy failures leave the map untouched.
    pub async fn admit_request_object_owned(
        &self,
        outer: &mut std::collections::HashMap<String, String>,
        claims: &RequestObjectClaims,
        policy: RequestObjectPolicy<'_>,
    ) -> Result<NormalizedRequestObject, AuthorizationRequestError> {
        let plan = prepare_request_object(outer, claims, policy)?;
        if let Some(replay) = plan.replay() {
            super::authorization_request::classify_request_object_replay(
                self.state
                    .consume_jar(&replay.client_id, &replay.jti, replay.ttl_seconds)
                    .await,
            )?;
        }
        Ok(apply_request_object_plan(outer, plan))
    }

    /// Discards only the already-committed PAR preparation version.
    /// The durable decision repository owns authorization and consumption.
    pub async fn discard_pushed_authorization_request(
        &self,
        request_uri: &str,
        expected_version: &str,
    ) -> Result<(), PushedAuthorizationRequestConsumeError> {
        match self
            .state
            .compare_and_delete_par(request_uri, expected_version)
            .await
        {
            Ok(true) => Ok(()),
            Ok(false) => Err(PushedAuthorizationRequestConsumeError::Missing),
            Err(error) => Err(PushedAuthorizationRequestConsumeError::Dependency(error)),
        }
    }
    pub async fn consume_private_key_jwt(
        &self,
        client_id: &str,
        jti: &str,
        ttl: u64,
    ) -> Result<bool, AuthorizationPortError> {
        self.state
            .consume_private_key_jwt(client_id, jti, ttl)
            .await
    }

    pub async fn consume_jwt_bearer(
        &self,
        client_id: &str,
        jti: &str,
        ttl: u64,
    ) -> Result<bool, AuthorizationPortError> {
        self.state.consume_jwt_bearer(client_id, jti, ttl).await
    }

    pub async fn consume_ciba_request_object(
        &self,
        client_id: &str,
        jti: &str,
        ttl: u64,
    ) -> Result<bool, AuthorizationPortError> {
        self.state
            .consume_ciba_request_object(client_id, jti, ttl)
            .await
    }

    pub async fn consume_jwt_bearer_assertion(
        &self,
        client_id: &str,
        assertion: &ValidatedJwtBearerAssertion,
    ) -> Result<(), JwtBearerGrantError> {
        super::extension_grants::classify_jwt_bearer_replay(
            self.state
                .consume_jwt_bearer(client_id, &assertion.jti, assertion.replay_ttl_seconds)
                .await,
        )
    }
    pub async fn consume_dpop(
        &self,
        thumbprint: &str,
        jti: &str,
        ttl: u64,
    ) -> Result<bool, AuthorizationPortError> {
        self.state.consume_dpop(thumbprint, jti, ttl).await
    }
    pub async fn issue_dpop_nonce(
        &self,
        nonce: &str,
        ttl: u64,
    ) -> Result<(), AuthorizationPortError> {
        self.state.issue_dpop_nonce(nonce, ttl).await
    }
    pub async fn validate_dpop_nonce(&self, nonce: &str) -> Result<bool, AuthorizationPortError> {
        self.state.validate_dpop_nonce(nonce).await
    }
    pub async fn increment_rate(
        &self,
        subject: &str,
        window: u64,
    ) -> Result<u64, AuthorizationPortError> {
        self.state
            .increment_rate(AuthorizationRateDimension::TokenManagement, subject, window)
            .await
    }

    pub async fn increment_token_rate(
        &self,
        subject: &str,
        window: u64,
    ) -> Result<u64, AuthorizationPortError> {
        self.state
            .increment_rate(AuthorizationRateDimension::Token, subject, window)
            .await
    }
    pub async fn sign_authorization_response(
        &self,
        input: AuthorizationResponseSignInput<'_>,
    ) -> Result<String, AuthorizationPortError> {
        self.signer.sign_authorization_response(input).await
    }

    pub async fn sign_jarm_authorization_response(
        &self,
        response: &JarmAuthorizationResponse,
        signing_algorithm: Option<&str>,
    ) -> Result<SignedJarmAuthorizationResponse, AuthorizationResponsePolicyError> {
        let signed = self
            .signer
            .sign_authorization_response(response.signing_input(signing_algorithm))
            .await
            .map_err(AuthorizationResponsePolicyError::Dependency)?;
        Ok(SignedJarmAuthorizationResponse {
            redirect_uri: response.redirect_uri.clone(),
            response: signed,
        })
    }
}

#[must_use]
pub fn stored_grant_covers_requested_authorization(
    stored: &StoredAuthorizationGrant,
    scopes: &[String],
    resources: &[String],
    details: &Value,
) -> bool {
    fn strings(value: &Value) -> std::collections::HashSet<&str> {
        value
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .collect()
    }
    let stored_scopes = strings(&stored.scopes);
    let stored_resources = strings(&stored.resource_indicators);
    if !scopes
        .iter()
        .all(|value| stored_scopes.contains(value.as_str()))
        || !resources
            .iter()
            .all(|value| stored_resources.contains(value.as_str()))
    {
        return false;
    }
    authorization_details_empty(details)
        || (!high_risk_authorization_details(details)
            && canonical_authorization_details(&stored.authorization_details).ok()
                == canonical_authorization_details(details).ok())
}

#[cfg(test)]
#[path = "../tests/unit/authorization_service.rs"]
mod tests;
