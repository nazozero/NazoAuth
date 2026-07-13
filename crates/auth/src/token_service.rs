use std::{future::Future, pin::Pin};

use chrono::{DateTime, Utc};
use nazo_identity::SubjectClaims;
use serde_json::Value;
use uuid::Uuid;

use crate::{
    AuthorizationCodeState, CodePayload, ConsumedAuthorizationCode, NewRefreshToken, OAuthClient,
    OidcClaimRequest, RefreshToken, RefreshTokenPersistResult,
};

pub type TokenFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, TokenPortError>> + Send + 'a>>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TokenPortError {
    Unavailable,
    Conflict,
    CorruptData,
    InvalidSenderConstraint,
    Unexpected,
}

impl std::fmt::Display for TokenPortError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Unavailable => "token dependency unavailable",
            Self::Conflict => "token state conflict",
            Self::CorruptData => "corrupt token state",
            Self::InvalidSenderConstraint => "multiple sender constraints are not allowed",
            Self::Unexpected => "unexpected token dependency failure",
        })
    }
}

impl std::error::Error for TokenPortError {}

#[derive(Clone, Debug)]
pub enum AuthorizationCodeBeginResult {
    Consuming(CodePayload),
    Busy,
    Consumed(AuthorizationCodeState),
    Failed,
    Missing,
    Malformed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthorizationCodeTransitionResult {
    Applied,
    Missing,
    Malformed,
    Pending,
    Consuming,
    Consumed,
    Failed,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IssuedAccessToken {
    pub token: String,
    pub jti: String,
    pub expires_at: i64,
}

pub struct AccessTokenSignInput<'a> {
    pub issuer: &'a str,
    pub tenant_id: Uuid,
    pub subject: &'a str,
    pub user_id: Option<Uuid>,
    pub subject_type: &'a str,
    pub client_id: &'a str,
    pub audiences: &'a [String],
    pub scopes: &'a [String],
    pub authorization_details: &'a Value,
    pub userinfo_claims: &'a [String],
    pub userinfo_claim_requests: &'a [OidcClaimRequest],
    pub ttl_seconds: i64,
    pub dpop_jkt: Option<&'a str>,
    pub mtls_x5t_s256: Option<&'a str>,
    pub actor: Option<&'a Value>,
}

pub struct IdTokenSignInput<'a> {
    pub issuer: &'a str,
    pub subject: &'a str,
    pub client_id: &'a str,
    pub nonce: Option<&'a str>,
    pub auth_time: Option<i64>,
    pub amr: &'a [String],
    pub sid: Option<&'a str>,
    pub acr: Option<&'a str>,
    pub extra_claims: Option<&'a Value>,
    pub ttl_seconds: i64,
    pub signing_algorithm: Option<&'a str>,
}

pub struct IssuedAuthorizationCodeTokens<'a> {
    pub tenant_id: Uuid,
    pub client_id: Uuid,
    pub code_hash: &'a str,
    pub access_token_jti: &'a str,
    pub access_token_expires_at: i64,
    pub refresh_token_family_id: Option<Uuid>,
    pub consumed_state_ttl_seconds: u64,
}

pub trait TokenRepositoryPort: Send + Sync {
    fn client_by_id(&self, client_id: Uuid) -> TokenFuture<'_, Option<OAuthClient>>;

    fn refresh_token<'a>(
        &'a self,
        tenant_id: Uuid,
        raw_token: &'a str,
    ) -> TokenFuture<'a, Option<RefreshToken>>;

    fn lost_response_successor_or_compromise<'a>(
        &'a self,
        token: &'a RefreshToken,
        client_id: Uuid,
        retry_started_at: DateTime<Utc>,
    ) -> TokenFuture<'a, Option<RefreshToken>>;

    fn persist_refresh_token<'a>(
        &'a self,
        token: NewRefreshToken,
    ) -> TokenFuture<'a, RefreshTokenPersistResult>;

    fn active_subject_claims(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
    ) -> TokenFuture<'_, Option<SubjectClaims>>;

    fn revoke_issued_tokens<'a>(
        &'a self,
        tenant_id: Uuid,
        client_id: Uuid,
        access_token_jti: &'a str,
        access_token_expires_at: Option<DateTime<Utc>>,
        refresh_token_family_id: Option<Uuid>,
    ) -> TokenFuture<'a, ()>;
}

pub trait TokenStateStorePort: Send + Sync {
    fn load_authorization_code<'a>(
        &'a self,
        code_hash: &'a str,
    ) -> TokenFuture<'a, Option<AuthorizationCodeState>>;

    fn begin_authorization_code<'a>(
        &'a self,
        code_hash: &'a str,
        consuming_at: DateTime<Utc>,
    ) -> TokenFuture<'a, AuthorizationCodeBeginResult>;

    fn mark_authorization_code<'a>(
        &'a self,
        code_hash: &'a str,
        replacement: &'a AuthorizationCodeState,
        ttl_seconds: u64,
    ) -> TokenFuture<'a, AuthorizationCodeTransitionResult>;

    fn store_access_token_subject<'a>(
        &'a self,
        tenant_id: Uuid,
        jti: &'a str,
        user_id: Uuid,
        ttl_seconds: u64,
    ) -> TokenFuture<'a, ()>;
}

pub trait TokenSignerPort: Send + Sync {
    fn sign_access_token<'a>(
        &'a self,
        input: AccessTokenSignInput<'a>,
    ) -> TokenFuture<'a, IssuedAccessToken>;

    fn sign_id_token<'a>(&'a self, input: IdTokenSignInput<'a>) -> TokenFuture<'a, String>;
}

pub struct TokenService<R, S, K> {
    repository: R,
    state: S,
    signer: K,
}

impl<R, S, K> TokenService<R, S, K>
where
    R: TokenRepositoryPort,
    S: TokenStateStorePort,
    K: TokenSignerPort,
{
    pub const fn new(repository: R, state: S, signer: K) -> Self {
        Self {
            repository,
            state,
            signer,
        }
    }

    pub async fn refresh_token(
        &self,
        tenant_id: Uuid,
        raw_token: &str,
    ) -> Result<Option<RefreshToken>, TokenPortError> {
        self.repository.refresh_token(tenant_id, raw_token).await
    }

    pub async fn client_by_id(
        &self,
        client_id: Uuid,
    ) -> Result<Option<OAuthClient>, TokenPortError> {
        self.repository.client_by_id(client_id).await
    }

    pub async fn recover_lost_refresh_response(
        &self,
        token: &RefreshToken,
        client_id: Uuid,
        retry_started_at: DateTime<Utc>,
    ) -> Result<Option<RefreshToken>, TokenPortError> {
        self.repository
            .lost_response_successor_or_compromise(token, client_id, retry_started_at)
            .await
    }

    pub async fn persist_refresh_token(
        &self,
        token: NewRefreshToken,
    ) -> Result<RefreshTokenPersistResult, TokenPortError> {
        self.repository.persist_refresh_token(token).await
    }

    pub async fn active_subject_claims(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
    ) -> Result<Option<SubjectClaims>, TokenPortError> {
        self.repository
            .active_subject_claims(tenant_id, user_id)
            .await
    }

    pub async fn revoke_issued_tokens(
        &self,
        tenant_id: Uuid,
        client_id: Uuid,
        access_token_jti: &str,
        access_token_expires_at: Option<DateTime<Utc>>,
        refresh_token_family_id: Option<Uuid>,
    ) -> Result<(), TokenPortError> {
        self.repository
            .revoke_issued_tokens(
                tenant_id,
                client_id,
                access_token_jti,
                access_token_expires_at,
                refresh_token_family_id,
            )
            .await
    }

    pub async fn load_authorization_code(
        &self,
        code_hash: &str,
    ) -> Result<Option<AuthorizationCodeState>, TokenPortError> {
        self.state.load_authorization_code(code_hash).await
    }

    pub async fn begin_authorization_code(
        &self,
        code_hash: &str,
        consuming_at: DateTime<Utc>,
    ) -> Result<AuthorizationCodeBeginResult, TokenPortError> {
        self.state
            .begin_authorization_code(code_hash, consuming_at)
            .await
    }

    pub async fn mark_authorization_code_failed(
        &self,
        code_hash: &str,
        error: &str,
        ttl_seconds: u64,
    ) -> Result<AuthorizationCodeTransitionResult, TokenPortError> {
        self.state
            .mark_authorization_code(
                code_hash,
                &AuthorizationCodeState::Failed {
                    failed_at: Utc::now(),
                    error: error.to_owned(),
                },
                ttl_seconds,
            )
            .await
    }

    pub async fn finalize_authorization_code(
        &self,
        issued: IssuedAuthorizationCodeTokens<'_>,
    ) -> Result<(), TokenPortError> {
        let marker = AuthorizationCodeState::Consumed {
            marker: ConsumedAuthorizationCode {
                client_id: issued.client_id,
                access_token_jti: issued.access_token_jti.to_owned(),
                access_token_expires_at: issued.access_token_expires_at,
                refresh_token_family_id: issued.refresh_token_family_id,
                consumed_at: Utc::now(),
            },
        };
        let transition = self
            .state
            .mark_authorization_code(issued.code_hash, &marker, issued.consumed_state_ttl_seconds)
            .await;
        if matches!(transition, Ok(AuthorizationCodeTransitionResult::Applied)) {
            return Ok(());
        }

        let expiry = DateTime::<Utc>::from_timestamp(issued.access_token_expires_at, 0);
        self.repository
            .revoke_issued_tokens(
                issued.tenant_id,
                issued.client_id,
                issued.access_token_jti,
                expiry,
                issued.refresh_token_family_id,
            )
            .await?;
        Err(transition.err().unwrap_or(TokenPortError::Conflict))
    }

    pub async fn store_access_token_subject(
        &self,
        tenant_id: Uuid,
        jti: &str,
        user_id: Uuid,
        ttl_seconds: u64,
    ) -> Result<(), TokenPortError> {
        self.state
            .store_access_token_subject(tenant_id, jti, user_id, ttl_seconds)
            .await
    }

    pub async fn sign_access_token(
        &self,
        input: AccessTokenSignInput<'_>,
    ) -> Result<IssuedAccessToken, TokenPortError> {
        validate_sender_constraint(input.dpop_jkt, input.mtls_x5t_s256)?;
        self.signer.sign_access_token(input).await
    }

    pub async fn sign_id_token(
        &self,
        input: IdTokenSignInput<'_>,
    ) -> Result<String, TokenPortError> {
        self.signer.sign_id_token(input).await
    }
}

pub fn validate_sender_constraint(
    dpop_jkt: Option<&str>,
    mtls_x5t_s256: Option<&str>,
) -> Result<(), TokenPortError> {
    if dpop_jkt.is_some() && mtls_x5t_s256.is_some() {
        return Err(TokenPortError::InvalidSenderConstraint);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{TokenPortError, validate_sender_constraint};

    #[test]
    fn access_token_cannot_bind_two_sender_constraints() {
        assert_eq!(
            validate_sender_constraint(Some("dpop"), Some("mtls")),
            Err(TokenPortError::InvalidSenderConstraint)
        );
        assert!(validate_sender_constraint(Some("dpop"), None).is_ok());
        assert!(validate_sender_constraint(None, Some("mtls")).is_ok());
    }
}
