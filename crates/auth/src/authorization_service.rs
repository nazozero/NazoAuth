use std::{future::Future, pin::Pin};

use serde_json::Value;
use uuid::Uuid;

use crate::{
    AuthorizationCodeState, ConsentPayload, OAuthClient, PushedAuthorizationRequest,
    authorization_details_empty, canonical_authorization_details, high_risk_authorization_details,
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

pub struct GrantWrite<'a> {
    pub tenant_id: Uuid,
    pub user_id: Uuid,
    pub client_id: Uuid,
    pub scopes: &'a [String],
    pub resource_indicators: &'a [String],
    pub authorization_details: &'a Value,
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
    TokenManagement,
}

pub trait AuthorizationRepositoryPort: Send + Sync {
    fn client_by_id<'a>(
        &'a self,
        client_id: &'a str,
    ) -> AuthorizationFuture<'a, Option<OAuthClient>>;
    fn grant<'a>(
        &'a self,
        user_id: Uuid,
        client_id: Uuid,
    ) -> AuthorizationFuture<'a, Option<StoredAuthorizationGrant>>;
    fn upsert_grant<'a>(&'a self, write: GrantWrite<'a>) -> AuthorizationFuture<'a, ()>;
    fn client_secret_salt<'a>(&'a self, client_id: Uuid)
    -> AuthorizationFuture<'a, Option<String>>;
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
    ) -> AuthorizationFuture<'a, Option<PushedAuthorizationRequest>>;
    fn take_par<'a>(
        &'a self,
        request_uri: &'a str,
    ) -> AuthorizationFuture<'a, Option<PushedAuthorizationRequest>>;
    fn store_par<'a>(
        &'a self,
        request_uri: &'a str,
        payload: &'a PushedAuthorizationRequest,
        ttl_seconds: u64,
    ) -> AuthorizationFuture<'a, ()>;
    fn load_consent<'a>(
        &'a self,
        request_id: &'a str,
    ) -> AuthorizationFuture<'a, Option<ConsentPayload>>;
    fn take_consent<'a>(
        &'a self,
        request_id: &'a str,
    ) -> AuthorizationFuture<'a, Option<ConsentPayload>>;
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
    fn consume_dpop_nonce<'a>(&'a self, nonce: &'a str) -> AuthorizationFuture<'a, bool>;
    fn increment_rate<'a>(
        &'a self,
        dimension: AuthorizationRateDimension,
        subject: &'a str,
        window_seconds: u64,
    ) -> AuthorizationFuture<'a, u64>;
}

pub trait AuthorizationResponseSignerPort: Send + Sync {
    fn sign_authorization_response<'a>(
        &'a self,
        input: AuthorizationResponseSignInput<'a>,
    ) -> AuthorizationFuture<'a, String>;
}

pub struct AuthorizationService<R, S, K> {
    repository: R,
    state: S,
    signer: K,
}

impl<R, S, K> AuthorizationService<R, S, K>
where
    R: AuthorizationRepositoryPort,
    S: AuthorizationStateStorePort,
    K: AuthorizationResponseSignerPort,
{
    pub const fn new(repository: R, state: S, signer: K) -> Self {
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

    pub async fn client_secret_salt(
        &self,
        client_id: Uuid,
    ) -> Result<Option<String>, AuthorizationPortError> {
        self.repository.client_secret_salt(client_id).await
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

    pub async fn approve(
        &self,
        code_hash: &str,
        code_state: &AuthorizationCodeState,
        code_ttl_seconds: u64,
        grant: GrantWrite<'_>,
    ) -> Result<(), AuthorizationPortError> {
        self.state
            .store_authorization_code(code_hash, code_state, code_ttl_seconds)
            .await?;
        if let Err(error) = self.repository.upsert_grant(grant).await {
            let _ = self.state.delete_authorization_code(code_hash).await;
            return Err(error);
        }
        Ok(())
    }

    pub async fn store_authorization_code(
        &self,
        hash: &str,
        state: &AuthorizationCodeState,
        ttl: u64,
    ) -> Result<(), AuthorizationPortError> {
        self.state.store_authorization_code(hash, state, ttl).await
    }

    pub async fn load_par(
        &self,
        uri: &str,
    ) -> Result<Option<PushedAuthorizationRequest>, AuthorizationPortError> {
        self.state.load_par(uri).await
    }
    pub async fn take_par(
        &self,
        uri: &str,
    ) -> Result<Option<PushedAuthorizationRequest>, AuthorizationPortError> {
        self.state.take_par(uri).await
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
        self.state.load_consent(id).await
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
    pub async fn consume_dpop_nonce(&self, nonce: &str) -> Result<bool, AuthorizationPortError> {
        self.state.consume_dpop_nonce(nonce).await
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
    pub async fn sign_authorization_response(
        &self,
        input: AuthorizationResponseSignInput<'_>,
    ) -> Result<String, AuthorizationPortError> {
        self.signer.sign_authorization_response(input).await
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
mod tests {
    use serde_json::json;

    use super::{StoredAuthorizationGrant, stored_grant_covers_requested_authorization};

    #[test]
    fn stored_grant_must_cover_every_scope_and_resource() {
        let stored = StoredAuthorizationGrant {
            scopes: json!(["openid", "profile"]),
            resource_indicators: json!(["https://api.example"]),
            authorization_details: json!([]),
        };

        assert!(stored_grant_covers_requested_authorization(
            &stored,
            &["openid".to_owned()],
            &["https://api.example".to_owned()],
            &json!([]),
        ));
        assert!(!stored_grant_covers_requested_authorization(
            &stored,
            &["email".to_owned()],
            &["https://api.example".to_owned()],
            &json!([]),
        ));
        assert!(!stored_grant_covers_requested_authorization(
            &stored,
            &["openid".to_owned()],
            &["https://other.example".to_owned()],
            &json!([]),
        ));
    }
}
