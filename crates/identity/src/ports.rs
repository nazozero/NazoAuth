use std::{collections::HashMap, sync::Mutex};
use std::{future::Future, pin::Pin};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

use crate::{Principal, SubjectClaims, TenantContext, TenantId, UserId};

pub type RepositoryFuture<'a, T> =
    Pin<Box<dyn Future<Output = Result<T, RepositoryError>> + Send + 'a>>;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RepositoryError {
    Unavailable,
    Conflict,
    Consistency(String),
    Unexpected(String),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TotpCredential {
    pub secret_base32: String,
    pub last_used_step: Option<i64>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct PasskeyCredential {
    pub id: Uuid,
    pub tenant_id: TenantId,
    pub user_id: UserId,
    pub credential_id: String,
    pub credential: Value,
    pub label: String,
    pub sign_count: i64,
    pub last_used_at: Option<i64>,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct FederationLink {
    pub id: Uuid,
    pub tenant_id: TenantId,
    pub user_id: UserId,
    pub provider_type: String,
    pub provider_id: String,
    pub subject: String,
    pub email: String,
    pub claims: Value,
    pub created_at: i64,
    pub updated_at: i64,
    pub last_login_at: Option<i64>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct NewFederationLink {
    pub tenant_id: TenantId,
    pub user_id: UserId,
    pub provider_type: String,
    pub provider_id: String,
    pub subject: String,
    pub email: String,
    pub claims: Value,
}

pub trait UserRepositoryPort: Send + Sync {
    fn principal_by_id<'a>(
        &'a self,
        tenant: TenantContext,
        user_id: UserId,
    ) -> RepositoryFuture<'a, Option<Principal>>;

    fn subject_claims_by_id<'a>(
        &'a self,
        tenant: TenantContext,
        user_id: UserId,
    ) -> RepositoryFuture<'a, Option<SubjectClaims>>;
}

pub trait MfaRepositoryPort: Send + Sync {
    fn totp_credential<'a>(
        &'a self,
        tenant_id: TenantId,
        user_id: UserId,
    ) -> RepositoryFuture<'a, Option<TotpCredential>>;
    fn compare_and_set_totp_step<'a>(
        &'a self,
        tenant_id: TenantId,
        user_id: UserId,
        step: i64,
    ) -> RepositoryFuture<'a, bool>;

    fn consume_backup_code<'a>(
        &'a self,
        tenant_id: TenantId,
        user_id: UserId,
        normalized_code: &'a str,
    ) -> RepositoryFuture<'a, bool>;

    fn replace_backup_code_hashes<'a>(
        &'a self,
        tenant_id: TenantId,
        user_id: UserId,
        hashes: Vec<String>,
    ) -> RepositoryFuture<'a, ()>;

    fn clear_mfa_state<'a>(
        &'a self,
        tenant_id: TenantId,
        user_id: UserId,
    ) -> RepositoryFuture<'a, ()>;
}

#[derive(Default)]
pub struct FakeUserRepository {
    principals: Mutex<HashMap<(TenantId, UserId), Principal>>,
    claims: Mutex<HashMap<(TenantId, UserId), SubjectClaims>>,
}

impl FakeUserRepository {
    pub fn insert_principal(&self, principal: Principal) {
        self.principals
            .lock()
            .expect("fake repository mutex poisoned")
            .insert((principal.tenant.tenant_id, principal.user_id), principal);
    }

    pub fn insert_subject_claims(&self, tenant_id: TenantId, claims: SubjectClaims) {
        self.claims
            .lock()
            .expect("fake repository mutex poisoned")
            .insert((tenant_id, claims.subject), claims);
    }
}

impl UserRepositoryPort for FakeUserRepository {
    fn principal_by_id<'a>(
        &'a self,
        tenant: TenantContext,
        user_id: UserId,
    ) -> RepositoryFuture<'a, Option<Principal>> {
        Box::pin(async move {
            Ok(self
                .principals
                .lock()
                .map_err(|error| RepositoryError::Unexpected(error.to_string()))?
                .get(&(tenant.tenant_id, user_id))
                .cloned())
        })
    }

    fn subject_claims_by_id<'a>(
        &'a self,
        tenant: TenantContext,
        user_id: UserId,
    ) -> RepositoryFuture<'a, Option<SubjectClaims>> {
        Box::pin(async move {
            Ok(self
                .claims
                .lock()
                .map_err(|error| RepositoryError::Unexpected(error.to_string()))?
                .get(&(tenant.tenant_id, user_id))
                .cloned())
        })
    }
}
