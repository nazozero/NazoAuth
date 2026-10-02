use crate::{Error, ValkeyConnection, command, keys};
use nazo_identity::TenantId;
use serde_json::Value;

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredEmailVerificationCode {
    owner: String,
    password_hash: String,
}

const DELETE_OWNED_EMAIL_CODE: &str = r#"
local raw = redis.call('GET', KEYS[1])
if not raw then return 'missing' end
local ok, value = pcall(cjson.decode, raw)
if not ok or type(value) ~= 'table' or value.owner ~= ARGV[1] then
  return 'changed'
end
redis.call('DEL', KEYS[1])
return 'deleted'
"#;

#[derive(Clone, Debug)]
pub struct AuthenticationStore {
    connection: ValkeyConnection,
}
impl AuthenticationStore {
    pub fn new(connection: &ValkeyConnection) -> Self {
        Self { connection: connection.clone() }
    }
    pub async fn reserve_email_send(&self, tenant_id: TenantId, email: &str, owner: &str, ttl: u64) -> Result<bool, Error> {
        command::set_ex_nx_string(&self.connection, keys::email_send(tenant_id, email), owner.to_owned(), ttl).await
    }
    pub async fn reserve_email_peer_send(&self, tenant_id: TenantId, subject: &str, owner: &str, ttl: u64) -> Result<bool, Error> {
        command::set_ex_nx_string(&self.connection, keys::email_peer_send(tenant_id, subject), owner.to_owned(), ttl).await
    }
    pub async fn store_email_code(&self, tenant_id: TenantId, email: &str, owner: &str, code: &str, ttl: u64) -> Result<(), Error> {
        let raw = serde_json::to_string(&StoredEmailVerificationCode { owner: owner.to_owned(), password_hash: code.to_owned() })
            .map_err(|_| Error::protocol("failed to serialize owned email verification code"))?;
        command::set_ex_string(&self.connection, keys::email_code(tenant_id, email), raw, ttl).await
    }
    pub async fn load_email_code(&self, tenant_id: TenantId, email: &str) -> Result<Option<String>, Error> {
        command::get(&self.connection, keys::email_code(tenant_id, email)).await?
            .map(|raw| serde_json::from_str::<StoredEmailVerificationCode>(&raw).map(|stored| stored.password_hash).map_err(|_| Error::corrupt_data("malformed owned email verification code"))).transpose()
    }
    async fn delete_email_code(&self, tenant_id: TenantId, email: &str, owner: &str) -> Result<(), Error> {
        match command::eval_string(&self.connection, DELETE_OWNED_EMAIL_CODE, vec![keys::email_code(tenant_id, email)], vec![owner.to_owned()]).await?.as_str() {
            "deleted" | "missing" | "changed" => Ok(()),
            _ => Err(Error::unexpected("unexpected owned email-code cleanup reply")),
        }
    }
    async fn delete_email_send(&self, tenant_id: TenantId, email: &str, owner: &str) -> Result<(), Error> {
        command::compare_delete(&self.connection, keys::email_send(tenant_id, email), owner).await.map(|_| ())
    }
    async fn delete_email_peer_send(&self, tenant_id: TenantId, subject: &str, owner: &str) -> Result<(), Error> {
        command::compare_delete(&self.connection, keys::email_peer_send(tenant_id, subject), owner).await.map(|_| ())
    }
    pub async fn store_passkey_registration(
        &self,
        id: &str,
        value: &Value,
        ttl: u64,
    ) -> Result<(), Error> {
        self.store_value(keys::passkey_registration(id), value, ttl)
            .await
    }
    pub async fn take_passkey_registration(&self, id: &str) -> Result<Option<Value>, Error> {
        self.take_value(keys::passkey_registration(id)).await
    }
    pub async fn store_passkey_authentication(
        &self,
        id: &str,
        value: &Value,
        ttl: u64,
    ) -> Result<(), Error> {
        self.store_value(keys::passkey_authentication(id), value, ttl)
            .await
    }
    pub async fn take_passkey_authentication(&self, id: &str) -> Result<Option<Value>, Error> {
        self.take_value(keys::passkey_authentication(id)).await
    }
    pub async fn store_oidc_federation(
        &self,
        state: &str,
        value: &Value,
        ttl: u64,
    ) -> Result<(), Error> {
        self.store_value(keys::oidc_federation(state), value, ttl)
            .await
    }
    pub async fn take_oidc_federation(&self, state: &str) -> Result<Option<Value>, Error> {
        self.take_value(keys::oidc_federation(state)).await
    }
    pub async fn store_social_federation(
        &self,
        state: &str,
        value: &Value,
        ttl: u64,
    ) -> Result<(), Error> {
        self.store_value(keys::social_federation(state), value, ttl)
            .await
    }
    pub async fn take_social_federation(&self, state: &str) -> Result<Option<Value>, Error> {
        self.take_value(keys::social_federation(state)).await
    }
    pub async fn reserve_saml_federation_replay(
        &self,
        signature: &str,
        ttl: u64,
    ) -> Result<bool, Error> {
        command::set_ex_nx(
            &self.connection,
            keys::saml_federation_replay(signature),
            "1",
            ttl,
        )
        .await
    }
    async fn store_value(&self, key: String, value: &Value, ttl: u64) -> Result<(), Error> {
        let raw = serde_json::to_string(value).map_err(|e| {
            Error::protocol(format!("failed to serialize authentication state: {e}"))
        })?;
        command::set_ex_string(&self.connection, key, raw, ttl).await
    }
    async fn take_value(&self, key: String) -> Result<Option<Value>, Error> {
        command::take(&self.connection, key)
            .await?
            .map(|raw| {
                serde_json::from_str(&raw).map_err(|e| {
                    Error::corrupt_data(format!("malformed authentication state: {e}"))
                })
            })
            .transpose()
    }
}

impl nazo_identity::ports::EmailVerificationStorePort for AuthenticationStore {
    fn reserve_peer_send<'a>(
        &'a self,
        tenant_id: TenantId,
        subject: &'a str,
        owner: &'a str,
        ttl_seconds: u64,
    ) -> nazo_identity::ports::RepositoryFuture<'a, bool> {
        Box::pin(async move {
            self.reserve_email_peer_send(tenant_id, subject, owner, ttl_seconds)
                .await
                .map_err(crate::identity_repository_error)
        })
    }

    fn reserve_email_send<'a>(
        &'a self,
        tenant_id: TenantId,
        email: &'a str,
        owner: &'a str,
        ttl_seconds: u64,
    ) -> nazo_identity::ports::RepositoryFuture<'a, bool> {
        Box::pin(async move {
            AuthenticationStore::reserve_email_send(self, tenant_id, email, owner, ttl_seconds)
                .await
                .map_err(crate::identity_repository_error)
        })
    }

    fn store_code<'a>(
        &'a self,
        tenant_id: TenantId,
        email: &'a str,
        owner: &'a str,
        password_hash: nazo_identity::ports::PasswordHashInput,
        ttl_seconds: u64,
    ) -> nazo_identity::ports::RepositoryFuture<'a, ()> {
        Box::pin(async move {
            self.store_email_code(
                tenant_id,
                email,
                owner,
                &password_hash.into_persistence_value(),
                ttl_seconds,
            )
            .await
            .map_err(crate::identity_repository_error)
        })
    }

    fn load_code<'a>(
        &'a self,
        tenant_id: TenantId,
        email: &'a str,
    ) -> nazo_identity::ports::RepositoryFuture<
        'a,
        Option<nazo_identity::ports::EmailVerificationRecord>,
    > {
        Box::pin(async move {
            let raw = command::get(&self.connection, keys::email_code(tenant_id, email))
                .await
                .map_err(crate::identity_repository_error)?;
            raw.map(|raw| {
                let stored: StoredEmailVerificationCode = serde_json::from_str(&raw).map_err(|_| nazo_identity::ports::RepositoryError::Consistency("malformed owned email verification code".to_owned()))?;
                let password_hash =
                    nazo_identity::PasswordHash::new(stored.password_hash).map_err(|error| {
                        nazo_identity::ports::RepositoryError::Consistency(error.to_string())
                    })?;
                Ok(nazo_identity::ports::EmailVerificationRecord {
                    password_hash,
                    opaque_version: raw,
                })
            })
            .transpose()
        })
    }

    fn consume_code<'a>(
        &'a self,
        tenant_id: TenantId,
        email: &'a str,
        expected: &'a nazo_identity::ports::EmailVerificationRecord,
    ) -> nazo_identity::ports::RepositoryFuture<'a, nazo_identity::ports::EmailVerificationConsume>
    {
        Box::pin(async move {
            command::compare_delete(
                &self.connection,
                keys::email_code(tenant_id, email),
                &expected.opaque_version,
            )
            .await
            .map(|outcome| match outcome {
                command::CompareDelete::Deleted => {
                    nazo_identity::ports::EmailVerificationConsume::Consumed
                }
                command::CompareDelete::MissingOrChanged => {
                    nazo_identity::ports::EmailVerificationConsume::MissingOrChanged
                }
            })
            .map_err(crate::identity_repository_error)
        })
    }

    fn delete_code<'a>(
        &'a self,
        tenant_id: TenantId,
        email: &'a str,
        owner: &'a str,
    ) -> nazo_identity::ports::RepositoryFuture<'a, ()> {
        Box::pin(async move {
            self.delete_email_code(tenant_id, email, owner)
                .await
                .map(|_| ())
                .map_err(crate::identity_repository_error)
        })
    }

    fn release_email_send<'a>(
        &'a self,
        tenant_id: TenantId,
        email: &'a str,
        owner: &'a str,
    ) -> nazo_identity::ports::RepositoryFuture<'a, ()> {
        Box::pin(async move {
            self.delete_email_send(tenant_id, email, owner)
                .await
                .map(|_| ())
                .map_err(crate::identity_repository_error)
        })
    }

    fn release_peer_send<'a>(
        &'a self,
        tenant_id: TenantId,
        subject: &'a str,
        owner: &'a str,
    ) -> nazo_identity::ports::RepositoryFuture<'a, ()> {
        Box::pin(async move {
            self.delete_email_peer_send(tenant_id, subject, owner)
                .await
                .map(|_| ())
                .map_err(crate::identity_repository_error)
        })
    }
}

impl nazo_identity::ports::PasskeyCeremonyPort for AuthenticationStore {
    fn store_registration<'a>(
        &'a self,
        ceremony_id: &'a str,
        ceremony: &'a nazo_identity::StoredPasskeyRegistration,
        ttl_seconds: u64,
    ) -> nazo_identity::ports::RepositoryFuture<'a, ()> {
        Box::pin(async move {
            let value = serde_json::to_value(ceremony).map_err(|error| {
                nazo_identity::ports::RepositoryError::Unexpected(error.to_string())
            })?;
            self.store_passkey_registration(ceremony_id, &value, ttl_seconds)
                .await
                .map_err(crate::identity_repository_error)
        })
    }

    fn take_registration<'a>(
        &'a self,
        ceremony_id: &'a str,
    ) -> nazo_identity::ports::RepositoryFuture<'a, Option<nazo_identity::StoredPasskeyRegistration>>
    {
        Box::pin(async move {
            self.take_passkey_registration(ceremony_id)
                .await
                .map_err(crate::identity_repository_error)?
                .map(serde_json::from_value)
                .transpose()
                .map_err(|error| {
                    nazo_identity::ports::RepositoryError::Consistency(error.to_string())
                })
        })
    }

    fn store_authentication<'a>(
        &'a self,
        ceremony_id: &'a str,
        ceremony: &'a nazo_identity::StoredPasskeyAuthentication,
        ttl_seconds: u64,
    ) -> nazo_identity::ports::RepositoryFuture<'a, ()> {
        Box::pin(async move {
            let value = serde_json::to_value(ceremony).map_err(|error| {
                nazo_identity::ports::RepositoryError::Unexpected(error.to_string())
            })?;
            self.store_passkey_authentication(ceremony_id, &value, ttl_seconds)
                .await
                .map_err(crate::identity_repository_error)
        })
    }

    fn take_authentication<'a>(
        &'a self,
        ceremony_id: &'a str,
    ) -> nazo_identity::ports::RepositoryFuture<
        'a,
        Option<nazo_identity::StoredPasskeyAuthentication>,
    > {
        Box::pin(async move {
            self.take_passkey_authentication(ceremony_id)
                .await
                .map_err(crate::identity_repository_error)?
                .map(serde_json::from_value)
                .transpose()
                .map_err(|error| {
                    nazo_identity::ports::RepositoryError::Consistency(error.to_string())
                })
        })
    }
}

impl nazo_identity::ports::FederationStatePort for AuthenticationStore {
    fn store_oidc<'a>(
        &'a self,
        state: &'a str,
        value: &'a nazo_identity::OidcFederationState,
        ttl_seconds: u64,
    ) -> nazo_identity::ports::RepositoryFuture<'a, ()> {
        Box::pin(async move {
            let value = serde_json::to_value(value).map_err(|error| {
                nazo_identity::ports::RepositoryError::Unexpected(error.to_string())
            })?;
            self.store_oidc_federation(state, &value, ttl_seconds)
                .await
                .map_err(crate::identity_repository_error)
        })
    }

    fn take_oidc<'a>(
        &'a self,
        state: &'a str,
    ) -> nazo_identity::ports::RepositoryFuture<'a, Option<nazo_identity::OidcFederationState>>
    {
        Box::pin(async move {
            self.take_oidc_federation(state)
                .await
                .map_err(crate::identity_repository_error)?
                .map(serde_json::from_value)
                .transpose()
                .map_err(|error| {
                    nazo_identity::ports::RepositoryError::Consistency(error.to_string())
                })
        })
    }

    fn store_social<'a>(
        &'a self,
        state: &'a str,
        value: &'a nazo_identity::SocialFederationState,
        ttl_seconds: u64,
    ) -> nazo_identity::ports::RepositoryFuture<'a, ()> {
        Box::pin(async move {
            let value = serde_json::to_value(value).map_err(|error| {
                nazo_identity::ports::RepositoryError::Unexpected(error.to_string())
            })?;
            self.store_social_federation(state, &value, ttl_seconds)
                .await
                .map_err(crate::identity_repository_error)
        })
    }

    fn take_social<'a>(
        &'a self,
        state: &'a str,
    ) -> nazo_identity::ports::RepositoryFuture<'a, Option<nazo_identity::SocialFederationState>>
    {
        Box::pin(async move {
            self.take_social_federation(state)
                .await
                .map_err(crate::identity_repository_error)?
                .map(serde_json::from_value)
                .transpose()
                .map_err(|error| {
                    nazo_identity::ports::RepositoryError::Consistency(error.to_string())
                })
        })
    }

    fn reserve_saml_replay<'a>(
        &'a self,
        assertion_signature: &'a str,
        ttl_seconds: u64,
    ) -> nazo_identity::ports::RepositoryFuture<'a, bool> {
        Box::pin(async move {
            self.reserve_saml_federation_replay(assertion_signature, ttl_seconds)
                .await
                .map_err(crate::identity_repository_error)
        })
    }
}
