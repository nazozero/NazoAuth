use crate::{Error, ValkeyConnection, command, keys};
use serde_json::Value;

#[derive(Clone, Debug)]
pub struct AuthenticationStore {
    connection: ValkeyConnection,
}
impl AuthenticationStore {
    pub fn new(connection: &ValkeyConnection) -> Self {
        Self {
            connection: connection.clone(),
        }
    }
    pub async fn reserve_email_send(&self, email: &str, ttl: u64) -> Result<bool, Error> {
        command::set_ex_nx(&self.connection, keys::email_send(email), "1", ttl).await
    }
    pub async fn reserve_email_peer_send(&self, subject: &str, ttl: u64) -> Result<bool, Error> {
        command::set_ex_nx(&self.connection, keys::email_peer_send(subject), "1", ttl).await
    }
    pub async fn store_email_code(&self, email: &str, code: &str, ttl: u64) -> Result<(), Error> {
        command::set_ex_string(
            &self.connection,
            keys::email_code(email),
            code.to_owned(),
            ttl,
        )
        .await
    }
    pub async fn load_email_code(&self, email: &str) -> Result<Option<String>, Error> {
        command::get(&self.connection, keys::email_code(email)).await
    }
    pub async fn delete_email_code(&self, email: &str) -> Result<i64, Error> {
        command::delete(&self.connection, keys::email_code(email)).await
    }
    pub async fn delete_email_send(&self, email: &str) -> Result<i64, Error> {
        command::delete(&self.connection, keys::email_send(email)).await
    }
    pub async fn delete_email_peer_send(&self, subject: &str) -> Result<i64, Error> {
        command::delete(&self.connection, keys::email_peer_send(subject)).await
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
        subject: &'a str,
        ttl_seconds: u64,
    ) -> nazo_identity::ports::RepositoryFuture<'a, bool> {
        Box::pin(async move {
            self.reserve_email_peer_send(subject, ttl_seconds)
                .await
                .map_err(crate::identity_repository_error)
        })
    }

    fn reserve_email_send<'a>(
        &'a self,
        email: &'a str,
        ttl_seconds: u64,
    ) -> nazo_identity::ports::RepositoryFuture<'a, bool> {
        Box::pin(async move {
            AuthenticationStore::reserve_email_send(self, email, ttl_seconds)
                .await
                .map_err(crate::identity_repository_error)
        })
    }

    fn store_code<'a>(
        &'a self,
        email: &'a str,
        password_hash: nazo_identity::ports::PasswordHashInput,
        ttl_seconds: u64,
    ) -> nazo_identity::ports::RepositoryFuture<'a, ()> {
        Box::pin(async move {
            self.store_email_code(email, &password_hash.into_persistence_value(), ttl_seconds)
                .await
                .map_err(crate::identity_repository_error)
        })
    }

    fn load_code<'a>(
        &'a self,
        email: &'a str,
    ) -> nazo_identity::ports::RepositoryFuture<
        'a,
        Option<nazo_identity::ports::EmailVerificationRecord>,
    > {
        Box::pin(async move {
            let raw = self
                .load_email_code(email)
                .await
                .map_err(crate::identity_repository_error)?;
            raw.map(|raw| {
                let password_hash =
                    nazo_identity::PasswordHash::new(raw.clone()).map_err(|error| {
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
        email: &'a str,
        expected: &'a nazo_identity::ports::EmailVerificationRecord,
    ) -> nazo_identity::ports::RepositoryFuture<'a, nazo_identity::ports::EmailVerificationConsume>
    {
        Box::pin(async move {
            command::compare_delete(
                &self.connection,
                keys::email_code(email),
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

    fn delete_code<'a>(&'a self, email: &'a str) -> nazo_identity::ports::RepositoryFuture<'a, ()> {
        Box::pin(async move {
            self.delete_email_code(email)
                .await
                .map(|_| ())
                .map_err(crate::identity_repository_error)
        })
    }

    fn release_email_send<'a>(
        &'a self,
        email: &'a str,
    ) -> nazo_identity::ports::RepositoryFuture<'a, ()> {
        Box::pin(async move {
            self.delete_email_send(email)
                .await
                .map(|_| ())
                .map_err(crate::identity_repository_error)
        })
    }

    fn release_peer_send<'a>(
        &'a self,
        subject: &'a str,
    ) -> nazo_identity::ports::RepositoryFuture<'a, ()> {
        Box::pin(async move {
            self.delete_email_peer_send(subject)
                .await
                .map(|_| ())
                .map_err(crate::identity_repository_error)
        })
    }
}
