use std::{future::Future, pin::Pin};

use chrono::{DateTime, Utc};
use nazo_identity::{
    LoginSuccess, PasskeyError, PasskeyLoginBegin, PasskeyRegistrationBegin, RememberedMfaProof,
    ports::PasskeyCredential,
};
use passkey_auth::{AuthenticationResponse, RegistrationResponse};
use uuid::Uuid;

pub type PasskeyFuture<'a, T> =
    Pin<Box<dyn Future<Output = Result<T, PasskeyEndpointError>> + Send + 'a>>;

#[derive(Debug)]
pub enum PasskeyEndpointError {
    Core(PasskeyError),
    SessionMissing,
    SessionUnavailable,
}

impl From<PasskeyError> for PasskeyEndpointError {
    fn from(error: PasskeyError) -> Self {
        Self::Core(error)
    }
}

pub struct PasskeyLoginFinishCommand {
    pub ceremony_id: String,
    pub response: AuthenticationResponse,
    pub source_ip: String,
    pub remembered_mfa: Option<RememberedMfaProof>,
    pub previous_session_id: Option<String>,
    pub now: DateTime<Utc>,
}

pub trait PasskeyLoginOperations: Send + Sync {
    fn login_begin(&self, email: String) -> PasskeyFuture<'_, PasskeyLoginBegin>;

    fn login_finish(&self, command: PasskeyLoginFinishCommand) -> PasskeyFuture<'_, LoginSuccess>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PasskeyProfileContext {
    pub session_id: String,
    pub now: i64,
}

pub struct PasskeyRegistrationFinishCommand {
    pub context: PasskeyProfileContext,
    pub ceremony_id: String,
    pub response: RegistrationResponse,
}

pub trait PasskeyProfileOperations: Send + Sync {
    fn registration_begin(
        &self,
        context: PasskeyProfileContext,
        label: Option<String>,
    ) -> PasskeyFuture<'_, PasskeyRegistrationBegin>;

    fn registration_finish(
        &self,
        command: PasskeyRegistrationFinishCommand,
    ) -> PasskeyFuture<'_, PasskeyCredential>;

    fn list(&self, context: PasskeyProfileContext) -> PasskeyFuture<'_, Vec<PasskeyCredential>>;

    fn delete(&self, context: PasskeyProfileContext, passkey_id: Uuid) -> PasskeyFuture<'_, ()>;
}
