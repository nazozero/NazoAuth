use std::{future::Future, pin::Pin};

use nazo_identity::{
    TenantContext,
    ports::PasswordHashInput,
    scim::{ScimCursorSubject, ScimRequiredScope},
};
use nazo_scim_events::EventReceiver;

pub type ScimFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

pub struct ScimAuthenticationFacts<'a> {
    pub bearer_token: Option<&'a str>,
    pub source_ip: String,
    pub user_agent: Option<&'a str>,
}

#[derive(Clone, Debug)]
pub struct ScimAuthorizedRequest {
    pub tenant: TenantContext,
    pub cursor_subject: ScimCursorSubject,
    pub event_receiver: Option<EventReceiver>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScimAuthorizationError {
    Disabled,
    MissingBearer,
    InvalidBearer,
    InsufficientScope,
    TenantMismatch,
    EventReceiverNotConfigured,
    BackendUnavailable,
}

pub trait ScimRequestAuthorizer: Send + Sync {
    fn authorize<'a>(
        &'a self,
        facts: ScimAuthenticationFacts<'a>,
        required_scope: ScimRequiredScope,
    ) -> ScimFuture<'a, Result<ScimAuthorizedRequest, ScimAuthorizationError>>;

    fn security_events_enabled(&self) -> bool {
        false
    }

    fn security_event_delivery_enabled(&self) -> bool {
        self.security_events_enabled()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScimDependencyError {
    Unavailable,
}

pub trait ScimCursorProtector: Send + Sync {
    fn protect(&self, plaintext: &[u8]) -> Result<Vec<u8>, ScimDependencyError>;
    fn unprotect(&self, protected: &[u8]) -> Result<Vec<u8>, ScimDependencyError>;
}

pub trait ScimBootstrapPasswordProvider: Send + Sync {
    fn password_hash(&self) -> ScimFuture<'_, Result<PasswordHashInput, ScimDependencyError>>;
}
