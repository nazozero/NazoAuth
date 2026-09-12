use std::{future::Future, pin::Pin};

pub type SessionManagementFuture<'a> =
    Pin<Box<dyn Future<Output = Result<Option<String>, SessionManagementError>> + Send + 'a>>;
pub type SessionManagementOriginFuture<'a> =
    Pin<Box<dyn Future<Output = Result<bool, SessionManagementError>> + Send + 'a>>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionManagementAvailability {
    Disabled,
    Enabled,
    Draining,
}

impl SessionManagementAvailability {
    pub const fn permits_existing_transaction(self) -> bool {
        matches!(self, Self::Enabled | Self::Draining)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionManagementError {
    SessionLookupUnavailable,
}

/// Storage and runtime-module boundary required by the session-management transport.
pub trait SessionManagementOperations: Send + Sync {
    fn availability(&self) -> SessionManagementAvailability;

    fn is_origin_allowed<'a>(
        &'a self,
        client_id: &'a str,
        origin: &'a str,
    ) -> SessionManagementOriginFuture<'a>;

    fn op_browser_state<'a>(&'a self, session_id: &'a str) -> SessionManagementFuture<'a>;
}
