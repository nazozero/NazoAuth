use std::{future::Future, pin::Pin};

use nazo_auth::UserAuthorizationDecision;
use nazo_identity::SessionId;

pub type AuthorizationDecisionFuture<'a> = Pin<
    Box<
        dyn Future<Output = Result<AuthorizationDecisionResponse, AuthorizationDecisionError>>
            + Send
            + 'a,
    >,
>;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorizationDecisionCommand {
    pub request_id: String,
    pub decision: UserAuthorizationDecision,
    pub session_id: SessionId,
    pub source_ip: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AuthorizationDecisionResponse {
    Redirect {
        location: String,
    },
    FormPost {
        action: String,
        parameters: Vec<(String, String)>,
        session_state: Option<String>,
        csp_nonce: String,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthorizationDecisionError {
    LoginRequired,
    SessionLookupUnavailable,
    ConsentInvalid,
    ConsentReadUnavailable,
    UserMismatch,
    AuditUnavailable,
    ApprovalUnavailable,
    UnsupportedResponseMode,
    ResponseProtectionUnavailable,
    ResponseSigningUnavailable,
}

pub trait AuthorizationDecisionOperations: Send + Sync {
    fn decide(&self, command: AuthorizationDecisionCommand) -> AuthorizationDecisionFuture<'_>;
}
