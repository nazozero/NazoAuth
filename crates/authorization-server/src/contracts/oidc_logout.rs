use std::{future::Future, pin::Pin};

pub type OidcLogoutFuture<'a> =
    Pin<Box<dyn Future<Output = Result<OidcLogoutSuccess, OidcLogoutError>> + Send + 'a>>;

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct OidcLogoutRequest {
    pub id_token_hint: Option<String>,
    pub client_id: Option<String>,
    pub post_logout_redirect_uri: Option<String>,
    pub state: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OidcLogoutCommand {
    pub request: OidcLogoutRequest,
    pub session_id: Option<String>,
    pub csrf_authorized: bool,
    pub user_confirmed: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OidcLogoutSuccess {
    pub redirect_uri: Option<String>,
    pub frontchannel_logout_urls: Vec<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OidcLogoutError {
    SessionLookupUnavailable,
    InvalidIdTokenHint,
    ClientAudienceMismatch,
    AmbiguousAudience,
    ClientRequiredForRedirect,
    ClientNotFound,
    ClientLookupUnavailable,
    RegisteredClientRequired,
    UnregisteredRedirect,
    InvalidRedirect,
    ConfirmationRequired,
    SigningUnavailable,
    OutboxUnavailable,
    SessionDeleteUnavailable,
}

pub trait OidcLogoutOperations: Send + Sync {
    fn logout(&self, command: OidcLogoutCommand) -> OidcLogoutFuture<'_>;
}

impl OidcLogoutError {
    pub const fn is_user_confirmable(self) -> bool {
        matches!(
            self,
            Self::InvalidIdTokenHint
                | Self::ClientAudienceMismatch
                | Self::AmbiguousAudience
                | Self::ClientRequiredForRedirect
                | Self::ClientNotFound
                | Self::RegisteredClientRequired
                | Self::UnregisteredRedirect
                | Self::InvalidRedirect
                | Self::ConfirmationRequired
        )
    }
}
