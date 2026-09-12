use std::{future::Future, pin::Pin};

use nazo_identity::{
    AccountProfileView, AuthorizedApplicationsView, PendingMfaProfileView, ProfilePatch,
    ProfileValidationError, SessionId,
};

pub type ProfileAccountFuture<'a, T> =
    Pin<Box<dyn Future<Output = Result<T, ProfileAccountError>> + Send + 'a>>;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProfileMe {
    Active(Box<AccountProfileView>),
    PendingMfa(PendingMfaProfileView),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProfileAccountError {
    LoginRequired,
    SessionLookupUnavailable,
    OverviewUnavailable,
    Validation(ProfileValidationError),
    UpdateUnavailable,
    UpdatedOverviewUnavailable,
    ApplicationsUnavailable,
}

pub trait ProfileAccountOperations: Send + Sync {
    fn me(&self, session_id: SessionId) -> ProfileAccountFuture<'_, ProfileMe>;

    fn update(
        &self,
        session_id: SessionId,
        patch: ProfilePatch,
    ) -> ProfileAccountFuture<'_, AccountProfileView>;

    fn applications(
        &self,
        session_id: SessionId,
    ) -> ProfileAccountFuture<'_, AuthorizedApplicationsView>;
}
